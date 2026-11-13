import {
  collection,
  collectionGroup,
  doc,
  getDoc,
  getDocs,
  onSnapshot,
  query,
  setDoc,
  updateDoc,
  where,
  type DocumentReference,
  type Firestore
} from "firebase/firestore";
import {
  assertNoEmailInProfilePatch,
  assertValidResourceId,
  DEFAULT_LANYARD_META_COLLECTION,
  readStoredRevocationEpoch,
  REVOCATION_EPOCH_DOC_ID,
  REVOCATION_EPOCH_FIELD,
  sanitizeAvatarUrl,
  type CardFieldsPlacement,
  type LanyardClientStore,
  type LanyardStorePlacementSource,
  type RevocationEpochListener,
  TIER_METADATA_KEY,
  type SubscribeToMembersOptions,
  type ScopedMember,
  type SubscribeToUsersOptions,
  type UserProfilePatch,
  type UserRecord
} from "../core/index.js";
import {
  assertCustomDocName,
  assertNoReservedTierKeys,
  readTierDocValues,
  resolveAttributeQueryLocation,
  resolveCardFields,
  splitAttributesTierValues,
  tierDocMetadata
} from "../core/tierDocs.js";

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function sanitizeObjectPatch<T extends Record<string, any>>(input: unknown): Partial<T> {
  const clean: Record<string, any> = {};
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return clean as Partial<T>;
  }
  for (const [k, v] of Object.entries(input as Record<string, any>)) {
    if (!FORBIDDEN_KEYS.has(k) && v !== undefined) {
      clean[k] = v;
    }
  }
  return clean as Partial<T>;
}

function assertValidFirestoreDocId(id: string | null | undefined, label: string): string {
  const valid = assertValidResourceId(id, label);
  if (/^__.*__$/.test(valid)) {
    throw new Error(`Invalid ${label}: reserved Firestore document ID format`);
  }
  return valid;
}

export interface FirestoreClientStoreConfig<TRole extends string = string> {
  db: Firestore;
  /** Optional default roles assigned if a stored document does not have a `roles` field (defaults to `[]`). */
  defaultRoles?: readonly TRole[];
  /** Canonical users collection name (defaults to `"users"`). */
  usersCollection?: string;
  scopeCollection?: string;
  membersSubcollection?: string;
  /** Collection holding Lanyard's metadata documents, such as the revocation epoch (defaults to `"lanyard_meta"`). */
  metaCollection?: string;
  /**
   * The app's `PermissionPolicy`, describing which fields (`cardFields`) live on the card rather than in their
   * private tier. Omit only if the policy doesn't set `cardFields`; `createLanyardClient` throws if they disagree.
   */
  policy?: LanyardStorePlacementSource;
}

/** Private tier documents the client store reads directly. */
type ClientTier = "preferences" | "attributes";

interface MultiplexedUserWatcher<
  TRole extends string,
  TCapability extends string,
  TPreferences extends Record<string, any>,
  TAttributes extends Record<string, any>
> {
  unsubFirestore: () => void;
  latestSnapshot: { exists: boolean; user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null } | null;
  userCallbacks: Set<(user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void>;
}

/**
 * Firestore implementation of `LanyardClientStore`.
 *
 * Uses a single canonical `users/{uid}` card for profile, presence, `isSystemAdmin`,
 * single-tenant `roles`, and card-placed `attributes` (`cardFields.attributes`), and multiplexes
 * `onSnapshot` listeners per UID so repeated `subscribeToUser` calls only ever open
 * **1 Firestore document listener**.
 *
 * Preferences live in the self-only `users/{uid}/private/preferences` document and other attributes (plus
 * `email`, unless `cardFields.email` is set) in the self + staff `users/{uid}/private/attributes` document
 * (or the same paths under
 * `{scope}/{scopeId}/members/{uid}` when scoped), so other readers of the card never see them.
 */
export class FirestoreClientStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> implements LanyardClientStore<TRole, TCapability, TPreferences, TAttributes> {
  private readonly db: Firestore;
  private readonly defaultRoles: readonly TRole[];
  private readonly usersCollection: string;
  private readonly scopeCollection: string;
  private readonly membersSubcollection: string;
  private readonly metaCollection: string;
  readonly cardFields: CardFieldsPlacement;

  private readonly userWatchers = new Map<
    string,
    MultiplexedUserWatcher<TRole, TCapability, TPreferences, TAttributes>
  >();

  constructor(config: FirestoreClientStoreConfig<TRole>) {
    this.db = config.db;
    this.defaultRoles = Object.freeze(Array.from(new Set(config.defaultRoles || [])));
    this.usersCollection = assertValidFirestoreDocId(config.usersCollection || "users", "usersCollection");
    this.scopeCollection = assertValidFirestoreDocId(config.scopeCollection || "workspaces", "scopeCollection");
    this.membersSubcollection = assertValidFirestoreDocId(
      config.membersSubcollection || "members",
      "membersSubcollection"
    );
    this.metaCollection = assertValidFirestoreDocId(
      config.metaCollection || DEFAULT_LANYARD_META_COLLECTION,
      "metaCollection"
    );
    this.cardFields = resolveCardFields(config.policy);
  }

  subscribeToRevocationEpoch(onChange: RevocationEpochListener, onError: (error: unknown) => void): () => void {
    return onSnapshot(
      doc(this.db, this.metaCollection, REVOCATION_EPOCH_DOC_ID),
      (snap) => {
        let epoch: number | null;
        try {
          epoch = readStoredRevocationEpoch(snap.data(), REVOCATION_EPOCH_FIELD);
        } catch (error) {
          onError(error);
          return;
        }
        onChange(epoch);
      },
      onError
    );
  }

  private extractRoles(data: Record<string, any>): TRole[] {
    if (Array.isArray(data.roles) && data.roles.length > 0) {
      return Array.from(new Set(data.roles as TRole[]));
    }
    return [...this.defaultRoles];
  }

  private parseUserRecord(
    uid: string,
    data: Record<string, any>
  ): UserRecord<TRole, TCapability, TPreferences, TAttributes> {
    const attrs =
      data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? sanitizeObjectPatch<TAttributes>(data.attributes)
        : ({} as Partial<TAttributes>);

    return {
      uid: data.uid || uid,
      // Private emails arrive through subscribeToAttributes
      email: this.cardFields.email ? data.email || "" : "",
      ...(data.displayName !== undefined ? { displayName: data.displayName } : {}),
      ...(data.firstName !== undefined ? { firstName: data.firstName } : {}),
      ...(data.lastName !== undefined ? { lastName: data.lastName } : {}),
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      ...(data.lastSeen !== undefined ? { lastSeen: data.lastSeen } : {}),
      ...(typeof data.isSystemAdmin === "boolean" ? { isSystemAdmin: data.isSystemAdmin } : {}),
      ...(data.addedBy !== undefined ? { addedBy: data.addedBy } : {}),
      roles: this.extractRoles(data),
      attributes: attrs,
      ...(data.createdAt !== undefined ? { createdAt: data.createdAt } : {}),
      ...(data.updatedAt !== undefined ? { updatedAt: data.updatedAt } : {})
    };
  }

  private ensureUserWatcher(cleanUid: string): MultiplexedUserWatcher<TRole, TCapability, TPreferences, TAttributes> {
    const existing = this.userWatchers.get(cleanUid);
    if (existing) return existing;

    const watcher: MultiplexedUserWatcher<TRole, TCapability, TPreferences, TAttributes> = {
      unsubFirestore: () => {},
      latestSnapshot: null,
      userCallbacks: new Set()
    };
    this.userWatchers.set(cleanUid, watcher);

    const userRef = doc(this.db, this.usersCollection, cleanUid);
    watcher.unsubFirestore = onSnapshot(
      userRef,
      (snap) => {
        if (snap.exists()) {
          const parsed = this.parseUserRecord(cleanUid, snap.data() || {});
          watcher.latestSnapshot = { exists: true, user: parsed };
          for (const cb of watcher.userCallbacks) {
            cb({ ...parsed, attributes: { ...(parsed.attributes || {}) } as Partial<TAttributes> });
          }
        } else {
          watcher.latestSnapshot = { exists: false, user: null };
          for (const cb of watcher.userCallbacks) {
            cb(null);
          }
        }
      },
      () => {
        // Ignore permission or offline errors cleanly; notify user callbacks with null
        for (const cb of watcher.userCallbacks) {
          cb(null);
        }
      }
    );

    return watcher;
  }

  private releaseWatcherIfUnused(cleanUid: string): void {
    const watcher = this.userWatchers.get(cleanUid);
    if (!watcher) return;
    if (watcher.userCallbacks.size === 0) {
      this.userWatchers.delete(cleanUid);
      watcher.unsubFirestore();
    }
  }

  subscribeToUser(
    uid: string,
    onChange: (user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void
  ): () => void {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const watcher = this.ensureUserWatcher(cleanUid);
    watcher.userCallbacks.add(onChange);
    if (watcher.latestSnapshot) {
      const u = watcher.latestSnapshot.user;
      onChange(u ? { ...u, attributes: { ...(u.attributes || {}) } as Partial<TAttributes> } : null);
    }
    return () => {
      watcher.userCallbacks.delete(onChange);
      this.releaseWatcherIfUnused(cleanUid);
    };
  }

  subscribeToUsers(
    onChange: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToUsersOptions
  ): () => void {
    const subscribeToCards = (
      onCards: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void,
      onError: () => void
    ) => {
      const colRef = collection(this.db, this.usersCollection);
      const target =
        typeof options?.isSystemAdmin === "boolean"
          ? query(colRef, where("isSystemAdmin", "==", options.isSystemAdmin))
          : colRef;
      return onSnapshot(
        target,
        (snapshot) => {
          const list: UserRecord<TRole, TCapability, TPreferences, TAttributes>[] = [];
          snapshot.forEach((docSnap) => {
            list.push(this.parseUserRecord(docSnap.id, docSnap.data() || {}));
          });
          onCards(list);
        },
        onError
      );
    };
    if (options?.include?.includes("attributes")) {
      return this.subscribeWithAttributesTiers(null, subscribeToCards, onChange);
    }
    return subscribeToCards(onChange, () => onChange([]));
  }

  /**
   * Listens to every `attributes` tier document of a scope (`scopeId`) or of global users (`scopeId === null`)
   * with a single collection-group query on `private`, emitting each uid's attributes and private email.
   */
  private subscribeToAttributesTiers(
    scopeId: string | null,
    onChange: (byUid: Map<string, { attributes: Partial<TAttributes>; email?: string }>) => void,
    onError: () => void
  ): () => void {
    const tiersQuery = query(
      collectionGroup(this.db, "private"),
      where(`${TIER_METADATA_KEY}.tier`, "==", "attributes"),
      where(`${TIER_METADATA_KEY}.scopeId`, "==", scopeId)
    );
    return onSnapshot(
      tiersQuery,
      (snapshot) => {
        const byUid = new Map<string, { attributes: Partial<TAttributes>; email?: string }>();
        snapshot.forEach((docSnap) => {
          const data = docSnap.data() || {};
          const uid = data[TIER_METADATA_KEY]?.uid;
          if (typeof uid !== "string") return;
          const { attributes, email } = splitAttributesTierValues<TAttributes>(readTierDocValues(data));
          byUid.set(uid, { attributes, email: this.cardFields.email ? undefined : email });
        });
        onChange(byUid);
      },
      onError
    );
  }

  /**
   * Combines a card list listener with the matching attributes tiers listener. Emits merged records once both
   * have loaded (so lists never flash without attributes), and `[]` if either listener fails.
   */
  private subscribeWithAttributesTiers<R extends { uid: string; email: string; attributes?: Partial<TAttributes> }>(
    scopeId: string | null,
    subscribeToCards: (onCards: (cards: R[]) => void, onError: () => void) => () => void,
    onChange: (records: R[]) => void
  ): () => void {
    let cards: R[] | null = null;
    let tiers: Map<string, { attributes: Partial<TAttributes>; email?: string }> | null = null;
    let failed = false;
    const emit = () => {
      if (failed || !cards || !tiers) return;
      const byUid = tiers;
      onChange(
        cards.map((card) => {
          const tier = byUid.get(card.uid);
          if (!tier) return card;
          return {
            ...card,
            attributes: { ...(card.attributes || {}), ...tier.attributes },
            ...(tier.email ? { email: tier.email } : {})
          };
        })
      );
    };
    const fail = () => {
      if (failed) return;
      failed = true;
      onChange([]);
    };
    const unsubCards = subscribeToCards((next) => {
      cards = next;
      emit();
    }, fail);
    const unsubTiers = this.subscribeToAttributesTiers(
      scopeId,
      (next) => {
        tiers = next;
        emit();
      },
      fail
    );
    return () => {
      unsubCards();
      unsubTiers();
    };
  }

  /** `users/{uid}/private/{tier}` (global, `scopeId === null`) or `{scope}/{scopeId}/members/{uid}/private/{tier}`. */
  private tierDocRef(tier: ClientTier, uid: string, scopeId: string | null) {
    return this.privateDocRef(tier, uid, scopeId);
  }

  /** `users/{uid}/private/{name}` (global, `scopeId === null`) or `{scope}/{scopeId}/members/{uid}/private/{name}`. */
  private privateDocRef(name: string, uid: string, scopeId: string | null) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    if (scopeId === null) return doc(this.db, this.usersCollection, cleanUid, "private", name);
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    return doc(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection, cleanUid, "private", name);
  }

  async getCustomDoc(name: string, uid: string, scopeId: string | null): Promise<Record<string, any>> {
    const snap = await getDoc(this.privateDocRef(assertCustomDocName(name), uid, scopeId));
    return snap.exists() ? readTierDocValues<Record<string, any>>(snap.data()) : {};
  }

  subscribeToCustomDoc(
    name: string,
    uid: string,
    scopeId: string | null,
    onChange: (values: Record<string, any>) => void
  ): () => void {
    return this.subscribeToTierDoc(this.privateDocRef(assertCustomDocName(name), uid, scopeId), onChange);
  }

  async updateCustomDoc(name: string, uid: string, scopeId: string | null, patch: Record<string, any>): Promise<void> {
    const cleanName = assertCustomDocName(name);
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanScopeId = scopeId === null ? null : assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanPatch = sanitizeObjectPatch<Record<string, any>>(patch);
    assertNoReservedTierKeys(cleanPatch, cleanName);
    await setDoc(
      this.privateDocRef(cleanName, cleanUid, cleanScopeId),
      { ...cleanPatch, ...tierDocMetadata(cleanName, cleanUid, cleanScopeId) },
      { merge: true }
    );
  }

  /**
   * Listens to a private tier document, emitting `{}` when it doesn't exist. Permission or offline
   * errors are ignored so cached values stay in place.
   */
  private subscribeToTierDoc<T extends Record<string, any>>(
    ref: DocumentReference,
    onChange: (values: Partial<T>) => void
  ): () => void {
    return onSnapshot(
      ref,
      (snap) => onChange(snap.exists() ? readTierDocValues<T>(snap.data()) : {}),
      () => {}
    );
  }

  /** Merges a preferences patch into a private preferences document, stamping tier metadata. */
  private async writePreferencesDoc(
    ref: DocumentReference,
    uid: string,
    scopeId: string | null,
    patch: Partial<TPreferences>
  ): Promise<void> {
    const cleanPatch = sanitizeObjectPatch<TPreferences>(patch);
    assertNoReservedTierKeys(cleanPatch, "preferences");
    await setDoc(ref, { ...cleanPatch, ...tierDocMetadata("preferences", uid, scopeId) }, { merge: true });
  }

  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void {
    return this.subscribeToTierDoc(this.tierDocRef("preferences", uid, null), onChange);
  }

  subscribeToScopePreferences(
    scopeId: string,
    uid: string,
    onChange: (prefs: Partial<TPreferences>) => void
  ): () => void {
    return this.subscribeToTierDoc(this.tierDocRef("preferences", uid, scopeId), onChange);
  }

  subscribeToAttributes(uid: string, onChange: (attrs: Partial<TAttributes>, email?: string) => void): () => void {
    return this.subscribeToAttributesDoc(this.tierDocRef("attributes", uid, null), onChange);
  }

  subscribeToScopeAttributes(
    scopeId: string,
    uid: string,
    onChange: (attrs: Partial<TAttributes>, email?: string) => void
  ): () => void {
    return this.subscribeToAttributesDoc(this.tierDocRef("attributes", uid, scopeId), onChange);
  }

  /** Listens to an `attributes` tier document, emitting its attributes and stored `email` separately. */
  private subscribeToAttributesDoc(
    ref: DocumentReference,
    onChange: (attrs: Partial<TAttributes>, email?: string) => void
  ): () => void {
    return this.subscribeToTierDoc(ref, (values) => {
      const { attributes, email } = splitAttributesTierValues<TAttributes>(values);
      onChange(attributes, this.cardFields.email ? undefined : email);
    });
  }

  async savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    await this.writePreferencesDoc(this.tierDocRef("preferences", cleanUid, null), cleanUid, null, patch);
  }

  async saveScopePreferences(scopeId: string, uid: string, patch: Partial<TPreferences>): Promise<void> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    if (Object.keys(sanitizeObjectPatch<TPreferences>(patch)).length === 0) return;
    await this.writePreferencesDoc(
      this.tierDocRef("preferences", cleanUid, cleanScopeId),
      cleanUid,
      cleanScopeId,
      patch
    );
  }

  async updateUserProfile(uid: string, patch: UserProfilePatch): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return;
    assertNoEmailInProfilePatch(patch);
    // Strictly allow ONLY Tier-1 self-editable profile fields (never email, isSystemAdmin, role, capabilities,
    // attributes, or secrets)
    const safePayload: Record<string, any> = {
      uid: cleanUid,
      updatedAt: new Date().toISOString()
    };
    if (typeof patch.firstName === "string") safePayload.firstName = patch.firstName.trim();
    if (typeof patch.lastName === "string") safePayload.lastName = patch.lastName.trim();
    if (typeof patch.displayName === "string") safePayload.displayName = patch.displayName.trim();
    if (patch.photoUrl !== undefined) safePayload.photoUrl = sanitizeAvatarUrl(patch.photoUrl);

    const userRef = doc(this.db, this.usersCollection, cleanUid);
    await setDoc(userRef, safePayload, { merge: true });
  }

  async updateScopeMemberProfile(scopeId: string, uid: string, patch: UserProfilePatch): Promise<void> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return;
    assertNoEmailInProfilePatch(patch);
    // Strictly allow ONLY Tier-1 self-editable profile fields on the existing scoped member doc
    const safePayload: Record<string, any> = {};
    if (typeof patch.firstName === "string") safePayload.firstName = patch.firstName.trim();
    if (typeof patch.lastName === "string") safePayload.lastName = patch.lastName.trim();
    if (typeof patch.displayName === "string") safePayload.displayName = patch.displayName.trim();
    if (patch.photoUrl !== undefined) safePayload.photoUrl = sanitizeAvatarUrl(patch.photoUrl);
    if (Object.keys(safePayload).length === 0) return;

    const memberRef = doc(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection, cleanUid);
    await updateDoc(memberRef, safePayload);
  }

  subscribeToUserMemberships(
    uid: string,
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
  ): () => void {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const membersQuery = query(collectionGroup(this.db, this.membersSubcollection), where("uid", "==", cleanUid));
    return onSnapshot(
      membersQuery,
      (snapshot) => {
        const list: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[] = [];
        snapshot.forEach((docSnap) => {
          const data = docSnap.data();
          const scopeId = data.scopeId || docSnap.ref.parent?.parent?.id;
          list.push(this.parseScopedMember(docSnap.id, scopeId, data));
        });
        onChange(list);
      },
      () => {
        onChange([]);
      }
    );
  }

  subscribeToScopeMembers(
    scopeId: string,
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToMembersOptions
  ): () => void {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const subscribeToCards = (
      onCards: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void,
      onError: () => void
    ) => {
      const colRef = collection(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection);
      return onSnapshot(
        colRef,
        (snapshot) => {
          const list: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[] = [];
          snapshot.forEach((docSnap) => {
            const data = docSnap.data();
            list.push(this.parseScopedMember(docSnap.id, cleanScopeId, data));
          });
          onCards(list);
        },
        onError
      );
    };
    if (options?.include?.includes("attributes")) {
      return this.subscribeWithAttributesTiers(cleanScopeId, subscribeToCards, onChange);
    }
    return subscribeToCards(onChange, () => onChange([]));
  }

  private parseScopedMember(
    docId: string,
    scopeId: string | undefined,
    data: Record<string, any>
  ): ScopedMember<TRole, TCapability, TPreferences, TAttributes> {
    return {
      uid: data.uid || docId,
      // Private emails arrive through subscribeToAttributes
      email: this.cardFields.email ? data.email || "" : "",
      firstName: data.firstName,
      lastName: data.lastName,
      displayName: data.displayName,
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      roles: this.extractRoles(data),
      scopeId,
      scopeName: data.scopeName,
      lastSeen: data.lastSeen,
      ...(data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? { attributes: sanitizeObjectPatch<TAttributes>(data.attributes) }
        : {})
    };
  }

  async queryMemberUids(scopeId: string | null, attributes: Partial<TAttributes>): Promise<string[]> {
    const cleanScopeId = scopeId === null ? null : assertValidFirestoreDocId(scopeId, "scopeId");
    const location = resolveAttributeQueryLocation(attributes, this.cardFields);
    const filters = Object.entries(attributes).map(([key, value]) =>
      where(location === "card" ? `attributes.${key}` : key, "==", value)
    );
    if (location === "card") {
      const cards =
        cleanScopeId === null
          ? collection(this.db, this.usersCollection)
          : collection(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection);
      const snap = await getDocs(query(cards, ...filters));
      return snap.docs.map((d) => (typeof d.data()?.uid === "string" ? d.data().uid : d.id));
    }
    const snap = await getDocs(
      query(
        collectionGroup(this.db, "private"),
        where(`${TIER_METADATA_KEY}.tier`, "==", "attributes"),
        where(`${TIER_METADATA_KEY}.scopeId`, "==", cleanScopeId),
        ...filters
      )
    );
    return snap.docs
      .map((d) => d.data()?.[TIER_METADATA_KEY]?.uid)
      .filter((uid): uid is string => typeof uid === "string");
  }

  async syncAvatar(params: {
    uid: string;
    photoUrl: string;
    scopeId?: string;
    displayName?: string | null;
  }): Promise<void> {
    const { uid, photoUrl, scopeId, displayName } = params;
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanPhotoUrl = sanitizeAvatarUrl(photoUrl);
    if (!cleanPhotoUrl) return;
    if (scopeId) {
      const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
      // Use updateDoc for existing scoped member docs so we never create a phantom member doc
      const memberRef = doc(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection, cleanUid);
      await updateDoc(memberRef, { photoUrl: cleanPhotoUrl });
    } else {
      const userRef = doc(this.db, this.usersCollection, cleanUid);
      const payload: Record<string, any> = { uid: cleanUid, photoUrl: cleanPhotoUrl };
      if (displayName) payload.displayName = displayName;
      await setDoc(userRef, payload, { merge: true });
    }
  }

  async recordPresenceHeartbeat(params: {
    uid: string;
    scopeId?: string;
    lastSeenIso: string;
    photoUrl?: string | null;
  }): Promise<void> {
    const { uid, scopeId, lastSeenIso, photoUrl } = params;
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanPhotoUrl = sanitizeAvatarUrl(photoUrl);
    const payload: Record<string, any> = { lastSeen: lastSeenIso };
    if (cleanPhotoUrl) {
      payload.photoUrl = cleanPhotoUrl;
    }

    if (scopeId) {
      const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
      const memberRef = doc(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection, cleanUid);
      await updateDoc(memberRef, payload);
    } else {
      const userRef = doc(this.db, this.usersCollection, cleanUid);
      await setDoc(userRef, payload, { merge: true });
    }
  }
}

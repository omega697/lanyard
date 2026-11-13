import { FieldValue, type Firestore } from "firebase-admin/firestore";
import {
  assertValidResourceId,
  assertValidRevocationEpoch,
  DEFAULT_LANYARD_META_COLLECTION,
  nextSessionRevocations,
  readStoredRevocationEpoch,
  readStoredSessionRevocations,
  REVOCATION_EPOCH_DOC_ID,
  REVOCATION_EPOCH_FIELD,
  SESSION_REVOCATION_RETENTION_MS,
  SESSION_REVOCATIONS_DOC_ID,
  SESSION_REVOCATIONS_FIELD,
  sanitizeAvatarUrl,
  type CardFieldsPlacement,
  type LanyardServerStore,
  type LanyardStorePlacementSource,
  type RevocationEpochListener,
  type SessionRevocationsListener,
  TIER_METADATA_KEY,
  type ScopedMember,
  type ScopedMemberUpsert,
  type SecretCipher,
  type StoredProfileFieldsPatch,
  type SystemAdminProfile,
  type UserRecord
} from "../core/index.js";
import {
  assertCustomDocName,
  assertDeclaredSecretKeys,
  assertNoReservedAttributeKeys,
  assertNoReservedTierKeys,
  readTierDocValues,
  resolveAttributeQueryLocation,
  resolveCardFields,
  resolveSecretKeys,
  splitAttributesByPlacement,
  splitAttributesTierValues,
  tierDocMetadata,
  withoutUndeclaredSecretKeys
} from "../core/tierDocs.js";
import { createSecretCipher, isEncryptedSecretData } from "./encryption.js";

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

function stripUndefinedFields(input: Record<string, any>): Record<string, any> {
  const clean: Record<string, any> = {};
  for (const [k, v] of Object.entries(input)) {
    if (!FORBIDDEN_KEYS.has(k) && v !== undefined) {
      clean[k] = v;
    }
  }
  return clean;
}

function assertValidFirestoreDocId(id: string | null | undefined, label: string): string {
  const valid = assertValidResourceId(id, label);
  if (/^__.*__$/.test(valid)) {
    throw new Error(`Invalid ${label}: reserved Firestore document ID format`);
  }
  return valid;
}

export interface FirestoreServerStoreConfig<_TRole extends string = string> {
  db: Firestore;
  /** Canonical users collection name (defaults to `"users"`). */
  usersCollection?: string;
  scopeCollection?: string;
  membersSubcollection?: string;
  /** Collection holding Lanyard's metadata documents, such as the revocation epoch (defaults to `"lanyard_meta"`). */
  metaCollection?: string;
  /**
   * Master encryption key used to encrypt and decrypt write-only secrets at rest (`private/secrets`)
   * with AES-256-GCM. Defaults to `process.env.MASTER_ENCRYPTION_KEY` if set.
   */
  encryptionKey?: string;
  /** Optional custom `SecretCipher` instance (overrides `encryptionKey`). */
  cipher?: SecretCipher;
  /**
   * The app's `PermissionPolicy`, used to place fields (`cardFields`) on the card or in their private tier.
   * Omit only if the policy doesn't set `cardFields`; `createLanyardServer` throws if they disagree.
   */
  policy?: LanyardStorePlacementSource;
}

/** Private tier documents whose values are merged into user/member records. */
type MergedTier = "preferences" | "attributes";

/**
 * Firebase Admin Firestore implementation of `LanyardServerStore`.
 *
 * Uses a single canonical `users/{uid}` card document for profile, presence, `isSystemAdmin`,
 * single-tenant `roles`, and card-placed fields (`cardFields`), plus private tier documents in the `private`
 * subcollection: self-only `private/preferences`, self + staff `private/attributes` (including `email` unless
 * `cardFields.email` is set),
 * `private/hiddenAttributes`, and AES-256-GCM encrypted `private/secrets`.
 * Scoped members (`{scopeCollection}/{scopeId}/{membersSubcollection}/{uid}`) use the same layout.
 * Reads merge the tiers back together, so records keep the same shape regardless of placement.
 */
export class FirestoreServerStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>,
  THiddenAttributes extends Record<string, any> = Record<string, any>,
  TSecrets extends Record<string, any> = Record<string, any>
> implements LanyardServerStore<TRole, TCapability, TPreferences, TAttributes, THiddenAttributes, TSecrets> {
  private readonly db: Firestore;
  private readonly usersCollection: string;
  private readonly scopeCollection: string;
  private readonly membersSubcollection: string;
  private readonly metaCollection: string;
  private readonly cipher?: SecretCipher;
  readonly cardFields: CardFieldsPlacement;
  /** Declared secret keys from the policy (none without one); secrets are closed-world. */
  readonly secretKeys: readonly string[];

  constructor(config: FirestoreServerStoreConfig<TRole>) {
    this.db = config.db;
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
    const key = config.encryptionKey || process.env.MASTER_ENCRYPTION_KEY;
    this.cipher = config.cipher ?? (key ? createSecretCipher(key) : undefined);
    this.cardFields = resolveCardFields(config.policy);
    this.secretKeys = resolveSecretKeys(config.policy);
  }

  private requireCipher(): SecretCipher {
    if (this.cipher) return this.cipher;
    if (process.env.MASTER_ENCRYPTION_KEY) {
      return createSecretCipher(process.env.MASTER_ENCRYPTION_KEY);
    }
    throw new Error(
      "Cannot encrypt or decrypt secrets: configure 'encryptionKey', 'cipher', or MASTER_ENCRYPTION_KEY on FirestoreServerStore."
    );
  }

  // --- Revocation Epoch ---

  private revocationEpochRef() {
    return this.db.collection(this.metaCollection).doc(REVOCATION_EPOCH_DOC_ID);
  }

  async getRevocationEpoch(): Promise<number | null> {
    const snap = await this.revocationEpochRef().get();
    return readStoredRevocationEpoch(snap.data(), REVOCATION_EPOCH_FIELD);
  }

  async bumpRevocationEpoch(atMs: number): Promise<number> {
    assertValidRevocationEpoch(atMs);
    const ref = this.revocationEpochRef();
    return this.db.runTransaction(async (tx) => {
      const current = readStoredRevocationEpoch((await tx.get(ref)).data(), REVOCATION_EPOCH_FIELD);
      const next = Math.max(current ?? 0, atMs);
      if (next !== current) tx.set(ref, { [REVOCATION_EPOCH_FIELD]: next }, { merge: true });
      return next;
    });
  }

  subscribeToRevocationEpoch(onChange: RevocationEpochListener, onError: (error: unknown) => void): () => void {
    return this.revocationEpochRef().onSnapshot((snap) => {
      let epoch: number | null;
      try {
        epoch = readStoredRevocationEpoch(snap.data(), REVOCATION_EPOCH_FIELD);
      } catch (error) {
        onError(error);
        return;
      }
      onChange(epoch);
    }, onError);
  }

  // --- Session Revocations ---

  private sessionRevocationsRef() {
    return this.db.collection(this.metaCollection).doc(SESSION_REVOCATIONS_DOC_ID);
  }

  async getSessionRevocations(): Promise<Readonly<Record<string, number>>> {
    const snap = await this.sessionRevocationsRef().get();
    return readStoredSessionRevocations(snap.data(), SESSION_REVOCATIONS_FIELD);
  }

  async recordSessionRevocation(uid: string, atMs: number): Promise<Readonly<Record<string, number>>> {
    // Validate before opening a transaction so invalid input never touches the stored map
    nextSessionRevocations({}, uid, atMs, SESSION_REVOCATION_RETENTION_MS);
    const ref = this.sessionRevocationsRef();
    return this.db.runTransaction(async (tx) => {
      const current = readStoredSessionRevocations((await tx.get(ref)).data(), SESSION_REVOCATIONS_FIELD);
      const next = nextSessionRevocations(current, uid, atMs, SESSION_REVOCATION_RETENTION_MS);
      // Replace the whole map so pruned entries are actually removed
      tx.set(ref, { [SESSION_REVOCATIONS_FIELD]: next });
      return next;
    });
  }

  subscribeToSessionRevocations(onChange: SessionRevocationsListener, onError: (error: unknown) => void): () => void {
    return this.sessionRevocationsRef().onSnapshot((snap) => {
      let revocations: Record<string, number>;
      try {
        revocations = readStoredSessionRevocations(snap.data(), SESSION_REVOCATIONS_FIELD);
      } catch (error) {
        onError(error);
        return;
      }
      onChange(revocations);
    }, onError);
  }

  /** A record's stored roles exactly as stored (deduplicated); a missing `roles` field means none. */
  private extractRoles(data: Record<string, any>): TRole[] {
    return Array.isArray(data.roles) ? Array.from(new Set(data.roles as TRole[])) : [];
  }

  private userDocRef(uid: string) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.usersCollection}/${cleanUid}`);
  }

  private userHiddenAttributesDocRef(uid: string) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.usersCollection}/${cleanUid}/private/hiddenAttributes`);
  }

  /** `users/{uid}/private/{tier}` (global, `scopeId === null`) or `{scope}/{scopeId}/members/{uid}/private/{tier}`. */
  private tierDocRef(tier: MergedTier, uid: string, scopeId: string | null) {
    return this.privateDocRef(tier, uid, scopeId);
  }

  /** `users/{uid}/private/{name}` (global, `scopeId === null`) or `{scope}/{scopeId}/members/{uid}/private/{name}`. */
  private privateDocRef(name: string, uid: string, scopeId: string | null) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    if (scopeId === null) return this.db.doc(`${this.usersCollection}/${cleanUid}/private/${name}`);
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    return this.db.doc(
      `${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}/${cleanUid}/private/${name}`
    );
  }

  async getCustomDoc(name: string, uid: string, scopeId: string | null): Promise<Record<string, any>> {
    const snap = await this.privateDocRef(assertCustomDocName(name), uid, scopeId).get();
    return snap.exists ? readTierDocValues<Record<string, any>>(snap.data()) : {};
  }

  async updateCustomDoc(name: string, uid: string, scopeId: string | null, patch: Record<string, any>): Promise<void> {
    const cleanName = assertCustomDocName(name);
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanScopeId = scopeId === null ? null : assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanPatch = sanitizeObjectPatch<Record<string, any>>(patch);
    assertNoReservedTierKeys(cleanPatch, cleanName);
    await this.privateDocRef(cleanName, cleanUid, cleanScopeId).set(
      { ...cleanPatch, ...tierDocMetadata(cleanName, cleanUid, cleanScopeId) },
      { merge: true }
    );
  }

  /** Merges `values` into a private tier document, stamping tier metadata. */
  private async writeTierDoc(
    tier: MergedTier,
    uid: string,
    scopeId: string | null,
    values: Record<string, any>
  ): Promise<void> {
    await this.tierDocRef(tier, uid, scopeId).set(
      { ...values, ...tierDocMetadata(tier, uid, scopeId) },
      { merge: true }
    );
  }

  /** Sanitizes and validates a patch for a tier document (throws on reserved keys). */
  private cleanTierPatch<T extends Record<string, any>>(patch: Partial<T>, tier: MergedTier): Partial<T> {
    const clean = sanitizeObjectPatch<T>(patch);
    if (tier === "attributes") assertNoReservedAttributeKeys(clean);
    else assertNoReservedTierKeys(clean, tier);
    return clean;
  }

  /**
   * Splits `attributes` into card-placed keys and `attributes`-tier keys, writing the tier keys (plus `email`,
   * when it belongs in the tier and is non-empty) to their private document. Returns the card-placed keys for
   * the caller to store on the card.
   */
  private async writeAttributesTier(
    uid: string,
    scopeId: string | null,
    attributes: Partial<TAttributes> | undefined,
    email?: string
  ): Promise<Partial<TAttributes>> {
    const { card, tier } = splitAttributesByPlacement(
      this.cleanTierPatch(attributes || {}, "attributes"),
      this.cardFields
    );
    const tierEmail = this.tierEmail(email);
    const tierValues: Record<string, any> = { ...tier, ...(tierEmail ? { email: tierEmail } : {}) };
    if (Object.keys(tierValues).length > 0) await this.writeTierDoc("attributes", uid, scopeId, tierValues);
    return card;
  }

  /**
   * Returns the email to store in the `attributes` tier, or `undefined` if email lives on the card or none was
   * given. Empty emails are never written, so records read without their tier can't erase a stored address.
   */
  private tierEmail(email: string | undefined): string | undefined {
    return !this.cardFields.email && typeof email === "string" && email ? email : undefined;
  }

  /** Card fields for `email`: kept on the card only when `cardFields.email` places it there. */
  private cardEmailField(email: string | undefined): { email?: string } {
    return this.cardFields.email && email !== undefined ? { email } : {};
  }

  /** Reads the private tiers of a user/member and merges them into its parsed card. */
  private async mergePrivateTiers<
    R extends { email: string; attributes?: Partial<TAttributes>; preferences?: Partial<TPreferences> }
  >(card: R, uid: string, scopeId: string | null): Promise<R> {
    const [prefsSnap, attrsSnap] = await Promise.all([
      this.tierDocRef("preferences", uid, scopeId).get(),
      this.tierDocRef("attributes", uid, scopeId).get()
    ]);
    const merged = { ...card };
    if (prefsSnap.exists) merged.preferences = readTierDocValues<TPreferences>(prefsSnap.data());
    if (attrsSnap.exists) {
      const { attributes, email } = splitAttributesTierValues<TAttributes>(readTierDocValues(attrsSnap.data()));
      merged.attributes = { ...(card.attributes || {}), ...attributes };
      if (!this.cardFields.email) merged.email = email || "";
    }
    return merged;
  }

  /** Reads a user's email from wherever `cardFields.email` places it. */
  private async readEmail(cardData: Record<string, any>, uid: string): Promise<string> {
    if (this.cardFields.email) return cardData.email || "";
    const snap = await this.tierDocRef("attributes", uid, null).get();
    return snap.exists ? splitAttributesTierValues(readTierDocValues(snap.data())).email || "" : "";
  }

  /** Deletes the private tier documents merged into user/member records. */
  private async deleteMergedTiers(uid: string, scopeId: string | null): Promise<void> {
    await Promise.all([
      this.tierDocRef("preferences", uid, scopeId).delete(),
      this.tierDocRef("attributes", uid, scopeId).delete()
    ]);
  }

  private userSecretsDocRef(uid: string) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.usersCollection}/${cleanUid}/private/secrets`);
  }

  private memberDocRef(scopeId: string, uid: string) {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}/${cleanUid}`);
  }

  private memberHiddenAttributesDocRef(scopeId: string, uid: string) {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(
      `${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}/${cleanUid}/private/hiddenAttributes`
    );
  }

  private memberSecretsDocRef(scopeId: string, uid: string) {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(
      `${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}/${cleanUid}/private/secrets`
    );
  }

  /** A secrets document's secret entries, dropping metadata and keys the policy doesn't declare. */
  private declaredSecretEntries(data: Record<string, any>, where: string): [string, any][] {
    const secrets = Object.fromEntries(
      Object.entries(data).filter(([k]) => !FORBIDDEN_KEYS.has(k) && k !== "updatedAt" && k !== TIER_METADATA_KEY)
    );
    return Object.entries(withoutUndeclaredSecretKeys(this.secretKeys, secrets, where));
  }

  private parseSecretsStatusFromDocData(
    data: Record<string, any>,
    where: string
  ): Partial<Record<keyof TSecrets & string, boolean>> {
    const status: Record<string, boolean> = {};
    for (const [k, v] of this.declaredSecretEntries(data, where)) {
      status[k] = isEncryptedSecretData(v) || (typeof v === "string" && v.length > 0);
    }
    return status as Partial<Record<keyof TSecrets & string, boolean>>;
  }

  private decryptSecretsFromDocData(
    data: Record<string, any>,
    where: string
  ): Partial<Record<keyof TSecrets & string, string>> {
    const out: Record<string, string> = {};
    const entries = this.declaredSecretEntries(data, where);
    if (entries.length === 0) return out as Partial<Record<keyof TSecrets & string, string>>;
    const cipher = this.requireCipher();
    for (const [k, v] of entries) {
      if (isEncryptedSecretData(v)) {
        out[k] = cipher.decrypt(v);
      } else if (typeof v === "string" && v.length > 0) {
        out[k] = v;
      }
    }
    return out as Partial<Record<keyof TSecrets & string, string>>;
  }

  private async writeEncryptedSecretsToRef(
    ref: FirebaseFirestore.DocumentReference,
    uid: string,
    scopeId: string | null,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
      const snap = await ref.get();
      return snap.exists ? this.parseSecretsStatusFromDocData(snap.data() || {}, `${scopeId ?? "global"}/${uid}`) : {};
    }
    assertNoReservedTierKeys(patch, "secrets");
    assertDeclaredSecretKeys(this.secretKeys, patch);
    const cipher = this.requireCipher();
    const firestorePayload: Record<string, any> = {};
    for (const [k, v] of Object.entries(patch)) {
      if (FORBIDDEN_KEYS.has(k) || v === undefined) continue;
      if (v === null || v === "") {
        firestorePayload[k] = FieldValue.delete();
      } else if (typeof v === "string") {
        firestorePayload[k] = cipher.encrypt(v);
      }
    }
    if (Object.keys(firestorePayload).length > 0) {
      await ref.set({ ...firestorePayload, ...tierDocMetadata("secrets", uid, scopeId) }, { merge: true });
    }
    const snap = await ref.get();
    return snap.exists ? this.parseSecretsStatusFromDocData(snap.data() || {}, `${scopeId ?? "global"}/${uid}`) : {};
  }

  private parseUserRecord(
    docId: string,
    data: Record<string, any>
  ): UserRecord<TRole, TCapability, TPreferences, TAttributes> {
    return {
      uid: data.uid || docId,
      // Private emails are merged from the attributes tier by mergePrivateTiers
      email: this.cardFields.email ? data.email || "" : "",
      ...(data.displayName !== undefined ? { displayName: data.displayName } : {}),
      ...(data.firstName !== undefined ? { firstName: data.firstName } : {}),
      ...(data.lastName !== undefined ? { lastName: data.lastName } : {}),
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      ...(data.lastSeen !== undefined ? { lastSeen: data.lastSeen } : {}),
      ...(typeof data.isSystemAdmin === "boolean" ? { isSystemAdmin: data.isSystemAdmin } : {}),
      ...(data.addedBy !== undefined ? { addedBy: data.addedBy } : {}),
      // A card with no roles field (e.g. one a user created themselves) has none, and reads as undefined so that
      // provisioning can still give it the policy's default roles
      ...(Array.isArray(data.roles) ? { roles: this.extractRoles(data) } : {}),
      ...(data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? { attributes: sanitizeObjectPatch<TAttributes>(data.attributes) }
        : {}),
      ...(data.createdAt !== undefined ? { createdAt: data.createdAt } : {}),
      ...(data.updatedAt !== undefined ? { updatedAt: data.updatedAt } : {})
    };
  }

  /** Reads `users/{uid}` and merges its `private/preferences` and `private/attributes` tiers into the record. */
  async getUser(uid: string): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null> {
    const snap = await this.userDocRef(uid).get();
    if (!snap.exists) return null;
    return this.mergePrivateTiers(this.parseUserRecord(snap.id, snap.data() || {}), snap.id, null);
  }

  async listUsers(): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>[]> {
    const snap = await this.db.collection(this.usersCollection).get();
    return Promise.all(
      snap.docs.map((doc) => this.mergePrivateTiers(this.parseUserRecord(doc.id, doc.data() || {}), doc.id, null))
    );
  }

  async deleteUser(uid: string): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const userRef = this.userDocRef(cleanUid);
    await Promise.all([
      userRef.delete(),
      this.deleteMergedTiers(cleanUid, null),
      this.userHiddenAttributesDocRef(cleanUid).delete(),
      this.userSecretsDocRef(cleanUid).delete()
    ]);
    if (typeof (this.db as any).recursiveDelete === "function") {
      await (this.db as any).recursiveDelete(userRef);
    }
  }

  /**
   * Upserts the `users/{uid}` card. `user.preferences` are merged into the self-only `private/preferences`
   * tier and `user.attributes` into the `private/attributes` tier (except keys placed on the card via
   * `cardFields.attributes`); neither tier is ever stored on the card.
   */
  async upsertUser(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(user.uid, "uid");
    const { preferences, attributes, email, ...card } = user;
    // Validate both tier patches before writing anything
    const cleanPrefs = preferences !== undefined ? this.cleanTierPatch(preferences, "preferences") : undefined;
    if (attributes !== undefined) this.cleanTierPatch(attributes, "attributes");
    if (cleanPrefs !== undefined) await this.writeTierDoc("preferences", cleanUid, null, cleanPrefs);
    const cardAttributes = await this.writeAttributesTier(cleanUid, null, attributes, email);
    const payload = stripUndefinedFields({
      ...card,
      ...this.cardEmailField(email),
      uid: cleanUid,
      ...(card.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(card.photoUrl) } : {}),
      ...(card.roles !== undefined ? { roles: Array.from(new Set(card.roles)) } : {}),
      ...(Object.keys(cardAttributes).length > 0 ? { attributes: cardAttributes } : {})
    });
    await this.userDocRef(cleanUid).set(payload, { merge: true });
  }

  /**
   * Card fields for a `patchUser`/`patchScopeMember` call: only the given profile fields (sanitized) and, when it lives
   * on the card, the email.
   */
  private profilePatchCardFields(fields: StoredProfileFieldsPatch): Record<string, any> {
    return stripUndefinedFields({
      firstName: typeof fields.firstName === "string" ? fields.firstName : undefined,
      lastName: typeof fields.lastName === "string" ? fields.lastName : undefined,
      displayName: typeof fields.displayName === "string" ? fields.displayName : undefined,
      ...(fields.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fields.photoUrl) } : {}),
      ...this.cardEmailField(fields.email),
      updatedAt: new Date().toISOString()
    });
  }

  async patchUser(uid: string, fields: StoredProfileFieldsPatch): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    // update() fails if the card doesn't exist, so a patch never creates a phantom user
    await this.userDocRef(cleanUid).update(this.profilePatchCardFields(fields));
    await this.writeAttributesTier(cleanUid, null, undefined, fields.email);
  }

  async patchScopeMember(scopeId: string, uid: string, fields: StoredProfileFieldsPatch): Promise<void> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    await this.memberDocRef(cleanScopeId, cleanUid).update(this.profilePatchCardFields(fields));
    await this.writeAttributesTier(cleanUid, cleanScopeId, undefined, fields.email);
  }

  async updateUserAttributes(
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cardAttributes = await this.writeAttributesTier(cleanUid, null, patch);
    await this.userDocRef(cleanUid).set(
      {
        uid: cleanUid,
        ...(Object.keys(cardAttributes).length > 0 ? { attributes: cardAttributes } : {}),
        updatedAt: new Date().toISOString()
      },
      { merge: true }
    );
    return (await this.getUser(cleanUid))!;
  }

  async getUserHiddenAttributes(uid: string): Promise<Partial<THiddenAttributes>> {
    const snap = await this.userHiddenAttributesDocRef(uid).get();
    if (!snap.exists) return {};
    return readTierDocValues<THiddenAttributes>(snap.data());
  }

  async updateUserHiddenAttributes(
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanPatch = sanitizeObjectPatch<THiddenAttributes>(patch);
    assertNoReservedTierKeys(cleanPatch, "hiddenAttributes");
    await this.userHiddenAttributesDocRef(cleanUid).set(
      { ...cleanPatch, ...tierDocMetadata("hiddenAttributes", cleanUid, null) },
      { merge: true }
    );
    return this.getUserHiddenAttributes(cleanUid);
  }

  async getUserSecrets(uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    const snap = await this.userSecretsDocRef(uid).get();
    if (!snap.exists) return {};
    return this.decryptSecretsFromDocData(snap.data() || {}, `${this.usersCollection}/${uid}`);
  }

  async getUserSecretsStatus(uid: string): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const snap = await this.userSecretsDocRef(uid).get();
    if (!snap.exists) return {};
    return this.parseSecretsStatusFromDocData(snap.data() || {}, `${this.usersCollection}/${uid}`);
  }

  async updateUserSecrets(
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.writeEncryptedSecretsToRef(this.userSecretsDocRef(cleanUid), cleanUid, null, patch);
  }

  async grantUserRoles(
    uid: string,
    roles: readonly TRole[],
    fallbackUser?: Omit<UserRecord<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const ref = this.userDocRef(cleanUid);
    const snap = await ref.get();
    if (!snap.exists) {
      if (!fallbackUser) {
        throw new Error(`User '${cleanUid}' does not exist`);
      }
      // Grants never add default roles: a new record gets exactly the granted roles
      const initialRoles = Array.from(new Set(roles));
      const created: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
        ...fallbackUser,
        ...(fallbackUser.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fallbackUser.photoUrl) } : {}),
        uid: cleanUid,
        roles: initialRoles
      };
      await this.upsertUser(created);
      return created;
    }

    if (roles.length > 0) {
      await ref.update({
        roles: FieldValue.arrayUnion(...roles)
      });
    }
    return (await this.getUser(cleanUid))!;
  }

  async revokeUserRoles(uid: string, roles: readonly TRole[]): Promise<void> {
    if (roles.length === 0) return;
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const ref = this.userDocRef(cleanUid);
    const snap = await ref.get();
    if (!snap.exists) return;
    await ref.update({
      roles: FieldValue.arrayRemove(...roles)
    });
  }

  async getSystemAdmin(uid: string): Promise<SystemAdminProfile | null> {
    const snap = await this.userDocRef(uid).get();
    if (!snap.exists) return null;
    const data = snap.data() || {};
    if (!data.isSystemAdmin) return null;
    return {
      uid: snap.id,
      email: await this.readEmail(data, snap.id),
      displayName: data.displayName,
      firstName: data.firstName,
      lastName: data.lastName,
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      lastSeen: data.lastSeen,
      isSystemAdmin: true,
      addedBy: data.addedBy,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt
    };
  }

  async listSystemAdmins(): Promise<SystemAdminProfile[]> {
    const col: any = this.db.collection(this.usersCollection);
    const queryTarget = typeof col.where === "function" ? col.where("isSystemAdmin", "==", true) : col;
    const snap = await queryTarget.get();
    const results: SystemAdminProfile[] = [];
    for (const d of snap.docs) {
      const data = d.data() || {};
      if (!data.isSystemAdmin) continue;
      results.push({
        uid: d.id,
        email: await this.readEmail(data, d.id),
        displayName: data.displayName,
        firstName: data.firstName,
        lastName: data.lastName,
        photoUrl: sanitizeAvatarUrl(data.photoUrl),
        lastSeen: data.lastSeen,
        isSystemAdmin: true,
        addedBy: data.addedBy,
        createdAt: data.createdAt,
        updatedAt: data.updatedAt
      });
    }
    return results;
  }

  async upsertSystemAdmin(profile: SystemAdminProfile): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(profile.uid, "uid");
    const { email, ...card } = profile;
    await this.writeAttributesTier(cleanUid, null, undefined, email);
    const payload = stripUndefinedFields({
      ...card,
      ...this.cardEmailField(email),
      uid: cleanUid,
      isSystemAdmin: profile.isSystemAdmin ?? true,
      ...(profile.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(profile.photoUrl) } : {})
    });
    await this.userDocRef(cleanUid).set(payload, { merge: true });
  }

  async deleteSystemAdmin(uid: string): Promise<void> {
    const ref = this.userDocRef(uid);
    const snap = await ref.get();
    if (!snap.exists) return;
    // Preserve the user document (preferences, attributes, profile) while setting isSystemAdmin: false
    await ref.set(
      {
        isSystemAdmin: false,
        updatedAt: new Date().toISOString()
      },
      { merge: true }
    );
  }

  private parseScopedMember(
    docId: string,
    cleanScopeId: string,
    data: Record<string, any>
  ): ScopedMember<TRole, TCapability, TPreferences, TAttributes> {
    return {
      uid: data.uid || docId,
      // Private emails are merged from the attributes tier by mergePrivateTiers
      email: this.cardFields.email ? data.email || "" : "",
      ...(data.firstName !== undefined ? { firstName: data.firstName } : {}),
      ...(data.lastName !== undefined ? { lastName: data.lastName } : {}),
      ...(data.displayName !== undefined ? { displayName: data.displayName } : {}),
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      roles: this.extractRoles(data),
      scopeId: cleanScopeId,
      ...(data.scopeName !== undefined ? { scopeName: data.scopeName } : {}),
      ...(data.lastSeen !== undefined ? { lastSeen: data.lastSeen } : {}),
      ...(data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? { attributes: sanitizeObjectPatch<TAttributes>(data.attributes) }
        : {})
    };
  }

  /** Reads a scoped member card and merges its `private/preferences` and `private/attributes` tiers into it. */
  async getScopeMember(
    scopeId: string,
    uid: string
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const snap = await this.memberDocRef(cleanScopeId, uid).get();
    if (!snap.exists) return null;
    return this.mergePrivateTiers(
      this.parseScopedMember(snap.id, cleanScopeId, snap.data() || {}),
      snap.id,
      cleanScopeId
    );
  }

  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const snap = await this.db.collection(`${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}`).get();
    return Promise.all(
      snap.docs.map((d) =>
        this.mergePrivateTiers(this.parseScopedMember(d.id, cleanScopeId, d.data() || {}), d.id, cleanScopeId)
      )
    );
  }

  /**
   * Upserts a scoped member card. `member.preferences` are merged into the self-only `private/preferences`
   * tier and `member.attributes` into the `private/attributes` tier (except keys placed on the card via
   * `cardFields.attributes`); neither tier is ever stored on the card.
   */
  async upsertScopeMember(
    scopeId: string,
    member: ScopedMemberUpsert<TRole, TCapability, TPreferences, TAttributes>
  ): Promise<void> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(member.uid, "uid");
    const { preferences, attributes, email, ...card } = member;
    // Validate both tier patches before writing anything
    const cleanPrefs = preferences !== undefined ? this.cleanTierPatch(preferences, "preferences") : undefined;
    if (attributes !== undefined) this.cleanTierPatch(attributes, "attributes");
    if (cleanPrefs !== undefined) await this.writeTierDoc("preferences", cleanUid, cleanScopeId, cleanPrefs);
    const cardAttributes = await this.writeAttributesTier(cleanUid, cleanScopeId, attributes, email);
    const payload = stripUndefinedFields({
      ...card,
      ...this.cardEmailField(email),
      ...(card.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(card.photoUrl) } : {}),
      uid: cleanUid,
      scopeId: cleanScopeId,
      // Omitted roles leave the stored roles untouched (merge write)
      ...(card.roles !== undefined ? { roles: Array.from(new Set(card.roles)) } : {}),
      ...(Object.keys(cardAttributes).length > 0 ? { attributes: cardAttributes } : {})
    });
    await this.memberDocRef(cleanScopeId, cleanUid).set(payload, { merge: true });
  }

  async updateScopeMemberAttributes(
    scopeId: string,
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const ref = this.memberDocRef(cleanScopeId, cleanUid);
    const snap = await ref.get();
    if (!snap.exists) {
      throw new Error(`Member '${cleanUid}' does not exist in scope '${cleanScopeId}'`);
    }
    const cardAttributes = await this.writeAttributesTier(cleanUid, cleanScopeId, patch);
    if (Object.keys(cardAttributes).length > 0) {
      await ref.set({ attributes: cardAttributes }, { merge: true });
    }
    return (await this.getScopeMember(cleanScopeId, cleanUid))!;
  }

  async getScopeMemberHiddenAttributes(scopeId: string, uid: string): Promise<Partial<THiddenAttributes>> {
    const snap = await this.memberHiddenAttributesDocRef(scopeId, uid).get();
    if (!snap.exists) return {};
    return readTierDocValues<THiddenAttributes>(snap.data());
  }

  async updateScopeMemberHiddenAttributes(
    scopeId: string,
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanPatch = sanitizeObjectPatch<THiddenAttributes>(patch);
    assertNoReservedTierKeys(cleanPatch, "hiddenAttributes");
    await this.memberHiddenAttributesDocRef(cleanScopeId, cleanUid).set(
      { ...cleanPatch, ...tierDocMetadata("hiddenAttributes", cleanUid, cleanScopeId) },
      { merge: true }
    );
    return this.getScopeMemberHiddenAttributes(cleanScopeId, cleanUid);
  }

  async getScopeMemberSecrets(scopeId: string, uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    const snap = await this.memberSecretsDocRef(scopeId, uid).get();
    if (!snap.exists) return {};
    return this.decryptSecretsFromDocData(snap.data() || {}, `${this.scopeCollection}/${scopeId}/${uid}`);
  }

  async getScopeMemberSecretsStatus(
    scopeId: string,
    uid: string
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const snap = await this.memberSecretsDocRef(scopeId, uid).get();
    if (!snap.exists) return {};
    return this.parseSecretsStatusFromDocData(snap.data() || {}, `${this.scopeCollection}/${scopeId}/${uid}`);
  }

  async updateScopeMemberSecrets(
    scopeId: string,
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.writeEncryptedSecretsToRef(
      this.memberSecretsDocRef(cleanScopeId, cleanUid),
      cleanUid,
      cleanScopeId,
      patch
    );
  }

  async grantScopeRoles(
    scopeId: string,
    uid: string,
    roles: readonly TRole[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    const ref = this.memberDocRef(scopeId, uid);
    const snap = await ref.get();
    if (!snap.exists) {
      if (!fallbackMember) {
        throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'`);
      }
      // Grants never add default roles: a new record gets exactly the granted roles
      const initialRoles = Array.from(new Set(roles));
      const created: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
        ...fallbackMember,
        ...(fallbackMember.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fallbackMember.photoUrl) } : {}),
        uid,
        scopeId,
        roles: initialRoles
      };
      await this.upsertScopeMember(scopeId, created);
      return created;
    }

    if (roles.length > 0) {
      await ref.update({
        roles: FieldValue.arrayUnion(...roles)
      });
    }
    return (await this.getScopeMember(scopeId, uid))!;
  }

  async revokeScopeRoles(scopeId: string, uid: string, roles: readonly TRole[]): Promise<void> {
    if (roles.length === 0) return;
    const ref = this.memberDocRef(scopeId, uid);
    const snap = await ref.get();
    if (!snap.exists) return;
    await ref.update({
      roles: FieldValue.arrayRemove(...roles)
    });
  }

  async queryMemberUids(scopeId: string | null, attributes: Partial<TAttributes>): Promise<string[]> {
    const cleanScopeId = scopeId === null ? null : assertValidFirestoreDocId(scopeId, "scopeId");
    const location = resolveAttributeQueryLocation(attributes, this.cardFields);
    let target: FirebaseFirestore.Query =
      location === "card"
        ? this.db.collection(
            cleanScopeId === null
              ? this.usersCollection
              : `${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}`
          )
        : this.db
            .collectionGroup("private")
            .where(`${TIER_METADATA_KEY}.tier`, "==", "attributes")
            .where(`${TIER_METADATA_KEY}.scopeId`, "==", cleanScopeId);
    for (const [key, value] of Object.entries(attributes)) {
      target = target.where(location === "card" ? `attributes.${key}` : key, "==", value);
    }
    const snap = await target.get();
    if (location === "card") return snap.docs.map((d) => (typeof d.data()?.uid === "string" ? d.data().uid : d.id));
    return snap.docs
      .map((d) => d.data()?.[TIER_METADATA_KEY]?.uid)
      .filter((uid): uid is string => typeof uid === "string");
  }

  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    await this.deleteMergedTiers(uid, assertValidFirestoreDocId(scopeId, "scopeId")).catch(() => {});
    await this.memberHiddenAttributesDocRef(scopeId, uid)
      .delete()
      .catch(() => {});
    await this.memberSecretsDocRef(scopeId, uid)
      .delete()
      .catch(() => {});
    const memberRef = this.memberDocRef(scopeId, uid);
    await memberRef.delete();
    // Also remove any remaining private documents (e.g. custom docs) under the member
    await this.db.recursiveDelete(memberRef);
  }
}

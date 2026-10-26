import {
  collection,
  collectionGroup,
  doc,
  onSnapshot,
  query,
  setDoc,
  updateDoc,
  where,
  type Firestore
} from "firebase/firestore";
import {
  assertValidResourceId,
  sanitizeAvatarUrl,
  type LanyardClientStore,
  type ScopedMember,
  type SubscribeToUsersOptions,
  type UserProfilePatch,
  type UserRecord
} from "../core/index.js";

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
}

interface MultiplexedUserWatcher<
  TRole extends string,
  TCapability extends string,
  TPreferences extends Record<string, any>,
  TAttributes extends Record<string, any>
> {
  unsubFirestore: () => void;
  latestSnapshot: { exists: boolean; user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null } | null;
  userCallbacks: Set<(user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void>;
  prefCallbacks: Set<(prefs: Partial<TPreferences>) => void>;
}

/**
 * Firestore implementation of `LanyardClientStore`.
 *
 * Uses a single canonical `users/{uid}` collection for profile, presence, `isSystemAdmin`,
 * single-tenant `roles`, `preferences`, and `attributes`, and multiplexes
 * `onSnapshot` listeners per UID so subscribing to both user state and preferences only
 * ever opens **1 Firestore document listener**.
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
  }

  private extractRoles(data: Record<string, any>): TRole[] {
    if (Array.isArray(data.roles) && data.roles.length > 0) {
      return Array.from(new Set(data.roles as TRole[]));
    }
    return [...this.defaultRoles];
  }

  private extractPreferencesFromDocData(data: Record<string, any>): Partial<TPreferences> {
    if (data.preferences && typeof data.preferences === "object" && !Array.isArray(data.preferences)) {
      return sanitizeObjectPatch<TPreferences>(data.preferences);
    }
    return {} as Partial<TPreferences>;
  }

  private parseUserRecord(
    uid: string,
    data: Record<string, any>
  ): UserRecord<TRole, TCapability, TPreferences, TAttributes> {
    const prefs = this.extractPreferencesFromDocData(data);
    const attrs =
      data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? sanitizeObjectPatch<TAttributes>(data.attributes)
        : ({} as Partial<TAttributes>);

    return {
      uid: data.uid || uid,
      email: data.email || "",
      ...(data.displayName !== undefined ? { displayName: data.displayName } : {}),
      ...(data.firstName !== undefined ? { firstName: data.firstName } : {}),
      ...(data.lastName !== undefined ? { lastName: data.lastName } : {}),
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      ...(data.lastSeen !== undefined ? { lastSeen: data.lastSeen } : {}),
      ...(typeof data.isSystemAdmin === "boolean" ? { isSystemAdmin: data.isSystemAdmin } : {}),
      ...(data.addedBy !== undefined ? { addedBy: data.addedBy } : {}),
      roles: this.extractRoles(data),
      preferences: prefs,
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
      userCallbacks: new Set(),
      prefCallbacks: new Set()
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
            cb({
              ...parsed,
              preferences: { ...(parsed.preferences || {}) } as Partial<TPreferences>,
              attributes: { ...(parsed.attributes || {}) } as Partial<TAttributes>
            });
          }
          for (const cb of watcher.prefCallbacks) {
            cb({ ...(parsed.preferences || {}) } as Partial<TPreferences>);
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
    if (watcher.userCallbacks.size === 0 && watcher.prefCallbacks.size === 0) {
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
      onChange(
        u
          ? {
              ...u,
              preferences: { ...(u.preferences || {}) } as Partial<TPreferences>,
              attributes: { ...(u.attributes || {}) } as Partial<TAttributes>
            }
          : null
      );
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
        onChange(list);
      },
      () => {
        onChange([]);
      }
    );
  }

  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const watcher = this.ensureUserWatcher(cleanUid);
    watcher.prefCallbacks.add(onChange);
    if (watcher.latestSnapshot?.exists && watcher.latestSnapshot.user) {
      onChange({ ...(watcher.latestSnapshot.user.preferences || {}) } as Partial<TPreferences>);
    }
    return () => {
      watcher.prefCallbacks.delete(onChange);
      this.releaseWatcherIfUnused(cleanUid);
    };
  }

  async savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const userRef = doc(this.db, this.usersCollection, cleanUid);
    const cleanPatch = sanitizeObjectPatch<TPreferences>(patch);
    await setDoc(
      userRef,
      {
        uid: cleanUid,
        preferences: cleanPatch,
        updatedAt: new Date().toISOString()
      },
      { merge: true }
    );
  }

  async saveScopePreferences(scopeId: string, uid: string, patch: Partial<TPreferences>): Promise<void> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanPatch = sanitizeObjectPatch<TPreferences>(patch);
    if (Object.keys(cleanPatch).length === 0) return;

    const memberRef = doc(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection, cleanUid);
    const dotPayload: Record<string, any> = {};
    for (const [k, v] of Object.entries(cleanPatch)) {
      dotPayload[`preferences.${k}`] = v;
    }
    await updateDoc(memberRef, dotPayload);
  }

  async updateUserProfile(uid: string, patch: UserProfilePatch): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return;
    // Strictly allow ONLY Tier-1 self-editable profile fields (never isSystemAdmin, role, capabilities, attributes, or secrets)
    const safePayload: Record<string, any> = {
      uid: cleanUid,
      updatedAt: new Date().toISOString()
    };
    if (typeof patch.email === "string" && patch.email.trim()) safePayload.email = patch.email.toLowerCase().trim();
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
    // Strictly allow ONLY Tier-1 self-editable profile fields on the existing scoped member doc
    const safePayload: Record<string, any> = {};
    if (typeof patch.email === "string" && patch.email.trim()) safePayload.email = patch.email.toLowerCase().trim();
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
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
  ): () => void {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const colRef = collection(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection);
    return onSnapshot(
      colRef,
      (snapshot) => {
        const list: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[] = [];
        snapshot.forEach((docSnap) => {
          const data = docSnap.data();
          list.push(this.parseScopedMember(docSnap.id, cleanScopeId, data));
        });
        onChange(list);
      },
      () => {
        onChange([]);
      }
    );
  }

  private parseScopedMember(
    docId: string,
    scopeId: string | undefined,
    data: Record<string, any>
  ): ScopedMember<TRole, TCapability, TPreferences, TAttributes> {
    return {
      uid: data.uid || docId,
      email: data.email || "",
      firstName: data.firstName,
      lastName: data.lastName,
      displayName: data.displayName,
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      roles: this.extractRoles(data),
      scopeId,
      scopeName: data.scopeName,
      lastSeen: data.lastSeen,
      ...(data.preferences && typeof data.preferences === "object" && !Array.isArray(data.preferences)
        ? { preferences: sanitizeObjectPatch<TPreferences>(data.preferences) }
        : {}),
      ...(data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? { attributes: sanitizeObjectPatch<TAttributes>(data.attributes) }
        : {})
    };
  }

  async syncAvatar(params: {
    uid: string;
    photoUrl: string;
    scopeId?: string;
    email?: string | null;
    displayName?: string | null;
  }): Promise<void> {
    const { uid, photoUrl, scopeId, email, displayName } = params;
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
      if (email) payload.email = email;
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

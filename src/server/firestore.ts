import { FieldValue, type Firestore } from "firebase-admin/firestore";
import {
  assertValidResourceId,
  sanitizeAvatarUrl,
  type LanyardServerStore,
  type ScopedMember,
  type SystemAdminProfile,
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

export interface FirestoreServerStoreConfig<TRole extends string = string> {
  db: Firestore;
  /** Default role assigned if a stored document does not have a `role` field. */
  defaultRole: TRole;
  /** Optional custom role resolver for migrating legacy documents (e.g., `isCreator` flags). */
  resolveRole?: (data: Record<string, any>) => TRole;
  /** Canonical users collection name (defaults to `"users"`). */
  usersCollection?: string;
  scopeCollection?: string;
  membersSubcollection?: string;
}

/**
 * Firebase Admin Firestore implementation of `LanyardServerStore`.
 *
 * Uses a single canonical `users/{uid}` collection for profile, presence, `isSystemAdmin`,
 * single-tenant `role`/`capabilities`, `preferences`, and `attributes`, plus isolated
 * `private/secrets` subdocuments (`users/{uid}/private/secrets` and
 * `{scopeCollection}/{scopeId}/{membersSubcollection}/{uid}/private/secrets`).
 */
export class FirestoreServerStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>,
  TSecrets extends Record<string, any> = Record<string, any>
> implements LanyardServerStore<TRole, TCapability, TPreferences, TAttributes, TSecrets> {
  private readonly db: Firestore;
  private readonly defaultRole: TRole;
  private readonly resolveRole?: (data: Record<string, any>) => TRole;
  private readonly usersCollection: string;
  private readonly scopeCollection: string;
  private readonly membersSubcollection: string;

  constructor(config: FirestoreServerStoreConfig<TRole>) {
    this.db = config.db;
    this.defaultRole = config.defaultRole;
    this.resolveRole = config.resolveRole;
    this.usersCollection = assertValidFirestoreDocId(config.usersCollection || "users", "usersCollection");
    this.scopeCollection = assertValidFirestoreDocId(config.scopeCollection || "workspaces", "scopeCollection");
    this.membersSubcollection = assertValidFirestoreDocId(
      config.membersSubcollection || "members",
      "membersSubcollection"
    );
  }

  private extractRole(data: Record<string, any>): TRole {
    if (this.resolveRole) {
      return this.resolveRole(data);
    }
    return (data.role as TRole) || this.defaultRole;
  }

  private userDocRef(uid: string) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.usersCollection}/${cleanUid}`);
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

  private memberSecretsDocRef(scopeId: string, uid: string) {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(
      `${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}/${cleanUid}/private/secrets`
    );
  }

  private parseUserRecord(
    docId: string,
    data: Record<string, any>
  ): UserRecord<TRole, TCapability, TPreferences, TAttributes> {
    return {
      uid: data.uid || docId,
      email: data.email || "",
      ...(data.displayName !== undefined ? { displayName: data.displayName } : {}),
      ...(data.firstName !== undefined ? { firstName: data.firstName } : {}),
      ...(data.lastName !== undefined ? { lastName: data.lastName } : {}),
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      ...(data.lastSeen !== undefined ? { lastSeen: data.lastSeen } : {}),
      ...(typeof data.isSystemAdmin === "boolean" ? { isSystemAdmin: data.isSystemAdmin } : {}),
      ...(data.addedBy !== undefined ? { addedBy: data.addedBy } : {}),
      role: this.extractRole(data),
      capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
      ...(data.preferences && typeof data.preferences === "object" && !Array.isArray(data.preferences)
        ? { preferences: sanitizeObjectPatch<TPreferences>(data.preferences) }
        : {}),
      ...(data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? { attributes: sanitizeObjectPatch<TAttributes>(data.attributes) }
        : {}),
      ...(data.createdAt !== undefined ? { createdAt: data.createdAt } : {}),
      ...(data.updatedAt !== undefined ? { updatedAt: data.updatedAt } : {})
    };
  }

  async getUser(uid: string): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null> {
    const snap = await this.userDocRef(uid).get();
    if (!snap.exists) return null;
    return this.parseUserRecord(snap.id, snap.data() || {});
  }

  async upsertUser(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(user.uid, "uid");
    const payload = stripUndefinedFields({
      ...user,
      uid: cleanUid,
      ...(user.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(user.photoUrl) } : {}),
      ...(user.capabilities !== undefined ? { capabilities: Array.from(new Set(user.capabilities)) } : {}),
      ...(user.preferences !== undefined ? { preferences: sanitizeObjectPatch<TPreferences>(user.preferences) } : {}),
      ...(user.attributes !== undefined ? { attributes: sanitizeObjectPatch<TAttributes>(user.attributes) } : {})
    });
    await this.userDocRef(cleanUid).set(payload, { merge: true });
  }

  async updateUserAttributes(
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const ref = this.userDocRef(cleanUid);
    const now = new Date().toISOString();
    await ref.set(
      {
        uid: cleanUid,
        attributes: sanitizeObjectPatch<TAttributes>(patch),
        updatedAt: now
      },
      { merge: true }
    );
    return (await this.getUser(cleanUid))!;
  }

  async getUserSecrets(uid: string): Promise<Partial<TSecrets>> {
    const snap = await this.userSecretsDocRef(uid).get();
    if (!snap.exists) return {};
    return sanitizeObjectPatch<TSecrets>(snap.data() || {});
  }

  async updateUserSecrets(uid: string, patch: Partial<TSecrets>): Promise<Partial<TSecrets>> {
    const ref = this.userSecretsDocRef(uid);
    const cleanPatch = sanitizeObjectPatch<TSecrets>(patch);
    await ref.set(cleanPatch, { merge: true });
    return this.getUserSecrets(uid);
  }

  async grantUserCapabilities(
    uid: string,
    capabilities: readonly TCapability[],
    fallbackUser?: Omit<UserRecord<TRole, TCapability, TPreferences, TAttributes>, "capabilities">
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const ref = this.userDocRef(cleanUid);
    const snap = await ref.get();
    if (!snap.exists) {
      if (!fallbackUser) {
        throw new Error(`User '${cleanUid}' does not exist`);
      }
      const created: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
        ...fallbackUser,
        ...(fallbackUser.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fallbackUser.photoUrl) } : {}),
        uid: cleanUid,
        role: fallbackUser.role ?? this.defaultRole,
        capabilities: Array.from(new Set(capabilities))
      };
      await ref.set(stripUndefinedFields(created), { merge: true });
      return created;
    }

    if (capabilities.length > 0) {
      await ref.update({
        capabilities: FieldValue.arrayUnion(...capabilities)
      });
    }
    return (await this.getUser(cleanUid))!;
  }

  async revokeUserCapabilities(uid: string, capabilities: readonly TCapability[]): Promise<void> {
    if (capabilities.length === 0) return;
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const ref = this.userDocRef(cleanUid);
    const snap = await ref.get();
    if (!snap.exists) return;
    await ref.update({
      capabilities: FieldValue.arrayRemove(...capabilities)
    });
  }

  async getSystemAdmin(uid: string): Promise<SystemAdminProfile | null> {
    const snap = await this.userDocRef(uid).get();
    if (!snap.exists) return null;
    const data = snap.data() || {};
    if (!data.isSystemAdmin) return null;
    return {
      uid: snap.id,
      email: data.email || "",
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
        email: data.email || "",
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
    const payload = stripUndefinedFields({
      ...profile,
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
      email: data.email || "",
      ...(data.firstName !== undefined ? { firstName: data.firstName } : {}),
      ...(data.lastName !== undefined ? { lastName: data.lastName } : {}),
      ...(data.displayName !== undefined ? { displayName: data.displayName } : {}),
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      role: this.extractRole(data),
      capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
      scopeId: cleanScopeId,
      ...(data.scopeName !== undefined ? { scopeName: data.scopeName } : {}),
      ...(data.lastSeen !== undefined ? { lastSeen: data.lastSeen } : {}),
      ...(data.preferences && typeof data.preferences === "object" && !Array.isArray(data.preferences)
        ? { preferences: sanitizeObjectPatch<TPreferences>(data.preferences) }
        : {}),
      ...(data.attributes && typeof data.attributes === "object" && !Array.isArray(data.attributes)
        ? { attributes: sanitizeObjectPatch<TAttributes>(data.attributes) }
        : {})
    };
  }

  async getScopeMember(
    scopeId: string,
    uid: string
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const snap = await this.memberDocRef(cleanScopeId, uid).get();
    if (!snap.exists) return null;
    return this.parseScopedMember(snap.id, cleanScopeId, snap.data() || {});
  }

  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const snap = await this.db.collection(`${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}`).get();
    return snap.docs.map((d) => this.parseScopedMember(d.id, cleanScopeId, d.data() || {}));
  }

  async upsertScopeMember(
    scopeId: string,
    member: ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  ): Promise<void> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(member.uid, "uid");
    const payload = stripUndefinedFields({
      ...member,
      ...(member.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(member.photoUrl) } : {}),
      uid: cleanUid,
      scopeId: cleanScopeId,
      capabilities: Array.from(new Set(member.capabilities || [])),
      ...(member.preferences !== undefined
        ? { preferences: sanitizeObjectPatch<TPreferences>(member.preferences) }
        : {}),
      ...(member.attributes !== undefined ? { attributes: sanitizeObjectPatch<TAttributes>(member.attributes) } : {})
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
    await ref.set(
      {
        attributes: sanitizeObjectPatch<TAttributes>(patch)
      },
      { merge: true }
    );
    return (await this.getScopeMember(cleanScopeId, cleanUid))!;
  }

  async getScopeMemberSecrets(scopeId: string, uid: string): Promise<Partial<TSecrets>> {
    const snap = await this.memberSecretsDocRef(scopeId, uid).get();
    if (!snap.exists) return {};
    return sanitizeObjectPatch<TSecrets>(snap.data() || {});
  }

  async updateScopeMemberSecrets(scopeId: string, uid: string, patch: Partial<TSecrets>): Promise<Partial<TSecrets>> {
    const ref = this.memberSecretsDocRef(scopeId, uid);
    const cleanPatch = sanitizeObjectPatch<TSecrets>(patch);
    await ref.set(cleanPatch, { merge: true });
    return this.getScopeMemberSecrets(scopeId, uid);
  }

  async grantScopeCapabilities(
    scopeId: string,
    uid: string,
    capabilities: readonly TCapability[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability, TPreferences, TAttributes>, "capabilities">
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    const ref = this.memberDocRef(scopeId, uid);
    const snap = await ref.get();
    if (!snap.exists) {
      if (!fallbackMember) {
        throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'`);
      }
      const created: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
        ...fallbackMember,
        ...(fallbackMember.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fallbackMember.photoUrl) } : {}),
        uid,
        scopeId,
        capabilities: Array.from(new Set(capabilities))
      };
      await ref.set(stripUndefinedFields(created), { merge: true });
      return created;
    }

    if (capabilities.length > 0) {
      await ref.update({
        capabilities: FieldValue.arrayUnion(...capabilities)
      });
    }
    return (await this.getScopeMember(scopeId, uid))!;
  }

  async revokeScopeCapabilities(scopeId: string, uid: string, capabilities: readonly TCapability[]): Promise<void> {
    if (capabilities.length === 0) return;
    const ref = this.memberDocRef(scopeId, uid);
    const snap = await ref.get();
    if (!snap.exists) return;
    await ref.update({
      capabilities: FieldValue.arrayRemove(...capabilities)
    });
  }

  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    await this.memberSecretsDocRef(scopeId, uid)
      .delete()
      .catch(() => {});
    await this.memberDocRef(scopeId, uid).delete();
  }
}

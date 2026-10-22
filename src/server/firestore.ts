import { FieldValue, type Firestore } from "firebase-admin/firestore";
import {
  assertValidResourceId,
  sanitizeAvatarUrl,
  type LanyardServerStore,
  type ScopedMember,
  type SecretCipher,
  type SystemAdminProfile,
  type UserRecord
} from "../core/index.js";
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

export interface FirestoreServerStoreConfig<TRole extends string = string> {
  db: Firestore;
  /** Default role assigned if a stored document does not have a `roles` field. */
  defaultRole: TRole;
  /** Canonical users collection name (defaults to `"users"`). */
  usersCollection?: string;
  scopeCollection?: string;
  membersSubcollection?: string;
  /**
   * Master encryption key used to encrypt and decrypt write-only secrets at rest (`private/secrets`)
   * with AES-256-GCM. Defaults to `process.env.MASTER_ENCRYPTION_KEY` if set.
   */
  encryptionKey?: string;
  /** Optional custom `SecretCipher` instance (overrides `encryptionKey`). */
  cipher?: SecretCipher;
}

/**
 * Firebase Admin Firestore implementation of `LanyardServerStore`.
 *
 * Uses a single canonical `users/{uid}` collection for profile, presence, `isSystemAdmin`,
 * single-tenant `roles`, `preferences`, and `attributes`, plus isolated
 * `private/hiddenAttributes` and AES-256-GCM encrypted `private/secrets` subdocuments.
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
  private readonly defaultRole: TRole;
  private readonly usersCollection: string;
  private readonly scopeCollection: string;
  private readonly membersSubcollection: string;
  private readonly cipher?: SecretCipher;

  constructor(config: FirestoreServerStoreConfig<TRole>) {
    this.db = config.db;
    this.defaultRole = config.defaultRole;
    this.usersCollection = assertValidFirestoreDocId(config.usersCollection || "users", "usersCollection");
    this.scopeCollection = assertValidFirestoreDocId(config.scopeCollection || "workspaces", "scopeCollection");
    this.membersSubcollection = assertValidFirestoreDocId(
      config.membersSubcollection || "members",
      "membersSubcollection"
    );
    const key = config.encryptionKey || process.env.MASTER_ENCRYPTION_KEY;
    this.cipher = config.cipher ?? (key ? createSecretCipher(key) : undefined);
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

  private extractRoles(data: Record<string, any>): TRole[] {
    if (Array.isArray(data.roles) && data.roles.length > 0) {
      return Array.from(new Set(data.roles as TRole[]));
    }
    return [this.defaultRole];
  }

  private userDocRef(uid: string) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.usersCollection}/${cleanUid}`);
  }

  private userHiddenAttributesDocRef(uid: string) {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.usersCollection}/${cleanUid}/private/hiddenAttributes`);
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

  private scopeSecretsDocRef(scopeId: string) {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    return this.db.doc(`${this.scopeCollection}/${cleanScopeId}/private/secrets`);
  }

  private parseSecretsStatusFromDocData(data: Record<string, any>): Partial<Record<keyof TSecrets & string, boolean>> {
    const status: Record<string, boolean> = {};
    for (const [k, v] of Object.entries(data)) {
      if (FORBIDDEN_KEYS.has(k) || k === "updatedAt") continue;
      status[k] = isEncryptedSecretData(v) || (typeof v === "string" && v.length > 0);
    }
    return status as Partial<Record<keyof TSecrets & string, boolean>>;
  }

  private decryptSecretsFromDocData(data: Record<string, any>): Partial<Record<keyof TSecrets & string, string>> {
    const out: Record<string, string> = {};
    const entries = Object.entries(data).filter(([k]) => !FORBIDDEN_KEYS.has(k) && k !== "updatedAt");
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
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
      const snap = await ref.get();
      return snap.exists ? this.parseSecretsStatusFromDocData(snap.data() || {}) : {};
    }
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
      await ref.set(firestorePayload, { merge: true });
    }
    const snap = await ref.get();
    return snap.exists ? this.parseSecretsStatusFromDocData(snap.data() || {}) : {};
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
      roles: this.extractRoles(data),
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

  async listUsers(): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>[]> {
    const snap = await this.db.collection(this.usersCollection).get();
    return snap.docs.map((doc) => this.parseUserRecord(doc.id, doc.data() || {}));
  }

  async deleteUser(uid: string): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const userRef = this.userDocRef(cleanUid);
    await Promise.all([
      userRef.delete(),
      this.userHiddenAttributesDocRef(cleanUid).delete(),
      this.userSecretsDocRef(cleanUid).delete()
    ]);
    if (typeof (this.db as any).recursiveDelete === "function") {
      await (this.db as any).recursiveDelete(userRef);
    }
  }

  async upsertUser(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(user.uid, "uid");
    const payload = stripUndefinedFields({
      ...user,
      uid: cleanUid,
      ...(user.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(user.photoUrl) } : {}),
      ...(user.roles !== undefined ? { roles: Array.from(new Set(user.roles)) } : {}),
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

  async getUserHiddenAttributes(uid: string): Promise<Partial<THiddenAttributes>> {
    const snap = await this.userHiddenAttributesDocRef(uid).get();
    if (!snap.exists) return {};
    return sanitizeObjectPatch<THiddenAttributes>(snap.data() || {});
  }

  async updateUserHiddenAttributes(
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    const ref = this.userHiddenAttributesDocRef(uid);
    const cleanPatch = sanitizeObjectPatch<THiddenAttributes>(patch);
    await ref.set(cleanPatch, { merge: true });
    return this.getUserHiddenAttributes(uid);
  }

  async getUserSecrets(uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    const snap = await this.userSecretsDocRef(uid).get();
    if (!snap.exists) return {};
    return this.decryptSecretsFromDocData(snap.data() || {});
  }

  async getUserSecretsStatus(uid: string): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const snap = await this.userSecretsDocRef(uid).get();
    if (!snap.exists) return {};
    return this.parseSecretsStatusFromDocData(snap.data() || {});
  }

  async updateUserSecrets(
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const ref = this.userSecretsDocRef(uid);
    return this.writeEncryptedSecretsToRef(ref, patch);
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
      const initialRoles = roles.length > 0 ? Array.from(new Set(roles)) : [this.defaultRole];
      const created: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
        ...fallbackUser,
        ...(fallbackUser.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fallbackUser.photoUrl) } : {}),
        uid: cleanUid,
        roles: initialRoles
      };
      await ref.set(stripUndefinedFields(created), { merge: true });
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
      roles: this.extractRoles(data),
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
      roles: Array.from(new Set(member.roles || [])),
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

  async getScopeMemberHiddenAttributes(scopeId: string, uid: string): Promise<Partial<THiddenAttributes>> {
    const snap = await this.memberHiddenAttributesDocRef(scopeId, uid).get();
    if (!snap.exists) return {};
    return sanitizeObjectPatch<THiddenAttributes>(snap.data() || {});
  }

  async updateScopeMemberHiddenAttributes(
    scopeId: string,
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    const ref = this.memberHiddenAttributesDocRef(scopeId, uid);
    const cleanPatch = sanitizeObjectPatch<THiddenAttributes>(patch);
    await ref.set(cleanPatch, { merge: true });
    return this.getScopeMemberHiddenAttributes(scopeId, uid);
  }

  async getScopeMemberSecrets(scopeId: string, uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    const snap = await this.memberSecretsDocRef(scopeId, uid).get();
    if (!snap.exists) return {};
    return this.decryptSecretsFromDocData(snap.data() || {});
  }

  async getScopeMemberSecretsStatus(
    scopeId: string,
    uid: string
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const snap = await this.memberSecretsDocRef(scopeId, uid).get();
    if (!snap.exists) return {};
    return this.parseSecretsStatusFromDocData(snap.data() || {});
  }

  async updateScopeMemberSecrets(
    scopeId: string,
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const ref = this.memberSecretsDocRef(scopeId, uid);
    return this.writeEncryptedSecretsToRef(ref, patch);
  }

  async getScopeSecrets(scopeId: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    const snap = await this.scopeSecretsDocRef(scopeId).get();
    if (!snap.exists) return {};
    return this.decryptSecretsFromDocData(snap.data() || {});
  }

  async getScopeSecretsStatus(scopeId: string): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const snap = await this.scopeSecretsDocRef(scopeId).get();
    if (!snap.exists) return {};
    return this.parseSecretsStatusFromDocData(snap.data() || {});
  }

  async updateScopeSecrets(
    scopeId: string,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    const ref = this.scopeSecretsDocRef(scopeId);
    return this.writeEncryptedSecretsToRef(ref, patch);
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
      const initialRoles = roles.length > 0 ? Array.from(new Set(roles)) : [this.defaultRole];
      const created: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
        ...fallbackMember,
        ...(fallbackMember.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fallbackMember.photoUrl) } : {}),
        uid,
        scopeId,
        roles: initialRoles
      };
      await ref.set(stripUndefinedFields(created), { merge: true });
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

  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    await this.memberHiddenAttributesDocRef(scopeId, uid)
      .delete()
      .catch(() => {});
    await this.memberSecretsDocRef(scopeId, uid)
      .delete()
      .catch(() => {});
    await this.memberDocRef(scopeId, uid).delete();
  }
}

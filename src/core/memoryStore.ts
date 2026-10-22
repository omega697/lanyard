import { assertValidResourceId, sanitizeAvatarUrl } from "./formatters.js";
import type {
  EncryptedSecretData,
  LanyardClientStore,
  LanyardServerStore,
  ScopedMember,
  SecretCipher,
  SystemAdminProfile,
  UserProfilePatch,
  UserRecord
} from "./models.js";

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function sanitizePatch<T extends Record<string, any>>(patch: Partial<T> | null | undefined): Partial<T> {
  const clean: Record<string, any> = {};
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
    return clean as Partial<T>;
  }
  for (const [k, v] of Object.entries(patch)) {
    if (!FORBIDDEN_KEYS.has(k)) {
      clean[k] = v;
    }
  }
  return clean as Partial<T>;
}

/**
 * In-memory storage implementation of BOTH `LanyardClientStore` and `LanyardServerStore`
 * for fast, deterministic unit tests without mocking external databases.
 *
 * Uses a unified `users` map (`users/{uid}`) for profile, presence, `isSystemAdmin`,
 * single-tenant `role`/`capabilities`, `preferences`, and `attributes`, plus isolated
 * maps for `userSecrets`, `scopeMembers`, and `scopeMemberSecrets`.
 */
export class InMemoryLanyardStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>,
  THiddenAttributes extends Record<string, any> = Record<string, any>,
  TSecrets extends Record<string, any> = Record<string, any>
>
  implements
    LanyardClientStore<TRole, TCapability, TPreferences, TAttributes>,
    LanyardServerStore<TRole, TCapability, TPreferences, TAttributes, THiddenAttributes, TSecrets>
{
  private readonly cipher?: SecretCipher;
  private users = new Map<string, UserRecord<TRole, TCapability, TPreferences, TAttributes>>();
  private userHiddenAttributes = new Map<string, Partial<THiddenAttributes>>();
  private userSecrets = new Map<string, Record<string, string | EncryptedSecretData>>();
  // scopeId -> (uid -> ScopedMember)
  private scopeMembers = new Map<string, Map<string, ScopedMember<TRole, TCapability, TPreferences, TAttributes>>>();
  // scopeId -> (uid -> Partial<THiddenAttributes>)
  private scopeMemberHiddenAttributes = new Map<string, Map<string, Partial<THiddenAttributes>>>();
  // scopeId -> (uid -> Record<string, string | EncryptedSecretData>)
  private scopeMemberSecrets = new Map<string, Map<string, Record<string, string | EncryptedSecretData>>>();

  constructor(options?: { cipher?: SecretCipher }) {
    this.cipher = options?.cipher;
  }

  private encryptSecretMapPatch(
    current: Record<string, string | EncryptedSecretData>,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Record<string, string | EncryptedSecretData> {
    const next: Record<string, string | EncryptedSecretData> = { ...current };
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return next;
    for (const [k, v] of Object.entries(patch)) {
      if (FORBIDDEN_KEYS.has(k) || v === undefined) continue;
      if (v === null || v === "") {
        delete next[k];
      } else if (typeof v === "string") {
        next[k] = this.cipher ? this.cipher.encrypt(v) : v;
      }
    }
    return next;
  }

  private decryptSecretMap(
    stored: Record<string, string | EncryptedSecretData> | undefined
  ): Partial<Record<keyof TSecrets & string, string>> {
    const out: Record<string, string> = {};
    if (!stored) return out as Partial<Record<keyof TSecrets & string, string>>;
    for (const [k, v] of Object.entries(stored)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      if (typeof v === "string") {
        out[k] = v;
      } else if (v && typeof v === "object" && typeof v.ciphertext === "string" && this.cipher) {
        out[k] = this.cipher.decrypt(v);
      }
    }
    return out as Partial<Record<keyof TSecrets & string, string>>;
  }

  private toSecretStatusMap(
    stored: Record<string, string | EncryptedSecretData> | undefined
  ): Partial<Record<keyof TSecrets & string, boolean>> {
    const out: Record<string, boolean> = {};
    if (!stored) return out as Partial<Record<keyof TSecrets & string, boolean>>;
    for (const [k, v] of Object.entries(stored)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      out[k] = Boolean(v);
    }
    return out as Partial<Record<keyof TSecrets & string, boolean>>;
  }

  private prefListeners = new Map<string, Set<(prefs: Partial<TPreferences>) => void>>();
  private userListeners = new Map<
    string,
    Set<(user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void>
  >();
  private usersDirectoryListeners = new Set<
    (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void
  >();
  private userMembershipListeners = new Map<
    string,
    Set<(members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void>
  >();
  private scopeMemberListeners = new Map<
    string,
    Set<(members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void>
  >();

  // --- Client Store Methods ---

  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void {
    assertValidResourceId(uid, "uid");
    if (!this.prefListeners.has(uid)) {
      this.prefListeners.set(uid, new Set());
    }
    this.prefListeners.get(uid)!.add(onChange);
    const existing = this.users.get(uid);
    onChange({ ...(existing?.preferences || {}) } as Partial<TPreferences>);

    return () => {
      this.prefListeners.get(uid)?.delete(onChange);
    };
  }

  async savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void> {
    assertValidResourceId(uid, "uid");
    const existing = this.users.get(uid);
    const currentPrefs = existing?.preferences || {};
    const updatedPrefs = { ...currentPrefs, ...sanitizePatch(patch) };
    const updatedUser: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || { uid, email: "" }),
      uid,
      preferences: updatedPrefs
    };
    this.users.set(uid, updatedUser);
    this.notifyUserAndPrefListeners(uid);
  }

  async saveScopePreferences(scopeId: string, uid: string, patch: Partial<TPreferences>): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const existing = await this.getScopeMember(scopeId, uid);
    if (!existing) {
      throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'.`);
    }
    const updated: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      preferences: {
        ...(existing.preferences || {}),
        ...sanitizePatch(patch)
      }
    };
    await this.upsertScopeMember(scopeId, updated);
  }

  subscribeToUser(
    uid: string,
    onChange: (user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void
  ): () => void {
    assertValidResourceId(uid, "uid");
    if (!this.userListeners.has(uid)) {
      this.userListeners.set(uid, new Set());
    }
    this.userListeners.get(uid)!.add(onChange);
    onChange(this.cloneUser(this.users.get(uid) || null));

    return () => {
      this.userListeners.get(uid)?.delete(onChange);
    };
  }

  subscribeToUsers(onChange: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void): () => void {
    this.usersDirectoryListeners.add(onChange);
    onChange(Array.from(this.users.values()).map((u) => this.cloneUser(u)!));

    return () => {
      this.usersDirectoryListeners.delete(onChange);
    };
  }

  async updateUserProfile(uid: string, patch: UserProfilePatch): Promise<void> {
    assertValidResourceId(uid, "uid");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return;
    const existing = this.users.get(uid) || { uid, email: "" };
    const next: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid
    };
    if (typeof patch.email === "string" && patch.email.trim()) next.email = patch.email.toLowerCase().trim();
    if (typeof patch.firstName === "string") next.firstName = patch.firstName.trim();
    if (typeof patch.lastName === "string") next.lastName = patch.lastName.trim();
    if (typeof patch.displayName === "string") next.displayName = patch.displayName.trim();
    if (patch.photoUrl !== undefined) next.photoUrl = sanitizeAvatarUrl(patch.photoUrl);
    next.updatedAt = new Date().toISOString();
    this.users.set(uid, next);
    this.notifyUserAndPrefListeners(uid);
  }

  async updateScopeMemberProfile(scopeId: string, uid: string, patch: UserProfilePatch): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return;
    const existing = await this.getScopeMember(scopeId, uid);
    if (!existing) {
      throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'.`);
    }
    const next: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid,
      scopeId
    };
    if (typeof patch.email === "string" && patch.email.trim()) next.email = patch.email.toLowerCase().trim();
    if (typeof patch.firstName === "string") next.firstName = patch.firstName.trim();
    if (typeof patch.lastName === "string") next.lastName = patch.lastName.trim();
    if (typeof patch.displayName === "string") next.displayName = patch.displayName.trim();
    if (patch.photoUrl !== undefined) next.photoUrl = sanitizeAvatarUrl(patch.photoUrl);
    await this.upsertScopeMember(scopeId, next);
  }

  subscribeToUserMemberships(
    uid: string,
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
  ): () => void {
    assertValidResourceId(uid, "uid");
    if (!this.userMembershipListeners.has(uid)) {
      this.userMembershipListeners.set(uid, new Set());
    }
    this.userMembershipListeners.get(uid)!.add(onChange);
    onChange(this.getMembershipsForUser(uid));

    return () => {
      this.userMembershipListeners.get(uid)?.delete(onChange);
    };
  }

  subscribeToScopeMembers(
    scopeId: string,
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
  ): () => void {
    assertValidResourceId(scopeId, "scopeId");
    if (!this.scopeMemberListeners.has(scopeId)) {
      this.scopeMemberListeners.set(scopeId, new Set());
    }
    this.scopeMemberListeners.get(scopeId)!.add(onChange);
    onChange(this.getMembersForScopeSync(scopeId));

    return () => {
      this.scopeMemberListeners.get(scopeId)?.delete(onChange);
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
    assertValidResourceId(uid, "uid");
    const cleanPhotoUrl = sanitizeAvatarUrl(photoUrl);
    if (!cleanPhotoUrl) return;
    if (scopeId) {
      assertValidResourceId(scopeId, "scopeId");
      const existing = await this.getScopeMember(scopeId, uid);
      if (existing && existing.photoUrl !== cleanPhotoUrl) {
        await this.upsertScopeMember(scopeId, { ...existing, photoUrl: cleanPhotoUrl });
      }
    } else {
      const existingUser = this.users.get(uid);
      if (existingUser) {
        if (existingUser.photoUrl !== cleanPhotoUrl) {
          await this.upsertUser({ ...existingUser, photoUrl: cleanPhotoUrl });
        }
      } else if (email) {
        await this.upsertUser({
          uid,
          email,
          displayName: displayName || email,
          photoUrl: cleanPhotoUrl,
          isSystemAdmin: true
        });
      }
    }
  }

  async recordPresenceHeartbeat(params: {
    uid: string;
    scopeId?: string;
    lastSeenIso: string;
    photoUrl?: string | null;
  }): Promise<void> {
    const { uid, scopeId, lastSeenIso, photoUrl } = params;
    assertValidResourceId(uid, "uid");
    const cleanPhotoUrl = sanitizeAvatarUrl(photoUrl);
    if (scopeId) {
      assertValidResourceId(scopeId, "scopeId");
      const existing = await this.getScopeMember(scopeId, uid);
      if (existing) {
        await this.upsertScopeMember(scopeId, {
          ...existing,
          lastSeen: lastSeenIso,
          ...(cleanPhotoUrl ? { photoUrl: cleanPhotoUrl } : {})
        });
      }
    } else {
      const existingUser = this.users.get(uid);
      if (existingUser) {
        await this.upsertUser({
          ...existingUser,
          lastSeen: lastSeenIso,
          ...(cleanPhotoUrl ? { photoUrl: cleanPhotoUrl } : {})
        });
      }
    }
  }

  // --- Server Store Methods: Global Users & System Admins ---

  async getUser(uid: string): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null> {
    assertValidResourceId(uid, "uid");
    return this.cloneUser(this.users.get(uid) || null);
  }

  async listUsers(): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>[]> {
    return Array.from(this.users.values()).map((u) => this.cloneUser(u)!);
  }

  async deleteUser(uid: string): Promise<void> {
    assertValidResourceId(uid, "uid");
    this.users.delete(uid);
    this.userHiddenAttributes.delete(uid);
    this.userSecrets.delete(uid);
    this.notifyUserAndPrefListeners(uid);
  }

  async upsertUser(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void> {
    assertValidResourceId(user.uid, "uid");
    const existing = this.users.get(user.uid);
    const merged: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || {}),
      ...user,
      uid: user.uid,
      ...(user.photoUrl !== undefined
        ? { photoUrl: sanitizeAvatarUrl(user.photoUrl) }
        : existing?.photoUrl !== undefined
          ? { photoUrl: existing.photoUrl }
          : {}),
      ...(user.roles !== undefined
        ? { roles: Array.from(new Set(user.roles)) }
        : existing?.roles !== undefined
          ? { roles: [...existing.roles] }
          : {}),
      ...(user.preferences !== undefined
        ? { preferences: { ...(existing?.preferences || {}), ...sanitizePatch(user.preferences) } }
        : existing?.preferences !== undefined
          ? { preferences: { ...existing.preferences } }
          : {}),
      ...(user.attributes !== undefined
        ? { attributes: { ...(existing?.attributes || {}), ...sanitizePatch(user.attributes) } }
        : existing?.attributes !== undefined
          ? { attributes: { ...existing.attributes } }
          : {})
    };
    this.users.set(user.uid, merged);
    this.notifyUserAndPrefListeners(user.uid);
  }

  async updateUserAttributes(
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(uid, "uid");
    const existing = this.users.get(uid) || { uid, email: "" };
    const updatedAttributes = {
      ...(existing.attributes || {}),
      ...sanitizePatch(patch)
    };
    const updated: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid,
      attributes: updatedAttributes,
      updatedAt: new Date().toISOString()
    };
    this.users.set(uid, updated);
    this.notifyUserAndPrefListeners(uid);
    return this.cloneUser(updated)!;
  }

  async getUserHiddenAttributes(uid: string): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(uid, "uid");
    return { ...(this.userHiddenAttributes.get(uid) || {}) } as Partial<THiddenAttributes>;
  }

  async updateUserHiddenAttributes(
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(uid, "uid");
    const current = this.userHiddenAttributes.get(uid) || {};
    const updated = { ...current, ...sanitizePatch(patch) };
    this.userHiddenAttributes.set(uid, updated);
    return { ...updated };
  }

  async getUserSecrets(uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    assertValidResourceId(uid, "uid");
    return this.decryptSecretMap(this.userSecrets.get(uid));
  }

  async getUserSecretsStatus(uid: string): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(uid, "uid");
    return this.toSecretStatusMap(this.userSecrets.get(uid));
  }

  async updateUserSecrets(
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(uid, "uid");
    const current = this.userSecrets.get(uid) || {};
    const updated = this.encryptSecretMapPatch(current, patch);
    this.userSecrets.set(uid, updated);
    return this.toSecretStatusMap(updated);
  }

  async grantUserRoles(
    uid: string,
    roles: readonly TRole[],
    fallbackUser?: Omit<UserRecord<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(uid, "uid");
    const existing = await this.getUser(uid);
    if (!existing && !fallbackUser) {
      throw new Error(`User '${uid}' does not exist and no fallbackUser was provided.`);
    }
    const base = existing || {
      ...fallbackUser!,
      uid,
      roles: [] as TRole[]
    };
    const mergedRoles = Array.from(new Set([...(base.roles || []), ...roles]));
    const updated: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...base,
      uid,
      roles: mergedRoles,
      updatedAt: new Date().toISOString()
    };
    await this.upsertUser(updated);
    return (await this.getUser(uid))!;
  }

  async revokeUserRoles(uid: string, roles: readonly TRole[]): Promise<void> {
    assertValidResourceId(uid, "uid");
    const existing = await this.getUser(uid);
    if (!existing) return;
    const revokeSet = new Set(roles);
    const remaining = (existing.roles || []).filter((r) => !revokeSet.has(r));
    await this.upsertUser({
      ...existing,
      roles: remaining,
      updatedAt: new Date().toISOString()
    });
  }

  async getSystemAdmin(uid: string): Promise<SystemAdminProfile | null> {
    assertValidResourceId(uid, "uid");
    const user = this.users.get(uid);
    if (!user || !user.isSystemAdmin) return null;
    return this.toAdminProfile(user);
  }

  async listSystemAdmins(): Promise<SystemAdminProfile[]> {
    const result: SystemAdminProfile[] = [];
    for (const user of this.users.values()) {
      if (user.isSystemAdmin) {
        result.push(this.toAdminProfile(user));
      }
    }
    return result;
  }

  async upsertSystemAdmin(profile: SystemAdminProfile): Promise<void> {
    assertValidResourceId(profile.uid, "uid");
    const existing = this.users.get(profile.uid);
    await this.upsertUser({
      ...(existing || {}),
      ...profile,
      uid: profile.uid,
      isSystemAdmin: profile.isSystemAdmin ?? true
    });
  }

  async deleteSystemAdmin(uid: string): Promise<void> {
    assertValidResourceId(uid, "uid");
    const existing = this.users.get(uid);
    if (!existing) return;
    // Preserve the user record (preferences, attributes, profile) while marking isSystemAdmin: false
    this.users.set(uid, {
      ...existing,
      isSystemAdmin: false,
      updatedAt: new Date().toISOString()
    });
    this.notifyUserAndPrefListeners(uid);
  }

  // --- Server Store Methods: Scoped Members ---

  async getScopeMember(
    scopeId: string,
    uid: string
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const member = this.scopeMembers.get(scopeId)?.get(uid);
    return member ? this.cloneMember(member) : null;
  }

  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]> {
    assertValidResourceId(scopeId, "scopeId");
    return this.getMembersForScopeSync(scopeId);
  }

  async upsertScopeMember(
    scopeId: string,
    member: ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  ): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(member.uid, "uid");
    if (!this.scopeMembers.has(scopeId)) {
      this.scopeMembers.set(scopeId, new Map());
    }
    const existing = this.scopeMembers.get(scopeId)!.get(member.uid);
    const normalized: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || {}),
      ...member,
      ...(member.photoUrl !== undefined
        ? { photoUrl: sanitizeAvatarUrl(member.photoUrl) }
        : existing?.photoUrl !== undefined
          ? { photoUrl: existing.photoUrl }
          : {}),
      scopeId,
      roles: Array.from(new Set(member.roles || [])),
      ...(member.preferences !== undefined
        ? { preferences: { ...(existing?.preferences || {}), ...sanitizePatch(member.preferences) } }
        : existing?.preferences !== undefined
          ? { preferences: { ...existing.preferences } }
          : {}),
      ...(member.attributes !== undefined
        ? { attributes: { ...(existing?.attributes || {}), ...sanitizePatch(member.attributes) } }
        : existing?.attributes !== undefined
          ? { attributes: { ...existing.attributes } }
          : {})
    };
    this.scopeMembers.get(scopeId)!.set(member.uid, normalized);
    this.notifyMembershipListeners(scopeId, member.uid);
  }

  async updateScopeMemberAttributes(
    scopeId: string,
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const existing = await this.getScopeMember(scopeId, uid);
    if (!existing) {
      throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'.`);
    }
    const updated: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      attributes: {
        ...(existing.attributes || {}),
        ...sanitizePatch(patch)
      }
    };
    await this.upsertScopeMember(scopeId, updated);
    return this.cloneMember(updated);
  }

  async getScopeMemberHiddenAttributes(scopeId: string, uid: string): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    return { ...(this.scopeMemberHiddenAttributes.get(scopeId)?.get(uid) || {}) } as Partial<THiddenAttributes>;
  }

  async updateScopeMemberHiddenAttributes(
    scopeId: string,
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    if (!this.scopeMemberHiddenAttributes.has(scopeId)) {
      this.scopeMemberHiddenAttributes.set(scopeId, new Map());
    }
    const current = this.scopeMemberHiddenAttributes.get(scopeId)!.get(uid) || {};
    const updated = { ...current, ...sanitizePatch(patch) };
    this.scopeMemberHiddenAttributes.get(scopeId)!.set(uid, updated);
    return { ...updated };
  }

  async getScopeMemberSecrets(scopeId: string, uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    return this.decryptSecretMap(this.scopeMemberSecrets.get(scopeId)?.get(uid));
  }

  async getScopeMemberSecretsStatus(
    scopeId: string,
    uid: string
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    return this.toSecretStatusMap(this.scopeMemberSecrets.get(scopeId)?.get(uid));
  }

  async updateScopeMemberSecrets(
    scopeId: string,
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    if (!this.scopeMemberSecrets.has(scopeId)) {
      this.scopeMemberSecrets.set(scopeId, new Map());
    }
    const current = this.scopeMemberSecrets.get(scopeId)!.get(uid) || {};
    const updated = this.encryptSecretMapPatch(current, patch);
    this.scopeMemberSecrets.get(scopeId)!.set(uid, updated);
    return this.toSecretStatusMap(updated);
  }

  async grantScopeRoles(
    scopeId: string,
    uid: string,
    roles: readonly TRole[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const existing = await this.getScopeMember(scopeId, uid);
    if (!existing && !fallbackMember) {
      throw new Error(`Member '${uid}' does not exist in scope '${scopeId}' and no fallbackMember was provided.`);
    }
    const base = existing || {
      ...fallbackMember!,
      uid,
      scopeId,
      roles: [] as TRole[]
    };
    const mergedRoles = Array.from(new Set([...(base.roles || []), ...roles]));
    const updated: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...base,
      scopeId,
      roles: mergedRoles
    };
    await this.upsertScopeMember(scopeId, updated);
    return this.cloneMember(updated);
  }

  async revokeScopeRoles(scopeId: string, uid: string, roles: readonly TRole[]): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const existing = await this.getScopeMember(scopeId, uid);
    if (!existing) return;
    const revokeSet = new Set(roles);
    const remaining = (existing.roles || []).filter((r) => !revokeSet.has(r));
    await this.upsertScopeMember(scopeId, {
      ...existing,
      roles: remaining
    });
  }

  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    this.scopeMembers.get(scopeId)?.delete(uid);
    this.scopeMemberHiddenAttributes.get(scopeId)?.delete(uid);
    this.scopeMemberSecrets.get(scopeId)?.delete(uid);
    this.notifyMembershipListeners(scopeId, uid);
  }

  // --- Internal Notification & Clone Helpers ---

  private toAdminProfile(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): SystemAdminProfile {
    return {
      uid: user.uid,
      email: user.email,
      displayName: user.displayName,
      firstName: user.firstName,
      lastName: user.lastName,
      photoUrl: user.photoUrl,
      lastSeen: user.lastSeen,
      isSystemAdmin: Boolean(user.isSystemAdmin),
      addedBy: user.addedBy,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }

  private cloneUser(
    user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null
  ): UserRecord<TRole, TCapability, TPreferences, TAttributes> | null {
    if (!user) return null;
    return {
      ...user,
      ...(user.roles ? { roles: [...user.roles] } : {}),
      ...(user.preferences ? { preferences: { ...user.preferences } } : {}),
      ...(user.attributes ? { attributes: { ...user.attributes } } : {})
    };
  }

  private cloneMember(
    member: ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  ): ScopedMember<TRole, TCapability, TPreferences, TAttributes> {
    return {
      ...member,
      roles: [...member.roles],
      ...(member.preferences ? { preferences: { ...member.preferences } } : {}),
      ...(member.attributes ? { attributes: { ...member.attributes } } : {})
    };
  }

  private getMembershipsForUser(uid: string): ScopedMember<TRole, TCapability, TPreferences, TAttributes>[] {
    const results: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[] = [];
    for (const [scopeId, membersMap] of this.scopeMembers.entries()) {
      const m = membersMap.get(uid);
      if (m) {
        results.push(this.cloneMember({ ...m, scopeId }));
      }
    }
    return results;
  }

  private getMembersForScopeSync(scopeId: string): ScopedMember<TRole, TCapability, TPreferences, TAttributes>[] {
    const map = this.scopeMembers.get(scopeId);
    if (!map) return [];
    return Array.from(map.values()).map((m) => this.cloneMember(m));
  }

  private notifyUserAndPrefListeners(uid: string): void {
    const user = this.users.get(uid) || null;
    const prefCallbacks = this.prefListeners.get(uid);
    if (prefCallbacks) {
      const snapshot = { ...(user?.preferences || {}) } as Partial<TPreferences>;
      for (const cb of prefCallbacks) {
        cb(snapshot);
      }
    }
    const userCallbacks = this.userListeners.get(uid);
    if (userCallbacks) {
      for (const cb of userCallbacks) {
        cb(this.cloneUser(user));
      }
    }
    if (this.usersDirectoryListeners.size > 0) {
      const allUsers = Array.from(this.users.values()).map((u) => this.cloneUser(u)!);
      for (const cb of this.usersDirectoryListeners) {
        cb(allUsers);
      }
    }
  }

  private notifyMembershipListeners(scopeId: string, uid: string): void {
    const userListeners = this.userMembershipListeners.get(uid);
    if (userListeners) {
      const userMemberships = this.getMembershipsForUser(uid);
      for (const cb of userListeners) {
        cb(userMemberships);
      }
    }

    const scopeListeners = this.scopeMemberListeners.get(scopeId);
    if (scopeListeners) {
      const scopeList = this.getMembersForScopeSync(scopeId);
      for (const cb of scopeListeners) {
        cb(scopeList);
      }
    }
  }
}

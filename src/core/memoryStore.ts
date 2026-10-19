import { assertValidResourceId, sanitizeAvatarUrl } from "./formatters.js";
import type { LanyardClientStore, LanyardServerStore, ScopedMember, SystemAdminProfile } from "./models.js";

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function sanitizePatch<T extends Record<string, any>>(patch: Partial<T>): Partial<T> {
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
 */
export class InMemoryLanyardStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>
>
  implements LanyardClientStore<TRole, TCapability, TPreferences>, LanyardServerStore<TRole, TCapability>
{
  private admins = new Map<string, SystemAdminProfile>();
  private preferences = new Map<string, Partial<TPreferences>>();
  // scopeId -> (uid -> ScopedMember)
  private scopeMembers = new Map<string, Map<string, ScopedMember<TRole, TCapability>>>();

  private prefListeners = new Map<string, Set<(prefs: Partial<TPreferences>) => void>>();
  private userMembershipListeners = new Map<string, Set<(members: ScopedMember<TRole, TCapability>[]) => void>>();
  private scopeMemberListeners = new Map<string, Set<(members: ScopedMember<TRole, TCapability>[]) => void>>();

  // --- Client Store Methods ---

  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void {
    assertValidResourceId(uid, "uid");
    if (!this.prefListeners.has(uid)) {
      this.prefListeners.set(uid, new Set());
    }
    this.prefListeners.get(uid)!.add(onChange);
    onChange({ ...(this.preferences.get(uid) || {}) } as Partial<TPreferences>);

    return () => {
      this.prefListeners.get(uid)?.delete(onChange);
    };
  }

  async savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void> {
    assertValidResourceId(uid, "uid");
    const current = this.preferences.get(uid) || {};
    const updated = { ...current, ...sanitizePatch(patch) };
    this.preferences.set(uid, updated);
    this.notifyPrefListeners(uid);
  }

  subscribeToUserMemberships(uid: string, onChange: (members: ScopedMember<TRole, TCapability>[]) => void): () => void {
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
    onChange: (members: ScopedMember<TRole, TCapability>[]) => void
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
      const existingAdmin = await this.getSystemAdmin(uid);
      if (existingAdmin) {
        if (existingAdmin.photoUrl !== cleanPhotoUrl) {
          await this.upsertSystemAdmin({ ...existingAdmin, photoUrl: cleanPhotoUrl });
        }
      } else if (email) {
        await this.upsertSystemAdmin({
          uid,
          email,
          displayName: displayName || email,
          photoUrl: cleanPhotoUrl
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
      const existingAdmin = await this.getSystemAdmin(uid);
      if (existingAdmin) {
        await this.upsertSystemAdmin({
          ...existingAdmin,
          lastSeen: lastSeenIso,
          ...(cleanPhotoUrl ? { photoUrl: cleanPhotoUrl } : {})
        });
      }
    }
  }

  // --- Server Store Methods ---

  async getSystemAdmin(uid: string): Promise<SystemAdminProfile | null> {
    assertValidResourceId(uid, "uid");
    const admin = this.admins.get(uid);
    return admin ? { ...admin } : null;
  }

  async listSystemAdmins(): Promise<SystemAdminProfile[]> {
    return Array.from(this.admins.values()).map((a) => ({ ...a }));
  }

  async upsertSystemAdmin(profile: SystemAdminProfile): Promise<void> {
    assertValidResourceId(profile.uid, "uid");
    this.admins.set(profile.uid, {
      ...profile,
      ...(profile.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(profile.photoUrl) } : {})
    });
  }

  async deleteSystemAdmin(uid: string): Promise<void> {
    assertValidResourceId(uid, "uid");
    this.admins.delete(uid);
  }

  async getScopeMember(scopeId: string, uid: string): Promise<ScopedMember<TRole, TCapability> | null> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const member = this.scopeMembers.get(scopeId)?.get(uid);
    return member ? { ...member, capabilities: [...member.capabilities] } : null;
  }

  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability>[]> {
    assertValidResourceId(scopeId, "scopeId");
    return this.getMembersForScopeSync(scopeId);
  }

  async upsertScopeMember(scopeId: string, member: ScopedMember<TRole, TCapability>): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(member.uid, "uid");
    if (!this.scopeMembers.has(scopeId)) {
      this.scopeMembers.set(scopeId, new Map());
    }
    const normalized: ScopedMember<TRole, TCapability> = {
      ...member,
      ...(member.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(member.photoUrl) } : {}),
      scopeId,
      capabilities: Array.from(new Set(member.capabilities || []))
    };
    this.scopeMembers.get(scopeId)!.set(member.uid, normalized);
    this.notifyMembershipListeners(scopeId, member.uid);
  }

  async grantScopeCapabilities(
    scopeId: string,
    uid: string,
    capabilities: readonly TCapability[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability>, "capabilities">
  ): Promise<ScopedMember<TRole, TCapability>> {
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
      capabilities: [] as TCapability[]
    };
    const mergedCapabilities = Array.from(new Set([...(base.capabilities || []), ...capabilities]));
    const updated: ScopedMember<TRole, TCapability> = {
      ...base,
      scopeId,
      capabilities: mergedCapabilities
    };
    await this.upsertScopeMember(scopeId, updated);
    return updated;
  }

  async revokeScopeCapabilities(scopeId: string, uid: string, capabilities: readonly TCapability[]): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const existing = await this.getScopeMember(scopeId, uid);
    if (!existing) return;
    const revokeSet = new Set(capabilities);
    const remaining = (existing.capabilities || []).filter((c) => !revokeSet.has(c));
    await this.upsertScopeMember(scopeId, {
      ...existing,
      capabilities: remaining
    });
  }

  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    this.scopeMembers.get(scopeId)?.delete(uid);
    this.notifyMembershipListeners(scopeId, uid);
  }

  // --- Internal Notification Helpers ---

  private getMembershipsForUser(uid: string): ScopedMember<TRole, TCapability>[] {
    const results: ScopedMember<TRole, TCapability>[] = [];
    for (const [scopeId, membersMap] of this.scopeMembers.entries()) {
      const m = membersMap.get(uid);
      if (m) {
        results.push({ ...m, scopeId, capabilities: [...m.capabilities] });
      }
    }
    return results;
  }

  private getMembersForScopeSync(scopeId: string): ScopedMember<TRole, TCapability>[] {
    const map = this.scopeMembers.get(scopeId);
    if (!map) return [];
    return Array.from(map.values()).map((m) => ({ ...m, capabilities: [...m.capabilities] }));
  }

  private notifyPrefListeners(uid: string): void {
    const listeners = this.prefListeners.get(uid);
    if (!listeners) return;
    const snapshot = { ...(this.preferences.get(uid) || {}) } as Partial<TPreferences>;
    for (const cb of listeners) {
      cb(snapshot);
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

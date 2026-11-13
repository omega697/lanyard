import {
  assertValidResourceId,
  assertValidRevocationEpoch,
  nextSessionRevocations,
  sanitizeAvatarUrl
} from "./formatters.js";
import { assertNoEmailInProfilePatch, SESSION_REVOCATION_RETENTION_MS } from "./models.js";
import type {
  CardFieldsPlacement,
  EncryptedSecretData,
  LanyardClientStore,
  LanyardServerStore,
  LanyardStorePlacementSource,
  RevocationEpochListener,
  SessionRevocationsListener,
  ScopedMember,
  ScopedMemberUpsert,
  SecretCipher,
  StoredProfileFieldsPatch,
  SubscribeToMembersOptions,
  SubscribeToUsersOptions,
  SystemAdminProfile,
  UserProfilePatch,
  UserRecord
} from "./models.js";
import {
  assertCustomDocName,
  assertNoReservedAttributeKeys,
  assertNoReservedTierKeys,
  resolveAttributeQueryLocation,
  resolveCardFields,
  splitAttributesByPlacement,
  splitAttributesTierValues
} from "./tierDocs.js";

/** Private tier documents whose values are merged into user/member records. */
type MergedTier = "preferences" | "attributes";

/** Equality matching Firestore `==` filters for the JSON-like values Lanyard stores. */
function firestoreValuesEqual(a: unknown, b: unknown): boolean {
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return Object.is(a, b);
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Map key for a tier document: global (`scopeId === null`) or scoped. */
function tierKey(scopeId: string | null, uid: string): string {
  return JSON.stringify([scopeId, uid]);
}

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
 * single-tenant `role`/`capabilities`, and card-placed `attributes` (`cardFields.attributes`), plus isolated
 * maps for each private tier (`preferences`, `attributes`, `hiddenAttributes`, `secrets`) and their scoped
 * equivalents.
 *
 * Mirrors the Firestore stores' tier layout: client subscriptions to users and members return only the card
 * (preferences and private attributes arrive via `subscribeToPreferences`/`subscribeToAttributes` and their
 * scoped variants), while server reads (`getUser`, `listUsers`, `getScopeMember`, `listScopeMembers`) merge
 * the tiers back in.
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
  readonly cardFields: CardFieldsPlacement;
  private users = new Map<string, UserRecord<TRole, TCapability, TPreferences, TAttributes>>();
  // tier -> (tierKey(scopeId, uid) -> values)
  private tierValues: Record<MergedTier, Map<string, Record<string, any>>> = {
    preferences: new Map(),
    attributes: new Map()
  };
  private userHiddenAttributes = new Map<string, Partial<THiddenAttributes>>();
  private userSecrets = new Map<string, Record<string, string | EncryptedSecretData>>();
  // scopeId -> (uid -> ScopedMember)
  private scopeMembers = new Map<string, Map<string, ScopedMember<TRole, TCapability, TPreferences, TAttributes>>>();
  // scopeId -> (uid -> Partial<THiddenAttributes>)
  private scopeMemberHiddenAttributes = new Map<string, Map<string, Partial<THiddenAttributes>>>();
  // scopeId -> (uid -> Record<string, string | EncryptedSecretData>)
  private scopeMemberSecrets = new Map<string, Map<string, Record<string, string | EncryptedSecretData>>>();

  /**
   * @param options.policy The app's `PermissionPolicy`, used to place `cardFields.attributes` on the card
   *   (omit if the policy doesn't set `cardFields`).
   */
  constructor(options?: { cipher?: SecretCipher; policy?: LanyardStorePlacementSource }) {
    this.cipher = options?.cipher;
    this.cardFields = resolveCardFields(options?.policy);
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

  // JSON.stringify([name, scopeId, uid]) -> custom document values / listeners
  private customDocValues = new Map<string, Record<string, any>>();
  private customDocListeners = new Map<string, Set<(values: Record<string, any>) => void>>();
  // tier -> (tierKey(scopeId, uid) -> listeners)
  private tierListeners: Record<MergedTier, Map<string, Set<(values: Record<string, any>) => void>>> = {
    preferences: new Map(),
    attributes: new Map()
  };
  private userListeners = new Map<
    string,
    Set<(user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void>
  >();
  private usersDirectoryListeners = new Set<{
    cb: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void;
    options?: SubscribeToUsersOptions;
  }>();
  private userMembershipListeners = new Map<
    string,
    Set<(members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void>
  >();
  private scopeMemberListeners = new Map<
    string,
    Set<(members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void>
  >();
  // Subset of scopeMemberListeners that include the attributes tier, re-notified when a member's tier changes
  private scopeMemberIncludeListeners = new Map<
    string,
    Set<(members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void>
  >();
  private revocationEpoch: number | null = null;
  private revocationEpochListeners = new Set<RevocationEpochListener>();

  // --- Revocation Epoch (shared by client and server sides) ---

  async getRevocationEpoch(): Promise<number | null> {
    return this.revocationEpoch;
  }

  async bumpRevocationEpoch(atMs: number): Promise<number> {
    assertValidRevocationEpoch(atMs);
    const next = Math.max(this.revocationEpoch ?? 0, atMs);
    if (next !== this.revocationEpoch) {
      this.revocationEpoch = next;
      for (const listener of [...this.revocationEpochListeners]) listener(next);
    }
    return next;
  }

  subscribeToRevocationEpoch(onChange: RevocationEpochListener, _onError: (error: unknown) => void): () => void {
    this.revocationEpochListeners.add(onChange);
    onChange(this.revocationEpoch);
    return () => {
      this.revocationEpochListeners.delete(onChange);
    };
  }

  private sessionRevocations: Readonly<Record<string, number>> = {};
  private sessionRevocationsListeners = new Set<SessionRevocationsListener>();

  async getSessionRevocations(): Promise<Readonly<Record<string, number>>> {
    return { ...this.sessionRevocations };
  }

  async recordSessionRevocation(uid: string, atMs: number): Promise<Readonly<Record<string, number>>> {
    this.sessionRevocations = nextSessionRevocations(
      this.sessionRevocations,
      uid,
      atMs,
      SESSION_REVOCATION_RETENTION_MS
    );
    for (const listener of [...this.sessionRevocationsListeners]) listener({ ...this.sessionRevocations });
    return { ...this.sessionRevocations };
  }

  subscribeToSessionRevocations(onChange: SessionRevocationsListener, _onError: (error: unknown) => void): () => void {
    this.sessionRevocationsListeners.add(onChange);
    onChange({ ...this.sessionRevocations });
    return () => {
      this.sessionRevocationsListeners.delete(onChange);
    };
  }

  // --- Client Store Methods ---

  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void {
    assertValidResourceId(uid, "uid");
    return this.subscribeToTier("preferences", null, uid, onChange);
  }

  subscribeToScopePreferences(
    scopeId: string,
    uid: string,
    onChange: (prefs: Partial<TPreferences>) => void
  ): () => void {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    return this.subscribeToTier("preferences", scopeId, uid, onChange);
  }

  subscribeToAttributes(uid: string, onChange: (attrs: Partial<TAttributes>, email?: string) => void): () => void {
    assertValidResourceId(uid, "uid");
    return this.subscribeToAttributesTier(null, uid, onChange);
  }

  subscribeToScopeAttributes(
    scopeId: string,
    uid: string,
    onChange: (attrs: Partial<TAttributes>, email?: string) => void
  ): () => void {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    return this.subscribeToAttributesTier(scopeId, uid, onChange);
  }

  async savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void> {
    assertValidResourceId(uid, "uid");
    this.mergeTier("preferences", null, uid, this.cleanTierPatch(patch, "preferences"));
  }

  async saveScopePreferences(scopeId: string, uid: string, patch: Partial<TPreferences>): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    if (!this.scopeMembers.get(scopeId)?.has(uid)) {
      throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'.`);
    }
    this.mergeTier("preferences", scopeId, uid, this.cleanTierPatch(patch, "preferences"));
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

  subscribeToUsers(
    onChange: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToUsersOptions
  ): () => void {
    const entry = { cb: onChange, options };
    this.usersDirectoryListeners.add(entry);
    onChange(this.getFilteredUsersSnapshot(options));

    return () => {
      this.usersDirectoryListeners.delete(entry);
    };
  }

  async updateUserProfile(uid: string, patch: UserProfilePatch): Promise<void> {
    assertValidResourceId(uid, "uid");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return;
    assertNoEmailInProfilePatch(patch);
    const existing = this.users.get(uid) || { uid, email: "" };
    const next: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid
    };
    if (typeof patch.firstName === "string") next.firstName = patch.firstName.trim();
    if (typeof patch.lastName === "string") next.lastName = patch.lastName.trim();
    if (typeof patch.displayName === "string") next.displayName = patch.displayName.trim();
    if (patch.photoUrl !== undefined) next.photoUrl = sanitizeAvatarUrl(patch.photoUrl);
    next.updatedAt = new Date().toISOString();
    this.users.set(uid, next);
    this.notifyUserListeners(uid);
  }

  async updateScopeMemberProfile(scopeId: string, uid: string, patch: UserProfilePatch): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return;
    assertNoEmailInProfilePatch(patch);
    const existing = this.getMemberCard(scopeId, uid);
    if (!existing) {
      throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'.`);
    }
    const next: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid,
      scopeId
    };
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
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToMembersOptions
  ): () => void {
    assertValidResourceId(scopeId, "scopeId");
    const includeAttributes = Boolean(options?.include?.includes("attributes"));
    const listener = includeAttributes
      ? (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) =>
          onChange(members.map((m) => this.withAttributesTier(m, scopeId)))
      : onChange;
    if (!this.scopeMemberListeners.has(scopeId)) {
      this.scopeMemberListeners.set(scopeId, new Set());
    }
    this.scopeMemberListeners.get(scopeId)!.add(listener);
    if (includeAttributes) {
      if (!this.scopeMemberIncludeListeners.has(scopeId)) this.scopeMemberIncludeListeners.set(scopeId, new Set());
      this.scopeMemberIncludeListeners.get(scopeId)!.add(listener);
    }
    listener(this.getMembersForScopeSync(scopeId));

    return () => {
      this.scopeMemberListeners.get(scopeId)?.delete(listener);
      this.scopeMemberIncludeListeners.get(scopeId)?.delete(listener);
    };
  }

  async syncAvatar(params: {
    uid: string;
    photoUrl: string;
    scopeId?: string;
    displayName?: string | null;
  }): Promise<void> {
    const { uid, photoUrl, scopeId, displayName } = params;
    assertValidResourceId(uid, "uid");
    const cleanPhotoUrl = sanitizeAvatarUrl(photoUrl);
    if (!cleanPhotoUrl) return;
    if (scopeId) {
      assertValidResourceId(scopeId, "scopeId");
      const existing = this.getMemberCard(scopeId, uid);
      if (existing && existing.photoUrl !== cleanPhotoUrl) {
        await this.upsertScopeMember(scopeId, { ...existing, photoUrl: cleanPhotoUrl });
      }
    } else {
      const existingUser = this.users.get(uid);
      if (existingUser) {
        if (existingUser.photoUrl !== cleanPhotoUrl) {
          await this.upsertUser({ ...existingUser, photoUrl: cleanPhotoUrl });
        }
      } else {
        // Like the Firestore client store's merge write: a plain card, never an admin directory entry
        await this.upsertUser({
          uid,
          email: "",
          ...(displayName ? { displayName } : {}),
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
      const existing = this.getMemberCard(scopeId, uid);
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

  async queryMemberUids(scopeId: string | null, attributes: Partial<TAttributes>): Promise<string[]> {
    if (scopeId !== null) assertValidResourceId(scopeId, "scopeId");
    const location = resolveAttributeQueryLocation(attributes, this.cardFields);
    const records: Array<{ uid: string; attributes?: Partial<TAttributes> }> =
      scopeId === null ? Array.from(this.users.values()) : Array.from(this.scopeMembers.get(scopeId)?.values() || []);
    return records
      .filter((record) => {
        const values: Record<string, any> =
          location === "card"
            ? record.attributes || {}
            : splitAttributesTierValues(this.tierValues.attributes.get(tierKey(scopeId, record.uid)) || {}).attributes;
        return Object.entries(attributes).every(([key, value]) => firestoreValuesEqual(values[key], value));
      })
      .map((record) => record.uid);
  }

  async getCustomDoc(name: string, uid: string, scopeId: string | null): Promise<Record<string, any>> {
    return { ...(this.customDocValues.get(this.customDocKey(name, uid, scopeId)) || {}) };
  }

  subscribeToCustomDoc(
    name: string,
    uid: string,
    scopeId: string | null,
    onChange: (values: Record<string, any>) => void
  ): () => void {
    const key = this.customDocKey(name, uid, scopeId);
    if (!this.customDocListeners.has(key)) this.customDocListeners.set(key, new Set());
    this.customDocListeners.get(key)!.add(onChange);
    onChange({ ...(this.customDocValues.get(key) || {}) });
    return () => {
      this.customDocListeners.get(key)?.delete(onChange);
    };
  }

  async updateCustomDoc(name: string, uid: string, scopeId: string | null, patch: Record<string, any>): Promise<void> {
    const key = this.customDocKey(name, uid, scopeId);
    const cleanPatch = sanitizePatch(patch);
    assertNoReservedTierKeys(cleanPatch, name);
    this.customDocValues.set(key, { ...(this.customDocValues.get(key) || {}), ...cleanPatch });
    this.notifyCustomDocListeners(key);
  }

  // --- Server Store Methods: Global Users & System Admins ---

  async getUser(uid: string): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null> {
    assertValidResourceId(uid, "uid");
    const user = this.users.get(uid);
    return user ? this.withPrivateTiers(user, null) : null;
  }

  async listUsers(): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>[]> {
    return Array.from(this.users.values()).map((u) => this.withPrivateTiers(u, null));
  }

  async deleteUser(uid: string): Promise<void> {
    assertValidResourceId(uid, "uid");
    this.users.delete(uid);
    this.userHiddenAttributes.delete(uid);
    this.userSecrets.delete(uid);
    this.notifyUserListeners(uid);
    this.deleteMergedTiers(null, uid);
  }

  async upsertUser(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void> {
    assertValidResourceId(user.uid, "uid");
    const { preferences, attributes, email, ...card } = user;
    // Validate both tier patches before writing anything
    const cleanPrefs = preferences !== undefined ? this.cleanTierPatch(preferences, "preferences") : undefined;
    const cleanAttrs = attributes !== undefined ? this.cleanTierPatch(attributes, "attributes") : undefined;
    if (cleanPrefs !== undefined) this.mergeTier("preferences", null, user.uid, cleanPrefs);
    const cardAttributes = this.writeAttributesTier(null, user.uid, cleanAttrs || {}, email);
    const existing = this.users.get(user.uid);
    const merged: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || {}),
      ...card,
      email: this.cardEmail(email, existing?.email),
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
      ...(Object.keys(cardAttributes).length > 0
        ? { attributes: { ...(existing?.attributes || {}), ...cardAttributes } }
        : existing?.attributes !== undefined
          ? { attributes: { ...existing.attributes } }
          : {})
    };
    this.users.set(user.uid, merged);
    this.notifyUserListeners(user.uid);
  }

  /** Applies a `patchUser`/`patchScopeMember` field patch to a card, routing a private email to its tier. */
  private applyProfileFieldsPatch<
    R extends
      | UserRecord<TRole, TCapability, TPreferences, TAttributes>
      | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >(card: R, scopeId: string | null, uid: string, fields: StoredProfileFieldsPatch): R {
    this.writeAttributesTier(scopeId, uid, {}, fields.email);
    return {
      ...card,
      ...(typeof fields.firstName === "string" ? { firstName: fields.firstName } : {}),
      ...(typeof fields.lastName === "string" ? { lastName: fields.lastName } : {}),
      ...(typeof fields.displayName === "string" ? { displayName: fields.displayName } : {}),
      ...(fields.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fields.photoUrl) } : {}),
      ...(this.cardFields.email && typeof fields.email === "string" ? { email: fields.email } : {}),
      updatedAt: new Date().toISOString()
    };
  }

  async patchUser(uid: string, fields: StoredProfileFieldsPatch): Promise<void> {
    assertValidResourceId(uid, "uid");
    const existing = this.users.get(uid);
    if (!existing) throw new Error(`User '${uid}' does not exist.`);
    this.users.set(uid, this.applyProfileFieldsPatch(existing, null, uid, fields));
    this.notifyUserListeners(uid);
  }

  async patchScopeMember(scopeId: string, uid: string, fields: StoredProfileFieldsPatch): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const existing = this.scopeMembers.get(scopeId)?.get(uid);
    if (!existing) throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'.`);
    this.scopeMembers.get(scopeId)!.set(uid, this.applyProfileFieldsPatch(existing, scopeId, uid, fields));
    this.notifyMembershipListeners(scopeId, uid);
  }

  async updateUserAttributes(
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(uid, "uid");
    const cardAttributes = this.writeAttributesTier(null, uid, this.cleanTierPatch(patch, "attributes"));
    const existing = this.users.get(uid) || { uid, email: "" };
    const updated: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid,
      ...(Object.keys(cardAttributes).length > 0
        ? { attributes: { ...(existing.attributes || {}), ...cardAttributes } }
        : {}),
      updatedAt: new Date().toISOString()
    };
    this.users.set(uid, updated);
    this.notifyUserListeners(uid);
    return this.withPrivateTiers(updated, null);
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
    const cleanPatch = sanitizePatch(patch);
    assertNoReservedTierKeys(cleanPatch, "hiddenAttributes");
    const updated = { ...current, ...cleanPatch };
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
    assertNoReservedTierKeys(patch || {}, "secrets");
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
    const existing = this.getUserCard(uid);
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
    const existing = this.getUserCard(uid);
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
    return this.toAdminProfile(this.withPrivateTiers(user, null));
  }

  async listSystemAdmins(): Promise<SystemAdminProfile[]> {
    const result: SystemAdminProfile[] = [];
    for (const user of this.users.values()) {
      if (user.isSystemAdmin) {
        result.push(this.toAdminProfile(this.withPrivateTiers(user, null)));
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
    this.notifyUserListeners(uid);
  }

  // --- Server Store Methods: Scoped Members ---

  async getScopeMember(
    scopeId: string,
    uid: string
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const member = this.scopeMembers.get(scopeId)?.get(uid);
    return member ? this.withPrivateTiers(member, scopeId) : null;
  }

  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]> {
    assertValidResourceId(scopeId, "scopeId");
    return Array.from(this.scopeMembers.get(scopeId)?.values() || []).map((m) => this.withPrivateTiers(m, scopeId));
  }

  async upsertScopeMember(
    scopeId: string,
    member: ScopedMemberUpsert<TRole, TCapability, TPreferences, TAttributes>
  ): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(member.uid, "uid");
    const { preferences, attributes, email, ...card } = member;
    // Validate both tier patches before writing anything
    const cleanPrefs = preferences !== undefined ? this.cleanTierPatch(preferences, "preferences") : undefined;
    const cleanAttrs = attributes !== undefined ? this.cleanTierPatch(attributes, "attributes") : undefined;
    if (cleanPrefs !== undefined) this.mergeTier("preferences", scopeId, member.uid, cleanPrefs);
    const cardAttributes = this.writeAttributesTier(scopeId, member.uid, cleanAttrs || {}, email);
    if (!this.scopeMembers.has(scopeId)) {
      this.scopeMembers.set(scopeId, new Map());
    }
    const existing = this.scopeMembers.get(scopeId)!.get(member.uid);
    const normalized: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || {}),
      ...card,
      email: this.cardEmail(email, existing?.email),
      ...(card.photoUrl !== undefined
        ? { photoUrl: sanitizeAvatarUrl(card.photoUrl) }
        : existing?.photoUrl !== undefined
          ? { photoUrl: existing.photoUrl }
          : {}),
      scopeId,
      // Omitted roles leave an existing member's roles untouched (a new member gets none)
      roles: card.roles !== undefined ? Array.from(new Set(card.roles)) : existing?.roles ? [...existing.roles] : [],
      ...(Object.keys(cardAttributes).length > 0
        ? { attributes: { ...(existing?.attributes || {}), ...cardAttributes } }
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
    const existing = this.getMemberCard(scopeId, uid);
    if (!existing) {
      throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'.`);
    }
    await this.upsertScopeMember(scopeId, { ...existing, attributes: sanitizePatch(patch) });
    return (await this.getScopeMember(scopeId, uid))!;
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
    const cleanPatch = sanitizePatch(patch);
    assertNoReservedTierKeys(cleanPatch, "hiddenAttributes");
    const updated = { ...current, ...cleanPatch };
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
    assertNoReservedTierKeys(patch || {}, "secrets");
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
    const existing = this.getMemberCard(scopeId, uid);
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
    return (await this.getScopeMember(scopeId, uid))!;
  }

  async revokeScopeRoles(scopeId: string, uid: string, roles: readonly TRole[]): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    const existing = this.getMemberCard(scopeId, uid);
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
    this.deleteMergedTiers(scopeId, uid);
  }

  // --- Internal Private Tier Helpers ---

  private cleanTierPatch<T extends Record<string, any>>(patch: Partial<T>, tier: MergedTier): Partial<T> {
    const clean = sanitizePatch(patch);
    if (tier === "attributes") assertNoReservedAttributeKeys(clean);
    else assertNoReservedTierKeys(clean, tier);
    return clean;
  }

  /** The card's `email`: the given one when `cardFields.email` places it on the card, otherwise always empty. */
  private cardEmail(email: string | undefined, existingCardEmail: string | undefined): string {
    if (!this.cardFields.email) return "";
    return email !== undefined ? email : existingCardEmail || "";
  }

  private subscribeToAttributesTier(
    scopeId: string | null,
    uid: string,
    onChange: (attrs: Partial<TAttributes>, email?: string) => void
  ): () => void {
    return this.subscribeToTier("attributes", scopeId, uid, (values) => {
      const { attributes, email } = splitAttributesTierValues<TAttributes>(values);
      onChange(attributes, email);
    });
  }

  private subscribeToTier<T extends Record<string, any>>(
    tier: MergedTier,
    scopeId: string | null,
    uid: string,
    onChange: (values: Partial<T>) => void
  ): () => void {
    const key = tierKey(scopeId, uid);
    const listeners = this.tierListeners[tier];
    if (!listeners.has(key)) listeners.set(key, new Set());
    const cb = onChange as (values: Record<string, any>) => void;
    listeners.get(key)!.add(cb);
    cb({ ...(this.tierValues[tier].get(key) || {}) });
    return () => {
      listeners.get(key)?.delete(cb);
    };
  }

  /** Merges an already-validated patch into a tier and notifies that tier's listeners. */
  private mergeTier(tier: MergedTier, scopeId: string | null, uid: string, patch: Record<string, any>): void {
    const key = tierKey(scopeId, uid);
    this.tierValues[tier].set(key, { ...(this.tierValues[tier].get(key) || {}), ...patch });
    this.notifyTierListeners(tier, scopeId, uid);
  }

  /**
   * Writes the `attributes`-tier keys of a validated patch (plus `email`, when it's private and non-empty, so
   * records read without their tier can't erase a stored address) and returns its card-placed keys.
   */
  private writeAttributesTier(
    scopeId: string | null,
    uid: string,
    attributes: Partial<TAttributes>,
    email?: string
  ): Partial<TAttributes> {
    const { card, tier } = splitAttributesByPlacement(attributes, this.cardFields);
    const tierValues: Record<string, any> = {
      ...tier,
      ...(!this.cardFields.email && typeof email === "string" && email ? { email } : {})
    };
    if (Object.keys(tierValues).length > 0) this.mergeTier("attributes", scopeId, uid, tierValues);
    return card;
  }

  private deleteMergedTiers(scopeId: string | null, uid: string): void {
    for (const tier of ["preferences", "attributes"] as const) {
      this.tierValues[tier].delete(tierKey(scopeId, uid));
      this.notifyTierListeners(tier, scopeId, uid);
    }
    // Custom documents live in the same private subcollection, so they're deleted with the user/member too
    for (const key of Array.from(this.customDocValues.keys())) {
      const [, keyScopeId, keyUid] = JSON.parse(key) as [string, string | null, string];
      if (keyScopeId === scopeId && keyUid === uid) {
        this.customDocValues.delete(key);
        this.notifyCustomDocListeners(key);
      }
    }
  }

  private customDocKey(name: string, uid: string, scopeId: string | null): string {
    assertCustomDocName(name);
    assertValidResourceId(uid, "uid");
    if (scopeId !== null) assertValidResourceId(scopeId, "scopeId");
    return JSON.stringify([name, scopeId, uid]);
  }

  private notifyCustomDocListeners(key: string): void {
    for (const cb of this.customDocListeners.get(key) || []) {
      cb({ ...(this.customDocValues.get(key) || {}) });
    }
  }

  private notifyTierListeners(tier: MergedTier, scopeId: string | null, uid: string): void {
    const key = tierKey(scopeId, uid);
    for (const cb of this.tierListeners[tier].get(key) || []) {
      cb({ ...(this.tierValues[tier].get(key) || {}) });
    }
    if (tier !== "attributes") return;
    // List subscriptions that include the attributes tier see tier changes too
    if (scopeId === null) {
      for (const entry of this.usersDirectoryListeners) {
        if (entry.options?.include?.includes("attributes")) entry.cb(this.getFilteredUsersSnapshot(entry.options));
      }
    } else {
      const members = this.getMembersForScopeSync(scopeId);
      for (const cb of this.scopeMemberIncludeListeners.get(scopeId) || []) cb(members);
    }
  }

  /** Returns a record with its private tiers merged in, matching what the Firestore server store reads. */
  private withPrivateTiers<
    R extends
      | UserRecord<TRole, TCapability, TPreferences, TAttributes>
      | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >(record: R, scopeId: string | null): R {
    const key = tierKey(scopeId, record.uid);
    const preferences = this.tierValues.preferences.get(key);
    return {
      ...this.withAttributesTier(record, scopeId),
      ...(preferences ? { preferences: { ...preferences } } : {})
    };
  }

  /** Returns a record with its `attributes` tier (and private email) merged in. */
  private withAttributesTier<
    R extends
      | UserRecord<TRole, TCapability, TPreferences, TAttributes>
      | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >(record: R, scopeId: string | null): R {
    const tierValues = this.tierValues.attributes.get(tierKey(scopeId, record.uid));
    const tier = tierValues ? splitAttributesTierValues<TAttributes>(tierValues) : undefined;
    return {
      ...record,
      ...(record.roles ? { roles: [...record.roles] } : {}),
      ...(record.attributes ? { attributes: { ...record.attributes } } : {}),
      ...(tier ? { attributes: { ...(record.attributes || {}), ...tier.attributes } } : {}),
      ...(tier && !this.cardFields.email ? { email: tier.email || "" } : {})
    };
  }

  private getUserCard(uid: string): UserRecord<TRole, TCapability, TPreferences, TAttributes> | null {
    return this.cloneUser(this.users.get(uid) || null);
  }

  private getMemberCard(
    scopeId: string,
    uid: string
  ): ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null {
    const member = this.scopeMembers.get(scopeId)?.get(uid);
    return member ? this.cloneMember(member) : null;
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
      ...(user.attributes ? { attributes: { ...user.attributes } } : {})
    };
  }

  private cloneMember(
    member: ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  ): ScopedMember<TRole, TCapability, TPreferences, TAttributes> {
    return {
      ...member,
      roles: [...member.roles],
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

  private getFilteredUsersSnapshot(
    options?: SubscribeToUsersOptions
  ): UserRecord<TRole, TCapability, TPreferences, TAttributes>[] {
    const all = Array.from(this.users.values());
    const filtered =
      typeof options?.isSystemAdmin === "boolean"
        ? all.filter((u) => Boolean(u.isSystemAdmin) === options.isSystemAdmin)
        : all;
    return options?.include?.includes("attributes")
      ? filtered.map((u) => this.withAttributesTier(u, null))
      : filtered.map((u) => this.cloneUser(u)!);
  }

  private notifyUserListeners(uid: string): void {
    const user = this.users.get(uid) || null;
    const userCallbacks = this.userListeners.get(uid);
    if (userCallbacks) {
      for (const cb of userCallbacks) {
        cb(this.cloneUser(user));
      }
    }
    if (this.usersDirectoryListeners.size > 0) {
      for (const entry of this.usersDirectoryListeners) {
        entry.cb(this.getFilteredUsersSnapshot(entry.options));
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

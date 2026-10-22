/**
 * Supported OAuth social identity providers for Lanyard client authentication and account linking.
 */
export type SocialProviderType = "google" | "microsoft" | "github";

/**
 * Defines a single role tier within an application's `PermissionPolicyConfig`.
 *
 * @typeParam TRole - Union of string literal role identifiers.
 * @typeParam TCapability - Union of string literal capability identifiers.
 */
export interface RoleDefinition<TRole extends string = string, TCapability extends string = string> {
  /**
   * Numeric weight for hierarchical role comparisons (`hasMinimumRole`).
   * Higher numbers outrank lower numbers (e.g., `owner: 30, coordinator: 20, member: 10`).
   */
  weight: number;
  /**
   * Optional list of roles whose capabilities (and `trackPresence`, unless explicitly overridden)
   * this role explicitly inherits. Supports directed acyclic graphs (e.g. sibling roles).
   */
  inherits?: readonly TRole[];
  /**
   * Capabilities automatically granted to any member holding this role:
   * - `"*"` grants all capabilities in `TCapability`.
   * - `readonly TCapability[]` grants a specific subset of capabilities (e.g. `["edit_content", "invite_members"]`).
   * - Omitting or passing `[]` means the role only holds capabilities inherited via `inherits`
   *   or explicitly listed on `member.capabilities`.
   */
  capabilities?: readonly TCapability[] | "*";
  /**
   * Whether members with this role should emit presence heartbeats (`lastSeen`).
   * If omitted, inherits `true` if any inherited role has `trackPresence: true`, otherwise defaults to `false`.
   * (Global system admins always emit presence heartbeats.)
   */
  trackPresence?: boolean;
}

/**
 * Specifies the required capability for reading and/or writing a specific `attributes` or `hiddenAttributes` field.
 * If a string `TCapability` is passed directly, it is treated as `{ write: capability }` for `attributes`,
 * or `{ read: capability, write: capability }` for `hiddenAttributes`.
 */
export type FieldCapabilityRule<TCapability extends string = string> =
  | TCapability
  | {
      read?: TCapability;
      write?: TCapability;
    };

/**
 * Specifies who is allowed to set or clear a write-only encrypted secret field (e.g., an API key or OAuth token).
 * Encrypted secrets can NEVER be read back out to any client—only boolean configured status is exposed,
 * and only trusted server-side code can decrypt them.
 */
export type SecretCapabilityRule<TCapability extends string = string> =
  | TCapability
  | {
      write?: TCapability;
      allowSelfWrite?: boolean;
    };

/**
 * AES-256-GCM encrypted secret payload stored at rest in `private/secrets`.
 */
export interface EncryptedSecretData {
  ciphertext: string;
  iv: string;
  tag: string;
}

/**
 * Cipher interface for encrypting and decrypting write-only secrets at rest.
 */
export interface SecretCipher {
  encrypt(plaintext: string): EncryptedSecretData;
  decrypt(encrypted: EncryptedSecretData): string;
}

/**
 * Configuration for creating a custom `PermissionPolicy<TRole, TCapability>`.
 *
 * Consuming applications define their own role hierarchy (`TRole`) and orthogonal capabilities (`TCapability`),
 * along with role inheritance (`inherits`), implied capabilities, presence tracking, and field-level
 * capability rules for `attributes`, `hiddenAttributes`, and write-only encrypted `secrets`.
 */
export interface PermissionPolicyConfig<TRole extends string = string, TCapability extends string = string> {
  /**
   * Map of every role in `TRole` to its `RoleDefinition` (weight, inherited roles, implied capabilities, and presence tracking).
   */
  roles: Record<TRole, RoleDefinition<TRole, TCapability>>;
  /**
   * Default role assigned when provisioning a member without an explicit role
   * (e.g., via `grantScopeCapabilitiesByEmail` or when reading a document missing a `role` field).
   * If omitted, defaults to the role with the lowest numeric weight in `roles`.
   */
  defaultRole?: TRole;
  /**
   * Optional capability rules governing who can read or write specific keys in `attributes`
   * (beyond global system admins). `self` can always read their own `attributes`.
   */
  attributeCapabilities?: Record<string, FieldCapabilityRule<TCapability>>;
  /**
   * Optional capability rules governing who can read or write specific keys in `hiddenAttributes`
   * (properties about a user that are hidden from the user and only readable/writable by authorized roles or system admins).
   */
  hiddenAttributeCapabilities?: Record<string, FieldCapabilityRule<TCapability>>;
  /**
   * Optional capability rules governing who can write/clear specific keys in write-only encrypted `secrets`.
   * If a key is not listed in `secretCapabilities`, `isSelf = true` (the user themselves) or `isSystemAdmin = true`
   * is allowed to set/clear their own secret by default.
   */
  secretCapabilities?: Record<string, SecretCapabilityRule<TCapability>>;
}

/**
 * Minimal subject shape accepted by `PermissionPolicy` evaluation methods
 * (satisfied by both `ScopedMember` and `UserRecord`).
 */
export interface PolicySubject<TRole extends string = string, TCapability extends string = string> {
  role?: TRole;
  capabilities?: readonly TCapability[];
}

/**
 * Evaluates hierarchical roles, explicit role inheritance (`inherits`), capabilities,
 * presence tracking, and field-level `attributes` / `secrets` access control.
 */
export interface PermissionPolicy<TRole extends string = string, TCapability extends string = string> {
  readonly roles: Readonly<Record<TRole, Readonly<RoleDefinition<TRole, TCapability>>>>;
  readonly roleWeights: Readonly<Record<TRole, number>>;
  readonly roleCapabilities: Readonly<Partial<Record<TRole, readonly TCapability[] | "*">>>;
  readonly roleInherits: Readonly<Record<TRole, readonly TRole[]>>;
  readonly defaultRole: TRole;

  /**
   * Evaluates whether a member/user (or global system admin) meets or exceeds the required `minimumRole`
   * (either via explicit `inherits` or numeric `weight`).
   */
  hasMinimumRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    minimumRole: TRole,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether `member.role` is `targetRole` or explicitly inherits from `targetRole` via `inherits`.
   */
  inheritsRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    targetRole: TRole,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member/user holds a specific capability—either implied by their `role`
   * (including inherited roles) or explicitly listed in `member.capabilities`.
   * Global system admins always return `true`.
   */
  hasCapability(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    capability: TCapability,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member/user holds at least one of the specified capabilities.
   */
  hasAnyCapability(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member/user holds all of the specified capabilities.
   */
  hasAllCapabilities(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether presence heartbeats should be tracked for the given member/user or system admin.
   */
  shouldTrackPresence(member: PolicySubject<TRole, TCapability> | null | undefined, isSystemAdmin?: boolean): boolean;

  /**
   * Evaluates whether the caller can read a specific `attributes` key.
   * By default, `isSelf = true` or `isSystemAdmin = true` can read attributes, unless a `read` capability
   * is configured for `key` and the non-self/non-admin caller lacks that capability.
   */
  canReadAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    options?: { isSystemAdmin?: boolean; isSelf?: boolean }
  ): boolean;

  /**
   * Evaluates whether the caller can write a specific `attributes` key.
   * `self` NEVER grants write access to `attributes`. Only `isSystemAdmin = true` or an actor holding
   * the configured `write` capability for `key` in `attributeCapabilities` is permitted.
   */
  canWriteAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether the caller can write all keys in the provided `attributes` patch.
   * Returns `false` if the patch is empty or contains any unauthorized/forbidden key.
   */
  canWriteAttributesPatch(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    patch: Record<string, any>,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether the caller can read a specific `hiddenAttributes` key.
   * `self` NEVER grants read access to `hiddenAttributes`. Only `isSystemAdmin = true` or an actor holding
   * the configured `read` capability for `key` in `hiddenAttributeCapabilities` is permitted.
   */
  canReadHiddenAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether the caller can write a specific `hiddenAttributes` key.
   * `self` NEVER grants write access to `hiddenAttributes`. Only `isSystemAdmin = true` or an actor holding
   * the configured `write` capability for `key` in `hiddenAttributeCapabilities` is permitted.
   */
  canWriteHiddenAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether the caller can write all keys in the provided `hiddenAttributes` patch.
   */
  canWriteHiddenAttributesPatch(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    patch: Record<string, any>,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether the caller can write or clear a specific write-only encrypted `secrets` key.
   * Encrypted secrets can NEVER be read back out to any client.
   */
  canWriteSecret(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    options?: boolean | { isSystemAdmin?: boolean; isSelf?: boolean }
  ): boolean;

  /**
   * Evaluates whether the caller can write or clear all keys in the provided `secrets` patch.
   */
  canWriteSecretsPatch(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    patch: Record<string, any>,
    options?: boolean | { isSystemAdmin?: boolean; isSelf?: boolean }
  ): boolean;

  /**
   * Returns a shallow copy of `attributes` containing only the keys that `actor` is permitted to read.
   */
  filterReadableAttributes<TAttributes extends Record<string, any>>(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    attributes: Partial<TAttributes> | null | undefined,
    options?: { isSystemAdmin?: boolean; isSelf?: boolean }
  ): Partial<TAttributes>;

  /**
   * Returns a shallow copy of `hiddenAttributes` containing only the keys that `actor` is permitted to read.
   */
  filterReadableHiddenAttributes<THiddenAttributes extends Record<string, any>>(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    hiddenAttributes: Partial<THiddenAttributes> | null | undefined,
    isSystemAdmin?: boolean
  ): Partial<THiddenAttributes>;
}

/**
 * Normalized, UID-keyed representation of an authenticated user across client and server.
 */
export interface LanyardUser {
  /** Primary key from Firebase Auth (`user.uid`). Stable across email changes and linked OAuth providers. */
  uid: string;
  /** Lowercased, trimmed primary email address (or `null` for anonymous accounts). */
  email: string | null;
  /** Whether the user's primary email address has been verified. */
  emailVerified: boolean;
  /** User's display name from their OAuth profile or registration. */
  displayName: string | null;
  /** Avatar URL from their OAuth profile, if available. */
  photoUrl: string | null;
  /** True if signed in via Firebase Anonymous Auth. */
  isAnonymous: boolean;
  /** True if the user holds the `{ admin: true }` custom claim (or is an active system admin). */
  isAdmin: boolean;
  /** Connected OAuth provider IDs (e.g. `["google.com", "github.com"]`). */
  providerIds: string[];
}

/**
 * Self-editable profile fields on a `UserRecord` (`users/{uid}`).
 */
export interface UserProfilePatch {
  firstName?: string;
  lastName?: string;
  displayName?: string;
  photoUrl?: string | null;
}

/**
 * Canonical global user record (`users/{uid}`).
 *
 * Unifies profile, presence (`lastSeen`), system admin status (`isSystemAdmin`),
 * optional single-tenant `role` & `capabilities`, user-writable `preferences`,
 * and role/admin-writable `attributes` into a single document per UID.
 *
 * (Read-restricted `secrets` are stored separately and never included on `UserRecord`.)
 */
export interface UserRecord<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> {
  uid: string;
  email: string;
  displayName?: string;
  firstName?: string;
  lastName?: string;
  photoUrl?: string | null;
  /** ISO-8601 timestamp updated by presence heartbeats. */
  lastSeen?: string;
  /** True if this user is a global system administrator; `false` if explicitly demoted. */
  isSystemAdmin?: boolean;
  /** UID or identifier of the administrator who promoted this user. */
  addedBy?: string;
  /** Optional single-tenant role for applications that assign roles at the global user level. */
  role?: TRole;
  /** Optional single-tenant capabilities explicitly granted to this user at the global level. */
  capabilities?: TCapability[];
  /** User-writable custom properties (`preferences`). */
  preferences?: Partial<TPreferences>;
  /** System/Admin/Role-writable custom properties (`attributes`), readable by the user. */
  attributes?: Partial<TAttributes>;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Directory record for a global System Administrator (stored in `users/{uid}` with `isSystemAdmin: true`).
 * Retained as a compatible type alias / subset of `UserRecord`.
 */
export interface SystemAdminProfile {
  uid: string;
  email: string;
  displayName?: string;
  firstName?: string;
  lastName?: string;
  photoUrl?: string | null;
  /** ISO-8601 timestamp updated by presence heartbeats. */
  lastSeen?: string;
  /** True if the user is currently an active system administrator; `false` if demoted. */
  isSystemAdmin?: boolean;
  /** UID or identifier of the administrator who promoted this user. */
  addedBy?: string;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Membership record for a user within a specific tenant/scope (e.g., `workspaces/{scopeId}/members/{uid}`).
 *
 * Combines a hierarchical `role` (`TRole`) with an array of orthogonal `capabilities` (`TCapability[]`),
 * plus optional tenant-scoped user-writable `preferences` and role/admin-writable `attributes`.
 */
export interface ScopedMember<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> {
  uid: string;
  email: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  photoUrl?: string | null;
  /** Hierarchical role tier within this scope. */
  role: TRole;
  /** Orthogonal capabilities explicitly granted to this user within this scope. */
  capabilities: TCapability[];
  /** Identifier of the parent scope/workspace (e.g., `workspaceId`). */
  scopeId?: string;
  /** Human-readable name of the parent scope/workspace. */
  scopeName?: string;
  /** ISO-8601 timestamp updated by presence heartbeats. */
  lastSeen?: string;
  /** Optional tenant-scoped user-writable preferences. */
  preferences?: Partial<TPreferences>;
  /** Optional tenant-scoped manager/role-writable attributes (readable by the member). */
  attributes?: Partial<TAttributes>;
}

/**
 * Minimal Svelte-compatible readable store contract (`$store` auto-subscription compatible).
 */
export interface LanyardReadable<T> {
  subscribe(run: (value: T) => void): () => void;
  get(): T;
}

/**
 * Writable store contract extending `LanyardReadable<T>`.
 */
export interface LanyardWritable<T> extends LanyardReadable<T> {
  set(value: T): void;
  update(updater: (value: T) => T): void;
}

/**
 * Storage-agnostic client adapter interface.
 *
 * Consuming applications can pass `FirestoreClientStore` (from `lanyard/client/firestore`),
 * `InMemoryLanyardStore` (for unit tests), or a custom implementation backed by REST/SQL/IndexedDB.
 */
export interface LanyardClientStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> {
  /** Subscribe to real-time updates for a user's global preferences. Returns an unsubscribe function. */
  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void;
  /** Persist a partial update to a user's global preferences. */
  savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void>;
  /** Optional: Persist a partial update to a user's tenant-scoped preferences within `scopeId`. */
  saveScopePreferences?(scopeId: string, uid: string, patch: Partial<TPreferences>): Promise<void>;

  /** Optional: Subscribe to the full global `UserRecord` (`users/{uid}`) including `attributes`, `preferences`, and `role`. */
  subscribeToUser?(
    uid: string,
    onChange: (user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void
  ): () => void;

  /** Optional: Subscribe to all global `UserRecord` documents (`usersCollection`) for single-tenant user directories. */
  subscribeToUsers?(onChange: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void): () => void;

  /** Optional: Self-service update of the user's own profile fields (`firstName`, `lastName`, `displayName`, `photoUrl`). */
  updateUserProfile?(uid: string, patch: UserProfilePatch): Promise<void>;

  /** Subscribe to all scope memberships for the given `uid` across the application. */
  subscribeToUserMemberships(
    uid: string,
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
  ): () => void;
  /** Optional: Subscribe to all members within a single scope (`scopeId`). */
  subscribeToScopeMembers?(
    scopeId: string,
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
  ): () => void;

  /**
   * Optional: Syncs the signed-in user's OAuth `photoUrl` (and optional `displayName`/`email`)
   * to an existing scoped member document (`scopeId` provided) or global `users/{uid}` document (`scopeId` omitted).
   */
  syncAvatar?(params: {
    uid: string;
    photoUrl: string;
    scopeId?: string;
    email?: string | null;
    displayName?: string | null;
  }): Promise<void>;

  /** Record a presence heartbeat (`lastSeen` ISO timestamp, plus optional `photoUrl` sync) for a user. */
  recordPresenceHeartbeat(params: {
    uid: string;
    scopeId?: string;
    lastSeenIso: string;
    photoUrl?: string | null;
  }): Promise<void>;
}

/**
 * Storage-agnostic server adapter interface used by Express middleware and provisioning helpers.
 *
 * Consuming applications can pass `FirestoreServerStore` (from `lanyard/server/firestore`),
 * `InMemoryLanyardStore` (for unit tests), or a custom database adapter.
 */
export interface LanyardServerStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>,
  THiddenAttributes extends Record<string, any> = Record<string, any>,
  TSecrets extends Record<string, any> = Record<string, any>
> {
  // --- Global User (`users/{uid}`) & System Admin Operations ---
  getUser?(uid: string): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null>;
  upsertUser?(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void>;
  updateUserAttributes?(
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  getUserHiddenAttributes?(uid: string): Promise<Partial<THiddenAttributes>>;
  updateUserHiddenAttributes?(uid: string, patch: Partial<THiddenAttributes>): Promise<Partial<THiddenAttributes>>;
  /**
   * Server-only: Retrieves decrypted secrets for `uid` (used by backend services when calling external APIs).
   * Never expose the return value of `getUserSecrets` to a client response.
   */
  getUserSecrets?(uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>>;
  /**
   * Returns a client-safe boolean map indicating which secret keys are currently configured for `uid`.
   */
  getUserSecretsStatus?(uid: string): Promise<Partial<Record<keyof TSecrets & string, boolean>>>;
  /**
   * Encrypts and saves non-empty secret strings for `uid`, or deletes keys whose value is `""` or `null`.
   * Returns the updated client-safe boolean status map.
   */
  updateUserSecrets?(
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null | undefined>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>>;
  /**
   * Optional: Additively grants `capabilities` to global `users/{uid}` without clobbering existing capabilities.
   * If the user does not yet exist, initializes the record using `fallbackUser`.
   */
  grantUserCapabilities?(
    uid: string,
    capabilities: readonly TCapability[],
    fallbackUser?: Omit<UserRecord<TRole, TCapability, TPreferences, TAttributes>, "capabilities">
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  /**
   * Optional: Removes the specified `capabilities` from global `users/{uid}` while preserving all other capabilities.
   */
  revokeUserCapabilities?(uid: string, capabilities: readonly TCapability[]): Promise<void>;

  getSystemAdmin(uid: string): Promise<SystemAdminProfile | null>;
  listSystemAdmins(): Promise<SystemAdminProfile[]>;
  upsertSystemAdmin(profile: SystemAdminProfile): Promise<void>;
  deleteSystemAdmin(uid: string): Promise<void>;

  // --- Tenant-Scoped (`{scopeCollection}/{scopeId}/members/{uid}`) Operations ---
  getScopeMember(
    scopeId: string,
    uid: string
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null>;
  listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]>;
  upsertScopeMember(
    scopeId: string,
    member: ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  ): Promise<void>;
  updateScopeMemberAttributes?(
    scopeId: string,
    uid: string,
    patch: Partial<TAttributes>
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  getScopeMemberHiddenAttributes?(scopeId: string, uid: string): Promise<Partial<THiddenAttributes>>;
  updateScopeMemberHiddenAttributes?(
    scopeId: string,
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>>;
  /**
   * Server-only: Retrieves decrypted secrets for member `(scopeId, uid)`.
   * Never expose the return value of `getScopeMemberSecrets` to a client response.
   */
  getScopeMemberSecrets?(scopeId: string, uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>>;
  /**
   * Returns a client-safe boolean map indicating which secret keys are currently configured for member `(scopeId, uid)`.
   */
  getScopeMemberSecretsStatus?(
    scopeId: string,
    uid: string
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>>;
  /**
   * Encrypts and saves non-empty secret strings for member `(scopeId, uid)`, or deletes keys whose value is `""` or `null`.
   * Returns the updated client-safe boolean status map.
   */
  updateScopeMemberSecrets?(
    scopeId: string,
    uid: string,
    patch: Partial<Record<keyof TSecrets & string, string | null | undefined>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>>;
  /**
   * Server-only: Retrieves decrypted scope-wide secrets (`{scopeCollection}/{scopeId}/private/secrets`).
   */
  getScopeSecrets?(scopeId: string): Promise<Partial<Record<keyof TSecrets & string, string>>>;
  /**
   * Returns a client-safe boolean map indicating which scope-wide secret keys are currently configured for `scopeId`.
   */
  getScopeSecretsStatus?(scopeId: string): Promise<Partial<Record<keyof TSecrets & string, boolean>>>;
  /**
   * Encrypts and saves non-empty scope-wide secret strings for `scopeId`, or deletes keys whose value is `""` or `null`.
   * Returns the updated client-safe boolean status map.
   */
  updateScopeSecrets?(
    scopeId: string,
    patch: Partial<Record<keyof TSecrets & string, string | null | undefined>>
  ): Promise<Partial<Record<keyof TSecrets & string, boolean>>>;
  /**
   * Additively grants `capabilities` to `(scopeId, uid)` without clobbering existing capabilities.
   * If the member does not yet exist in `scopeId`, initializes the record using `fallbackMember`.
   */
  grantScopeCapabilities(
    scopeId: string,
    uid: string,
    capabilities: readonly TCapability[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability, TPreferences, TAttributes>, "capabilities">
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  /**
   * Removes the specified `capabilities` from `(scopeId, uid)` while preserving all other capabilities.
   */
  revokeScopeCapabilities(scopeId: string, uid: string, capabilities: readonly TCapability[]): Promise<void>;
  deleteScopeMember(scopeId: string, uid: string): Promise<void>;
}

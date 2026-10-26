/**
 * Supported OAuth social identity providers for Lanyard client authentication and account linking.
 */
export type SocialProviderType = "google" | "microsoft" | "github";

/**
 * Unique symbol identifying the explicit global (unscoped / single-tenant) scope.
 *
 * Because `GLOBAL_SCOPE` is a `symbol`, an untrusted string from an HTTP route parameter
 * (`req.params.scopeId`) can never spoof or collide with `GLOBAL_SCOPE`.
 */
export const GLOBAL_SCOPE: unique symbol = Symbol.for("lanyard.GLOBAL_SCOPE");

/**
 * Type of the explicit `GLOBAL_SCOPE` symbol.
 */
export type GlobalScope = typeof GLOBAL_SCOPE;

/**
 * Explicit scope identifier: either `GLOBAL_SCOPE` (for global `users/{uid}` operations)
 * or a non-empty tenant/workspace scope string (e.g. `"campaign-123"`).
 */
export type ScopeId = string | GlobalScope;

/**
 * Defines a single role tier within an application's `PermissionPolicyConfig`.
 *
 * @typeParam TRole - Union of string literal role identifiers.
 * @typeParam TCapability - Union of string literal capability identifiers.
 */
export interface RoleDefinition<TRole extends string = string, TCapability extends string = string> {
  /**
   * Optional list of roles whose capabilities (and `trackPresence`, unless explicitly overridden)
   * this role explicitly inherits. Supports directed acyclic graphs (e.g. sibling roles).
   */
  inherits?: readonly TRole[];
  /**
   * Capabilities automatically granted to any member holding this role:
   * - `"*"` grants all capabilities in `TCapability`.
   * - `readonly TCapability[]` grants a specific subset of capabilities (e.g. `["edit_content", "invite_members"]`).
   * - Omitting or passing `[]` means the role only holds capabilities inherited via `inherits`.
   */
  capabilities?: readonly TCapability[] | "*";
  /**
   * Whether members with this role should emit presence heartbeats (`lastSeen`).
   * If omitted, inherits `true` if any inherited role has `trackPresence: true`, otherwise defaults to `false`.
   * (Global system admins always emit presence heartbeats.)
   */
  trackPresence?: boolean;
  /**
   * If `true`, this role is an abstract grouping of capabilities/inheritance only:
   * - It is excluded from `policy.assignableRoles` (so it does not appear in UI role pickers).
   * - It cannot be used as `defaultRole` or directly assigned to a user/member.
   * - Concrete roles that inherit from it still inherit all of its capabilities and satisfy `hasRole(user, abstractRole)`.
   */
  abstract?: boolean;
}

/**
 * Specifies the required capabilities for reading, updating/deleting, or assigning roles on user records.
 * If a string `TCapability` is passed directly, it gates `read`, `write`, and `assignRoles`.
 */
export type UserCapabilitiesRule<TCapability extends string = string> =
  | TCapability
  | {
      read?: TCapability;
      write?: TCapability;
      assignRoles?: TCapability;
    };

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
   * Map of every role in `TRole` to its `RoleDefinition` (inherited roles, implied capabilities, and presence tracking).
   */
  roles: Record<TRole, RoleDefinition<TRole, TCapability>>;
  /**
   * Default role assigned when provisioning a member without an explicit role
   * (e.g., via `grantScopeCapabilitiesByEmail` or when reading a document missing a `role` field).
   * If omitted, defaults to the first root role (a role that does not inherit from any other role).
   */
  defaultRole?: TRole;
  /**
   * Optional capability rule governing who can read, write (update profile/delete), or assign roles (`assignRoles`)
   * on other users' records (beyond global system admins). `self` can always read and update their own profile/account.
   */
  userCapabilities?: UserCapabilitiesRule<TCapability>;
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
 * Users/members hold one or more roles (`roles`), and all capabilities are derived from those roles.
 */
export interface PolicySubject<TRole extends string = string, _TCapability extends string = string> {
  roles?: readonly TRole[];
}

/**
 * Evaluates explicit role inheritance (`inherits`), role-derived capabilities,
 * presence tracking, user record access, and field-level `attributes` / `secrets` access control.
 */
export interface PermissionPolicy<TRole extends string = string, TCapability extends string = string> {
  readonly roles: Readonly<Record<TRole, Readonly<RoleDefinition<TRole, TCapability>>>>;
  readonly roleCapabilities: Readonly<Partial<Record<TRole, readonly TCapability[] | "*">>>;
  readonly roleInherits: Readonly<Record<TRole, readonly TRole[]>>;
  readonly assignableRoles: readonly TRole[];
  readonly defaultRole: TRole;

  /**
   * Returns `true` if `role` is defined in `policy.roles` and is concrete (`!roleDef.abstract`).
   */
  isAssignableRole(role: TRole): boolean;

  /**
   * Evaluates whether a member/user (or global system admin) holds `requiredRole`
   * directly in `member.roles` or transitively via `inherits`.
   */
  hasRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    requiredRole: TRole,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member/user holds at least one of the specified roles (directly or via `inherits`).
   */
  hasAnyRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    requiredRoles: readonly TRole[],
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member/user holds all of the specified roles (directly or via `inherits`).
   */
  hasAllRoles(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    requiredRoles: readonly TRole[],
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member/user holds a specific capability implied by any of their `roles`
   * (including inherited roles). Global system admins always return `true`.
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
   * Evaluates whether the caller can read a user/member record.
   * Returns `true` if `isSelf = true`, `isSystemAdmin = true`, or the caller holds the `read` capability
   * configured in `userCapabilities`.
   */
  canReadUser(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    options?: { isSystemAdmin?: boolean; isSelf?: boolean }
  ): boolean;

  /**
   * Evaluates whether the caller can write (update profile or delete) another user/member record.
   * Returns `true` if `isSystemAdmin = true` or the caller holds the `write` capability configured in `userCapabilities`.
   */
  canWriteUser(actor: PolicySubject<TRole, TCapability> | null | undefined, isSystemAdmin?: boolean): boolean;

  /**
   * Evaluates whether the caller can assign or modify roles on a user/member record.
   * Returns `true` if `isSystemAdmin = true` or the caller holds the `assignRoles` capability configured in `userCapabilities`.
   */
  canAssignRoles(actor: PolicySubject<TRole, TCapability> | null | undefined, isSystemAdmin?: boolean): boolean;

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
  /** Lowercased, trimmed primary email address. */
  email: string | null;
  /** Whether the user's primary email address has been verified. */
  emailVerified: boolean;
  /** User's display name from their OAuth profile or registration. */
  displayName: string | null;
  /** Avatar URL from their OAuth profile, if available. */
  photoUrl: string | null;
  /** True if the user holds the `{ admin: true }` custom claim (or is an active system admin). */
  isAdmin: boolean;
  /** Connected OAuth provider IDs (e.g. `["google.com", "github.com"]`). */
  providerIds: string[];
}

/**
 * Minimal user identity passed into `lanyardServer` operations to authorize the caller.
 *
 * Satisfied directly by `req.user` (`LanyardUser`), `UserRecord`, `ScopedMember`,
 * `SystemAdminProfile`, or `{ uid: string, isAdmin?: boolean }`.
 */
export interface LanyardActor {
  uid: string;
  isAdmin?: boolean;
}

/**
 * Self-editable profile fields on a `UserRecord` (`users/{uid}`).
 */
export interface UserProfilePatch {
  email?: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  photoUrl?: string | null;
}

/**
 * Event payload emitted to `onVerifiedEmailChange` when a user's verified email address
 * in Firebase Auth differs from the email stored on their `UserRecord` (`users/{uid}`).
 */
export interface VerifiedEmailChangeEvent {
  uid: string;
  email: string;
  previousEmail: string;
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
  _TCapability extends string = string,
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
  /** Single-tenant roles assigned to this user at the global level (capabilities are derived from these roles). */
  roles?: TRole[];
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
 * Assigns one or more `roles` (`TRole[]`) within the scope (from which all capabilities are derived),
 * plus optional tenant-scoped user-writable `preferences` and role/admin-writable `attributes`.
 */
export interface ScopedMember<
  TRole extends string = string,
  _TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> {
  uid: string;
  email: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  photoUrl?: string | null;
  /** Assigned roles within this scope (capabilities are derived from these roles). */
  roles: TRole[];
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

  /** Optional: Subscribe to the full global `UserRecord` (`users/{uid}`) including `attributes`, `preferences`, and `roles`. */
  subscribeToUser?(
    uid: string,
    onChange: (user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void
  ): () => void;

  /** Optional: Subscribe to all global `UserRecord` documents (`usersCollection`) for single-tenant user directories. */
  subscribeToUsers?(onChange: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void): () => void;

  /** Optional: Self-service update of the user's own global profile fields (`firstName`, `lastName`, `displayName`, `photoUrl`). */
  updateUserProfile?(uid: string, patch: UserProfilePatch): Promise<void>;
  /** Optional: Self-service update of the user's own tenant-scoped member profile fields within `scopeId`. */
  updateScopeMemberProfile?(scopeId: string, uid: string, patch: UserProfilePatch): Promise<void>;

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
  listUsers?(): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>[]>;
  upsertUser?(user: UserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void>;
  deleteUser?(uid: string): Promise<void>;
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
   * Optional: Additively grants `roles` to global `users/{uid}` without clobbering existing roles.
   * If the user does not yet exist, initializes the record using `fallbackUser`.
   */
  grantUserRoles?(
    uid: string,
    roles: readonly TRole[],
    fallbackUser?: Omit<UserRecord<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  /**
   * Optional: Removes the specified `roles` from global `users/{uid}` while preserving all other roles.
   */
  revokeUserRoles?(uid: string, roles: readonly TRole[]): Promise<void>;

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
   * Additively grants `roles` to `(scopeId, uid)` without clobbering existing roles.
   * If the member does not yet exist in `scopeId`, initializes the record using `fallbackMember`.
   */
  grantScopeRoles(
    scopeId: string,
    uid: string,
    roles: readonly TRole[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  /**
   * Removes the specified `roles` from `(scopeId, uid)` while preserving all other roles.
   */
  revokeScopeRoles(scopeId: string, uid: string, roles: readonly TRole[]): Promise<void>;
  deleteScopeMember(scopeId: string, uid: string): Promise<void>;
}

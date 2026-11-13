/**
 * Supported OAuth social identity providers for Lanyard client authentication and account linking.
 */
export type SocialProviderType = "google" | "microsoft" | "github";

/**
 * Error code a Lanyard server sends (as `code` in its 401 JSON body) when a request's ID token carries an email that
 * isn't verified, so clients can prompt the user to verify their address instead of showing a generic sign-in failure.
 */
export const EMAIL_NOT_VERIFIED_ERROR_CODE = "auth/email-not-verified";

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
   * - It cannot be used in `defaultRoles` or directly assigned to a user/member.
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
 * Specifies the required capability for writing a specific `attributes` or `hiddenAttributes` key.
 * If a string `TCapability` is passed directly, it is treated as `{ write: capability }`.
 *
 * Reads are NOT configured per key: Firestore security rules grant or deny whole documents,
 * so read access is defined per storage tier (see `LanyardTier` and `PermissionPolicyConfig.staffCapability`).
 */
export type FieldCapabilityRule<TCapability extends string = string> =
  | TCapability
  | {
      write?: TCapability;
    };

/**
 * Storage tiers for user/member data. Each tier is stored in its own Firestore document so that
 * read access (which Firestore enforces per document) matches the tier's audience:
 *
 * - `card`: the main `users/{uid}` / `members/{uid}` document. Readable by anyone allowed to know the user exists.
 * - `preferences`: readable/writable only by the user themselves (and system admins).
 * - `attributes`: readable by the user themselves and scope staff; writable by staff/server per key.
 * - `hiddenAttributes`: readable/writable only by scope staff (and system admins).
 * - `secrets`: never readable by any client; write-only encrypted values decrypted on the server.
 */
export type LanyardTier = "card" | "preferences" | "attributes" | "hiddenAttributes" | "secrets";

/**
 * Field under which Lanyard stamps metadata on every private tier document (`…/{uid}/private/{tier}`).
 * The metadata identifies the document for collection-group queries and security rules (e.g.
 * `where("_lanyard.tier", "==", "attributes")`, `resource.data._lanyard.tier`), so this one key can't be
 * used as a preference/attribute key.
 */
export const TIER_METADATA_KEY = "_lanyard";

/** Metadata Lanyard stamps on every private tier document under `TIER_METADATA_KEY`. */
export interface TierDocMetadata {
  /** Built-in tier name, or the `customDocs` name for app-defined custom documents. */
  tier: LanyardTier | (string & {});
  uid: string;
  /** Owning scope, or `null` for global (`users/{uid}`) documents. */
  scopeId: string | null;
  /** ISO timestamp of the last write through Lanyard. */
  updatedAt: string;
}

/**
 * Who can read the `card` tier of a scoped member (`{scope}/{scopeId}/members/{uid}`):
 * - `"members"` (default): any member of the same scope.
 * - `"staff"`: only scope staff (holders of `staffCapability`).
 * - `{ capability }`: only holders of the given capability in the scope.
 *
 * The member themselves and system admins can always read their own card.
 * The global card (`users/{uid}`) is always governed by `userCapabilities.read` (default: self + system admins).
 */
export type CardVisibilityRule<TCapability extends string = string> = "members" | "staff" | { capability: TCapability };

/**
 * Fields stored on the `card` instead of their default private tier (opt-in exposure).
 * A field always lives in exactly one location: placing it on the card moves it (it is never copied).
 */
export interface CardFieldsConfig {
  /**
   * Store `email` on the card instead of the `attributes` tier (default: `false`). When private, `email` is a
   * reserved key in the `attributes` tier document.
   */
  email?: boolean;
  /** `attributes` keys stored on the card instead of the `attributes` tier (default: none; `email` is not allowed). */
  attributes?: readonly string[];
}

/** Normalized card field placement (see `CardFieldsConfig`). */
export type CardFieldsPlacement = Readonly<{ email: boolean; attributes: readonly string[] }>;

/**
 * Storage placement a Lanyard store needs to route fields to the right document. Pass your
 * `PermissionPolicy` (which satisfies this interface) so the store and the policy agree;
 * `createLanyardServer`/`createLanyardClient` throw if they don't.
 */
export interface LanyardStorePlacementSource {
  readonly cardFields: CardFieldsPlacement;
}

/**
 * Access rule for one side (read or write) of an app-defined custom document (`…/{uid}/private/{name}`).
 * Access is granted if any listed condition matches; system admins always have access.
 * An empty rule (`{}`) means system admins and trusted server code only.
 */
export interface CustomDocAccessRule<TCapability extends string = string> {
  /** The user/member the document belongs to. */
  self?: boolean;
  /** Scope staff (holders of `staffCapability`). */
  staff?: boolean;
  /** Holders of a specific capability in the scope. */
  capability?: TCapability;
}

/**
 * Definition of an app-defined custom private document (escape hatch for audiences that the built-in tiers
 * don't cover, e.g. "readable by roles holding `view_shift_notes`").
 */
export interface CustomDocDefinition<TCapability extends string = string> {
  read: CustomDocAccessRule<TCapability>;
  write: CustomDocAccessRule<TCapability>;
}

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
   * Closed list of every capability in `TCapability` (e.g. `export const CAPS = [...] as const`).
   * Required whenever any role specifies `capabilities: "*"` so `"*"` expands to a known closed set at runtime
   * and in generated security rules. When omitted (and no role uses `"*"`), `policy.capabilities` is inferred
   * from the capabilities referenced across `roles` and tier rules.
   */
  capabilities?: readonly TCapability[];
  /**
   * Optional map of every role in `TRole` to its `RoleDefinition` (inherited roles, implied capabilities, and presence tracking).
   * Omit or pass `{}` for applications where users do not hold roles and only `isSystemAdmin` grants elevated privileges.
   */
  roles?: Record<TRole, RoleDefinition<TRole, TCapability>>;
  /**
   * Default roles assigned when provisioning a user/member without explicit roles
   * or when reading a document missing a `roles` field.
   * If omitted, defaults to `[rootConcreteRole]` when `roles` are defined, or `[]` when `roles` is empty/omitted.
   * Pass `[]` explicitly if defined roles are privileged-only and regular users should start with no roles.
   */
  defaultRoles?: readonly TRole[];
  /**
   * Optional capability rule governing who can read, write (update profile/delete), or assign roles (`assignRoles`)
   * on other users' records (beyond global system admins). `self` can always read and update their own profile/account.
   */
  userCapabilities?: UserCapabilitiesRule<TCapability>;
  /**
   * Capability identifying "scope staff": holders can read members' `attributes` and `hiddenAttributes` tiers
   * within the scope (or, for `GLOBAL_SCOPE`, users' tiers via their global roles). System admins are always staff.
   * If omitted, only system admins count as staff.
   */
  staffCapability?: TCapability;
  /**
   * Who can read scoped member cards (`{scope}/{scopeId}/members/{uid}`). Defaults to `"members"`.
   */
  cardVisibility?: CardVisibilityRule<TCapability>;
  /**
   * Fields stored on the card instead of their default private tier (opt-in exposure; moved, never copied).
   */
  cardFields?: CardFieldsConfig;
  /**
   * Optional per-key WRITE capability rules for `attributes` (beyond global system admins).
   * Reads are governed by the `attributes` tier: the user themselves, scope staff, and system admins
   * (plus card readers for keys listed in `cardFields.attributes`).
   */
  attributeCapabilities?: Record<string, FieldCapabilityRule<TCapability>>;
  /**
   * Optional per-key WRITE capability rules for `hiddenAttributes` (properties about a user that are hidden
   * from the user). Reads are governed by the `hiddenAttributes` tier: scope staff and system admins only.
   */
  hiddenAttributeCapabilities?: Record<string, FieldCapabilityRule<TCapability>>;
  /**
   * Optional capability rules governing who can write/clear specific keys in write-only encrypted `secrets`.
   * If a key is not listed in `secretCapabilities`, `isSelf = true` (the user themselves) or `isSystemAdmin = true`
   * is allowed to set/clear their own secret by default.
   */
  secretCapabilities?: Record<string, SecretCapabilityRule<TCapability>>;
  /**
   * App-defined custom private documents (`…/{uid}/{name}/data`) with their own read/write audiences.
   * Names must not collide with built-in tier names.
   */
  customDocs?: Record<string, CustomDocDefinition<TCapability>>;
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
  readonly capabilities: readonly TCapability[];
  readonly roles: Readonly<Record<TRole, Readonly<RoleDefinition<TRole, TCapability>>>>;
  readonly roleCapabilities: Readonly<Partial<Record<TRole, readonly TCapability[]>>>;
  readonly roleInherits: Readonly<Record<TRole, readonly TRole[]>>;
  readonly assignableRoles: readonly TRole[];
  readonly defaultRoles: readonly TRole[];
  /** Normalized global user record access capabilities. */
  readonly userCapabilities: Readonly<{
    read?: TCapability;
    write?: TCapability;
    assignRoles?: TCapability;
  }>;
  /** Capability identifying scope staff (`undefined` means only system admins are staff). */
  readonly staffCapability: TCapability | undefined;
  /** Normalized scoped card visibility rule (defaults to `"members"`). */
  readonly cardVisibility: CardVisibilityRule<TCapability>;
  /** Normalized card field placement (`email` defaults to `false`, `attributes` to `[]`). */
  readonly cardFields: CardFieldsPlacement;
  /** Normalized app-defined custom private documents. */
  readonly customDocs: Readonly<Record<string, Readonly<CustomDocDefinition<TCapability>>>>;

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
   * Evaluates whether `actor` counts as scope staff: system admins, or holders of `staffCapability`.
   */
  isStaff(actor: PolicySubject<TRole, TCapability> | null | undefined, isSystemAdmin?: boolean): boolean;

  /**
   * Evaluates whether the caller can read a storage tier of a user/member record.
   *
   * - `card`: self, system admins, and, for the global card, `userCapabilities.read` holders;
   *   for scoped cards, the audience configured by `cardVisibility` (`isScopeMember` is required for `"members"`).
   * - `preferences`: self and system admins.
   * - `attributes`: self, scope staff, and system admins.
   * - `hiddenAttributes`: scope staff and system admins.
   * - `secrets`: never (write-only; decrypted only by trusted server code).
   */
  canReadTier(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    tier: LanyardTier,
    options?: { isSystemAdmin?: boolean; isSelf?: boolean; isGlobal?: boolean; isScopeMember?: boolean }
  ): boolean;

  /**
   * Returns `true` if `key` is an `attributes` key placed on the card via `cardFields.attributes`.
   */
  isCardAttribute(key: string): boolean;

  /**
   * Evaluates whether the caller can read an app-defined custom document (`customDocs[name].read`).
   * Returns `false` for unknown custom document names.
   */
  canReadCustomDoc(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    name: string,
    options?: { isSystemAdmin?: boolean; isSelf?: boolean }
  ): boolean;

  /**
   * Evaluates whether the caller can write an app-defined custom document (`customDocs[name].write`).
   * Returns `false` for unknown custom document names.
   */
  canWriteCustomDoc(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    name: string,
    options?: { isSystemAdmin?: boolean; isSelf?: boolean }
  ): boolean;

  /**
   * Evaluates whether the caller can read a specific `attributes` key.
   * Keys in the `attributes` tier are readable by self, scope staff, and system admins.
   * Keys placed on the card (`cardFields.attributes`) are additionally readable when `canReadCard` is `true`.
   */
  canReadAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    options?: { isSystemAdmin?: boolean; isSelf?: boolean; canReadCard?: boolean }
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
   * `self` NEVER grants read access to `hiddenAttributes`. Only scope staff (holders of `staffCapability`)
   * and system admins can read the `hiddenAttributes` tier.
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
    options?: { isSystemAdmin?: boolean; isSelf?: boolean; canReadCard?: boolean }
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
 * Optional filter options when subscribing to `usersCollection` via `subscribeToUsers`.
 */
/** Private tiers that user/member list subscriptions can merge into each record. */
export type IncludableTier = "attributes";

export interface SubscribeToMembersOptions {
  /**
   * Private tiers to merge into each record. `"attributes"` adds every member's `attributes` tier (and private
   * `email`); only readers allowed to read that tier for others (scope staff and system admins) may request it.
   * In Firestore this adds one collection-group listener on `private` (see the README for the required index).
   */
  include?: readonly IncludableTier[];
}

export interface SubscribeToUsersOptions extends SubscribeToMembersOptions {
  /**
   * When set to a boolean (`true` or `false`), filters the query to documents matching `isSystemAdmin == options.isSystemAdmin`
   * (using an indexed `where("isSystemAdmin", "==", ...)` query in Firestore).
   */
  isSystemAdmin?: boolean;
}

/**
 * Receives a store's revocation epoch: the time (epoch milliseconds) of the most recent revocation Lanyard recorded,
 * or `null` if nothing has been revoked. ID tokens issued before it are treated as stale and must be refreshed.
 */
export type RevocationEpochListener = (epochMs: number | null) => void;

/** Default collection holding Lanyard's own metadata documents (such as the revocation epoch). */
export const DEFAULT_LANYARD_META_COLLECTION = "lanyard_meta";
/** Document id of the revocation epoch within the Lanyard metadata collection. */
export const REVOCATION_EPOCH_DOC_ID = "revocation";
/** Field of the revocation epoch document holding the epoch, in epoch milliseconds. */
export const REVOCATION_EPOCH_FIELD = "lastRevocationAtMs";

/**
 * Receives a store's session revocations: uid to the time (epoch milliseconds) that user's sessions were revoked
 * (signed out everywhere or disabled). Tokens whose `auth_time` (sign-in time) is at or before that time are rejected,
 * even if refreshed afterwards.
 */
export type SessionRevocationsListener = (revocations: Readonly<Record<string, number>>) => void;

/** Document id of the session revocations map within the Lanyard metadata collection. */
export const SESSION_REVOCATIONS_DOC_ID = "session_revocations";
/** Field of the session revocations document holding the uid-to-epoch-milliseconds map. */
export const SESSION_REVOCATIONS_FIELD = "revokedAtMs";
/**
 * How long a session revocation is kept, relative to newer revocations, before it's pruned. ID tokens live for one
 * hour and Firebase refuses to refresh a revoked session, so an entry is only needed briefly; 24 hours leaves a wide
 * margin for clock differences.
 */
export const SESSION_REVOCATION_RETENTION_MS = 24 * 60 * 60 * 1000;

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
  /**
   * Subscribe to real-time updates for a user's global preferences (the self-only `preferences` tier,
   * stored separately from the card). Returns an unsubscribe function.
   */
  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void;
  /** Persist a partial update to a user's global preferences. */
  savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void>;
  /**
   * Required: Subscribe to the revocation epoch (see {@link RevocationEpochListener}). Must emit the current value
   * promptly after subscribing, then every change; report failures through `onError`. Returns an unsubscribe function.
   * Verify implementations with `assertRevocationEpochConformance` from `lanyard/testing`.
   */
  subscribeToRevocationEpoch(onChange: RevocationEpochListener, onError: (error: unknown) => void): () => void;
  /** Optional: Persist a partial update to a user's tenant-scoped preferences within `scopeId`. */
  saveScopePreferences?(scopeId: string, uid: string, patch: Partial<TPreferences>): Promise<void>;
  /**
   * Optional: Subscribe to real-time updates for a user's tenant-scoped preferences within `scopeId`
   * (the self-only `preferences` tier of `{scope}/{scopeId}/members/{uid}`). Returns an unsubscribe function.
   */
  subscribeToScopePreferences?(
    scopeId: string,
    uid: string,
    onChange: (prefs: Partial<TPreferences>) => void
  ): () => void;
  /**
   * Optional: Subscribe to a user's global `attributes` tier (`users/{uid}/private/attributes`), readable by the
   * user, staff, and system admins. Emits only the keys stored there; keys placed on the card via
   * `cardFields.attributes` arrive with the card. Also emits the user's `email` stored in this tier
   * (`undefined` when `cardFields.email` places it on the card or none is stored). Returns an unsubscribe function.
   */
  subscribeToAttributes?(uid: string, onChange: (attrs: Partial<TAttributes>, email?: string) => void): () => void;
  /** Optional: Like `subscribeToAttributes`, for a member's `attributes` tier within `scopeId`. */
  subscribeToScopeAttributes?(
    scopeId: string,
    uid: string,
    onChange: (attrs: Partial<TAttributes>, email?: string) => void
  ): () => void;
  /** Optional: The card field placement this store routes reads by; must match the client's policy. */
  readonly cardFields?: CardFieldsPlacement;
  /**
   * Optional: Returns the uids of members of `scopeId` (or global users when `scopeId` is `null`) whose attributes
   * equal every value in `attributes`. Keys must be all card-placed or all in the `attributes` tier. Callers must
   * be allowed to read that location for other users (security rules enforce this in Firestore).
   */
  queryMemberUids?(scopeId: string | null, attributes: Partial<TAttributes>): Promise<string[]>;
  /**
   * Optional: Reads an app-defined custom document (`…/{uid}/private/{name}`, global when `scopeId` is `null`),
   * returning `{}` if it doesn't exist. Security rules decide who may read it.
   */
  getCustomDoc?(name: string, uid: string, scopeId: string | null): Promise<Record<string, any>>;
  /** Optional: Subscribes to an app-defined custom document, emitting `{}` while it doesn't exist. */
  subscribeToCustomDoc?(
    name: string,
    uid: string,
    scopeId: string | null,
    onChange: (values: Record<string, any>) => void
  ): () => void;
  /** Optional: Merges `patch` into an app-defined custom document (security rules decide who may write it). */
  updateCustomDoc?(name: string, uid: string, scopeId: string | null, patch: Record<string, any>): Promise<void>;

  /**
   * Optional: Subscribe to the global `UserRecord` card (`users/{uid}`) including `roles` and any card-placed
   * `attributes`. Preferences and private attributes are NOT included; subscribe to them with
   * `subscribeToPreferences` and `subscribeToAttributes`.
   */
  subscribeToUser?(
    uid: string,
    onChange: (user: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null) => void
  ): () => void;

  /** Optional: Subscribe to global `UserRecord` documents (`usersCollection`), optionally filtered (e.g. `{ isSystemAdmin: true }`). */
  subscribeToUsers?(
    onChange: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToUsersOptions
  ): () => void;

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
    onChange: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToMembersOptions
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
  /** Optional: The card field placement this store routes writes by; must match the server's policy. */
  readonly cardFields?: CardFieldsPlacement;
  /**
   * Optional: Returns the uids of members of `scopeId` (or global users when `scopeId` is `null`) whose attributes
   * equal every value in `attributes`. Keys must be all card-placed or all in the `attributes` tier.
   */
  queryMemberUids?(scopeId: string | null, attributes: Partial<TAttributes>): Promise<string[]>;
  /** Optional: Reads an app-defined custom document (`…/{uid}/private/{name}`), returning `{}` if it doesn't exist. */
  getCustomDoc?(name: string, uid: string, scopeId: string | null): Promise<Record<string, any>>;
  /** Optional: Merges `patch` into an app-defined custom document. */
  updateCustomDoc?(name: string, uid: string, scopeId: string | null, patch: Record<string, any>): Promise<void>;

  // --- Revocation epoch (required; verify with `assertRevocationEpochConformance` from `lanyard/testing`) ---
  /** Required: Resolves the revocation epoch (see {@link RevocationEpochListener}), or `null` if none is recorded. */
  getRevocationEpoch(): Promise<number | null>;
  /**
   * Required: Records a revocation at `atMs` (non-negative integer epoch milliseconds; rejects anything else).
   * Monotonic: the stored epoch becomes the larger of its current value and `atMs`, atomically under concurrent
   * callers. Resolves the epoch stored afterwards.
   */
  bumpRevocationEpoch(atMs: number): Promise<number>;
  /**
   * Required: Subscribe to the revocation epoch. Must emit the current value promptly after subscribing, then every
   * change; report failures through `onError`. Returns an unsubscribe function.
   */
  subscribeToRevocationEpoch(onChange: RevocationEpochListener, onError: (error: unknown) => void): () => void;

  // --- Session revocations (required; verify with `assertSessionRevocationConformance` from `lanyard/testing`) ---
  /** Required: Resolves the session revocations (see {@link SessionRevocationsListener}); `{}` if none are recorded. */
  getSessionRevocations(): Promise<Readonly<Record<string, number>>>;
  /**
   * Required: Records that `uid`'s sessions were revoked at `atMs` (non-negative integer epoch milliseconds), keeping
   * the later time if the user already has an entry, and pruning entries older than
   * `atMs - SESSION_REVOCATION_RETENTION_MS` in the same atomic write. Rejects an invalid uid or time. Resolves the
   * map stored afterwards.
   */
  recordSessionRevocation(uid: string, atMs: number): Promise<Readonly<Record<string, number>>>;
  /**
   * Required: Subscribe to the session revocations. Must emit the current map promptly after subscribing, then every
   * change; report failures through `onError`. Returns an unsubscribe function.
   */
  subscribeToSessionRevocations(onChange: SessionRevocationsListener, onError: (error: unknown) => void): () => void;

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

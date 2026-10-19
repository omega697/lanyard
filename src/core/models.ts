/**
 * Supported OAuth social identity providers for Lanyard client authentication and account linking.
 */
export type SocialProviderType = "google" | "microsoft" | "github";

/**
 * Defines a single role tier within an application's `PermissionPolicyConfig`.
 *
 * @typeParam TCapability - Union of string literal capability identifiers.
 */
export interface RoleDefinition<TCapability extends string = string> {
  /**
   * Numeric weight for hierarchical role comparisons (`hasMinimumRole`).
   * Higher numbers outrank lower numbers (e.g., `owner: 30, coordinator: 20, member: 10`).
   */
  weight: number;
  /**
   * Capabilities automatically granted to any member holding this role:
   * - `"*"` grants all capabilities in `TCapability`.
   * - `readonly TCapability[]` grants a specific subset of capabilities (e.g. `["edit_content", "invite_members"]`).
   * - Omitting or passing `[]` means the role only holds capabilities explicitly listed on `member.capabilities`.
   */
  capabilities?: readonly TCapability[] | "*";
  /**
   * Whether members with this role should emit presence heartbeats (`lastSeen`).
   * Defaults to `false`. (Global system admins always emit presence heartbeats.)
   */
  trackPresence?: boolean;
}

/**
 * Configuration for creating a custom `PermissionPolicy<TRole, TCapability>`.
 *
 * Consuming applications define their own role hierarchy (`TRole`) and orthogonal capabilities (`TCapability`),
 * along with which capabilities and presence tracking settings apply to each role.
 */
export interface PermissionPolicyConfig<TRole extends string = string, TCapability extends string = string> {
  /**
   * Map of every role in `TRole` to its `RoleDefinition` (weight, implied capabilities, and presence tracking).
   */
  roles: Record<TRole, RoleDefinition<TCapability>>;
  /**
   * Default role assigned when provisioning a member without an explicit role
   * (e.g., via `grantScopeCapabilitiesByEmail` or when reading a document missing a `role` field).
   * If omitted, defaults to the role with the lowest numeric weight in `roles`.
   */
  defaultRole?: TRole;
}

/**
 * Evaluates hierarchical roles, capabilities (both role-implied and explicitly assigned),
 * and role-based presence tracking for an application's custom `TRole` and `TCapability` types.
 */
export interface PermissionPolicy<TRole extends string = string, TCapability extends string = string> {
  readonly roles: Readonly<Record<TRole, Readonly<RoleDefinition<TCapability>>>>;
  readonly roleWeights: Readonly<Record<TRole, number>>;
  readonly roleCapabilities: Readonly<Partial<Record<TRole, readonly TCapability[] | "*">>>;
  readonly defaultRole: TRole;

  /**
   * Evaluates whether a member (or global system admin) meets or exceeds the required `minimumRole`.
   */
  hasMinimumRole(
    member: Pick<ScopedMember<TRole, TCapability>, "role"> | null | undefined,
    minimumRole: TRole,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member holds a specific capability—either implied by their `role` in `roles`
   * or explicitly listed in `member.capabilities`. Global system admins always return `true`.
   */
  hasCapability(
    member: Pick<ScopedMember<TRole, TCapability>, "role" | "capabilities"> | null | undefined,
    capability: TCapability,
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member holds at least one of the specified capabilities.
   */
  hasAnyCapability(
    member: Pick<ScopedMember<TRole, TCapability>, "role" | "capabilities"> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether a member holds all of the specified capabilities.
   */
  hasAllCapabilities(
    member: Pick<ScopedMember<TRole, TCapability>, "role" | "capabilities"> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin?: boolean
  ): boolean;

  /**
   * Evaluates whether presence heartbeats should be tracked for the given member or system admin.
   * System admins always return `true`; scoped members return `true` if their role's `trackPresence` is `true`.
   */
  shouldTrackPresence(
    member: Pick<ScopedMember<TRole, TCapability>, "role"> | null | undefined,
    isSystemAdmin?: boolean
  ): boolean;
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
  /** True if the user holds the `{ admin: true }` custom claim (or is listed in `system_admins`). */
  isAdmin: boolean;
  /** Connected OAuth provider IDs (e.g. `["google.com", "github.com"]`). */
  providerIds: string[];
}

/**
 * Directory record for a global System Administrator (`system_admins/{uid}`).
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
  /** UID or identifier of the administrator who promoted this user. */
  addedBy?: string;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Membership record for a user within a specific tenant/scope (e.g., `workspaces/{scopeId}/members/{uid}`).
 *
 * Combines a hierarchical `role` (`TRole`) with an array of orthogonal `capabilities` (`TCapability[]`)
 * so a single user can hold multiple capabilities (such as `["edit_content", "invite_members"]`) simultaneously.
 *
 * @typeParam TRole - Union of string literal role identifiers defined by the consuming application.
 * @typeParam TCapability - Union of string literal capability identifiers defined by the consuming application.
 */
export interface ScopedMember<TRole extends string = string, TCapability extends string = string> {
  uid: string;
  email: string;
  firstName?: string;
  lastName?: string;
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
  TPreferences extends Record<string, any> = Record<string, any>
> {
  /** Subscribe to real-time updates for a user's global preferences. Returns an unsubscribe function. */
  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void;
  /** Persist a partial update to a user's global preferences. */
  savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void>;

  /** Subscribe to all scope memberships for the given `uid` across the application. */
  subscribeToUserMemberships(uid: string, onChange: (members: ScopedMember<TRole, TCapability>[]) => void): () => void;
  /** Optional: Subscribe to all members within a single scope (`scopeId`). */
  subscribeToScopeMembers?(
    scopeId: string,
    onChange: (members: ScopedMember<TRole, TCapability>[]) => void
  ): () => void;

  /**
   * Optional: Syncs the signed-in user's OAuth `photoUrl` (and optional `displayName`/`email`)
   * to an existing scoped member document (`scopeId` provided) or global `system_admins` document (`scopeId` omitted).
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
export interface LanyardServerStore<TRole extends string = string, TCapability extends string = string> {
  getSystemAdmin(uid: string): Promise<SystemAdminProfile | null>;
  listSystemAdmins(): Promise<SystemAdminProfile[]>;
  upsertSystemAdmin(profile: SystemAdminProfile): Promise<void>;
  deleteSystemAdmin(uid: string): Promise<void>;

  getScopeMember(scopeId: string, uid: string): Promise<ScopedMember<TRole, TCapability> | null>;
  listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability>[]>;
  upsertScopeMember(scopeId: string, member: ScopedMember<TRole, TCapability>): Promise<void>;
  /**
   * Additively grants `capabilities` to `(scopeId, uid)` without clobbering existing capabilities.
   * If the member does not yet exist in `scopeId`, initializes the record using `fallbackMember`.
   */
  grantScopeCapabilities(
    scopeId: string,
    uid: string,
    capabilities: readonly TCapability[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability>, "capabilities">
  ): Promise<ScopedMember<TRole, TCapability>>;
  /**
   * Removes the specified `capabilities` from `(scopeId, uid)` while preserving all other capabilities.
   */
  revokeScopeCapabilities(scopeId: string, uid: string, capabilities: readonly TCapability[]): Promise<void>;
  deleteScopeMember(scopeId: string, uid: string): Promise<void>;
}

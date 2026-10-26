import type { NextFunction, Request, Response } from "express";
import {
  GLOBAL_SCOPE,
  assertValidResourceId,
  isValidEmail,
  isValidResourceId,
  sanitizeAvatarUrl,
  type GlobalScope,
  type LanyardActor,
  type LanyardServerStore,
  type PermissionPolicy,
  type ScopeId,
  type ScopedMember,
  type SystemAdminProfile,
  type UserProfilePatch,
  type UserRecord,
  type VerifiedEmailChangeEvent
} from "../core/index.js";

export { GLOBAL_SCOPE, type GlobalScope, type LanyardActor, type ScopeId, type VerifiedEmailChangeEvent };
export * from "./encryption.js";

export interface AuthenticatedUser {
  uid: string;
  email: string;
  emailVerified?: boolean;
  name?: string;
  photoUrl?: string | null;
  isAdmin?: boolean;
}

export interface AuthenticatedRequest<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> extends Request {
  user?: AuthenticatedUser;
  userRecord?: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null;
  scopeMember?: ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null;
}

export interface AuthService {
  verifyToken(authHeader: string | undefined, headers?: Record<string, any>): Promise<AuthenticatedUser | null>;
}

/**
 * Minimal subset of `firebase-admin/auth` `Auth` required by Lanyard Server,
 * allowing either the real Firebase Admin Auth instance or lightweight test doubles.
 */
export interface AdminAuthAdapter {
  verifyIdToken(
    idToken: string,
    checkRevoked?: boolean
  ): Promise<{
    uid: string;
    email?: string;
    email_verified?: boolean;
    name?: string;
    picture?: string;
    admin?: boolean;
    [key: string]: any;
  }>;
  getUserByEmail(
    email: string
  ): Promise<{ uid: string; email?: string; displayName?: string; customClaims?: Record<string, any> }>;
  createUser(properties: {
    email: string;
    displayName?: string;
    emailVerified?: boolean;
  }): Promise<{ uid: string; email?: string; displayName?: string; customClaims?: Record<string, any> }>;
  setCustomUserClaims(uid: string, customUserClaims: Record<string, any> | null): Promise<void>;
  updateUser?(
    uid: string,
    properties: { displayName?: string | null; email?: string; photoURL?: string | null }
  ): Promise<any>;
  deleteUser?(uid: string): Promise<void>;
}

const SAFE_AUTH_ERROR_PREFIXES = ["Token must contain an email claim", "Token email must be verified"];

function formatClientAuthError(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (message && SAFE_AUTH_ERROR_PREFIXES.some((prefix) => message.startsWith(prefix))) {
    return `Unauthorized: ${message}`;
  }
  return "Unauthorized: Invalid or expired authentication token";
}

export class GoogleAuthService implements AuthService {
  constructor(
    private readonly adminAuth: Pick<AdminAuthAdapter, "verifyIdToken">,
    private readonly requireVerifiedEmail = true,
    private readonly checkRevoked = false
  ) {}

  async verifyToken(authHeader: string | undefined): Promise<AuthenticatedUser | null> {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return null;
    }
    const idToken = authHeader.slice("Bearer ".length).trim();
    if (!idToken) {
      return null;
    }
    const decodedToken = this.checkRevoked
      ? await this.adminAuth.verifyIdToken(idToken, true)
      : await this.adminAuth.verifyIdToken(idToken);
    if (!decodedToken.email) {
      throw new Error("Token must contain an email claim");
    }
    if (this.requireVerifiedEmail && decodedToken.email_verified === false) {
      throw new Error("Token email must be verified");
    }
    return {
      uid: decodedToken.uid,
      email: decodedToken.email.toLowerCase().trim(),
      emailVerified: decodedToken.email_verified !== false,
      name: decodedToken.name,
      photoUrl: sanitizeAvatarUrl(decodedToken.picture),
      isAdmin: Boolean(decodedToken.admin)
    };
  }
}

export interface LanyardServerConfig<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>,
  THiddenAttributes extends Record<string, any> = Record<string, any>,
  TSecrets extends Record<string, any> = Record<string, any>
> {
  /** Firebase Admin Auth instance (or lightweight `AdminAuthAdapter` test double). */
  adminAuth: AdminAuthAdapter;
  /** Backing storage adapter implementing `LanyardServerStore` (e.g. `FirestoreServerStore` or `InMemoryLanyardStore`). */
  store: LanyardServerStore<TRole, TCapability, TPreferences, TAttributes, THiddenAttributes, TSecrets>;
  /** Application permission policy defining role hierarchy, inheritance, capabilities, and attribute/hiddenAttribute/secret rules. */
  policy: PermissionPolicy<TRole, TCapability>;
  /** Optional override for token verification (defaults to `new GoogleAuthService(adminAuth)`). */
  authService?: AuthService;
  /** Default Express route parameter name for the tenant/scope ID (defaults to `"scopeId"`). */
  defaultScopeParam?: string;
  /**
   * Optional callback invoked in `checkAuth` when an authenticated user's verified token email
   * differs from `userRecord.email` on `users/{uid}`. Once `onVerifiedEmailChange` resolves,
   * Lanyard updates `userRecord.email` via `store.upsertUser` so the callback fires only once per email change.
   */
  onVerifiedEmailChange?: (event: VerifiedEmailChangeEvent) => void | Promise<void>;
}

/**
 * Creates a storage-agnostic Lanyard server instance providing Express authentication/authorization
 * middleware (`checkAuth`, `requireAdmin`, `requireRole`, `requireCapability`),
 * deterministic UID & role provisioning helpers, and capability-gated `attributes`, `hiddenAttributes`,
 * and encrypted `secrets` accessors unified around explicit `scopeId: ScopeId` (`GLOBAL_SCOPE` or tenant `string`).
 */
export function createLanyardServer<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>,
  THiddenAttributes extends Record<string, any> = Record<string, any>,
  TSecrets extends Record<string, any> = Record<string, any>
>(config: LanyardServerConfig<TRole, TCapability, TPreferences, TAttributes, THiddenAttributes, TSecrets>) {
  const {
    adminAuth,
    store,
    policy,
    authService = new GoogleAuthService(adminAuth),
    defaultScopeParam = "scopeId",
    onVerifiedEmailChange
  } = config;

  // Tracks in-flight verified email change syncs per (uid -> targetEmail) so concurrent requests don't double-fire
  const inFlightEmailSyncs = new Map<string, Promise<void>>();

  /**
   * Resolves whether an actor is an active system admin, guarding against stale 1-hour JWT custom claims
   * when the user has been explicitly demoted (`isSystemAdmin === false` on their `users/{uid}` record).
   */
  async function resolveEffectiveAdminStatus(actor: LanyardActor): Promise<{
    isAdmin: boolean;
    userRecord: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null;
  }> {
    if (!actor || typeof actor !== "object") {
      throw new Error("Invalid actor: actor object with uid is required");
    }
    assertValidResourceId(actor.uid, "actor.uid");

    const userRecord = typeof store.getUser === "function" ? await store.getUser(actor.uid) : null;
    if (userRecord && userRecord.isSystemAdmin === false) {
      // Explicitly demoted in the backing store: immediately revoke admin privileges even if JWT hasn't expired
      return { isAdmin: false, userRecord };
    }
    if (userRecord?.isSystemAdmin === true) {
      return { isAdmin: true, userRecord };
    }
    const sysAdmin = await store.getSystemAdmin(actor.uid);
    if (sysAdmin?.isSystemAdmin !== false && sysAdmin !== null) {
      return { isAdmin: true, userRecord };
    }
    return { isAdmin: Boolean(actor.isAdmin), userRecord };
  }

  async function syncAdminProfileIfNeeded(user: AuthenticatedUser): Promise<void> {
    const existing = await store.getSystemAdmin(user.uid);
    if (!existing) {
      await store.upsertSystemAdmin({
        uid: user.uid,
        email: user.email.toLowerCase().trim(),
        displayName: user.name || user.email,
        photoUrl: user.photoUrl || null,
        isSystemAdmin: true,
        addedBy: "auto-provision",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    } else if (user.photoUrl && existing.photoUrl !== user.photoUrl) {
      await store.upsertSystemAdmin({
        ...existing,
        photoUrl: user.photoUrl,
        updatedAt: new Date().toISOString()
      });
    }
  }

  function assertValidScopeId(scopeId: ScopeId): void {
    if (scopeId === GLOBAL_SCOPE) return;
    assertValidResourceId(scopeId, "scopeId");
  }

  // --- Express Middleware ---

  async function checkAuth(
    req: AuthenticatedRequest<TRole, TCapability, TPreferences, TAttributes>,
    res: Response,
    next: NextFunction
  ) {
    try {
      const user = await authService.verifyToken(req.headers.authorization, req.headers);
      if (!user) {
        return res.status(401).json({ error: "Unauthorized: Missing or invalid authentication credentials" });
      }
      try {
        const { isAdmin, userRecord } = await resolveEffectiveAdminStatus(user);
        user.isAdmin = isAdmin;
        req.userRecord = userRecord;
        if (isAdmin) {
          await syncAdminProfileIfNeeded(user);
        }
        if (
          user.email &&
          user.emailVerified !== false &&
          userRecord?.email &&
          userRecord.email.toLowerCase() !== user.email.toLowerCase() &&
          (typeof onVerifiedEmailChange === "function" || typeof store.upsertUser === "function")
        ) {
          const syncKey = `${user.uid}:${user.email.toLowerCase()}`;
          let syncPromise = inFlightEmailSyncs.get(syncKey);
          if (!syncPromise) {
            const previousEmail = userRecord.email;
            const nextEmail = user.email.toLowerCase().trim();
            syncPromise = (async () => {
              if (typeof onVerifiedEmailChange === "function") {
                await onVerifiedEmailChange({
                  uid: user.uid,
                  email: nextEmail,
                  previousEmail
                });
              }
              if (typeof store.upsertUser === "function") {
                const updatedRecord = {
                  ...userRecord,
                  email: nextEmail,
                  updatedAt: new Date().toISOString()
                };
                await store.upsertUser(updatedRecord);
                req.userRecord = updatedRecord;
              }
            })().finally(() => {
              inFlightEmailSyncs.delete(syncKey);
            });
            inFlightEmailSyncs.set(syncKey, syncPromise);
          }
          await syncPromise;
        }
      } catch {
        // If backing store is unreachable during checkAuth, preserve verified token claim
      }
      req.user = user;
      next();
    } catch (error: unknown) {
      res.status(401).json({ error: formatClientAuthError(error) });
    }
  }

  async function requireAdmin(
    req: AuthenticatedRequest<TRole, TCapability, TPreferences, TAttributes>,
    res: Response,
    next: NextFunction
  ) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden: Administrative access required" });
    }

    try {
      const { isAdmin, userRecord } = await resolveEffectiveAdminStatus(req.user);
      if (!isAdmin) {
        req.user.isAdmin = false;
        return res.status(403).json({ error: "Forbidden: Administrative access required" });
      }
      req.user.isAdmin = true;
      req.userRecord = userRecord;
      await syncAdminProfileIfNeeded(req.user);
    } catch {
      // If store check fails when verifying explicit demotion, continue only if token claim was verified
      if (!req.user.isAdmin) {
        return res.status(403).json({ error: "Forbidden: Administrative access required" });
      }
    }

    next();
  }

  function assertAssignableRole(role: TRole): void {
    if (typeof role !== "string" || !Object.hasOwn(policy.roles, role)) {
      throw new Error(`Invalid role '${String(role)}': role is not defined in policy.roles`);
    }
    if (!policy.isAssignableRole(role)) {
      throw new Error(`Invalid role '${String(role)}': abstract roles cannot be directly assigned to a user`);
    }
  }

  function assertAssignableRoles(roles: readonly TRole[]): void {
    if (!Array.isArray(roles)) {
      throw new Error("Invalid roles: must be an array of assignable roles");
    }
    for (const r of roles) {
      assertAssignableRole(r);
    }
  }

  /**
   * Role authorization middleware:
   * - When `scopeParamOrGlobal` is `GLOBAL_SCOPE`, verifies the authenticated user's global `users/{uid}` record
   *   holds `requiredRole` (or at least one from an array, directly or via `inherits`), or is an active system admin.
   * - When `scopeParamOrGlobal` is a route parameter name string (defaults to `defaultScopeParam`, e.g. `"scopeId"`),
   *   reads `req.params[scopeParamOrGlobal]` and verifies the user holds the role within that scope (or is an active system admin).
   */
  function requireRole(requiredRoleOrRoles: TRole | readonly TRole[], scopeParamOrGlobal: ScopeId = defaultScopeParam) {
    const requiredList = Array.isArray(requiredRoleOrRoles) ? requiredRoleOrRoles : [requiredRoleOrRoles as TRole];

    return async (
      req: AuthenticatedRequest<TRole, TCapability, TPreferences, TAttributes>,
      res: Response,
      next: NextFunction
    ) => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
      }

      if (scopeParamOrGlobal === GLOBAL_SCOPE) {
        try {
          const { isAdmin, userRecord } = await resolveEffectiveAdminStatus(req.user);
          req.user.isAdmin = isAdmin;
          req.userRecord = userRecord;

          const isAllowed =
            requiredList.length === 1
              ? policy.hasRole(userRecord, requiredList[0], isAdmin)
              : policy.hasAnyRole(userRecord, requiredList, isAdmin);

          if (!isAllowed) {
            return res.status(403).json({
              error: `Forbidden: Requires '${requiredList.join(" or ")}' role`
            });
          }

          if (userRecord && req.user.photoUrl && userRecord.photoUrl !== req.user.photoUrl && store.upsertUser) {
            const updated = { ...userRecord, photoUrl: req.user.photoUrl };
            req.userRecord = updated;
            await store.upsertUser(updated);
          }

          next();
        } catch {
          return res.status(500).json({ error: "Internal server error during authorization check" });
        }
        return;
      }

      const scopeParamName = scopeParamOrGlobal;
      const scopeId = req.params[scopeParamName];
      if (!scopeId || !isValidResourceId(scopeId)) {
        return res.status(400).json({ error: `Missing or invalid scope parameter '${scopeParamName}'` });
      }

      try {
        const { isAdmin } = await resolveEffectiveAdminStatus(req.user);
        req.user.isAdmin = isAdmin;

        const member = await store.getScopeMember(scopeId, req.user.uid);
        req.scopeMember = member;

        const isAllowed =
          requiredList.length === 1
            ? policy.hasRole(member, requiredList[0], isAdmin)
            : policy.hasAnyRole(member, requiredList, isAdmin);

        if (!isAllowed) {
          return res.status(403).json({
            error: `Forbidden: Requires '${requiredList.join(" or ")}' role in scope '${scopeId}'`
          });
        }

        if (member && req.user.photoUrl && member.photoUrl !== req.user.photoUrl) {
          const updated = { ...member, photoUrl: req.user.photoUrl };
          req.scopeMember = updated;
          await store.upsertScopeMember(scopeId, updated);
        }

        next();
      } catch {
        return res.status(500).json({ error: "Internal server error during authorization check" });
      }
    };
  }

  /**
   * Capability authorization middleware:
   * - When `scopeParamOrGlobal` is `GLOBAL_SCOPE`, verifies the authenticated user's global `users/{uid}` record
   *   holds the required capability (or at least one from an array), or is an active system admin.
   * - When `scopeParamOrGlobal` is a route parameter name string (defaults to `defaultScopeParam`, e.g. `"scopeId"`),
   *   reads `req.params[scopeParamOrGlobal]` and verifies the user holds the capability within that scope (or is an active system admin).
   */
  function requireCapability(
    capabilityOrCapabilities: TCapability | readonly TCapability[],
    scopeParamOrGlobal: ScopeId = defaultScopeParam
  ) {
    const requiredList = Array.isArray(capabilityOrCapabilities)
      ? capabilityOrCapabilities
      : [capabilityOrCapabilities as TCapability];

    return async (
      req: AuthenticatedRequest<TRole, TCapability, TPreferences, TAttributes>,
      res: Response,
      next: NextFunction
    ) => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
      }

      if (scopeParamOrGlobal === GLOBAL_SCOPE) {
        try {
          const { isAdmin, userRecord } = await resolveEffectiveAdminStatus(req.user);
          req.user.isAdmin = isAdmin;
          req.userRecord = userRecord;

          const isAllowed =
            requiredList.length === 1
              ? policy.hasCapability(userRecord, requiredList[0], isAdmin)
              : policy.hasAnyCapability(userRecord, requiredList, isAdmin);

          if (!isAllowed) {
            return res.status(403).json({
              error: `Forbidden: Missing required capability (${requiredList.join(" or ")})`
            });
          }

          if (userRecord && req.user.photoUrl && userRecord.photoUrl !== req.user.photoUrl && store.upsertUser) {
            const updated = { ...userRecord, photoUrl: req.user.photoUrl };
            req.userRecord = updated;
            await store.upsertUser(updated);
          }

          next();
        } catch {
          return res.status(500).json({ error: "Internal server error during capability check" });
        }
        return;
      }

      const scopeParamName = scopeParamOrGlobal;
      const scopeId = req.params[scopeParamName];
      if (!scopeId || !isValidResourceId(scopeId)) {
        return res.status(400).json({ error: `Missing or invalid scope parameter '${scopeParamName}'` });
      }

      try {
        const { isAdmin } = await resolveEffectiveAdminStatus(req.user);
        req.user.isAdmin = isAdmin;

        const member = await store.getScopeMember(scopeId, req.user.uid);
        req.scopeMember = member;

        const isAllowed =
          requiredList.length === 1
            ? policy.hasCapability(member, requiredList[0], isAdmin)
            : policy.hasAnyCapability(member, requiredList, isAdmin);

        if (!isAllowed) {
          return res.status(403).json({
            error: `Forbidden: Missing required capability (${requiredList.join(" or ")}) in scope '${scopeId}'`
          });
        }

        if (member && req.user.photoUrl && member.photoUrl !== req.user.photoUrl) {
          const updated = { ...member, photoUrl: req.user.photoUrl };
          req.scopeMember = updated;
          await store.upsertScopeMember(scopeId, updated);
        }

        next();
      } catch {
        return res.status(500).json({ error: "Internal server error during capability check" });
      }
    };
  }

  // --- User & Role Provisioning Helpers ---

  async function getOrProvisionUidByEmail(params: {
    email: string;
    displayName?: string;
  }): Promise<{ uid: string; email: string; created: boolean }> {
    const cleanEmail = (params.email || "").toLowerCase().trim();
    if (!isValidEmail(cleanEmail)) {
      throw new Error("Valid email address is required");
    }

    try {
      const existing = await adminAuth.getUserByEmail(cleanEmail);
      return { uid: existing.uid, email: cleanEmail, created: false };
    } catch (err: any) {
      if (err?.code === "auth/user-not-found") {
        try {
          const createdUser = await adminAuth.createUser({
            email: cleanEmail,
            displayName: params.displayName || cleanEmail,
            emailVerified: true
          });
          return { uid: createdUser.uid, email: cleanEmail, created: true };
        } catch (createErr: any) {
          if (createErr?.code === "auth/email-already-exists") {
            const raceExisting = await adminAuth.getUserByEmail(cleanEmail);
            return { uid: raceExisting.uid, email: cleanEmail, created: false };
          }
          throw createErr;
        }
      }
      throw err;
    }
  }

  async function setSystemAdminStatus(params: {
    email: string;
    isAdmin: boolean;
    firstName?: string;
    lastName?: string;
    actor: LanyardActor;
  }): Promise<SystemAdminProfile | null> {
    const { email, isAdmin, firstName = "", lastName = "", actor } = params;
    if (!actor || typeof actor !== "object") {
      throw new Error("Invalid actor: actor object with uid is required");
    }
    assertValidResourceId(actor.uid, "actor.uid");
    const displayName = [firstName.trim(), lastName.trim()].filter(Boolean).join(" ") || email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({ email, displayName });

    if (!isAdmin && uid === actor.uid) {
      throw new Error("Cannot remove yourself from system administrators");
    }

    let existingClaims: Record<string, any> = {};
    try {
      const userRecord = await adminAuth.getUserByEmail(cleanEmail);
      if (userRecord.customClaims && typeof userRecord.customClaims === "object") {
        existingClaims = { ...userRecord.customClaims };
      }
    } catch {
      // Ignore if customClaims lookup is unavailable
    }

    await adminAuth.setCustomUserClaims(uid, { ...existingClaims, admin: isAdmin });

    if (isAdmin) {
      const existing =
        (typeof store.getUser === "function" ? await store.getUser(uid) : null) || (await store.getSystemAdmin(uid));
      const now = new Date().toISOString();
      const profile: SystemAdminProfile = {
        uid,
        email: cleanEmail,
        firstName: firstName.trim() || existing?.firstName,
        lastName: lastName.trim() || existing?.lastName,
        displayName,
        photoUrl: existing?.photoUrl,
        lastSeen: existing?.lastSeen,
        isSystemAdmin: true,
        addedBy: existing?.addedBy || actor.uid,
        createdAt: existing?.createdAt || now,
        updatedAt: now
      };
      await store.upsertSystemAdmin(profile);
      return profile;
    } else {
      await store.deleteSystemAdmin(uid);
      return null;
    }
  }

  /**
   * Provisions or updates a user record by email in either `GLOBAL_SCOPE` (`users/{uid}`)
   * or a specific tenant `scopeId` (`{scopeCollection}/{scopeId}/{membersSubcollection}/{uid}`).
   */
  async function upsertUserByEmail(params: {
    scopeId: GlobalScope;
    email: string;
    firstName?: string;
    lastName?: string;
    roles?: readonly TRole[];
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  async function upsertUserByEmail(params: {
    scopeId: string;
    email: string;
    firstName?: string;
    lastName?: string;
    roles?: readonly TRole[];
    scopeName?: string;
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  async function upsertUserByEmail(params: {
    scopeId: ScopeId;
    email: string;
    firstName?: string;
    lastName?: string;
    roles?: readonly TRole[];
    scopeName?: string;
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >;
  async function upsertUserByEmail(params: {
    scopeId: ScopeId;
    email: string;
    firstName?: string;
    lastName?: string;
    roles?: readonly TRole[];
    scopeName?: string;
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  > {
    assertValidScopeId(params.scopeId);
    if (params.roles !== undefined) {
      assertAssignableRoles(params.roles);
    }

    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.upsertUser !== "function" || typeof store.getUser !== "function") {
        throw new Error("Backing store does not implement getUser / upsertUser");
      }
      const existing = await store.getUser(uid);
      const now = new Date().toISOString();
      const resolvedRoles = params.roles
        ? Array.from(new Set(params.roles))
        : (existing?.roles ?? [policy.defaultRole]);

      const record: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
        ...(existing || {}),
        uid,
        email: cleanEmail,
        firstName: params.firstName?.trim() ?? existing?.firstName,
        lastName: params.lastName?.trim() ?? existing?.lastName,
        displayName: params.firstName || params.lastName ? displayName : existing?.displayName || displayName,
        roles: resolvedRoles,
        ...(params.preferences ? { preferences: { ...(existing?.preferences || {}), ...params.preferences } } : {}),
        ...(params.attributes ? { attributes: { ...(existing?.attributes || {}), ...params.attributes } } : {}),
        createdAt: existing?.createdAt || now,
        updatedAt: now
      };

      await store.upsertUser(record);
      return (await store.getUser(uid))!;
    }

    const existing = await store.getScopeMember(params.scopeId, uid);
    const resolvedRoles = params.roles ? Array.from(new Set(params.roles)) : (existing?.roles ?? [policy.defaultRole]);
    const member: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || {}),
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim() ?? existing?.firstName,
      lastName: params.lastName?.trim() ?? existing?.lastName,
      displayName: params.firstName || params.lastName ? displayName : existing?.displayName || displayName,
      roles: resolvedRoles,
      scopeId: params.scopeId,
      scopeName: params.scopeName ?? existing?.scopeName,
      ...(params.preferences ? { preferences: { ...(existing?.preferences || {}), ...params.preferences } } : {}),
      ...(params.attributes ? { attributes: { ...(existing?.attributes || {}), ...params.attributes } } : {})
    };

    await store.upsertScopeMember(params.scopeId, member);
    return (await store.getScopeMember(params.scopeId, uid)) || member;
  }

  /**
   * Additively grants `roles` to a user (identifying or provisioning by email) in either
   * `GLOBAL_SCOPE` (`users/{uid}`) or a specific tenant `scopeId`.
   */
  async function grantRolesByEmail(params: {
    scopeId: GlobalScope;
    email: string;
    roles: readonly TRole[];
    firstName?: string;
    lastName?: string;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  async function grantRolesByEmail(params: {
    scopeId: string;
    email: string;
    roles: readonly TRole[];
    firstName?: string;
    lastName?: string;
    scopeName?: string;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  async function grantRolesByEmail(params: {
    scopeId: ScopeId;
    email: string;
    roles: readonly TRole[];
    firstName?: string;
    lastName?: string;
    scopeName?: string;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >;
  async function grantRolesByEmail(params: {
    scopeId: ScopeId;
    email: string;
    roles: readonly TRole[];
    firstName?: string;
    lastName?: string;
    scopeName?: string;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  > {
    assertValidScopeId(params.scopeId);
    assertAssignableRoles(params.roles);
    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.grantUserRoles !== "function") {
        throw new Error("Backing store does not implement grantUserRoles");
      }
      return store.grantUserRoles(uid, params.roles, {
        uid,
        email: cleanEmail,
        firstName: params.firstName?.trim(),
        lastName: params.lastName?.trim(),
        displayName
      });
    }

    return store.grantScopeRoles(params.scopeId, uid, params.roles, {
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim(),
      lastName: params.lastName?.trim(),
      displayName,
      scopeId: params.scopeId,
      scopeName: params.scopeName
    });
  }

  /**
   * Removes the specified `roles` from `uid` in `GLOBAL_SCOPE` or a specific tenant `scopeId`.
   */
  async function revokeRoles(scopeId: ScopeId, uid: string, roles: readonly TRole[]): Promise<void> {
    assertValidScopeId(scopeId);
    assertValidResourceId(uid, "uid");
    if (scopeId === GLOBAL_SCOPE) {
      if (typeof store.revokeUserRoles !== "function") {
        throw new Error("Backing store does not implement revokeUserRoles");
      }
      await store.revokeUserRoles(uid, roles);
      return;
    }
    await store.revokeScopeRoles(scopeId, uid, roles);
  }

  /**
   * Reads a user's record in `GLOBAL_SCOPE` (`users/{targetUid}`) or a specific tenant `scopeId`
   * after verifying the caller (`actor`) is the user themselves, holds the `read` capability
   * in `userCapabilities` within that scope, or is an active system admin.
   * Automatically filters `attributes` to only keys readable by `actor`.
   */
  async function getUser(params: {
    scopeId: GlobalScope;
    actor: LanyardActor;
    targetUid: string;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null>;
  async function getUser(params: {
    scopeId: string;
    actor: LanyardActor;
    targetUid: string;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null>;
  async function getUser(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
    | null
  >;
  async function getUser(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
    | null
  > {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUser !== "function") {
        throw new Error("Backing store does not implement getUser");
      }
      const isSelf = actorUid === params.targetUid;
      if (!policy.canReadUser(actorGlobalRecord, { isSystemAdmin: isAdmin, isSelf })) {
        throw new Error("Forbidden: Insufficient permissions to read user profile");
      }
      const targetUser = await store.getUser(params.targetUid);
      if (!targetUser) return null;
      const filteredAttributes = policy.filterReadableAttributes<TAttributes>(
        actorGlobalRecord,
        targetUser.attributes,
        {
          isSystemAdmin: isAdmin,
          isSelf
        }
      );
      return {
        ...targetUser,
        ...(targetUser.attributes !== undefined ? { attributes: filteredAttributes } : {})
      };
    }

    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const isSelf = Boolean(actorMember && actorUid === params.targetUid);
    if (!policy.canReadUser(actorMember, { isSystemAdmin: isAdmin, isSelf })) {
      throw new Error(`Forbidden: Insufficient permissions to read member profile in scope '${params.scopeId}'`);
    }
    const targetMember = await store.getScopeMember(params.scopeId, params.targetUid);
    if (!targetMember) return null;
    const filteredAttributes = policy.filterReadableAttributes<TAttributes>(actorMember, targetMember.attributes, {
      isSystemAdmin: isAdmin,
      isSelf
    });
    return {
      ...targetMember,
      ...(targetMember.attributes !== undefined ? { attributes: filteredAttributes } : {})
    };
  }

  /**
   * Lists all users in `GLOBAL_SCOPE` (`usersCollection`) or all members in a tenant `scopeId`
   * after verifying the caller (`actor`) holds the `read` capability in `userCapabilities`
   * within that scope or is an active system admin.
   * Automatically filters each user's `attributes` to only keys readable by `actor`.
   */
  async function listUsers(params: {
    scopeId: GlobalScope;
    actor: LanyardActor;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>[]>;
  async function listUsers(params: {
    scopeId: string;
    actor: LanyardActor;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]>;
  async function listUsers(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>[]
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]
  >;
  async function listUsers(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>[]
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]
  > {
    assertValidScopeId(params.scopeId);
    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.listUsers !== "function") {
        throw new Error("Backing store does not implement listUsers");
      }
      if (!policy.canReadUser(actorGlobalRecord, { isSystemAdmin: isAdmin, isSelf: false })) {
        throw new Error("Forbidden: Insufficient permissions to list users");
      }
      const allUsers = await store.listUsers();
      return allUsers.map((u) => {
        const isSelf = u.uid === actorUid;
        const filteredAttributes = policy.filterReadableAttributes<TAttributes>(actorGlobalRecord, u.attributes, {
          isSystemAdmin: isAdmin,
          isSelf
        });
        return {
          ...u,
          ...(u.attributes !== undefined ? { attributes: filteredAttributes } : {})
        };
      });
    }

    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    if (!policy.canReadUser(actorMember, { isSystemAdmin: isAdmin, isSelf: false })) {
      throw new Error(`Forbidden: Insufficient permissions to list members in scope '${params.scopeId}'`);
    }
    const allMembers = await store.listScopeMembers(params.scopeId);
    return allMembers.map((m) => {
      const isSelf = Boolean(actorMember && m.uid === actorUid);
      const filteredAttributes = policy.filterReadableAttributes<TAttributes>(actorMember, m.attributes, {
        isSystemAdmin: isAdmin,
        isSelf
      });
      return {
        ...m,
        ...(m.attributes !== undefined ? { attributes: filteredAttributes } : {})
      };
    });
  }

  /**
   * Updates a user's profile fields (`firstName`, `lastName`, `displayName`, `photoUrl`, `email`) in
   * `GLOBAL_SCOPE` (`users/{targetUid}`) or a specific tenant `scopeId` after verifying the caller (`actor`)
   * is the user themselves, holds the `write` capability in `userCapabilities` within that scope,
   * or is an active system admin. When `scopeId === GLOBAL_SCOPE`, also syncs `displayName` to Firebase Auth.
   */
  async function updateUserProfile(params: {
    scopeId: GlobalScope;
    actor: LanyardActor;
    targetUid: string;
    patch: UserProfilePatch;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  async function updateUserProfile(params: {
    scopeId: string;
    actor: LanyardActor;
    targetUid: string;
    patch: UserProfilePatch;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  async function updateUserProfile(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    patch: UserProfilePatch;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >;
  async function updateUserProfile(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    patch: UserProfilePatch;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  > {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUser !== "function" || typeof store.upsertUser !== "function") {
        throw new Error("Backing store does not implement getUser / upsertUser");
      }
      const isSelf = actorUid === params.targetUid;
      if (!isSelf && !policy.canWriteUser(actorGlobalRecord, isAdmin)) {
        throw new Error("Forbidden: Insufficient permissions to update user profile");
      }
      const existing = await store.getUser(params.targetUid);
      if (!existing) {
        throw new Error(`Target user '${params.targetUid}' not found`);
      }
      if (!isAdmin && !isSelf && existing.isSystemAdmin === true) {
        throw new Error("Forbidden: Non-system administrators cannot modify a system administrator");
      }

      const patch = params.patch || {};
      const firstName = typeof patch.firstName === "string" ? patch.firstName.trim() : existing.firstName;
      const lastName = typeof patch.lastName === "string" ? patch.lastName.trim() : existing.lastName;
      const computedDisplayName = [firstName, lastName].filter(Boolean).join(" ").trim();
      const displayName =
        typeof patch.displayName === "string"
          ? patch.displayName.trim()
          : typeof patch.firstName === "string" || typeof patch.lastName === "string"
            ? computedDisplayName || existing.displayName
            : existing.displayName;
      const email =
        typeof patch.email === "string" && patch.email.trim() ? patch.email.toLowerCase().trim() : existing.email;
      const photoUrl = patch.photoUrl !== undefined ? sanitizeAvatarUrl(patch.photoUrl) : existing.photoUrl;

      const updated: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
        ...existing,
        uid: params.targetUid,
        email,
        ...(firstName !== undefined ? { firstName } : {}),
        ...(lastName !== undefined ? { lastName } : {}),
        ...(displayName !== undefined ? { displayName } : {}),
        ...(photoUrl !== undefined ? { photoUrl } : {}),
        updatedAt: new Date().toISOString()
      };

      await store.upsertUser(updated);
      if (displayName && displayName !== existing.displayName && typeof adminAuth.updateUser === "function") {
        await adminAuth.updateUser(params.targetUid, { displayName }).catch(() => {});
      }
      return (await store.getUser(params.targetUid))!;
    }

    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const isSelf = Boolean(actorMember && actorUid === params.targetUid);
    if (!isSelf && !policy.canWriteUser(actorMember, isAdmin)) {
      throw new Error(`Forbidden: Insufficient permissions to update member profile in scope '${params.scopeId}'`);
    }
    const existing = await store.getScopeMember(params.scopeId, params.targetUid);
    if (!existing) {
      throw new Error(`Target member '${params.targetUid}' not found in scope '${params.scopeId}'`);
    }

    const patch = params.patch || {};
    const firstName = typeof patch.firstName === "string" ? patch.firstName.trim() : existing.firstName;
    const lastName = typeof patch.lastName === "string" ? patch.lastName.trim() : existing.lastName;
    const computedDisplayName = [firstName, lastName].filter(Boolean).join(" ").trim();
    const displayName =
      typeof patch.displayName === "string"
        ? patch.displayName.trim()
        : typeof patch.firstName === "string" || typeof patch.lastName === "string"
          ? computedDisplayName || existing.displayName
          : existing.displayName;
    const email =
      typeof patch.email === "string" && patch.email.trim() ? patch.email.toLowerCase().trim() : existing.email;
    const photoUrl = patch.photoUrl !== undefined ? sanitizeAvatarUrl(patch.photoUrl) : existing.photoUrl;

    const updated: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid: params.targetUid,
      email,
      ...(firstName !== undefined ? { firstName } : {}),
      ...(lastName !== undefined ? { lastName } : {}),
      ...(displayName !== undefined ? { displayName } : {}),
      ...(photoUrl !== undefined ? { photoUrl } : {})
    };

    await store.upsertScopeMember(params.scopeId, updated);
    return (await store.getScopeMember(params.scopeId, params.targetUid))!;
  }

  /**
   * Replaces a user's `roles` in `GLOBAL_SCOPE` (`users/{targetUid}`) or a specific tenant `scopeId`
   * after verifying the caller (`actor`) holds the `assignRoles` capability in `userCapabilities`
   * within that scope (or is an active system admin), and that every role in `roles` is concrete (`!abstract`).
   */
  async function updateUserRoles(params: {
    scopeId: GlobalScope;
    actor: LanyardActor;
    targetUid: string;
    roles: readonly TRole[];
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  async function updateUserRoles(params: {
    scopeId: string;
    actor: LanyardActor;
    targetUid: string;
    roles: readonly TRole[];
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  async function updateUserRoles(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    roles: readonly TRole[];
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >;
  async function updateUserRoles(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    roles: readonly TRole[];
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  > {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");
    assertAssignableRoles(params.roles);

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUser !== "function" || typeof store.upsertUser !== "function") {
        throw new Error("Backing store does not implement getUser / upsertUser");
      }
      if (!policy.canAssignRoles(actorGlobalRecord, isAdmin)) {
        throw new Error("Forbidden: Insufficient permissions to assign user roles");
      }
      const existing = await store.getUser(params.targetUid);
      if (!existing) {
        throw new Error(`Target user '${params.targetUid}' not found`);
      }
      if (!isAdmin && existing.isSystemAdmin === true) {
        throw new Error("Forbidden: Non-system administrators cannot modify a system administrator");
      }

      const updated: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
        ...existing,
        uid: params.targetUid,
        roles: Array.from(new Set(params.roles)),
        updatedAt: new Date().toISOString()
      };
      await store.upsertUser(updated);
      return (await store.getUser(params.targetUid))!;
    }

    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    if (!policy.canAssignRoles(actorMember, isAdmin)) {
      throw new Error(`Forbidden: Insufficient permissions to assign member roles in scope '${params.scopeId}'`);
    }
    const existing = await store.getScopeMember(params.scopeId, params.targetUid);
    if (!existing) {
      throw new Error(`Target member '${params.targetUid}' not found in scope '${params.scopeId}'`);
    }

    const updated: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...existing,
      uid: params.targetUid,
      roles: Array.from(new Set(params.roles))
    };
    await store.upsertScopeMember(params.scopeId, updated);
    return (await store.getScopeMember(params.scopeId, params.targetUid))!;
  }

  /**
   * Deletes a user record with email-confirmation protection against accidental or swapped-UID deletion:
   * - When `scopeId === GLOBAL_SCOPE`: deletes `users/{targetUid}`, its private subdocuments, and the Firebase Auth user.
   * - When `scopeId` is a tenant string: removes `{scopeCollection}/{scopeId}/{membersSubcollection}/{targetUid}`
   *   and its private subdocuments without deleting the global user or Firebase Auth account.
   * - If `actor.uid === targetUid` (self-deletion / leaving a scope), no `userCapabilities.write` capability is required.
   * - If `actor.uid !== targetUid` (deleting another user/member), `actor` must hold `userCapabilities.write`
   *   in `scopeId` (or be `isSystemAdmin`), and in `GLOBAL_SCOPE` non-system admins cannot delete a `systemAdmin`.
   * - In all cases, `confirmTargetEmail` must match `targetUid`'s stored email address case-insensitively.
   */
  async function deleteUser(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    confirmTargetEmail: string;
  }): Promise<void> {
    assertValidScopeId(params.scopeId);
    if (!params.actor || typeof params.actor !== "object") {
      throw new Error("Invalid actor: actor object with uid is required");
    }
    assertValidResourceId(params.actor.uid, "actor.uid");
    assertValidResourceId(params.targetUid, "targetUid");
    const actorUid = params.actor.uid;
    const cleanConfirmEmail = (params.confirmTargetEmail || "").toLowerCase().trim();
    if (!cleanConfirmEmail) {
      throw new Error("confirmTargetEmail is required to delete user");
    }

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUser !== "function" || typeof store.deleteUser !== "function") {
        throw new Error("Backing store does not implement getUser / deleteUser");
      }

      const isSelf = actorUid === params.targetUid;
      let isAdmin = false;
      if (!isSelf) {
        const resolved = await resolveEffectiveAdminStatus(params.actor);
        isAdmin = resolved.isAdmin;
        if (!policy.canWriteUser(resolved.userRecord, isAdmin)) {
          throw new Error("Forbidden: Insufficient permissions to delete user");
        }
      }

      const targetUser = await store.getUser(params.targetUid);
      if (!targetUser) {
        if (!isSelf) {
          throw new Error(`Target user '${params.targetUid}' not found`);
        }
      } else {
        if (!isSelf && !isAdmin && targetUser.isSystemAdmin === true) {
          throw new Error("Forbidden: Non-system administrators cannot delete a system administrator");
        }
        const targetEmail = (targetUser.email || "").toLowerCase().trim();
        if (!targetEmail || targetEmail !== cleanConfirmEmail) {
          throw new Error(
            `Refusing to delete user '${params.targetUid}': confirmTargetEmail '${cleanConfirmEmail}' does not match target user's email`
          );
        }
      }

      await store.deleteUser(params.targetUid);
      if (typeof adminAuth.deleteUser === "function") {
        await adminAuth.deleteUser(params.targetUid);
      }
      return;
    }

    const { isAdmin } = await resolveEffectiveAdminStatus(params.actor);
    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const isSelf = Boolean(actorMember && actorUid === params.targetUid);
    if (!isSelf && !policy.canWriteUser(actorMember, isAdmin)) {
      throw new Error(`Forbidden: Insufficient permissions to delete member in scope '${params.scopeId}'`);
    }

    const targetMember = await store.getScopeMember(params.scopeId, params.targetUid);
    if (!targetMember) {
      if (!isSelf) {
        throw new Error(`Target member '${params.targetUid}' not found in scope '${params.scopeId}'`);
      }
    } else {
      const targetEmail = (targetMember.email || "").toLowerCase().trim();
      if (!targetEmail || targetEmail !== cleanConfirmEmail) {
        throw new Error(
          `Refusing to delete member '${params.targetUid}' in scope '${params.scopeId}': confirmTargetEmail '${cleanConfirmEmail}' does not match target member's email`
        );
      }
    }

    await store.deleteScopeMember(params.scopeId, params.targetUid);
  }

  // --- Capability-Gated Attributes & Secrets Operations ---

  /**
   * Reads a user's `attributes` in `GLOBAL_SCOPE` (`users/{targetUid}`) or a specific tenant `scopeId`,
   * filtering out any keys the caller (`actor`) is not permitted to read in that exact `scopeId`.
   */
  async function readUserAttributes(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
  }): Promise<Partial<TAttributes>> {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUser !== "function") {
        throw new Error("Backing store does not implement getUser");
      }
      const targetUser = await store.getUser(params.targetUid);
      return policy.filterReadableAttributes<TAttributes>(actorGlobalRecord, targetUser?.attributes, {
        isSystemAdmin: isAdmin,
        isSelf: actorUid === params.targetUid
      });
    }

    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const targetMember = await store.getScopeMember(params.scopeId, params.targetUid);
    return policy.filterReadableAttributes<TAttributes>(actorMember, targetMember?.attributes, {
      isSystemAdmin: isAdmin,
      isSelf: Boolean(actorMember && actorUid === params.targetUid)
    });
  }

  /**
   * Updates a user's `attributes` in `GLOBAL_SCOPE` (`users/{targetUid}`) or a specific tenant `scopeId`
   * after verifying the caller (`actor`) holds the required write capability for every key in `patch`
   * within that exact `scopeId` (or is an active system admin).
   * Self-ownership (`actor.uid === targetUid`) and roles in other scopes NEVER grant write access to `attributes`.
   */
  async function updateUserAttributes(params: {
    scopeId: GlobalScope;
    actor: LanyardActor;
    targetUid: string;
    patch: Partial<TAttributes>;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>>;
  async function updateUserAttributes(params: {
    scopeId: string;
    actor: LanyardActor;
    targetUid: string;
    patch: Partial<TAttributes>;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>>;
  async function updateUserAttributes(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    patch: Partial<TAttributes>;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  >;
  async function updateUserAttributes(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    patch: Partial<TAttributes>;
  }): Promise<
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  > {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.updateUserAttributes !== "function") {
        throw new Error("Backing store does not implement updateUserAttributes");
      }
      if (!policy.canWriteAttributesPatch(actorGlobalRecord, params.patch as Record<string, any>, isAdmin)) {
        throw new Error("Forbidden: Insufficient permissions to update the requested user attributes");
      }
      return store.updateUserAttributes(params.targetUid, params.patch);
    }

    if (typeof store.updateScopeMemberAttributes !== "function") {
      throw new Error("Backing store does not implement updateScopeMemberAttributes");
    }
    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!policy.canWriteAttributesPatch(actorMember, params.patch as Record<string, any>, isAdmin)) {
      throw new Error(`Forbidden: Insufficient permissions to update member attributes in scope '${params.scopeId}'`);
    }
    return store.updateScopeMemberAttributes(params.scopeId, params.targetUid, params.patch);
  }

  /**
   * Reads a user's `hiddenAttributes` in `GLOBAL_SCOPE` (`users/{targetUid}/private/hiddenAttributes`)
   * or a specific tenant `scopeId`, returning only keys the caller (`actor`) holds the required `read`
   * capability for in that scope (or all keys if `isSystemAdmin`).
   * Self-ownership (`actor.uid === targetUid`) never grants read access to `hiddenAttributes`.
   */
  async function readUserHiddenAttributes(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
  }): Promise<Partial<THiddenAttributes>> {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUserHiddenAttributes !== "function") {
        throw new Error("Backing store does not implement getUserHiddenAttributes");
      }
      const rawHiddenAttributes = await store.getUserHiddenAttributes(params.targetUid);
      const filtered = policy.filterReadableHiddenAttributes<THiddenAttributes>(
        actorGlobalRecord,
        rawHiddenAttributes,
        isAdmin
      );
      if (!isAdmin && Object.keys(rawHiddenAttributes).length > 0 && Object.keys(filtered).length === 0) {
        throw new Error("Forbidden: Insufficient permissions to read user hiddenAttributes");
      }
      return filtered;
    }

    if (typeof store.getScopeMemberHiddenAttributes !== "function") {
      throw new Error("Backing store does not implement getScopeMemberHiddenAttributes");
    }
    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const rawHiddenAttributes = await store.getScopeMemberHiddenAttributes(params.scopeId, params.targetUid);
    const filtered = policy.filterReadableHiddenAttributes<THiddenAttributes>(
      actorMember,
      rawHiddenAttributes,
      isAdmin
    );
    if (!isAdmin && Object.keys(rawHiddenAttributes).length > 0 && Object.keys(filtered).length === 0) {
      throw new Error(
        `Forbidden: Insufficient permissions to read member hiddenAttributes in scope '${params.scopeId}'`
      );
    }
    return filtered;
  }

  /**
   * Updates a user's `hiddenAttributes` in `GLOBAL_SCOPE` (`users/{targetUid}/private/hiddenAttributes`)
   * or a specific tenant `scopeId` after verifying the caller (`actor`) holds the required `write`
   * capability for every key in `patch` within that scope (or is an active system admin).
   */
  async function updateUserHiddenAttributes(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    patch: Partial<THiddenAttributes>;
  }): Promise<Partial<THiddenAttributes>> {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.updateUserHiddenAttributes !== "function") {
        throw new Error("Backing store does not implement updateUserHiddenAttributes");
      }
      if (!policy.canWriteHiddenAttributesPatch(actorGlobalRecord, params.patch as Record<string, any>, isAdmin)) {
        throw new Error("Forbidden: Insufficient permissions to update the requested user hiddenAttributes");
      }
      return store.updateUserHiddenAttributes(params.targetUid, params.patch);
    }

    if (typeof store.updateScopeMemberHiddenAttributes !== "function") {
      throw new Error("Backing store does not implement updateScopeMemberHiddenAttributes");
    }
    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!policy.canWriteHiddenAttributesPatch(actorMember, params.patch as Record<string, any>, isAdmin)) {
      throw new Error(
        `Forbidden: Insufficient permissions to update member hiddenAttributes in scope '${params.scopeId}'`
      );
    }
    return store.updateScopeMemberHiddenAttributes(params.scopeId, params.targetUid, params.patch);
  }

  // --- Write-Only Encrypted User Secrets Operations ---

  /**
   * Returns a boolean status map (`{ [key]: boolean }`) indicating which secrets are configured
   * for `targetUid` in `GLOBAL_SCOPE` (`users/{targetUid}/private/secrets`) or a specific tenant `scopeId`
   * (`{scopeCollection}/{scopeId}/{membersSubcollection}/{targetUid}/private/secrets`),
   * without ever exposing or decrypting secret values.
   */
  async function getUserSecretsStatus(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUserSecretsStatus !== "function") {
        throw new Error("Backing store does not implement getUserSecretsStatus");
      }
      const isSelf = actorUid === params.targetUid;
      const rawStatus = await store.getUserSecretsStatus(params.targetUid);
      if (isAdmin || isSelf) {
        return rawStatus;
      }
      const filtered: Partial<Record<keyof TSecrets & string, boolean>> = {};
      for (const [key, isConfigured] of Object.entries(rawStatus)) {
        if (policy.canWriteSecret(actorGlobalRecord, key, { isSystemAdmin: isAdmin, isSelf })) {
          filtered[key as keyof TSecrets & string] = Boolean(isConfigured);
        }
      }
      if (Object.keys(rawStatus).length > 0 && Object.keys(filtered).length === 0) {
        throw new Error("Forbidden: Insufficient permissions to inspect user secrets status");
      }
      return filtered;
    }

    if (typeof store.getScopeMemberSecretsStatus !== "function") {
      throw new Error("Backing store does not implement getScopeMemberSecretsStatus");
    }
    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const isSelf = Boolean(actorMember && actorUid === params.targetUid);
    const rawStatus = await store.getScopeMemberSecretsStatus(params.scopeId, params.targetUid);
    if (isAdmin || isSelf) {
      return rawStatus;
    }
    const filtered: Partial<Record<keyof TSecrets & string, boolean>> = {};
    for (const [key, isConfigured] of Object.entries(rawStatus)) {
      if (policy.canWriteSecret(actorMember, key, { isSystemAdmin: isAdmin, isSelf })) {
        filtered[key as keyof TSecrets & string] = Boolean(isConfigured);
      }
    }
    if (Object.keys(rawStatus).length > 0 && Object.keys(filtered).length === 0) {
      throw new Error(
        `Forbidden: Insufficient permissions to inspect member secrets status in scope '${params.scopeId}'`
      );
    }
    return filtered;
  }

  /**
   * Encrypts and writes (or clears when `""` or `null` is passed) user secrets for `targetUid`
   * in `GLOBAL_SCOPE` (`users/{targetUid}/private/secrets`) or a specific tenant `scopeId`.
   * Returns the updated boolean status map (`{ [key]: boolean }`) and NEVER returns plaintext or ciphertext values.
   */
  async function updateUserSecrets(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    patch: Partial<Record<keyof TSecrets & string, string | null | undefined>>;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.updateUserSecrets !== "function") {
        throw new Error("Backing store does not implement updateUserSecrets");
      }
      const isSelf = actorUid === params.targetUid;
      if (
        !policy.canWriteSecretsPatch(actorGlobalRecord, params.patch as Record<string, any>, {
          isSystemAdmin: isAdmin,
          isSelf
        })
      ) {
        throw new Error("Forbidden: Insufficient permissions to update the requested user secrets");
      }
      return store.updateUserSecrets(params.targetUid, params.patch);
    }

    if (typeof store.updateScopeMemberSecrets !== "function") {
      throw new Error("Backing store does not implement updateScopeMemberSecrets");
    }
    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    const isSelf = Boolean(actorMember && actorUid === params.targetUid);
    if (
      !policy.canWriteSecretsPatch(actorMember, params.patch as Record<string, any>, { isSystemAdmin: isAdmin, isSelf })
    ) {
      throw new Error(`Forbidden: Insufficient permissions to update member secrets in scope '${params.scopeId}'`);
    }
    return store.updateScopeMemberSecrets(params.scopeId, params.targetUid, params.patch);
  }

  /**
   * Server-only helper that decrypts and returns plaintext secrets for `uid` in `GLOBAL_SCOPE`
   * (`users/{uid}/private/secrets`) or a specific tenant `scopeId`
   * (`{scopeCollection}/{scopeId}/{membersSubcollection}/{uid}/private/secrets`).
   * Never expose the return value of this method in client HTTP responses.
   */
  async function getDecryptedUserSecrets(
    scopeId: ScopeId,
    uid: string
  ): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    assertValidScopeId(scopeId);
    assertValidResourceId(uid, "uid");
    if (scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUserSecrets !== "function") {
        throw new Error("Backing store does not implement getUserSecrets");
      }
      return store.getUserSecrets(uid);
    }
    if (typeof store.getScopeMemberSecrets !== "function") {
      throw new Error("Backing store does not implement getScopeMemberSecrets");
    }
    return store.getScopeMemberSecrets(scopeId, uid);
  }

  return {
    authService,
    checkAuth,
    requireAdmin,
    requireRole,
    requireCapability,
    getOrProvisionUidByEmail,
    setSystemAdminStatus,
    upsertUserByEmail,
    grantRolesByEmail,
    revokeRoles,
    getUser,
    listUsers,
    updateUserProfile,
    updateUserRoles,
    deleteUser,
    readUserAttributes,
    updateUserAttributes,
    readUserHiddenAttributes,
    updateUserHiddenAttributes,
    getUserSecretsStatus,
    updateUserSecrets,
    getDecryptedUserSecrets
  };
}

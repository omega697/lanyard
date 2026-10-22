import type { NextFunction, Request, Response } from "express";
import {
  assertValidResourceId,
  isValidEmail,
  isValidResourceId,
  sanitizeAvatarUrl,
  type LanyardServerStore,
  type PermissionPolicy,
  type ScopedMember,
  type SystemAdminProfile,
  type UserProfilePatch,
  type UserRecord
} from "../core/index.js";

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
}

/**
 * Creates a storage-agnostic Lanyard server instance providing Express authentication/authorization
 * middleware (`checkAuth`, `requireAdmin`, `requireUserRole`, `requireUserCapability`,
 * `requireScopeRole`, `requireScopeCapability`), deterministic UID & role provisioning helpers,
 * and capability-gated `attributes`, `hiddenAttributes`, and encrypted `secrets` accessors.
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
    defaultScopeParam = "scopeId"
  } = config;

  /**
   * Resolves whether an actor is an active system admin, guarding against stale 1-hour JWT custom claims
   * when the user has been explicitly demoted (`isSystemAdmin === false` on their `users/{uid}` record).
   */
  async function resolveEffectiveAdminStatus(
    uid: string,
    tokenClaimIsAdmin: boolean
  ): Promise<{
    isAdmin: boolean;
    userRecord: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null;
  }> {
    const userRecord = typeof store.getUser === "function" ? await store.getUser(uid) : null;
    if (userRecord && userRecord.isSystemAdmin === false) {
      // Explicitly demoted in the backing store: immediately revoke admin privileges even if JWT hasn't expired
      return { isAdmin: false, userRecord };
    }
    const isAdmin = Boolean(tokenClaimIsAdmin || userRecord?.isSystemAdmin === true);
    return { isAdmin, userRecord };
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
      const { isAdmin, userRecord } = await resolveEffectiveAdminStatus(req.user.uid, Boolean(req.user.isAdmin));
      if (!isAdmin) {
        req.user.isAdmin = false;
        return res.status(403).json({ error: "Forbidden: Administrative access required" });
      }
      req.user.isAdmin = true;
      req.userRecord = userRecord;

      // Auto-seed logged-in admin or sync updated photoUrl to the backing store
      const existing = await store.getSystemAdmin(req.user.uid);
      if (!existing) {
        await store.upsertSystemAdmin({
          uid: req.user.uid,
          email: req.user.email.toLowerCase().trim(),
          displayName: req.user.name || req.user.email,
          photoUrl: req.user.photoUrl || null,
          isSystemAdmin: true,
          addedBy: "auto-provision",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        });
      } else if (req.user.photoUrl && existing.photoUrl !== req.user.photoUrl) {
        await store.upsertSystemAdmin({
          ...existing,
          photoUrl: req.user.photoUrl,
          updatedAt: new Date().toISOString()
        });
      }
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
   * Single-tenant role middleware: verifies the authenticated user's global `users/{uid}` record
   * holds `requiredRole` (or at least one from an array, directly or via `inherits`), or is an active system admin.
   */
  function requireUserRole(requiredRoleOrRoles: TRole | readonly TRole[]) {
    const requiredList = Array.isArray(requiredRoleOrRoles) ? requiredRoleOrRoles : [requiredRoleOrRoles as TRole];

    return async (
      req: AuthenticatedRequest<TRole, TCapability, TPreferences, TAttributes>,
      res: Response,
      next: NextFunction
    ) => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
      }

      try {
        const { isAdmin, userRecord } = await resolveEffectiveAdminStatus(req.user.uid, Boolean(req.user.isAdmin));
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
    };
  }

  /**
   * Single-tenant capability middleware: verifies the authenticated user's global `users/{uid}` record
   * holds the required capability (or at least one from an array), or is an active system admin.
   */
  function requireUserCapability(capabilityOrCapabilities: TCapability | readonly TCapability[]) {
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

      try {
        const { isAdmin, userRecord } = await resolveEffectiveAdminStatus(req.user.uid, Boolean(req.user.isAdmin));
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
    };
  }

  function requireScopeRole(requiredRoleOrRoles: TRole | readonly TRole[], scopeParamName = defaultScopeParam) {
    const requiredList = Array.isArray(requiredRoleOrRoles) ? requiredRoleOrRoles : [requiredRoleOrRoles as TRole];

    return async (
      req: AuthenticatedRequest<TRole, TCapability, TPreferences, TAttributes>,
      res: Response,
      next: NextFunction
    ) => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
      }

      const scopeId = req.params[scopeParamName];
      if (!scopeId || !isValidResourceId(scopeId)) {
        return res.status(400).json({ error: `Missing or invalid scope parameter '${scopeParamName}'` });
      }

      try {
        const { isAdmin } = await resolveEffectiveAdminStatus(req.user.uid, Boolean(req.user.isAdmin));
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

        // Sync updated photoUrl if changed
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

  function requireScopeCapability(
    capabilityOrCapabilities: TCapability | readonly TCapability[],
    scopeParamName = defaultScopeParam
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

      const scopeId = req.params[scopeParamName];
      if (!scopeId || !isValidResourceId(scopeId)) {
        return res.status(400).json({ error: `Missing or invalid scope parameter '${scopeParamName}'` });
      }

      try {
        const { isAdmin } = await resolveEffectiveAdminStatus(req.user.uid, Boolean(req.user.isAdmin));
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

        // Sync updated photoUrl if changed (e.g. pre-provisioned member signing in with OAuth)
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
    actorUid: string;
  }): Promise<SystemAdminProfile | null> {
    const { email, isAdmin, firstName = "", lastName = "", actorUid } = params;
    assertValidResourceId(actorUid, "actorUid");
    const displayName = [firstName.trim(), lastName.trim()].filter(Boolean).join(" ") || email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({ email, displayName });

    if (!isAdmin && uid === actorUid) {
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
        addedBy: existing?.addedBy || actorUid,
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
   * Provisions or updates a single-tenant user record (`users/{uid}`) by email.
   */
  async function upsertUserByEmail(params: {
    email: string;
    firstName?: string;
    lastName?: string;
    roles?: readonly TRole[];
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    if (params.roles !== undefined) {
      assertAssignableRoles(params.roles);
    }
    if (typeof store.upsertUser !== "function" || typeof store.getUser !== "function") {
      throw new Error("Backing store does not implement getUser / upsertUser");
    }
    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    const existing = await store.getUser(uid);
    const now = new Date().toISOString();
    const resolvedRoles = params.roles ? Array.from(new Set(params.roles)) : (existing?.roles ?? [policy.defaultRole]);

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

  async function grantUserRolesByEmail(params: {
    email: string;
    roles: readonly TRole[];
    firstName?: string;
    lastName?: string;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    assertAssignableRoles(params.roles);
    if (typeof store.grantUserRoles !== "function") {
      throw new Error("Backing store does not implement grantUserRoles");
    }
    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    return store.grantUserRoles(uid, params.roles, {
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim(),
      lastName: params.lastName?.trim(),
      displayName
    });
  }

  async function revokeUserRoles(uid: string, roles: readonly TRole[]): Promise<void> {
    assertValidResourceId(uid, "uid");
    if (typeof store.revokeUserRoles !== "function") {
      throw new Error("Backing store does not implement revokeUserRoles");
    }
    await store.revokeUserRoles(uid, roles);
  }

  /**
   * Reads a user's `UserRecord` (`users/{targetUid}`) after verifying the caller (`actorUid`)
   * is the user themselves, holds the `read` capability in `userCapabilities`, or is an active system admin.
   * Automatically filters `attributes` to only keys readable by `actorUid`.
   */
  async function getUser(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getUser !== "function") {
      throw new Error("Backing store does not implement getUser");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    const isSelf = params.actorUid === params.targetUid;
    if (!policy.canReadUser(actorRecord, { isSystemAdmin: isAdmin, isSelf })) {
      throw new Error("Forbidden: Insufficient permissions to read user profile");
    }
    const targetUser = await store.getUser(params.targetUid);
    if (!targetUser) return null;
    const filteredAttributes = policy.filterReadableAttributes<TAttributes>(actorRecord, targetUser.attributes, {
      isSystemAdmin: isAdmin,
      isSelf
    });
    return {
      ...targetUser,
      ...(targetUser.attributes !== undefined ? { attributes: filteredAttributes } : {})
    };
  }

  /**
   * Lists all global `UserRecord` documents (`usersCollection`) after verifying the caller (`actorUid`)
   * holds the `read` capability in `userCapabilities` or is an active system admin.
   * Automatically filters each user's `attributes` to only keys readable by `actorUid`.
   */
  async function listUsers(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>[]> {
    assertValidResourceId(params.actorUid, "actorUid");
    if (typeof store.listUsers !== "function") {
      throw new Error("Backing store does not implement listUsers");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    if (!policy.canReadUser(actorRecord, { isSystemAdmin: isAdmin, isSelf: false })) {
      throw new Error("Forbidden: Insufficient permissions to list users");
    }
    const allUsers = await store.listUsers();
    return allUsers.map((u) => {
      const isSelf = u.uid === params.actorUid;
      const filteredAttributes = policy.filterReadableAttributes<TAttributes>(actorRecord, u.attributes, {
        isSystemAdmin: isAdmin,
        isSelf
      });
      return {
        ...u,
        ...(u.attributes !== undefined ? { attributes: filteredAttributes } : {})
      };
    });
  }

  /**
   * Updates a user's profile fields (`firstName`, `lastName`, `displayName`, `photoUrl`, `email`) on `users/{targetUid}`
   * after verifying the caller (`actorUid`) is the user themselves, holds the `write` capability in `userCapabilities`,
   * or is an active system admin. Also syncs `displayName` to Firebase Auth when `adminAuth.updateUser` is available.
   */
  async function updateUserProfile(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    patch: UserProfilePatch;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getUser !== "function" || typeof store.upsertUser !== "function") {
      throw new Error("Backing store does not implement getUser / upsertUser");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    const isSelf = params.actorUid === params.targetUid;
    if (!isSelf && !policy.canWriteUser(actorRecord, isAdmin)) {
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

  /**
   * Replaces a user's `roles` on `users/{targetUid}` after verifying the caller (`actorUid`)
   * holds the `assignRoles` capability in `userCapabilities` or is an active system admin,
   * and that every role in `roles` is a concrete (`!abstract`) role defined in `policy.roles`.
   */
  async function updateUserRoles(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    roles: readonly TRole[];
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    assertAssignableRoles(params.roles);
    if (typeof store.getUser !== "function" || typeof store.upsertUser !== "function") {
      throw new Error("Backing store does not implement getUser / upsertUser");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    if (!policy.canAssignRoles(actorRecord, isAdmin)) {
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

  /**
   * Deletes a user's account (`users/{targetUid}`, private subdocuments, and Firebase Auth account)
   * with email-confirmation protection against accidental or swapped-UID deletion:
   * - If `actorUid === targetUid` (self-deletion), no `userCapabilities.write` capability is required.
   * - If `actorUid !== targetUid` (deleting another user), `actorUid` must hold the `write` capability in
   *   `userCapabilities` (or be `isSystemAdmin`), and non-system administrators cannot delete a `systemAdmin`.
   * - In all cases, `confirmTargetEmail` must match `targetUid`'s stored email address case-insensitively,
   *   preventing accidental deletion if `actorUid` and `targetUid` are ever swapped.
   */
  async function deleteUser(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    confirmTargetEmail: string;
  }): Promise<void> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getUser !== "function" || typeof store.deleteUser !== "function") {
      throw new Error("Backing store does not implement getUser / deleteUser");
    }
    const cleanConfirmEmail = (params.confirmTargetEmail || "").toLowerCase().trim();
    if (!cleanConfirmEmail) {
      throw new Error("confirmTargetEmail is required to delete user");
    }

    const isSelf = params.actorUid === params.targetUid;
    let isAdmin = false;
    if (!isSelf) {
      const resolved = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
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
  }

  async function upsertScopeMemberByEmail(params: {
    scopeId: string;
    email: string;
    firstName?: string;
    lastName?: string;
    roles: readonly TRole[];
    scopeName?: string;
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertAssignableRoles(params.roles);
    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    const existing = await store.getScopeMember(params.scopeId, uid);
    const member: ScopedMember<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || {}),
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim() ?? existing?.firstName,
      lastName: params.lastName?.trim() ?? existing?.lastName,
      roles: Array.from(new Set(params.roles)),
      scopeId: params.scopeId,
      scopeName: params.scopeName ?? existing?.scopeName,
      ...(params.preferences ? { preferences: { ...(existing?.preferences || {}), ...params.preferences } } : {}),
      ...(params.attributes ? { attributes: { ...(existing?.attributes || {}), ...params.attributes } } : {})
    };

    await store.upsertScopeMember(params.scopeId, member);
    return member;
  }

  async function grantScopeRolesByEmail(params: {
    scopeId: string;
    email: string;
    roles: readonly TRole[];
    firstName?: string;
    lastName?: string;
    scopeName?: string;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertAssignableRoles(params.roles);
    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    return store.grantScopeRoles(params.scopeId, uid, params.roles, {
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim(),
      lastName: params.lastName?.trim(),
      scopeId: params.scopeId,
      scopeName: params.scopeName
    });
  }

  async function revokeScopeRoles(scopeId: string, uid: string, roles: readonly TRole[]): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    await store.revokeScopeRoles(scopeId, uid, roles);
  }

  // --- Capability-Gated Attributes & Secrets Operations ---

  /**
   * Reads a user's global `attributes`, filtering out any keys the caller (`actorUid`) is not permitted to read.
   * Global user operations NEVER consult tenant-scoped roles—only the caller's global `users/{actorUid}` record
   * or `isSystemAdmin` status is evaluated.
   */
  async function readUserAttributes(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
  }): Promise<Partial<TAttributes>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getUser !== "function") {
      throw new Error("Backing store does not implement getUser");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    const targetUser = await store.getUser(params.targetUid);
    return policy.filterReadableAttributes<TAttributes>(actorRecord, targetUser?.attributes, {
      isSystemAdmin: isAdmin,
      isSelf: params.actorUid === params.targetUid
    });
  }

  /**
   * Updates a user's global `attributes` on `users/{targetUid}` after verifying the caller (`actorUid`)
   * holds the required write capability for every key in `patch` (or is an active system admin).
   * Self-ownership (`actorUid === targetUid`) and tenant-scoped roles NEVER grant write access to global `attributes`.
   */
  async function updateUserAttributes(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    patch: Partial<TAttributes>;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.updateUserAttributes !== "function") {
      throw new Error("Backing store does not implement updateUserAttributes");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    if (!policy.canWriteAttributesPatch(actorRecord, params.patch as Record<string, any>, isAdmin)) {
      throw new Error("Forbidden: Insufficient permissions to update the requested user attributes");
    }
    return store.updateUserAttributes(params.targetUid, params.patch);
  }

  /**
   * Reads a user's global `hiddenAttributes` (`users/{targetUid}/private/hiddenAttributes`), returning only keys
   * the caller (`actorUid`) holds the required `read` capability for (or all keys if `isSystemAdmin`).
   * Self-ownership (`actorUid === targetUid`) never grants read access to `hiddenAttributes`.
   * Throws `Forbidden` if a non-admin caller has no readable hiddenAttribute keys and no read capability.
   */
  async function readUserHiddenAttributes(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
  }): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getUserHiddenAttributes !== "function") {
      throw new Error("Backing store does not implement getUserHiddenAttributes");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    const rawHiddenAttributes = await store.getUserHiddenAttributes(params.targetUid);
    const filtered = policy.filterReadableHiddenAttributes<THiddenAttributes>(
      actorRecord,
      rawHiddenAttributes,
      isAdmin
    );
    if (!isAdmin && Object.keys(rawHiddenAttributes).length > 0 && Object.keys(filtered).length === 0) {
      throw new Error("Forbidden: Insufficient permissions to read user hiddenAttributes");
    }
    return filtered;
  }

  /**
   * Updates a user's global `hiddenAttributes` (`users/{targetUid}/private/hiddenAttributes`) after verifying
   * the caller (`actorUid`) holds the required `write` capability for every key in `patch` (or is an active system admin).
   */
  async function updateUserHiddenAttributes(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    patch: Partial<THiddenAttributes>;
  }): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.updateUserHiddenAttributes !== "function") {
      throw new Error("Backing store does not implement updateUserHiddenAttributes");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    if (!policy.canWriteHiddenAttributesPatch(actorRecord, params.patch as Record<string, any>, isAdmin)) {
      throw new Error("Forbidden: Insufficient permissions to update the requested user hiddenAttributes");
    }
    return store.updateUserHiddenAttributes(params.targetUid, params.patch);
  }

  /**
   * Reads a scoped member's `attributes` within `scopeId`, filtering out any keys the caller (`actorUid`)
   * is not permitted to read in that exact `scopeId` (or returning all keys if `isSystemAdmin`).
   */
  async function readScopeMemberAttributes(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
  }): Promise<Partial<TAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const targetMember = await store.getScopeMember(params.scopeId, params.targetUid);
    return policy.filterReadableAttributes<TAttributes>(actorMember, targetMember?.attributes, {
      isSystemAdmin: isAdmin,
      isSelf: Boolean(actorMember && params.actorUid === params.targetUid)
    });
  }

  /**
   * Updates a scoped member's `attributes` within `scopeId` after verifying the caller (`actorUid`)
   * holds the required write capability **within that exact `scopeId`** (or is an active system admin).
   * Roles in other scopes grant zero privileges in `scopeId`.
   */
  async function updateScopeMemberAttributes(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    patch: Partial<TAttributes>;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.updateScopeMemberAttributes !== "function") {
      throw new Error("Backing store does not implement updateScopeMemberAttributes");
    }
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
    if (!policy.canWriteAttributesPatch(actorMember, params.patch as Record<string, any>, isAdmin)) {
      throw new Error(`Forbidden: Insufficient permissions to update member attributes in scope '${params.scopeId}'`);
    }
    return store.updateScopeMemberAttributes(params.scopeId, params.targetUid, params.patch);
  }

  /**
   * Reads a scoped member's `hiddenAttributes` within `scopeId`, strictly checking the caller's membership
   * in `scopeId` (or active system admin status). Self-ownership (`actorUid === targetUid`) never grants read access.
   */
  async function readScopeMemberHiddenAttributes(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
  }): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getScopeMemberHiddenAttributes !== "function") {
      throw new Error("Backing store does not implement getScopeMemberHiddenAttributes");
    }
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
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
   * Updates a scoped member's `hiddenAttributes` within `scopeId`, strictly checking the caller's membership
   * and capabilities in `scopeId` (or active system admin status).
   */
  async function updateScopeMemberHiddenAttributes(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    patch: Partial<THiddenAttributes>;
  }): Promise<Partial<THiddenAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.updateScopeMemberHiddenAttributes !== "function") {
      throw new Error("Backing store does not implement updateScopeMemberHiddenAttributes");
    }
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
    if (!policy.canWriteHiddenAttributesPatch(actorMember, params.patch as Record<string, any>, isAdmin)) {
      throw new Error(
        `Forbidden: Insufficient permissions to update member hiddenAttributes in scope '${params.scopeId}'`
      );
    }
    return store.updateScopeMemberHiddenAttributes(params.scopeId, params.targetUid, params.patch);
  }

  // --- Write-Only Encrypted Secrets Operations ---

  /**
   * Returns a boolean status map (`{ [key]: boolean }`) indicating which secrets are configured
   * on `users/{targetUid}/private/secrets` without ever exposing or decrypting secret values.
   * Allowed for the user themselves (`actorUid === targetUid`), any actor who can write at least one
   * secret key in the status map, or an active system admin.
   */
  async function getUserSecretsStatus(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getUserSecretsStatus !== "function") {
      throw new Error("Backing store does not implement getUserSecretsStatus");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    const isSelf = params.actorUid === params.targetUid;
    const rawStatus = await store.getUserSecretsStatus(params.targetUid);
    if (isAdmin || isSelf) {
      return rawStatus;
    }
    const filtered: Partial<Record<keyof TSecrets & string, boolean>> = {};
    for (const [key, isConfigured] of Object.entries(rawStatus)) {
      if (policy.canWriteSecret(actorRecord, key, { isSystemAdmin: isAdmin, isSelf })) {
        filtered[key as keyof TSecrets & string] = Boolean(isConfigured);
      }
    }
    if (Object.keys(rawStatus).length > 0 && Object.keys(filtered).length === 0) {
      throw new Error("Forbidden: Insufficient permissions to inspect user secrets status");
    }
    return filtered;
  }

  /**
   * Encrypts and writes (or clears when `""` or `null` is passed) user secrets on
   * `users/{targetUid}/private/secrets`. Returns the updated boolean status map (`{ [key]: boolean }`)
   * and NEVER returns plaintext or ciphertext values.
   */
  async function updateUserSecrets(params: {
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    patch: Partial<Record<keyof TSecrets & string, string | null | undefined>>;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.updateUserSecrets !== "function") {
      throw new Error("Backing store does not implement updateUserSecrets");
    }
    const { isAdmin, userRecord: actorRecord } = await resolveEffectiveAdminStatus(
      params.actorUid,
      Boolean(params.isSystemAdmin)
    );
    const isSelf = params.actorUid === params.targetUid;
    if (
      !policy.canWriteSecretsPatch(actorRecord, params.patch as Record<string, any>, { isSystemAdmin: isAdmin, isSelf })
    ) {
      throw new Error("Forbidden: Insufficient permissions to update the requested user secrets");
    }
    return store.updateUserSecrets(params.targetUid, params.patch);
  }

  /**
   * Server-only helper that decrypts and returns plaintext secrets from `users/{uid}/private/secrets`
   * for backend services making external API calls (e.g. BYOK AI keys or OAuth tokens).
   * Never expose the return value of this method in client HTTP responses.
   */
  async function getDecryptedUserSecrets(uid: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    assertValidResourceId(uid, "uid");
    if (typeof store.getUserSecrets !== "function") {
      throw new Error("Backing store does not implement getUserSecrets");
    }
    return store.getUserSecrets(uid);
  }

  /**
   * Returns a boolean status map (`{ [key]: boolean }`) indicating which secrets are configured
   * on `{scopeCollection}/{scopeId}/{membersSubcollection}/{targetUid}/private/secrets`.
   */
  async function getScopeMemberSecretsStatus(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.getScopeMemberSecretsStatus !== "function") {
      throw new Error("Backing store does not implement getScopeMemberSecretsStatus");
    }
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const isSelf = Boolean(actorMember && params.actorUid === params.targetUid);
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
   * Encrypts and writes (or clears when `""` or `null` is passed) scoped member secrets on
   * `{scopeCollection}/{scopeId}/{membersSubcollection}/{targetUid}/private/secrets`.
   * Returns the updated boolean status map (`{ [key]: boolean }`).
   */
  async function updateScopeMemberSecrets(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
    targetUid: string;
    patch: Partial<Record<keyof TSecrets & string, string | null | undefined>>;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    assertValidResourceId(params.targetUid, "targetUid");
    if (typeof store.updateScopeMemberSecrets !== "function") {
      throw new Error("Backing store does not implement updateScopeMemberSecrets");
    }
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
    const isSelf = Boolean(actorMember && params.actorUid === params.targetUid);
    if (
      !policy.canWriteSecretsPatch(actorMember, params.patch as Record<string, any>, { isSystemAdmin: isAdmin, isSelf })
    ) {
      throw new Error(`Forbidden: Insufficient permissions to update member secrets in scope '${params.scopeId}'`);
    }
    return store.updateScopeMemberSecrets(params.scopeId, params.targetUid, params.patch);
  }

  /**
   * Server-only helper that decrypts and returns plaintext secrets from
   * `{scopeCollection}/{scopeId}/{membersSubcollection}/{uid}/private/secrets`.
   * Never expose the return value of this method in client HTTP responses.
   */
  async function getDecryptedScopeMemberSecrets(
    scopeId: string,
    uid: string
  ): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    if (typeof store.getScopeMemberSecrets !== "function") {
      throw new Error("Backing store does not implement getScopeMemberSecrets");
    }
    return store.getScopeMemberSecrets(scopeId, uid);
  }

  /**
   * Returns a boolean status map (`{ [key]: boolean }`) indicating which scope-level secrets are configured
   * on `{scopeCollection}/{scopeId}/private/secrets` (e.g. BYOK workspace API keys).
   * Allowed for any member of `scopeId` or an active system admin.
   */
  async function getScopeSecretsStatus(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    if (typeof store.getScopeSecretsStatus !== "function") {
      throw new Error("Backing store does not implement getScopeSecretsStatus");
    }
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    return store.getScopeSecretsStatus(params.scopeId);
  }

  /**
   * Encrypts and writes (or clears when `""` or `null` is passed) scope-level secrets on
   * `{scopeCollection}/{scopeId}/private/secrets` (e.g. BYOK workspace API keys).
   * Requires the caller to hold the configured `write` capability in `secretCapabilities` within `scopeId`
   * (or be an active system admin). Note: `isSelf` is always `false` for shared scope-level secrets.
   */
  async function updateScopeSecrets(params: {
    scopeId: string;
    actorUid: string;
    isSystemAdmin?: boolean;
    patch: Partial<Record<keyof TSecrets & string, string | null | undefined>>;
  }): Promise<Partial<Record<keyof TSecrets & string, boolean>>> {
    assertValidResourceId(params.scopeId, "scopeId");
    assertValidResourceId(params.actorUid, "actorUid");
    if (typeof store.updateScopeSecrets !== "function") {
      throw new Error("Backing store does not implement updateScopeSecrets");
    }
    const { isAdmin } = await resolveEffectiveAdminStatus(params.actorUid, Boolean(params.isSystemAdmin));
    const actorMember = await store.getScopeMember(params.scopeId, params.actorUid);
    if (
      !policy.canWriteSecretsPatch(actorMember, params.patch as Record<string, any>, {
        isSystemAdmin: isAdmin,
        isSelf: false
      })
    ) {
      throw new Error(`Forbidden: Insufficient permissions to update secrets in scope '${params.scopeId}'`);
    }
    return store.updateScopeSecrets(params.scopeId, params.patch);
  }

  /**
   * Server-only helper that decrypts and returns plaintext scope-level secrets from
   * `{scopeCollection}/{scopeId}/private/secrets`.
   * Never expose the return value of this method in client HTTP responses.
   */
  async function getDecryptedScopeSecrets(scopeId: string): Promise<Partial<Record<keyof TSecrets & string, string>>> {
    assertValidResourceId(scopeId, "scopeId");
    if (typeof store.getScopeSecrets !== "function") {
      throw new Error("Backing store does not implement getScopeSecrets");
    }
    return store.getScopeSecrets(scopeId);
  }

  return {
    authService,
    checkAuth,
    requireAdmin,
    requireUserRole,
    requireUserCapability,
    requireScopeRole,
    requireScopeCapability,
    getOrProvisionUidByEmail,
    setSystemAdminStatus,
    upsertUserByEmail,
    grantUserRolesByEmail,
    revokeUserRoles,
    getUser,
    listUsers,
    updateUserProfile,
    updateUserRoles,
    deleteUser,
    upsertScopeMemberByEmail,
    grantScopeRolesByEmail,
    revokeScopeRoles,
    readUserAttributes,
    updateUserAttributes,
    readUserHiddenAttributes,
    updateUserHiddenAttributes,
    readScopeMemberAttributes,
    updateScopeMemberAttributes,
    readScopeMemberHiddenAttributes,
    updateScopeMemberHiddenAttributes,
    getUserSecretsStatus,
    updateUserSecrets,
    getDecryptedUserSecrets,
    getScopeMemberSecretsStatus,
    updateScopeMemberSecrets,
    getDecryptedScopeMemberSecrets,
    getScopeSecretsStatus,
    updateScopeSecrets,
    getDecryptedScopeSecrets
  };
}

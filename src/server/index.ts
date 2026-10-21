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
}

const SAFE_AUTH_ERROR_PREFIXES = [
  "Token must contain an email claim",
  "Token email must be verified",
  "Missing Authorization header",
  "Invalid x-mock-user-uid",
  "SECURITY VIOLATION:"
];

function formatClientAuthError(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (message && SAFE_AUTH_ERROR_PREFIXES.some((prefix) => message.startsWith(prefix))) {
    return `Unauthorized: ${message}`;
  }
  return "Unauthorized: Invalid or expired authentication token";
}

/**
 * Ensures mock/emulator authentication services can never be instantiated or invoked in production.
 */
export function assertNotProduction(featureName: string): void {
  const isCloudRunOrFunctions =
    Boolean(process.env.K_SERVICE) ||
    Boolean(process.env.FUNCTION_TARGET) ||
    (Boolean(process.env.FIREBASE_CONFIG) && !process.env.FIREBASE_AUTH_EMULATOR_HOST);
  const isProdEnv = process.env.NODE_ENV === "production" || isCloudRunOrFunctions;

  if (isProdEnv) {
    throw new Error(`SECURITY VIOLATION: ${featureName} cannot be used in a production environment.`);
  }
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

export class FakeAuthService implements AuthService {
  private readonly fallbackAuth?: GoogleAuthService;

  constructor(adminAuth?: Pick<AdminAuthAdapter, "verifyIdToken">, requireVerifiedEmail = true) {
    assertNotProduction("FakeAuthService");
    if (adminAuth) {
      this.fallbackAuth = new GoogleAuthService(adminAuth, requireVerifiedEmail);
    }
  }

  async verifyToken(
    authHeader: string | undefined,
    headers: Record<string, any> = {}
  ): Promise<AuthenticatedUser | null> {
    assertNotProduction("FakeAuthService");
    const mockEmail = headers["x-mock-user-email"];
    if (mockEmail) {
      if (!authHeader || !authHeader.startsWith("Bearer ") || !authHeader.slice("Bearer ".length).trim()) {
        throw new Error("Missing Authorization header (required to prevent production authentication bypass)");
      }
      const emailStr = String(mockEmail).trim().toLowerCase();
      const mockUid = headers["x-mock-user-uid"] ? String(headers["x-mock-user-uid"]).trim() : `mock-uid-${emailStr}`;
      assertValidResourceId(mockUid, "x-mock-user-uid");

      return {
        uid: mockUid,
        email: emailStr,
        emailVerified: true,
        name: (headers["x-mock-user-name"] as string) || "Mock User",
        photoUrl: sanitizeAvatarUrl(headers["x-mock-user-photo-url"] as string),
        isAdmin: headers["x-mock-user-admin"] === "true"
      };
    }
    if (this.fallbackAuth) {
      return this.fallbackAuth.verifyToken(authHeader);
    }
    return null;
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

  /**
   * Single-tenant role middleware: verifies the authenticated user's global `users/{uid}` record
   * meets or exceeds `minimumRole` (via `inherits` or `weight`), or is an active system admin.
   */
  function requireUserRole(minimumRole: TRole) {
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

        if (!policy.hasMinimumRole(userRecord, minimumRole, isAdmin)) {
          return res.status(403).json({
            error: `Forbidden: Requires at least '${minimumRole}' role`
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

  function requireScopeRole(minimumRole: TRole, scopeParamName = defaultScopeParam) {
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

        if (!policy.hasMinimumRole(member, minimumRole, isAdmin)) {
          return res.status(403).json({
            error: `Forbidden: Requires at least '${minimumRole}' role in scope '${scopeId}'`
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
    role?: TRole;
    capabilities?: TCapability[];
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    if (params.role !== undefined && (typeof params.role !== "string" || !Object.hasOwn(policy.roles, params.role))) {
      throw new Error(`Invalid role '${String(params.role)}': role is not defined in policy.roles`);
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
    const record: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
      ...(existing || {}),
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim() ?? existing?.firstName,
      lastName: params.lastName?.trim() ?? existing?.lastName,
      displayName: params.firstName || params.lastName ? displayName : existing?.displayName || displayName,
      role: params.role ?? existing?.role ?? policy.defaultRole,
      capabilities: Array.from(new Set(params.capabilities ?? existing?.capabilities ?? [])),
      ...(params.preferences ? { preferences: { ...(existing?.preferences || {}), ...params.preferences } } : {}),
      ...(params.attributes ? { attributes: { ...(existing?.attributes || {}), ...params.attributes } } : {}),
      createdAt: existing?.createdAt || now,
      updatedAt: now
    };

    await store.upsertUser(record);
    return (await store.getUser(uid))!;
  }

  async function grantUserCapabilitiesByEmail(params: {
    email: string;
    capabilities: readonly TCapability[];
    firstName?: string;
    lastName?: string;
    role?: TRole;
  }): Promise<UserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    const targetRole = params.role ?? policy.defaultRole;
    if (typeof targetRole !== "string" || !Object.hasOwn(policy.roles, targetRole)) {
      throw new Error(`Invalid role '${String(targetRole)}': role is not defined in policy.roles`);
    }
    if (typeof store.grantUserCapabilities !== "function") {
      throw new Error("Backing store does not implement grantUserCapabilities");
    }
    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    return store.grantUserCapabilities(uid, params.capabilities, {
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim(),
      lastName: params.lastName?.trim(),
      displayName,
      role: targetRole
    });
  }

  async function revokeUserCapabilities(uid: string, capabilities: readonly TCapability[]): Promise<void> {
    assertValidResourceId(uid, "uid");
    if (typeof store.revokeUserCapabilities !== "function") {
      throw new Error("Backing store does not implement revokeUserCapabilities");
    }
    await store.revokeUserCapabilities(uid, capabilities);
  }

  async function upsertScopeMemberByEmail(params: {
    scopeId: string;
    email: string;
    firstName?: string;
    lastName?: string;
    role: TRole;
    capabilities?: TCapability[];
    scopeName?: string;
    preferences?: Partial<TPreferences>;
    attributes?: Partial<TAttributes>;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    if (typeof params.role !== "string" || !Object.hasOwn(policy.roles, params.role)) {
      throw new Error(`Invalid role '${String(params.role)}': role is not defined in policy.roles`);
    }
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
      role: params.role,
      capabilities: Array.from(new Set(params.capabilities ?? existing?.capabilities ?? [])),
      scopeId: params.scopeId,
      scopeName: params.scopeName ?? existing?.scopeName,
      ...(params.preferences ? { preferences: { ...(existing?.preferences || {}), ...params.preferences } } : {}),
      ...(params.attributes ? { attributes: { ...(existing?.attributes || {}), ...params.attributes } } : {})
    };

    await store.upsertScopeMember(params.scopeId, member);
    return member;
  }

  async function grantScopeCapabilitiesByEmail(params: {
    scopeId: string;
    email: string;
    capabilities: readonly TCapability[];
    firstName?: string;
    lastName?: string;
    role?: TRole;
    scopeName?: string;
  }): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    assertValidResourceId(params.scopeId, "scopeId");
    const targetRole = params.role ?? policy.defaultRole;
    if (typeof targetRole !== "string" || !Object.hasOwn(policy.roles, targetRole)) {
      throw new Error(`Invalid role '${String(targetRole)}': role is not defined in policy.roles`);
    }
    const displayName =
      [params.firstName?.trim(), params.lastName?.trim()].filter(Boolean).join(" ") || params.email.trim();
    const { uid, email: cleanEmail } = await getOrProvisionUidByEmail({
      email: params.email,
      displayName
    });

    return store.grantScopeCapabilities(params.scopeId, uid, params.capabilities, {
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim(),
      lastName: params.lastName?.trim(),
      role: targetRole,
      scopeId: params.scopeId,
      scopeName: params.scopeName
    });
  }

  async function revokeScopeCapabilities(
    scopeId: string,
    uid: string,
    capabilities: readonly TCapability[]
  ): Promise<void> {
    assertValidResourceId(scopeId, "scopeId");
    assertValidResourceId(uid, "uid");
    await store.revokeScopeCapabilities(scopeId, uid, capabilities);
  }

  // --- Capability-Gated Attributes & Secrets Operations ---

  /**
   * Reads a user's global `attributes`, filtering out any keys the caller (`actorUid`) is not permitted to read.
   * Global user operations NEVER consult tenant-scoped roles—only the caller's global `users/{actorUid}` record
   * or `isSystemAdmin` status is evaluated.
   */
  async function readUserAttributesAs(params: {
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
  async function updateUserAttributesAs(params: {
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
  async function readUserHiddenAttributesAs(params: {
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
  async function updateUserHiddenAttributesAs(params: {
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
  async function readScopeMemberAttributesAs(params: {
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
  async function updateScopeMemberAttributesAs(params: {
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
  async function readScopeMemberHiddenAttributesAs(params: {
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
  async function updateScopeMemberHiddenAttributesAs(params: {
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
  async function getUserSecretsStatusAs(params: {
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
  async function updateUserSecretsAs(params: {
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
  async function getScopeMemberSecretsStatusAs(params: {
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
  async function updateScopeMemberSecretsAs(params: {
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
  async function getScopeSecretsStatusAs(params: {
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
  async function updateScopeSecretsAs(params: {
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
    grantUserCapabilitiesByEmail,
    revokeUserCapabilities,
    upsertScopeMemberByEmail,
    grantScopeCapabilitiesByEmail,
    revokeScopeCapabilities,
    readUserAttributesAs,
    updateUserAttributesAs,
    readUserHiddenAttributesAs,
    updateUserHiddenAttributesAs,
    readScopeMemberAttributesAs,
    updateScopeMemberAttributesAs,
    readScopeMemberHiddenAttributesAs,
    updateScopeMemberHiddenAttributesAs,
    getUserSecretsStatusAs,
    updateUserSecretsAs,
    getDecryptedUserSecrets,
    getScopeMemberSecretsStatusAs,
    updateScopeMemberSecretsAs,
    getDecryptedScopeMemberSecrets,
    getScopeSecretsStatusAs,
    updateScopeSecretsAs,
    getDecryptedScopeSecrets
  };
}

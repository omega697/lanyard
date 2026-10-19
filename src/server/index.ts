import type { NextFunction, Request, Response } from "express";
import {
  assertValidResourceId,
  isValidEmail,
  isValidResourceId,
  sanitizeAvatarUrl,
  type LanyardServerStore,
  type PermissionPolicy,
  type ScopedMember,
  type SystemAdminProfile
} from "../core/index.js";

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
  TCapability extends string = string
> extends Request {
  user?: AuthenticatedUser;
  scopeMember?: ScopedMember<TRole, TCapability> | null;
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

export interface LanyardServerConfig<TRole extends string = string, TCapability extends string = string> {
  /** Firebase Admin Auth instance (or lightweight `AdminAuthAdapter` test double). */
  adminAuth: AdminAuthAdapter;
  /** Backing storage adapter implementing `LanyardServerStore` (e.g. `FirestoreServerStore` or `InMemoryLanyardStore`). */
  store: LanyardServerStore<TRole, TCapability>;
  /** Application permission policy defining role hierarchy weights and role-implied capabilities. */
  policy: PermissionPolicy<TRole, TCapability>;
  /** Optional override for token verification (defaults to `new GoogleAuthService(adminAuth)`). */
  authService?: AuthService;
  /** Default Express route parameter name for the tenant/scope ID (defaults to `"scopeId"`). */
  defaultScopeParam?: string;
}

/**
 * Creates a storage-agnostic Lanyard server instance providing Express authentication/authorization
 * middleware (`checkAuth`, `requireAdmin`, `requireScopeRole`, `requireScopeCapability`) and
 * deterministic UID & capability provisioning helpers.
 */
export function createLanyardServer<TRole extends string = string, TCapability extends string = string>(
  config: LanyardServerConfig<TRole, TCapability>
) {
  const {
    adminAuth,
    store,
    policy,
    authService = new GoogleAuthService(adminAuth),
    defaultScopeParam = "scopeId"
  } = config;

  // --- Express Middleware ---

  async function checkAuth(req: AuthenticatedRequest<TRole, TCapability>, res: Response, next: NextFunction) {
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

  async function requireAdmin(req: AuthenticatedRequest<TRole, TCapability>, res: Response, next: NextFunction) {
    if (!req.user || !req.user.isAdmin) {
      return res.status(403).json({ error: "Forbidden: Administrative access required" });
    }

    // Auto-seed logged-in admin or sync updated photoUrl to the backing store
    try {
      const existing = await store.getSystemAdmin(req.user.uid);
      if (!existing) {
        await store.upsertSystemAdmin({
          uid: req.user.uid,
          email: req.user.email.toLowerCase().trim(),
          displayName: req.user.name || req.user.email,
          photoUrl: req.user.photoUrl || null,
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
      // Non-fatal auto-seed error
    }

    next();
  }

  function requireScopeRole(minimumRole: TRole, scopeParamName = defaultScopeParam) {
    return async (req: AuthenticatedRequest<TRole, TCapability>, res: Response, next: NextFunction) => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
      }

      const scopeId = req.params[scopeParamName];
      if (!scopeId || !isValidResourceId(scopeId)) {
        return res.status(400).json({ error: `Missing or invalid scope parameter '${scopeParamName}'` });
      }

      try {
        const member = await store.getScopeMember(scopeId, req.user.uid);
        req.scopeMember = member;

        if (!policy.hasMinimumRole(member, minimumRole, Boolean(req.user.isAdmin))) {
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

    return async (req: AuthenticatedRequest<TRole, TCapability>, res: Response, next: NextFunction) => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
      }

      const scopeId = req.params[scopeParamName];
      if (!scopeId || !isValidResourceId(scopeId)) {
        return res.status(400).json({ error: `Missing or invalid scope parameter '${scopeParamName}'` });
      }

      try {
        const member = await store.getScopeMember(scopeId, req.user.uid);
        req.scopeMember = member;

        const isAllowed =
          requiredList.length === 1
            ? policy.hasCapability(member, requiredList[0], Boolean(req.user.isAdmin))
            : policy.hasAnyCapability(member, requiredList, Boolean(req.user.isAdmin));

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
      const existing = await store.getSystemAdmin(uid);
      const now = new Date().toISOString();
      const profile: SystemAdminProfile = {
        ...(existing || {}),
        uid,
        email: cleanEmail,
        firstName: firstName.trim() || existing?.firstName,
        lastName: lastName.trim() || existing?.lastName,
        displayName,
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

  async function upsertScopeMemberByEmail(params: {
    scopeId: string;
    email: string;
    firstName?: string;
    lastName?: string;
    role: TRole;
    capabilities?: TCapability[];
    scopeName?: string;
  }): Promise<ScopedMember<TRole, TCapability>> {
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
    const member: ScopedMember<TRole, TCapability> = {
      ...(existing || {}),
      uid,
      email: cleanEmail,
      firstName: params.firstName?.trim() ?? existing?.firstName,
      lastName: params.lastName?.trim() ?? existing?.lastName,
      role: params.role,
      capabilities: Array.from(new Set(params.capabilities ?? existing?.capabilities ?? [])),
      scopeId: params.scopeId,
      scopeName: params.scopeName ?? existing?.scopeName
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
  }): Promise<ScopedMember<TRole, TCapability>> {
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

  return {
    authService,
    checkAuth,
    requireAdmin,
    requireScopeRole,
    requireScopeCapability,
    getOrProvisionUidByEmail,
    setSystemAdminStatus,
    upsertScopeMemberByEmail,
    grantScopeCapabilitiesByEmail,
    revokeScopeCapabilities
  };
}

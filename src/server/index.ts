import type { NextFunction, Request, Response } from "express";
import {
  EMAIL_NOT_VERIFIED_ERROR_CODE,
  EmailNotVerifiedError,
  GLOBAL_SCOPE,
  REVOCATION_CLOCK_SKEW_MS,
  SESSION_REVOKED_ERROR_CODE,
  TOKEN_STALE_ERROR_CODE,
  assertNoEmailInProfilePatch,
  assertValidResourceId,
  createPermissionPolicy,
  isValidEmail,
  isValidResourceId,
  sanitizeAvatarUrl,
  type GlobalScope,
  type LanyardActor,
  type LanyardServerStore,
  type PermissionPolicy,
  type PolicySubject,
  type ScopeId,
  type ScopedMember,
  type SystemAdminProfile,
  type StoredProfileFieldsPatch,
  type UserProfilePatch,
  type UserRecord,
  type VerifiedEmailChangeEvent
} from "../core/index.js";
import {
  assertStoreMatchesPolicyPlacement,
  assertStoreMatchesPolicySecretKeys,
  resolveAttributeQueryLocation
} from "../core/tierDocs.js";

export {
  EMAIL_NOT_VERIFIED_ERROR_CODE,
  GLOBAL_SCOPE,
  REVOCATION_CLOCK_SKEW_MS,
  SESSION_REVOKED_ERROR_CODE,
  TOKEN_STALE_ERROR_CODE,
  type GlobalScope,
  type LanyardActor,
  type ScopeId,
  type VerifiedEmailChangeEvent
};
export * from "./encryption.js";

/**
 * The request's user, produced only by `checkAuth` after it verified the token and its freshness (revocation checks).
 * `isAdmin` is the effective admin status: the token's admin claim, kept current by those checks.
 */
export interface AuthenticatedUser {
  uid: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  photoUrl?: string | null;
  isAdmin: boolean;
}

/**
 * What an `AuthService` reports about a signature-verified ID token. It is not freshness-checked: `adminClaim` may be
 * stale (a demoted or signed-out admin's token still says `true` until it expires), so never authorize on it directly;
 * `checkAuth` turns it into `AuthenticatedUser.isAdmin` after the revocation checks.
 */
export interface VerifiedToken {
  uid: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  photoUrl?: string | null;
  /** The token's raw `admin` custom claim (signature-checked, not revocation-checked). */
  adminClaim: boolean;
  /** When the token was issued (`iat`, seconds); tokens issued before the revocation epoch are rejected. */
  issuedAtSeconds: number;
  /** When the user signed in (`auth_time`, seconds), which refreshed tokens keep; checked against session revocations. */
  authTimeSeconds: number;
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
  verifyToken(authHeader: string | undefined, headers?: Record<string, any>): Promise<VerifiedToken | null>;
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
  getUserByEmail(email: string): Promise<{
    uid: string;
    email?: string;
    emailVerified?: boolean;
    displayName?: string;
    customClaims?: Record<string, any>;
  }>;
  createUser(properties: { email: string; displayName?: string; emailVerified?: boolean }): Promise<{
    uid: string;
    email?: string;
    emailVerified?: boolean;
    displayName?: string;
    customClaims?: Record<string, any>;
  }>;
  setCustomUserClaims(uid: string, customUserClaims: Record<string, any> | null): Promise<void>;
  updateUser?(
    uid: string,
    properties: { displayName?: string | null; email?: string; photoURL?: string | null }
  ): Promise<any>;
  deleteUser?(uid: string): Promise<void>;
  /** Revokes the user's refresh tokens (required by `revokeUserSessions`). */
  revokeRefreshTokens?(uid: string): Promise<void>;
  /**
   * Required: reads a user's current custom claims, which decide whether hand-built actors and the targets of user
   * management are admins. Firebase Admin's `Auth` provides it.
   */
  getUser(uid: string): Promise<{ uid: string; customClaims?: Record<string, any> | null }>;
}

/**
 * Thrown by `GoogleAuthService.verifyToken` when the token's email isn't verified. `checkAuth` turns it into a 401
 * whose JSON body carries `code: EMAIL_NOT_VERIFIED_ERROR_CODE`; custom middleware can check `code` the same way.
 * Defined in `lanyard/core` so browser code can check `instanceof` too.
 */
export { EmailNotVerifiedError };

const SAFE_AUTH_ERROR_PREFIXES = ["Token must contain an email claim", "Token email must be verified"];

type LiveValueState<T> = { status: "loading" } | { status: "ready"; value: T } | { status: "error"; error: unknown };

/**
 * Keeps the latest value from a store subscription in memory. After a listener error (which ends a Firestore
 * listener) it reports the error state and resubscribes with exponential backoff, so callers fail closed until the
 * data is current again. `current(timeoutMs)` waits for the first value instead of failing during startup.
 */
function trackLiveValue<T>(
  subscribe: (onChange: (value: T) => void, onError: (error: unknown) => void) => () => void,
  initialRetryDelayMs: number
) {
  let state: LiveValueState<T> = { status: "loading" };
  let waiters: Array<() => void> = [];
  let unsubscribe: (() => void) | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let retryDelayMs = initialRetryDelayMs;
  let closed = false;

  const settle = (next: LiveValueState<T>) => {
    state = next;
    const pending = waiters;
    waiters = [];
    pending.forEach((resolve) => resolve());
  };
  const start = () => {
    if (closed) return;
    let failed = false;
    unsubscribe = subscribe(
      (value) => {
        if (failed || closed) return;
        retryDelayMs = initialRetryDelayMs;
        settle({ status: "ready", value });
      },
      (error) => {
        if (failed || closed) return;
        failed = true;
        settle({ status: "error", error });
        unsubscribe?.();
        retryTimer = setTimeout(start, retryDelayMs);
        (retryTimer as any)?.unref?.();
        retryDelayMs = Math.min(retryDelayMs * 2, 30_000);
      }
    );
    // A synchronous error inside subscribe() ran before unsubscribe was assigned
    if (failed) unsubscribe?.();
  };
  start();

  return {
    async current(timeoutMs: number): Promise<LiveValueState<T>> {
      if (state.status !== "loading") return state;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, timeoutMs);
        waiters.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
      return state;
    },
    set(value: T) {
      settle({ status: "ready", value });
    },
    close() {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      unsubscribe?.();
    }
  };
}

function formatClientAuthError(error: unknown): { error: string; code?: typeof EMAIL_NOT_VERIFIED_ERROR_CODE } {
  if (error instanceof EmailNotVerifiedError) {
    return { error: `Unauthorized: ${error.message}`, code: error.code };
  }
  const message = error instanceof Error ? error.message : "";
  if (message && SAFE_AUTH_ERROR_PREFIXES.some((prefix) => message.startsWith(prefix))) {
    return { error: `Unauthorized: ${message}` };
  }
  return { error: "Unauthorized: Invalid or expired authentication token" };
}

/**
 * The profile fields a patch changes, trimmed and sanitized. When only the first or last name changes, `displayName`
 * is recomputed from the resulting names (falling back to the current display name if both are empty).
 */
function profileFieldsToWrite(
  patch: UserProfilePatch,
  existing: { firstName?: string; lastName?: string; displayName?: string }
): StoredProfileFieldsPatch {
  const fields: StoredProfileFieldsPatch = {};
  if (typeof patch.firstName === "string") fields.firstName = patch.firstName.trim();
  if (typeof patch.lastName === "string") fields.lastName = patch.lastName.trim();
  if (typeof patch.displayName === "string") {
    fields.displayName = patch.displayName.trim();
  } else if (fields.firstName !== undefined || fields.lastName !== undefined) {
    const firstName = fields.firstName ?? existing.firstName;
    const lastName = fields.lastName ?? existing.lastName;
    const computed = [firstName, lastName].filter(Boolean).join(" ").trim();
    if (computed || existing.displayName !== undefined) fields.displayName = computed || existing.displayName;
  }
  if (patch.photoUrl !== undefined) fields.photoUrl = sanitizeAvatarUrl(patch.photoUrl);
  return fields;
}

export interface GoogleAuthServiceOptions {
  /** Reject tokens whose email isn't verified (default `true`). */
  requireVerifiedEmail?: boolean;
  /** Also ask Firebase whether the token was revoked, at the cost of a lookup per request (default `false`). */
  checkRevoked?: boolean;
}

export class GoogleAuthService implements AuthService {
  private readonly requireVerifiedEmail: boolean;
  private readonly checkRevoked: boolean;

  constructor(
    private readonly adminAuth: Pick<AdminAuthAdapter, "verifyIdToken">,
    options: GoogleAuthServiceOptions = {}
  ) {
    this.requireVerifiedEmail = options.requireVerifiedEmail ?? true;
    this.checkRevoked = options.checkRevoked ?? false;
  }

  async verifyToken(authHeader: string | undefined): Promise<VerifiedToken | null> {
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
    if (this.requireVerifiedEmail && decodedToken.email_verified !== true) {
      throw new EmailNotVerifiedError();
    }
    if (!Number.isInteger(decodedToken.iat) || !Number.isInteger(decodedToken.auth_time)) {
      throw new Error("Token must contain iat and auth_time claims");
    }
    return {
      uid: decodedToken.uid,
      email: decodedToken.email.toLowerCase().trim(),
      emailVerified: decodedToken.email_verified === true,
      name: decodedToken.name,
      photoUrl: sanitizeAvatarUrl(decodedToken.picture),
      adminClaim: decodedToken.admin === true,
      issuedAtSeconds: decodedToken.iat,
      authTimeSeconds: decodedToken.auth_time
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
  /** Optional application permission policy defining role hierarchy, inheritance, capabilities, and attribute/hiddenAttribute/secret rules. */
  policy?: PermissionPolicy<TRole, TCapability>;
  /** Optional override for token verification (defaults to `new GoogleAuthService(adminAuth)`). */
  authService?: AuthService;
  /** Default Express route parameter name for the tenant/scope ID (defaults to `"scopeId"`). */
  defaultScopeParam?: string;
  /**
   * Optional callback invoked in `checkAuth` when an authenticated user's verified token email differs from the email
   * Lanyard last stored for them (a record with no email yet is filled in without calling it). Once it resolves,
   * Lanyard stores the new email so the callback normally fires once per change. It's at-least-once: it can fire again
   * if two server instances see the change at the same moment, and it's retried on the next request if it (or saving
   * the email) fails. Only this server-side sync writes the stored email; clients never do.
   */
  onVerifiedEmailChange?: (event: VerifiedEmailChangeEvent) => void | Promise<void>;
  /**
   * How long `checkAuth` waits for the store's first revocation data before failing closed with 503, in milliseconds
   * (default 5000). Only matters right after startup.
   */
  revocationLoadTimeoutMs?: number;
  /** Delay before resubscribing after a revocation listener error, in milliseconds (default 1000, doubling to 30s). */
  revocationResubscribeDelayMs?: number;
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
    policy = createPermissionPolicy<TRole, TCapability>({}),
    authService = new GoogleAuthService(adminAuth),
    defaultScopeParam = "scopeId",
    onVerifiedEmailChange,
    revocationLoadTimeoutMs = 5000,
    revocationResubscribeDelayMs = 1000
  } = config;
  assertStoreMatchesPolicyPlacement(store, policy.cardFields);
  assertStoreMatchesPolicySecretKeys(store, policy.secretKeys);
  if (typeof adminAuth?.getUser !== "function") {
    throw new Error(
      "createLanyardServer requires adminAuth.getUser to read users' admin claims (Firebase Admin's Auth has it)"
    );
  }
  for (const method of ["patchUser", "patchScopeMember"] as const) {
    if (typeof (store as any)[method] !== "function") {
      throw new Error(
        `Lanyard server store must implement ${method}() (syncs and profile edits write only the fields they change)`
      );
    }
  }
  if (typeof (store as any).listUserMembershipScopeIds !== "function") {
    throw new Error(
      "Lanyard server store must implement listUserMembershipScopeIds() (the verified-email sync updates every membership)"
    );
  }
  for (const method of [
    "getRevocationEpoch",
    "bumpRevocationEpoch",
    "subscribeToRevocationEpoch",
    "getSessionRevocations",
    "recordSessionRevocation",
    "subscribeToSessionRevocations"
  ] as const) {
    if (typeof (store as any)[method] !== "function") {
      throw new Error(
        `Lanyard server store must implement ${method}() (required for immediate revocation); verify custom stores with lanyard/testing`
      );
    }
  }

  const revocationEpoch = trackLiveValue<number | null>(
    (onChange, onError) => store.subscribeToRevocationEpoch(onChange, onError),
    revocationResubscribeDelayMs
  );
  const sessionRevocations = trackLiveValue<Readonly<Record<string, number>>>(
    (onChange, onError) => store.subscribeToSessionRevocations(onChange, onError),
    revocationResubscribeDelayMs
  );

  /** Stops the revocation subscriptions (for tests and graceful shutdown). */
  function close(): void {
    revocationEpoch.close();
    sessionRevocations.close();
  }

  /**
   * Rejects tokens that a revocation has superseded: sessions revoked after the user signed in (`auth_time`), and
   * tokens issued (`iat`) before the revocation epoch. Fails closed when token times or revocation data are missing.
   */
  async function checkTokenFreshness(
    token: VerifiedToken
  ): Promise<{ status: number; body: { error: string; code?: string } } | null> {
    // Checked at runtime too: a custom AuthService can return anything
    const { issuedAtSeconds: iat, authTimeSeconds: authTime } = token;
    if (!Number.isInteger(iat) || !Number.isInteger(authTime)) {
      return { status: 401, body: { error: "Unauthorized: Invalid or expired authentication token" } };
    }
    const [epoch, sessions] = await Promise.all([
      revocationEpoch.current(revocationLoadTimeoutMs),
      sessionRevocations.current(revocationLoadTimeoutMs)
    ]);
    if (epoch.status !== "ready" || sessions.status !== "ready") {
      return { status: 503, body: { error: "Service unavailable: unable to verify token freshness" } };
    }
    const revokedAt = sessions.value[token.uid];
    if (revokedAt !== undefined && authTime * 1000 <= revokedAt + REVOCATION_CLOCK_SKEW_MS) {
      return {
        status: 401,
        body: { error: "Unauthorized: Session has been revoked; sign in again", code: SESSION_REVOKED_ERROR_CODE }
      };
    }
    if (epoch.value !== null && iat * 1000 <= epoch.value + REVOCATION_CLOCK_SKEW_MS) {
      return {
        status: 401,
        body: {
          error: "Unauthorized: Token was issued before a recent revocation; refresh it and retry",
          code: TOKEN_STALE_ERROR_CODE
        }
      };
    }
    return null;
  }

  // Tracks in-flight verified email change syncs per (uid -> targetEmail) so concurrent requests don't double-fire
  const inFlightEmailSyncs = new Map<string, Promise<void>>();
  // For each user, the email change (from their global email, to the verified one) whose memberships this server has
  // already updated, so while onVerifiedEmailChange keeps failing, retries go straight to the hook. Matching both ends
  // means a note left over from an earlier change (say, one another server finished) never skips a later one. One
  // entry per user, removed once their global record is updated.
  const membershipEmailsSynced = new Map<string, { from: string; to: string }>();

  // The admin status checkAuth decided for each request user it produced (verified claim plus revocation checks), keyed
  // by object identity. It's never read back from the object, so code that later sets `req.user.isAdmin` gains nothing.
  const verifiedAdminStatus = new WeakMap<object, boolean>();

  /** Whether Firebase currently gives `uid` the admin claim. Fails closed if it can't be confirmed. */
  async function firebaseClaimIsAdmin(uid: string): Promise<boolean> {
    try {
      const record = await adminAuth.getUser(uid);
      return record?.customClaims?.admin === true;
    } catch {
      return false;
    }
  }

  /**
   * Whether a *target* may be a system admin, for guards that stop non-admins from managing admins. Uses the current
   * Firebase claim (the store's directory flag isn't authoritative), and fails closed the other way from actor checks:
   * if the claim can't be read, the target is treated as an admin. A target with no Firebase account can't be one.
   */
  async function targetMayBeAdmin(uid: string): Promise<boolean> {
    try {
      const record = await adminAuth.getUser(uid);
      return record?.customClaims?.admin === true;
    } catch (error: any) {
      return error?.code !== "auth/user-not-found";
    }
  }

  /** Throws unless the actor is an admin or the target can't be one (see `targetMayBeAdmin`). */
  async function assertMayManageTarget(actorIsAdmin: boolean, targetUid: string, action: string): Promise<void> {
    if (actorIsAdmin) return;
    if (await targetMayBeAdmin(targetUid)) {
      throw new Error(`Forbidden: Non-system administrators cannot ${action} a system administrator`);
    }
  }

  /**
   * Whether an actor is a system admin. The Firebase `admin` claim is the only authority: for a `req.user` produced by
   * `checkAuth` it's the status checkAuth decided (the verified claim, kept current by the revocation checks); for any
   * other actor object it's the user's current claim from Firebase.
   */
  async function isActorAdmin(actor: LanyardActor): Promise<boolean> {
    if (!actor || typeof actor !== "object") {
      throw new Error("Invalid actor: actor object with uid is required");
    }
    assertValidResourceId(actor.uid, "actor.uid");
    const verified = verifiedAdminStatus.get(actor);
    if (verified !== undefined) return verified;
    return firebaseClaimIsAdmin(actor.uid);
  }

  /** Resolves an actor's admin status (see `isActorAdmin`) along with their global user record. */
  async function resolveEffectiveAdminStatus(actor: LanyardActor): Promise<{
    isAdmin: boolean;
    userRecord: UserRecord<TRole, TCapability, TPreferences, TAttributes> | null;
  }> {
    const isAdmin = await isActorAdmin(actor);
    const userRecord = typeof store.getUser === "function" ? await store.getUser(actor.uid) : null;
    return { isAdmin, userRecord };
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
      const token = await authService.verifyToken(req.headers.authorization, req.headers);
      if (!token) {
        return res.status(401).json({ error: "Unauthorized: Missing or invalid authentication credentials" });
      }
      const rejection = await checkTokenFreshness(token);
      if (rejection) {
        return res.status(rejection.status).json(rejection.body);
      }
      // Admin status is the verified token's claim, kept current by the revocation checks above; nothing here consults
      // or writes admin records, so a stale record or claim can't override a demotion
      const user: AuthenticatedUser = {
        uid: token.uid,
        email: token.email,
        emailVerified: token.emailVerified === true,
        ...(token.name !== undefined ? { name: token.name } : {}),
        ...(token.photoUrl !== undefined ? { photoUrl: token.photoUrl } : {}),
        isAdmin: token.adminClaim === true
      };
      try {
        const userRecord = typeof store.getUser === "function" ? await store.getUser(user.uid) : null;
        req.userRecord = userRecord;
        if (
          userRecord &&
          user.email &&
          user.emailVerified === true &&
          (userRecord.email || "").toLowerCase() !== user.email.toLowerCase()
        ) {
          const syncKey = `${user.uid}:${user.email.toLowerCase()}`;
          let syncPromise = inFlightEmailSyncs.get(syncKey);
          if (!syncPromise) {
            const previousEmail = userRecord.email || "";
            const nextEmail = user.email.toLowerCase().trim();
            syncPromise = (async () => {
              // Memberships first, then the hook, then the global record. The global email is what marks the sync as
              // done, so if anything fails the next request retries; the membership writes are idempotent, and a
              // failure among them doesn't fire the hook. Only the email is written, so a role or admin change made
              // since userRecord was read can't be undone.
              const synced = membershipEmailsSynced.get(user.uid);
              if (synced?.from !== previousEmail || synced?.to !== nextEmail) {
                const scopeIds = await store.listUserMembershipScopeIds(user.uid);
                await Promise.all(
                  scopeIds.map(async (scopeId) => {
                    try {
                      await store.patchScopeMember(scopeId, user.uid, { email: nextEmail });
                    } catch (error) {
                      // They left the scope since it was listed: nothing to update there
                      const stillMember = await store.getScopeMember(scopeId, user.uid).then(
                        (member) => member !== null,
                        () => true
                      );
                      if (stillMember) throw error;
                    }
                  })
                );
                membershipEmailsSynced.set(user.uid, { from: previousEmail, to: nextEmail });
              }
              // A record with no email yet is simply filled in: that's not a change of address
              if (previousEmail && typeof onVerifiedEmailChange === "function") {
                await onVerifiedEmailChange({
                  uid: user.uid,
                  email: nextEmail,
                  previousEmail
                });
              }
              await store.patchUser(user.uid, { email: nextEmail });
              membershipEmailsSynced.delete(user.uid);
              req.userRecord = { ...userRecord, email: nextEmail };
            })().finally(() => {
              inFlightEmailSyncs.delete(syncKey);
            });
            inFlightEmailSyncs.set(syncKey, syncPromise);
          }
          await syncPromise.catch((error: unknown) => {
            // The stored email is left as it was, so the next request retries (and calls the hook again)
            console.warn(`[lanyard] Syncing the verified email for user '${user.uid}' failed; will retry`, error);
          });
        }
      } catch {
        // If the backing store is unreachable, the caller is still authenticated, and admin status doesn't depend on it
      }
      verifiedAdminStatus.set(user, user.isAdmin);
      req.user = user;
      next();
    } catch (error: unknown) {
      res.status(401).json(formatClientAuthError(error));
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

    if (!(await isActorAdmin(req.user))) {
      req.user.isAdmin = false;
      return res.status(403).json({ error: "Forbidden: Administrative access required" });
    }
    req.user.isAdmin = true;
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

          if (userRecord && req.user.photoUrl && userRecord.photoUrl !== req.user.photoUrl) {
            req.userRecord = { ...userRecord, photoUrl: req.user.photoUrl };
            await store.patchUser(req.user.uid, { photoUrl: req.user.photoUrl });
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
          req.scopeMember = { ...member, photoUrl: req.user.photoUrl };
          await store.patchScopeMember(scopeId, req.user.uid, { photoUrl: req.user.photoUrl });
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

          if (userRecord && req.user.photoUrl && userRecord.photoUrl !== req.user.photoUrl) {
            req.userRecord = { ...userRecord, photoUrl: req.user.photoUrl };
            await store.patchUser(req.user.uid, { photoUrl: req.user.photoUrl });
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
          req.scopeMember = { ...member, photoUrl: req.user.photoUrl };
          await store.patchScopeMember(scopeId, req.user.uid, { photoUrl: req.user.photoUrl });
        }

        next();
      } catch {
        return res.status(500).json({ error: "Internal server error during capability check" });
      }
    };
  }

  // --- User & Role Provisioning Helpers ---

  function assertExistingAccountVerified(account: { uid: string; emailVerified?: boolean }, email: string): void {
    if (account.emailVerified !== true) {
      throw new EmailNotVerifiedError(
        `Cannot provision or grant access for '${email}': existing account has not verified its email address`
      );
    }
  }

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
      assertExistingAccountVerified(existing, cleanEmail);
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
            assertExistingAccountVerified(raceExisting, cleanEmail);
            return { uid: raceExisting.uid, email: cleanEmail, created: false };
          }
          throw createErr;
        }
      }
      throw err;
    }
  }

  /**
   * Signs a user out everywhere: revokes their Firebase refresh tokens, then records the revocation so `checkAuth`
   * immediately rejects every token from a session that started before it (even refreshed ones). Users may revoke their
   * own sessions; revoking anyone else's requires an admin actor. If Firebase revocation fails, nothing is recorded.
   */
  async function revokeUserSessions(params: { uid: string; actor: LanyardActor }): Promise<void> {
    const { uid, actor } = params;
    assertValidResourceId(uid, "uid");
    if (!actor || typeof actor !== "object") {
      throw new Error("Invalid actor: actor object with uid is required");
    }
    assertValidResourceId(actor.uid, "actor.uid");
    if (actor.uid !== uid) {
      const { isAdmin } = await resolveEffectiveAdminStatus(actor);
      if (!isAdmin) {
        throw new Error("Forbidden: only administrators can revoke other users' sessions");
      }
    }
    if (typeof adminAuth.revokeRefreshTokens !== "function") {
      throw new Error("adminAuth must implement revokeRefreshTokens to revoke sessions");
    }
    await adminAuth.revokeRefreshTokens(uid);
    const revocations = await store.recordSessionRevocation(uid, Date.now());
    // Apply on this instance right away instead of waiting for the store subscription to deliver it
    sessionRevocations.set(revocations);
  }

  async function setSystemAdminStatus(params: {
    email: string;
    isAdmin: boolean;
    firstName?: string;
    lastName?: string;
    actor: LanyardActor;
  }): Promise<SystemAdminProfile | null> {
    const { email, isAdmin, firstName = "", lastName = "", actor } = params;
    // Authorize before touching anything: no account is provisioned and no claim changes for a non-admin actor
    if (!(await isActorAdmin(actor))) {
      throw new Error("Forbidden: only administrators can change system admin status");
    }
    const displayName = [firstName.trim(), lastName.trim()].filter(Boolean).join(" ") || email.trim();
    let uid: string;
    let cleanEmail: string;
    if (isAdmin) {
      ({ uid, email: cleanEmail } = await getOrProvisionUidByEmail({ email, displayName }));
    } else {
      // Demoting someone without an account is a no-op: never provision an account just to demote it
      cleanEmail = (email || "").toLowerCase().trim();
      if (!isValidEmail(cleanEmail)) throw new Error("Invalid email address");
      try {
        uid = (await adminAuth.getUserByEmail(cleanEmail)).uid;
      } catch (error: any) {
        if (error?.code === "auth/user-not-found") return null;
        throw error;
      }
    }

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

    if (!isAdmin) {
      // The claim is the admin authority, so a demotion must supersede the user's existing admin:true tokens right
      // away: bump the revocation epoch (after the claim change, so refreshed tokens carry admin:false)
      revocationEpoch.set(await store.bumpRevocationEpoch(Date.now()));
    }

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
      // Default roles only seed a record that has never had roles; otherwise roles are written only when given, so a
      // revocation (or a role or admin change made since `existing` was read) is never overwritten. An existing card
      // that had no roles when read gets the defaults through grantUserRoles, an atomic union, so a role granted
      // meanwhile isn't lost. (In the rare race where roles were granted and then all revoked meanwhile, the defaults
      // are still added, since a union can't tell "never had roles" from "had them revoked".)
      const roles = params.roles ? Array.from(new Set(params.roles)) : !existing ? [...policy.defaultRoles] : undefined;
      const fillInDefaults =
        !params.roles && existing && existing.roles === undefined && policy.defaultRoles.length > 0;

      // Only the fields this call sets are written; the store merges them into the existing record
      const record: UserRecord<TRole, TCapability, TPreferences, TAttributes> = {
        uid,
        email: cleanEmail,
        ...(params.firstName !== undefined ? { firstName: params.firstName.trim() } : {}),
        ...(params.lastName !== undefined ? { lastName: params.lastName.trim() } : {}),
        ...(params.firstName || params.lastName || !existing?.displayName ? { displayName } : {}),
        ...(roles !== undefined ? { roles } : {}),
        ...(params.preferences ? { preferences: params.preferences } : {}),
        ...(params.attributes ? { attributes: params.attributes } : {}),
        ...(existing?.createdAt ? {} : { createdAt: now }),
        updatedAt: now
      };

      await store.upsertUser(record);
      if (fillInDefaults) {
        if (typeof store.grantUserRoles !== "function")
          throw new Error("Backing store does not implement grantUserRoles");
        await store.grantUserRoles(uid, policy.defaultRoles);
      }
      return (await store.getUser(uid))!;
    }

    const existing = await store.getScopeMember(params.scopeId, uid);
    const roles = params.roles ? Array.from(new Set(params.roles)) : existing ? undefined : [...policy.defaultRoles];
    const member = {
      uid,
      email: cleanEmail,
      ...(params.firstName !== undefined ? { firstName: params.firstName.trim() } : {}),
      ...(params.lastName !== undefined ? { lastName: params.lastName.trim() } : {}),
      ...(params.firstName || params.lastName || !existing?.displayName ? { displayName } : {}),
      ...(roles !== undefined ? { roles } : {}),
      scopeId: params.scopeId,
      ...(params.scopeName !== undefined ? { scopeName: params.scopeName } : {}),
      ...(params.preferences ? { preferences: params.preferences } : {}),
      ...(params.attributes ? { attributes: params.attributes } : {})
    };

    await store.upsertScopeMember(params.scopeId, member);
    return (await store.getScopeMember(params.scopeId, uid))!;
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
   * `attributes` are returned only if `actor` can read the attributes tier (self, scope staff, or system admin);
   * otherwise only keys placed on the card via `cardFields.attributes` are returned.
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
          isSelf,
          canReadCard: true
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
      isSelf,
      canReadCard: true
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
   * Each user's `attributes` are returned only if `actor` can read that user's attributes tier
   * (self, scope staff, or system admin); otherwise only card-placed attribute keys are returned.
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
          isSelf,
          canReadCard: true
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
        isSelf,
        canReadCard: true
      });
      return {
        ...m,
        ...(m.attributes !== undefined ? { attributes: filteredAttributes } : {})
      };
    });
  }

  /**
   * Updates a user's profile fields (`firstName`, `lastName`, `displayName`, `photoUrl`; never the email) in
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
    assertNoEmailInProfilePatch(params.patch);

    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const actorUid = params.actor.uid;

    if (params.scopeId === GLOBAL_SCOPE) {
      if (typeof store.getUser !== "function") {
        throw new Error("Backing store does not implement getUser");
      }
      const isSelf = actorUid === params.targetUid;
      if (!isSelf && !policy.canWriteUser(actorGlobalRecord, isAdmin)) {
        throw new Error("Forbidden: Insufficient permissions to update user profile");
      }
      const existing = await store.getUser(params.targetUid);
      if (!existing) {
        throw new Error(`Target user '${params.targetUid}' not found`);
      }
      if (!isSelf) {
        await assertMayManageTarget(isAdmin, params.targetUid, "modify");
        assertTargetWithinRank(isAdmin, actorGlobalRecord, existing.roles);
      }

      const fields = profileFieldsToWrite(params.patch || {}, existing);
      // Only the edited fields are written, so roles or admin status changed since `existing` was read stay changed
      await store.patchUser(params.targetUid, fields);
      if (
        fields.displayName &&
        fields.displayName !== existing.displayName &&
        typeof adminAuth.updateUser === "function"
      ) {
        await adminAuth.updateUser(params.targetUid, { displayName: fields.displayName }).catch(() => {});
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
    if (!isSelf) {
      await assertMayManageTarget(isAdmin, params.targetUid, "modify");
      assertTargetWithinRank(isAdmin, actorMember, existing.roles);
    }

    await store.patchScopeMember(params.scopeId, params.targetUid, profileFieldsToWrite(params.patch || {}, existing));
    return (await store.getScopeMember(params.scopeId, params.targetUid))!;
  }

  /**
   * Refuses a non-admin actor acting on a target who holds a role outside the actor's rank (a role they neither hold nor
   * inherit), so staff can't remove, edit, or re-role someone who outranks them. System-managed roles don't count.
   */
  function assertTargetWithinRank(
    isAdmin: boolean,
    actorRecord: PolicySubject<TRole, TCapability> | null | undefined,
    targetRoles: readonly TRole[] | undefined
  ): void {
    if (isAdmin) return;
    for (const role of Array.isArray(targetRoles) ? targetRoles : []) {
      if (!policy.isSystemManagedRole(role) && !policy.hasRole(actorRecord, role)) {
        throw new Error(`Forbidden: Target holds '${role}', which is outside your rank`);
      }
    }
  }

  /**
   * Plans a role change for `updateUserRoles`, returning the roles to grant and revoke. System-managed roles the target
   * holds are kept and none can be added (by anyone). A non-admin actor can't change their own roles, can't change a
   * target holding a role outside their rank, and can only add or remove roles within it (see `policy.canAssignRole`).
   */
  function planRoleChange(params: {
    isAdmin: boolean;
    actorRecord: PolicySubject<TRole, TCapability> | null | undefined;
    actorUid: string;
    targetUid: string;
    currentRoles: readonly TRole[] | undefined;
    requestedRoles: readonly TRole[];
  }): { grant: TRole[]; revoke: TRole[] } {
    const current = Array.isArray(params.currentRoles) ? params.currentRoles : [];
    const requested = Array.from(new Set(params.requestedRoles));
    for (const role of requested) {
      if (policy.isSystemManagedRole(role) && !current.includes(role)) {
        throw new Error(`Invalid role change: '${role}' is system-managed, so only trusted server code assigns it`);
      }
    }
    const next = Array.from(
      new Set([
        ...current.filter((role) => policy.isSystemManagedRole(role)),
        ...requested.filter((role) => !policy.isSystemManagedRole(role))
      ])
    );
    const grant = next.filter((role) => !current.includes(role));
    const revoke = current.filter((role) => !next.includes(role));

    if (!params.isAdmin) {
      if (params.actorUid === params.targetUid) {
        throw new Error("Forbidden: Users can't change their own roles");
      }
      assertTargetWithinRank(false, params.actorRecord, current);
      for (const role of [...grant, ...revoke]) {
        if (!policy.canAssignRole(params.actorRecord, role)) {
          throw new Error(`Forbidden: Role '${role}' is outside your rank`);
        }
      }
    }
    return { grant, revoke };
  }

  /**
   * Sets a user's human-assigned `roles` in `GLOBAL_SCOPE` (`users/{targetUid}`) or a specific tenant `scopeId`.
   * The caller (`actor`) must hold the `assignRoles` capability in `userCapabilities` within that scope (or be an
   * active system admin), and every role in `roles` must be concrete (`!abstract`). Non-admins are also held to their
   * rank: they can't change their own roles, can't change a target holding a role outside their rank, and can only add
   * or remove roles within it (`policy.canAssignRole`). System-managed roles the target holds are kept, and none can
   * be added. Only the `roles` field is written.
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
      if (
        typeof store.getUser !== "function" ||
        typeof store.grantUserRoles !== "function" ||
        typeof store.revokeUserRoles !== "function"
      ) {
        throw new Error("Backing store does not implement getUser / grantUserRoles / revokeUserRoles");
      }
      if (!policy.canAssignRoles(actorGlobalRecord, isAdmin)) {
        throw new Error("Forbidden: Insufficient permissions to assign user roles");
      }
      const existing = await store.getUser(params.targetUid);
      if (!existing) {
        throw new Error(`Target user '${params.targetUid}' not found`);
      }
      await assertMayManageTarget(isAdmin, params.targetUid, "modify");

      const { grant, revoke } = planRoleChange({
        isAdmin,
        actorRecord: actorGlobalRecord,
        actorUid,
        targetUid: params.targetUid,
        currentRoles: existing.roles,
        requestedRoles: params.roles
      });
      // Write only the roles that change, so fields the snapshot read (such as isSystemAdmin) are never written back
      if (grant.length > 0) await store.grantUserRoles(params.targetUid, grant);
      if (revoke.length > 0) await store.revokeUserRoles(params.targetUid, revoke);
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
    await assertMayManageTarget(isAdmin, params.targetUid, "modify");

    const { grant, revoke } = planRoleChange({
      isAdmin,
      actorRecord: actorMember,
      actorUid,
      targetUid: params.targetUid,
      currentRoles: existing.roles,
      requestedRoles: params.roles
    });
    if (grant.length > 0) await store.grantScopeRoles(params.scopeId, params.targetUid, grant);
    if (revoke.length > 0) await store.revokeScopeRoles(params.scopeId, params.targetUid, revoke);
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
      let actorRecord: PolicySubject<TRole, TCapability> | null | undefined = null;
      if (!isSelf) {
        const resolved = await resolveEffectiveAdminStatus(params.actor);
        isAdmin = resolved.isAdmin;
        actorRecord = resolved.userRecord;
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
        if (!isSelf) {
          await assertMayManageTarget(isAdmin, params.targetUid, "delete");
          assertTargetWithinRank(isAdmin, actorRecord, targetUser.roles);
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
      if (!isSelf) {
        await assertMayManageTarget(isAdmin, params.targetUid, "remove");
        assertTargetWithinRank(isAdmin, actorMember, targetMember.roles);
      }
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
   * Reads a user's `attributes` in `GLOBAL_SCOPE` (`users/{targetUid}`) or a specific tenant `scopeId`.
   * The whole attributes tier is returned to the user themselves, scope staff (`staffCapability`), and system admins;
   * other callers receive only keys placed on the card via `cardFields.attributes`.
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
      const isSelf = actorUid === params.targetUid;
      return policy.filterReadableAttributes<TAttributes>(actorGlobalRecord, targetUser?.attributes, {
        isSystemAdmin: isAdmin,
        isSelf,
        canReadCard: policy.canReadTier(actorGlobalRecord, "card", { isSystemAdmin: isAdmin, isSelf, isGlobal: true })
      });
    }

    const actorMember = await store.getScopeMember(params.scopeId, actorUid);
    if (!isAdmin && !actorMember) {
      throw new Error(`Forbidden: Caller is not a member of scope '${params.scopeId}'`);
    }
    const targetMember = await store.getScopeMember(params.scopeId, params.targetUid);
    const isSelf = Boolean(actorMember && actorUid === params.targetUid);
    return policy.filterReadableAttributes<TAttributes>(actorMember, targetMember?.attributes, {
      isSystemAdmin: isAdmin,
      isSelf,
      canReadCard: policy.canReadTier(actorMember, "card", {
        isSystemAdmin: isAdmin,
        isSelf,
        isScopeMember: Boolean(actorMember)
      })
    });
  }

  /**
   * Returns the uids of members of `scopeId` (or global users for `GLOBAL_SCOPE`) whose attributes equal every value
   * in `attributes`, after verifying the caller (`actor`) may read that location for other users: staff (or system
   * admins) for `attributes`-tier keys, card readers for keys placed on the card. Keys from both locations can't be
   * combined.
   */
  async function queryMembers(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    attributes: Partial<TAttributes>;
  }): Promise<string[]> {
    assertValidScopeId(params.scopeId);
    if (typeof store.queryMemberUids !== "function") {
      throw new Error("Backing store does not implement queryMemberUids");
    }
    const location = resolveAttributeQueryLocation(params.attributes, policy.cardFields);
    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const scopeId = params.scopeId === GLOBAL_SCOPE ? null : params.scopeId;
    const isGlobal = scopeId === null;
    const actorRecord = scopeId === null ? actorGlobalRecord : await store.getScopeMember(scopeId, params.actor.uid);
    if (scopeId !== null && !isAdmin && !actorRecord) {
      throw new Error(`Forbidden: Caller is not a member of scope '${scopeId}'`);
    }
    const allowed =
      location === "attributes"
        ? policy.canReadTier(actorRecord, "attributes", { isSystemAdmin: isAdmin })
        : policy.canReadTier(actorRecord, "card", {
            isSystemAdmin: isAdmin,
            isGlobal,
            isScopeMember: Boolean(actorRecord)
          });
    if (!allowed) {
      throw new Error(
        location === "attributes"
          ? "Forbidden: queryMembers on attributes-tier keys requires staff access"
          : "Forbidden: queryMembers on card-placed keys requires card access"
      );
    }
    return store.queryMemberUids(scopeId, params.attributes);
  }

  /**
   * Verifies `actor` may `mode` the policy's custom document `name` of an existing user/member `targetUid` in
   * `scopeId` (per `customDocs[name].read` / `.write`), returning the store's `scopeId` (`null` for global).
   */
  async function authorizeCustomDoc(
    params: { scopeId: ScopeId; actor: LanyardActor; targetUid: string; name: string },
    mode: "read" | "write"
  ): Promise<string | null> {
    assertValidScopeId(params.scopeId);
    assertValidResourceId(params.targetUid, "targetUid");
    if (!Object.hasOwn(policy.customDocs, params.name)) throw new Error(`Unknown custom doc '${params.name}'`);
    const { isAdmin, userRecord: actorGlobalRecord } = await resolveEffectiveAdminStatus(params.actor);
    const scopeId = params.scopeId === GLOBAL_SCOPE ? null : params.scopeId;
    let actorRecord:
      | UserRecord<TRole, TCapability, TPreferences, TAttributes>
      | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
      | null = actorGlobalRecord;
    if (scopeId === null) {
      if (typeof store.getUser !== "function") throw new Error("Backing store does not implement getUser");
      if (!(await store.getUser(params.targetUid))) throw new Error(`Target user '${params.targetUid}' not found`);
    } else {
      actorRecord = await store.getScopeMember(scopeId, params.actor.uid);
      if (!isAdmin && !actorRecord) throw new Error(`Forbidden: Caller is not a member of scope '${scopeId}'`);
      if (!(await store.getScopeMember(scopeId, params.targetUid))) {
        throw new Error(`Target member '${params.targetUid}' not found in scope '${scopeId}'`);
      }
    }
    const options = { isSystemAdmin: isAdmin, isSelf: params.actor.uid === params.targetUid };
    const allowed =
      mode === "read"
        ? policy.canReadCustomDoc(actorRecord, params.name, options)
        : policy.canWriteCustomDoc(actorRecord, params.name, options);
    if (!allowed) throw new Error(`Forbidden: Insufficient permissions to ${mode} custom doc '${params.name}'`);
    return scopeId;
  }

  /** Reads the policy's custom document `name` of `targetUid` in `scopeId` after verifying `actor` may read it. */
  async function getCustomDoc(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    name: string;
  }): Promise<Record<string, any>> {
    if (typeof store.getCustomDoc !== "function") throw new Error("Backing store does not implement getCustomDoc");
    const scopeId = await authorizeCustomDoc(params, "read");
    return store.getCustomDoc(params.name, params.targetUid, scopeId);
  }

  /** Merges `patch` into the policy's custom document `name` of `targetUid` after verifying `actor` may write it. */
  async function updateCustomDoc(params: {
    scopeId: ScopeId;
    actor: LanyardActor;
    targetUid: string;
    name: string;
    patch: Record<string, any>;
  }): Promise<Record<string, any>> {
    if (typeof store.updateCustomDoc !== "function" || typeof store.getCustomDoc !== "function") {
      throw new Error("Backing store does not implement updateCustomDoc/getCustomDoc");
    }
    const scopeId = await authorizeCustomDoc(params, "write");
    await store.updateCustomDoc(params.name, params.targetUid, scopeId, params.patch);
    return store.getCustomDoc(params.name, params.targetUid, scopeId);
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
   * or a specific tenant `scopeId`. The whole hiddenAttributes tier is returned to scope staff
   * (`staffCapability`) and system admins; other callers get a `Forbidden` error when the tier contains data.
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
    checkAuth,
    requireAdmin,
    requireRole,
    requireCapability,
    revokeUserSessions,
    close,
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
    queryMembers,
    getCustomDoc,
    updateCustomDoc,
    updateUserAttributes,
    readUserHiddenAttributes,
    updateUserHiddenAttributes,
    getUserSecretsStatus,
    updateUserSecrets,
    getDecryptedUserSecrets
  };
}

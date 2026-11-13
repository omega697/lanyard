import { describe, expect, it, vi } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore } from "../core/index.js";
import { createLanyardServer, GoogleAuthService, type AdminAuthAdapter, type AuthService } from "./index.js";

/**
 * Only checkAuth decides whether a request is from an admin (the verified claim, after revocation checks). Nothing
 * else may be able to produce or alter that decision.
 */

const nowSeconds = () => Math.floor(Date.now() / 1000);

function tokenFor(uid: string, adminClaim: boolean): AuthService {
  return {
    async verifyToken() {
      const t = nowSeconds();
      return {
        uid,
        email: `${uid}@example.com`,
        emailVerified: true,
        adminClaim,
        issuedAtSeconds: t,
        authTimeSeconds: t - 60
      };
    }
  };
}

function fakeAdminAuth(claims: Record<string, Record<string, any>>) {
  return {
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async (email: string) => {
      if (email !== "target@example.com") {
        throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
      }
      return { uid: "u-target", email, emailVerified: true, customClaims: claims["u-target"] };
    },
    createUser: async () => ({ uid: "unused" }),
    setCustomUserClaims: vi.fn(async (uid: string, c: Record<string, any> | null) => {
      claims[uid] = { ...(c || {}) };
    }),
    revokeRefreshTokens: async () => {},
    getUser: async (uid: string) => ({ uid, customClaims: claims[uid] ?? {} })
  } satisfies AdminAuthAdapter;
}

async function run(middleware: (req: any, res: any, next: () => void) => unknown, req: any) {
  const res: any = { statusCode: 200, status: (c: number) => ((res.statusCode = c), res), json: () => res };
  let nextCalled = false;
  await middleware(req, res, () => {
    nextCalled = true;
  });
  return { req, res, nextCalled };
}

describe("only checkAuth produces isAdmin", () => {
  it("setting req.user.isAdmin after checkAuth grants nothing: not requireAdmin, not admin-only server methods", async () => {
    const claims: Record<string, Record<string, any>> = { "u-member": {}, "u-target": {} };
    const adminAuth = fakeAdminAuth(claims);
    const store = new InMemoryLanyardStore();
    const server = createLanyardServer({ adminAuth, store, authService: tokenFor("u-member", false) });
    try {
      const { req } = await run(server.checkAuth, { headers: { authorization: "Bearer t" } });
      expect(req.user.isAdmin).toBe(false);

      // App code (or a mock-admin header, or a bug) flips the flag on the verified request user
      req.user.isAdmin = true;

      expect((await run(server.requireAdmin, req)).nextCalled).toBe(false);
      await expect(
        server.setSystemAdminStatus({ email: "target@example.com", isAdmin: true, actor: req.user })
      ).rejects.toThrow(/Forbidden/);
      expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
      await expect(server.revokeUserSessions({ uid: "u-target", actor: req.user })).rejects.toThrow(/Forbidden/);
    } finally {
      server.close();
    }
  });

  it("a verified admin's req.user still works as an actor without a Firebase lookup", async () => {
    const claims: Record<string, Record<string, any>> = { "u-admin": { admin: true }, "u-target": {} };
    const adminAuth = fakeAdminAuth(claims);
    const getUser = vi.spyOn(adminAuth, "getUser");
    const server = createLanyardServer({
      adminAuth,
      store: new InMemoryLanyardStore(),
      authService: tokenFor("u-admin", true)
    });
    try {
      const { req } = await run(server.checkAuth, { headers: { authorization: "Bearer t" } });
      expect(req.user.isAdmin).toBe(true);
      expect((await run(server.requireAdmin, req)).nextCalled).toBe(true);
      await server.setSystemAdminStatus({ email: "target@example.com", isAdmin: true, actor: req.user });
      expect(claims["u-target"].admin).toBe(true);
      expect(getUser).not.toHaveBeenCalled();
    } finally {
      server.close();
    }
  });

  it("verifyToken returns the raw claim as adminClaim, never as isAdmin, and the server doesn't expose its AuthService", async () => {
    const service = new GoogleAuthService({
      verifyIdToken: async () => ({
        uid: "u-1",
        email: "U1@Example.com",
        email_verified: true,
        admin: true,
        iat: 1_700_000_000,
        auth_time: 1_699_999_000
      })
    });
    const token = await service.verifyToken("Bearer raw");
    expect(token).toEqual({
      uid: "u-1",
      email: "u1@example.com",
      emailVerified: true,
      name: undefined,
      photoUrl: null,
      adminClaim: true,
      issuedAtSeconds: 1_700_000_000,
      authTimeSeconds: 1_699_999_000
    });
    expect(token).not.toHaveProperty("isAdmin");
    // @ts-expect-error VerifiedToken deliberately has no isAdmin: only checkAuth produces it
    void token?.isAdmin;

    const server = createLanyardServer({ adminAuth: fakeAdminAuth({}), store: new InMemoryLanyardStore() });
    expect(server).not.toHaveProperty("authService");
    server.close();
  });

  it("GoogleAuthService takes named options instead of positional booleans", async () => {
    const verifyIdToken = vi.fn(async () => ({
      uid: "u-1",
      email: "u1@example.com",
      email_verified: false,
      iat: 1_700_000_000,
      auth_time: 1_700_000_000
    }));
    const lenient = new GoogleAuthService({ verifyIdToken }, { requireVerifiedEmail: false, checkRevoked: true });
    expect(await lenient.verifyToken("Bearer t")).toMatchObject({ uid: "u-1", emailVerified: false });
    expect(verifyIdToken).toHaveBeenCalledWith("t", true);

    // Tokens without iat/auth_time can't be freshness-checked, so they're rejected rather than passed through
    verifyIdToken.mockResolvedValueOnce({ uid: "u-1", email: "u1@example.com", email_verified: false } as any);
    await expect(lenient.verifyToken("Bearer t")).rejects.toThrow(/iat and auth_time/);
  });

  it("hand-built actors are plain { uid } objects, judged by their current Firebase claim", async () => {
    const claims: Record<string, Record<string, any>> = { "u-admin": { admin: true }, "u-target": {} };
    const server = createLanyardServer({ adminAuth: fakeAdminAuth(claims), store: new InMemoryLanyardStore() });
    try {
      await server.setSystemAdminStatus({ email: "target@example.com", isAdmin: true, actor: { uid: "u-admin" } });
      expect(claims["u-target"].admin).toBe(true);
      await expect(
        server.updateUserRoles({
          scopeId: GLOBAL_SCOPE,
          // @ts-expect-error LanyardActor has no isAdmin: actors can't vouch for themselves
          actor: { uid: "u-nobody", isAdmin: true },
          targetUid: "u-target",
          roles: []
        })
      ).rejects.toThrow();
    } finally {
      server.close();
    }
  });
});

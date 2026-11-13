import { describe, it, expect, vi } from "vitest";
import {
  InMemoryLanyardStore,
  REVOCATION_CLOCK_SKEW_MS,
  SESSION_REVOKED_ERROR_CODE,
  TOKEN_STALE_ERROR_CODE
} from "../core/index.js";
import { createLanyardServer, GoogleAuthService, type AuthService, type AdminAuthAdapter } from "./index.js";

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** An AuthService whose tokens are keys into `users`, each with an explicit issue time and sign-in time (seconds). */
function tokenTable(
  users: Record<string, { uid: string; iat?: number; authTime?: number; admin?: boolean }>
): AuthService {
  return {
    async verifyToken(authHeader) {
      const entry = users[(authHeader || "").replace(/^Bearer /, "")];
      if (!entry) return null;
      return {
        uid: entry.uid,
        email: `${entry.uid}@example.com`,
        emailVerified: true,
        adminClaim: entry.admin ?? false,
        // Missing times are possible from a custom AuthService at runtime; checkAuth must fail closed on them
        issuedAtSeconds: entry.iat as number,
        authTimeSeconds: entry.authTime as number
      };
    }
  };
}

function fakeAdminAuth(): AdminAuthAdapter & { revoked: string[] } {
  const revoked: string[] = [];
  return {
    revoked,
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async () => {
      throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
    },
    createUser: async () => ({ uid: "unused" }),
    setCustomUserClaims: async () => {},
    revokeRefreshTokens: async (uid: string) => {
      revoked.push(uid);
    }
  };
}

function mockRes() {
  const res: any = {
    statusCode: 200,
    body: undefined,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: any) {
      res.body = body;
      return res;
    }
  };
  return res;
}

async function authenticate(server: ReturnType<typeof createLanyardServer>, token: string) {
  const req: any = { headers: { authorization: `Bearer ${token}` } };
  const res = mockRes();
  let nextCalled = false;
  await server.checkAuth(req, res, () => {
    nextCalled = true;
  });
  return { req, res, nextCalled };
}

describe("checkAuth token freshness", () => {
  it("rejects a token issued before (or within clock skew of) the revocation epoch with auth/token-stale", async () => {
    const store = new InMemoryLanyardStore();
    const t = nowSeconds();
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth(),
      store,
      authService: tokenTable({
        old: { uid: "u-a", iat: t - 60, authTime: t - 3600 },
        withinSkew: { uid: "u-a", iat: t, authTime: t - 3600 },
        fresh: { uid: "u-a", iat: t + 10, authTime: t - 3600 }
      })
    });
    await store.bumpRevocationEpoch(t * 1000 - REVOCATION_CLOCK_SKEW_MS + 500);

    for (const token of ["old", "withinSkew"]) {
      const outcome = await authenticate(server, token);
      expect(outcome.nextCalled).toBe(false);
      expect(outcome.res.statusCode).toBe(401);
      expect(outcome.res.body).toMatchObject({ code: TOKEN_STALE_ERROR_CODE });
      expect(outcome.req.user).toBeUndefined();
    }
    expect((await authenticate(server, "fresh")).nextCalled).toBe(true);
    server.close();
  });

  it("rejects a revoked session by sign-in time even after the token is refreshed, without affecting other users", async () => {
    const store = new InMemoryLanyardStore();
    const t = nowSeconds();
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth(),
      store,
      authService: tokenTable({
        refreshedAfterRevocation: { uid: "u-revoked", iat: t + 60, authTime: t - 3600 },
        signedInAgain: { uid: "u-revoked", iat: t + 60, authTime: t + 60 },
        otherUser: { uid: "u-other", iat: t - 3600, authTime: t - 7200 }
      })
    });
    await store.recordSessionRevocation("u-revoked", t * 1000);

    const refreshed = await authenticate(server, "refreshedAfterRevocation");
    expect(refreshed.nextCalled).toBe(false);
    expect(refreshed.res.statusCode).toBe(401);
    expect(refreshed.res.body).toMatchObject({ code: SESSION_REVOKED_ERROR_CODE });
    expect((await authenticate(server, "signedInAgain")).nextCalled).toBe(true);
    expect((await authenticate(server, "otherUser")).nextCalled).toBe(true);
    server.close();
  });

  it("fails closed when a token's issue or sign-in time is missing", async () => {
    const t = nowSeconds();
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth(),
      store: new InMemoryLanyardStore(),
      authService: tokenTable({ noIat: { uid: "u-a", authTime: t }, noAuthTime: { uid: "u-a", iat: t } })
    });
    for (const token of ["noIat", "noAuthTime"]) {
      const outcome = await authenticate(server, token);
      expect(outcome.nextCalled).toBe(false);
      expect(outcome.res.statusCode).toBe(401);
    }
    server.close();
  });

  it("waits for the first revocation data, and fails closed with 503 when it can't be loaded", async () => {
    const t = nowSeconds();
    const base = new InMemoryLanyardStore();
    let deliverEpoch: (() => void) | undefined;
    const slowStore = Object.assign(Object.create(base), {
      subscribeToRevocationEpoch: (onChange: (v: number | null) => void) => {
        deliverEpoch = () => onChange(null);
        return () => {};
      }
    });
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth(),
      store: slowStore,
      authService: tokenTable({ ok: { uid: "u-a", iat: t, authTime: t } })
    });
    const pending = authenticate(server, "ok");
    await new Promise((resolve) => setTimeout(resolve, 20));
    deliverEpoch!();
    expect((await pending).nextCalled).toBe(true);
    server.close();

    const brokenStore = Object.assign(Object.create(base), {
      subscribeToSessionRevocations: (_onChange: unknown, onError: (e: unknown) => void) => {
        onError(new Error("listener failed"));
        return () => {};
      }
    });
    const broken = createLanyardServer({
      adminAuth: fakeAdminAuth(),
      store: brokenStore,
      authService: tokenTable({ ok: { uid: "u-a", iat: t, authTime: t } })
    });
    const outcome = await authenticate(broken, "ok");
    expect(outcome.nextCalled).toBe(false);
    expect(outcome.res.statusCode).toBe(503);
    broken.close();

    const neverLoads = Object.assign(Object.create(base), {
      subscribeToRevocationEpoch: () => () => {}
    });
    const timingOut = createLanyardServer({
      adminAuth: fakeAdminAuth(),
      store: neverLoads,
      revocationLoadTimeoutMs: 50,
      authService: tokenTable({ ok: { uid: "u-a", iat: t, authTime: t } })
    });
    expect((await authenticate(timingOut, "ok")).res.statusCode).toBe(503);
    timingOut.close();
  });

  it("resubscribes after a revocation listener error and recovers", async () => {
    const t = nowSeconds();
    const base = new InMemoryLanyardStore();
    let attempts = 0;
    const flakyStore = Object.assign(Object.create(base), {
      subscribeToRevocationEpoch: (onChange: (v: number | null) => void, onError: (e: unknown) => void) => {
        attempts++;
        if (attempts === 1) onError(new Error("transient"));
        else onChange(null);
        return () => {};
      }
    });
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth(),
      store: flakyStore,
      revocationResubscribeDelayMs: 10,
      authService: tokenTable({ ok: { uid: "u-a", iat: t, authTime: t } })
    });
    expect((await authenticate(server, "ok")).res.statusCode).toBe(503);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect((await authenticate(server, "ok")).nextCalled).toBe(true);
    expect(attempts).toBeGreaterThanOrEqual(2);
    server.close();
  });

  it("refuses to start with a store that doesn't implement the revocation methods", () => {
    const partial = Object.assign(Object.create(new InMemoryLanyardStore()), {
      subscribeToSessionRevocations: undefined
    });
    expect(() => createLanyardServer({ adminAuth: fakeAdminAuth(), store: partial })).toThrow(
      /subscribeToSessionRevocations/
    );
  });

  it("close() stops the revocation subscriptions", () => {
    const base = new InMemoryLanyardStore();
    const unsubscribed: string[] = [];
    const store = Object.assign(Object.create(base), {
      subscribeToRevocationEpoch: (onChange: (v: number | null) => void) => {
        onChange(null);
        return () => unsubscribed.push("epoch");
      },
      subscribeToSessionRevocations: (onChange: (v: Record<string, number>) => void) => {
        onChange({});
        return () => unsubscribed.push("sessions");
      }
    });
    createLanyardServer({ adminAuth: fakeAdminAuth(), store }).close();
    expect(unsubscribed.sort()).toEqual(["epoch", "sessions"]);
  });

  it("GoogleAuthService reports the token's issue and sign-in times", async () => {
    const user = await new GoogleAuthService({
      verifyIdToken: async () => ({
        uid: "u-a",
        email: "a@example.com",
        email_verified: true,
        iat: 1000,
        auth_time: 900
      })
    }).verifyToken("Bearer t");
    expect(user).toMatchObject({ issuedAtSeconds: 1000, authTimeSeconds: 900 });
  });
});

describe("revokeUserSessions", () => {
  it("lets users sign themselves out everywhere and admins revoke anyone, and the revoked session is refused at once", async () => {
    const t = nowSeconds();
    const adminAuth = Object.assign(fakeAdminAuth(), {
      // Admin status comes from the user's current Firebase claim
      getUser: async (uid: string) => ({ uid, customClaims: uid === "u-admin" ? { admin: true } : {} })
    });
    const store = new InMemoryLanyardStore();
    const server = createLanyardServer({
      adminAuth,
      store,
      authService: tokenTable({ victimToken: { uid: "u-victim", iat: t - 10, authTime: t - 10 } })
    });
    expect((await authenticate(server, "victimToken")).nextCalled).toBe(true);

    await server.revokeUserSessions({ uid: "u-self", actor: { uid: "u-self" } });
    await server.revokeUserSessions({ uid: "u-victim", actor: { uid: "u-admin" } });

    expect(adminAuth.revoked).toEqual(["u-self", "u-victim"]);
    expect(Object.keys(await store.getSessionRevocations()).sort()).toEqual(["u-self", "u-victim"]);
    // Applied to this server instance immediately, without waiting for the store subscription
    const outcome = await authenticate(server, "victimToken");
    expect(outcome.nextCalled).toBe(false);
    expect(outcome.res.body).toMatchObject({ code: SESSION_REVOKED_ERROR_CODE });
    server.close();
  });

  it("refuses to let a non-admin revoke someone else's sessions", async () => {
    const adminAuth = fakeAdminAuth();
    const store = new InMemoryLanyardStore();
    const server = createLanyardServer({ adminAuth, store });
    await expect(server.revokeUserSessions({ uid: "u-victim", actor: { uid: "u-attacker" } })).rejects.toThrow(
      /Forbidden/
    );
    expect(adminAuth.revoked).toEqual([]);
    expect(await store.getSessionRevocations()).toEqual({});
    server.close();
  });

  it("records nothing if Firebase revocation fails", async () => {
    const adminAuth = fakeAdminAuth();
    adminAuth.revokeRefreshTokens = vi.fn(async () => {
      throw new Error("Firebase unavailable");
    });
    const store = new InMemoryLanyardStore();
    const server = createLanyardServer({ adminAuth, store });
    await expect(server.revokeUserSessions({ uid: "u-self", actor: { uid: "u-self" } })).rejects.toThrow(
      /Firebase unavailable/
    );
    expect(await store.getSessionRevocations()).toEqual({});
    server.close();
  });
});

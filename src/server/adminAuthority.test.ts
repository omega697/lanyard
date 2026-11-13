import { describe, expect, it, vi } from "vitest";
import { InMemoryLanyardStore } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter, type AuthService } from "./index.js";

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Tokens are keys into `users`; each carries the admin claim it was issued with. */
function tokenTable(users: Record<string, { uid: string; admin: boolean }>): AuthService {
  return {
    async verifyToken(authHeader) {
      const entry = users[(authHeader || "").replace(/^Bearer /, "")];
      if (!entry) return null;
      const t = nowSeconds();
      return {
        uid: entry.uid,
        email: `${entry.uid}@example.com`,
        emailVerified: true,
        isAdmin: entry.admin,
        tokenIssuedAtSeconds: t,
        authTimeSeconds: t - 60
      };
    }
  };
}

/** Firebase Admin double whose `getUser` reports each user's *current* custom claims. */
function fakeAdminAuth(currentClaims: Record<string, Record<string, any>>) {
  const adminAuth = {
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async () => {
      throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
    },
    createUser: async () => ({ uid: "unused" }),
    setCustomUserClaims: async () => {},
    revokeRefreshTokens: async () => {},
    getUser: vi.fn(async (uid: string) => {
      if (!(uid in currentClaims)) throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
      return { uid, customClaims: currentClaims[uid] };
    })
  } satisfies AdminAuthAdapter;
  return adminAuth;
}

function mockRes() {
  const res: any = {
    statusCode: 200,
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

async function run(middleware: (req: any, res: any, next: () => void) => unknown, req: any) {
  const res = mockRes();
  let nextCalled = false;
  await middleware(req, res, () => {
    nextCalled = true;
  });
  return { req, res, nextCalled };
}

const authed = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

describe("the Firebase admin claim is the only admin authority", () => {
  it("checkAuth takes admin status from the verified claim, ignoring admin records in the store", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-record-says-admin", email: "a@example.com", roles: [], isSystemAdmin: true });
    await store.upsertUser({ uid: "u-record-says-demoted", email: "b@example.com", roles: [], isSystemAdmin: false });
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth({}),
      store,
      authService: tokenTable({
        recordOnly: { uid: "u-record-says-admin", admin: false },
        claimOnly: { uid: "u-record-says-demoted", admin: true }
      })
    });

    expect((await run(server.checkAuth, authed("recordOnly"))).req.user.isAdmin).toBe(false);
    expect((await run(server.checkAuth, authed("claimOnly"))).req.user.isAdmin).toBe(true);
    server.close();
  });

  it("never creates or changes admin records from a request, so a stale claim can't resurrect a demotion", async () => {
    const store = new InMemoryLanyardStore();
    const upsertSystemAdmin = vi.spyOn(store, "upsertSystemAdmin");
    const upsertUser = vi.spyOn(store, "upsertUser");
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth({ "u-admin": { admin: true } }),
      store,
      authService: tokenTable({ adminToken: { uid: "u-admin", admin: true } })
    });

    const authedReq = await run(server.checkAuth, authed("adminToken"));
    const admin = await run(server.requireAdmin, authedReq.req);

    expect(admin.nextCalled).toBe(true);
    expect(upsertSystemAdmin).not.toHaveBeenCalled();
    expect(upsertUser).not.toHaveBeenCalled();
    expect(await store.getSystemAdmin("u-admin")).toBeNull();
    server.close();
  });

  it("admin checks don't depend on the store being reachable", async () => {
    const store = new InMemoryLanyardStore();
    vi.spyOn(store, "getUser").mockRejectedValue(new Error("store outage"));
    vi.spyOn(store, "getSystemAdmin").mockRejectedValue(new Error("store outage"));
    const server = createLanyardServer({
      adminAuth: fakeAdminAuth({}),
      store,
      authService: tokenTable({
        adminToken: { uid: "u-admin", admin: true },
        memberToken: { uid: "u-m", admin: false }
      })
    });

    const admin = await run(server.checkAuth, authed("adminToken"));
    expect(admin.nextCalled).toBe(true);
    expect((await run(server.requireAdmin, admin.req)).nextCalled).toBe(true);
    const member = await run(server.checkAuth, authed("memberToken"));
    expect((await run(server.requireAdmin, member.req)).res.statusCode).toBe(403);
    server.close();
  });

  it("requireAdmin doesn't trust a req.user that checkAuth didn't verify: it asks Firebase for the current claim", async () => {
    const adminAuth = fakeAdminAuth({ "u-real-admin": { admin: true }, "u-pretender": {} });
    const server = createLanyardServer({ adminAuth, store: new InMemoryLanyardStore() });

    const pretender = await run(server.requireAdmin, {
      user: { uid: "u-pretender", email: "p@example.com", isAdmin: true }
    });
    expect(pretender.nextCalled).toBe(false);
    expect(pretender.res.statusCode).toBe(403);

    const realAdmin = await run(server.requireAdmin, { user: { uid: "u-real-admin", email: "r@example.com" } });
    expect(realAdmin.nextCalled).toBe(true);
    server.close();
  });

  it("actor-based methods ignore actor.isAdmin on hand-built actors and use Firebase's current claim; verified req.user actors need no lookup", async () => {
    const adminAuth = fakeAdminAuth({ "u-real-admin": { admin: true }, "u-pretender": { admin: false } });
    const server = createLanyardServer({
      adminAuth,
      store: new InMemoryLanyardStore(),
      authService: tokenTable({ adminToken: { uid: "u-real-admin", admin: true } })
    });

    await expect(
      server.revokeUserSessions({ uid: "u-victim", actor: { uid: "u-pretender", isAdmin: true } })
    ).rejects.toThrow(/Forbidden/);
    await server.revokeUserSessions({ uid: "u-victim", actor: { uid: "u-real-admin" } });

    adminAuth.getUser.mockClear();
    const { req } = await run(server.checkAuth, authed("adminToken"));
    await server.revokeUserSessions({ uid: "u-victim-2", actor: req.user });
    expect(adminAuth.getUser).not.toHaveBeenCalled();
    server.close();
  });

  it("treats a hand-built actor as not an admin when Firebase can't confirm the claim", async () => {
    const adminAuth = fakeAdminAuth({});
    adminAuth.getUser.mockRejectedValue(new Error("Firebase unavailable"));
    const server = createLanyardServer({ adminAuth, store: new InMemoryLanyardStore() });
    await expect(
      server.revokeUserSessions({ uid: "u-victim", actor: { uid: "u-admin", isAdmin: true } })
    ).rejects.toThrow(/Forbidden/);
    server.close();
  });
});

describe("setSystemAdminStatus authorizes its actor (H2)", () => {
  function fakeAuthWithAccounts(accounts: Record<string, { uid: string; claims?: Record<string, any> }>) {
    const claims = new Map(Object.values(accounts).map((a) => [a.uid, { ...(a.claims || {}) }]));
    const created: string[] = [];
    const adminAuth = {
      verifyIdToken: async () => {
        throw new Error("not used");
      },
      getUserByEmail: async (email: string) => {
        const account = accounts[email.toLowerCase()];
        if (!account) throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
        return { uid: account.uid, email, customClaims: claims.get(account.uid) };
      },
      createUser: vi.fn(async (props: { email: string }) => {
        created.push(props.email);
        const uid = `created-${created.length}`;
        accounts[props.email.toLowerCase()] = { uid };
        return { uid, email: props.email };
      }),
      setCustomUserClaims: vi.fn(async (uid: string, c: Record<string, any> | null) => {
        claims.set(uid, { ...(c || {}) });
      }),
      revokeRefreshTokens: async () => {},
      getUser: async (uid: string) => ({ uid, customClaims: claims.get(uid) ?? null })
    } satisfies AdminAuthAdapter;
    return { adminAuth, claims, created };
  }

  it("refuses a non-admin actor before provisioning anyone or changing any claim", async () => {
    const { adminAuth, claims, created } = fakeAuthWithAccounts({
      "attacker@example.com": { uid: "u-attacker" }
    });
    const store = new InMemoryLanyardStore();
    const server = createLanyardServer({ adminAuth, store });

    for (const email of ["attacker@example.com", "brand-new@example.com"]) {
      await expect(
        server.setSystemAdminStatus({ email, isAdmin: true, actor: { uid: "u-attacker", isAdmin: true } })
      ).rejects.toThrow(/Forbidden/);
    }
    expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
    expect(created).toEqual([]);
    expect(claims.get("u-attacker")?.admin).toBeUndefined();
    expect(await store.getSystemAdmin("u-attacker")).toBeNull();
    server.close();
  });

  it("lets a real admin (by Firebase claim, or a verified req.user) grant and revoke admin", async () => {
    const { adminAuth, claims } = fakeAuthWithAccounts({
      "admin@example.com": { uid: "u-admin", claims: { admin: true } },
      "target@example.com": { uid: "u-target" }
    });
    const store = new InMemoryLanyardStore();
    const server = createLanyardServer({
      adminAuth,
      store,
      authService: tokenTable({ adminToken: { uid: "u-admin", admin: true } })
    });

    await server.setSystemAdminStatus({ email: "target@example.com", isAdmin: true, actor: { uid: "u-admin" } });
    expect(claims.get("u-target")?.admin).toBe(true);

    const { req } = await run(server.checkAuth, authed("adminToken"));
    await server.setSystemAdminStatus({ email: "target@example.com", isAdmin: false, actor: req.user });
    expect(claims.get("u-target")?.admin).toBe(false);
    server.close();
  });

  it("doesn't create an account when demoting an email that has none", async () => {
    const { adminAuth, created } = fakeAuthWithAccounts({
      "admin@example.com": { uid: "u-admin", claims: { admin: true } }
    });
    const store = new InMemoryLanyardStore();
    const server = createLanyardServer({ adminAuth, store });

    expect(
      await server.setSystemAdminStatus({ email: "nobody@example.com", isAdmin: false, actor: { uid: "u-admin" } })
    ).toBeNull();
    expect(created).toEqual([]);
    expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
    server.close();
  });
});

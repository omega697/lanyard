import { describe, expect, it, vi } from "vitest";
import { InMemoryLanyardStore, createPermissionPolicy } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter, type AuthService } from "./index.js";

/**
 * The server owns every stored copy of a user's email, so when their verified email changes, checkAuth updates the
 * copy on each of their scope memberships as well as their global record. Staff then see the current address, and
 * scoped deleteUser confirms against it.
 */

const nowSeconds = () => Math.floor(Date.now() / 1000);

function tokenWithEmail(email: string): AuthService {
  return {
    async verifyToken() {
      const t = nowSeconds();
      return { uid: "u-1", email, emailVerified: true, adminClaim: false, issuedAtSeconds: t, authTimeSeconds: t - 60 };
    }
  };
}

const adminAuth = {
  verifyIdToken: async () => {
    throw new Error("not used");
  },
  getUserByEmail: async () => {
    throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
  },
  createUser: async () => ({ uid: "unused" }),
  setCustomUserClaims: async () => {},
  getUser: async (uid: string) => ({ uid, customClaims: {} })
} satisfies AdminAuthAdapter;

async function checkAuth(server: ReturnType<typeof createLanyardServer>) {
  const req: any = { headers: { authorization: "Bearer t" } };
  const res: any = { status: () => res, json: () => res };
  let nextCalled = false;
  await server.checkAuth(req, res, () => {
    nextCalled = true;
  });
  return nextCalled;
}

describe("verified email sync", () => {
  const policy = createPermissionPolicy({ roles: { member: { capabilities: [] } } });

  async function setup() {
    const store = new InMemoryLanyardStore({ policy });
    await store.upsertUser({ uid: "u-1", email: "old@example.com", roles: [] });
    for (const scopeId of ["org-a", "org-b"]) {
      await store.upsertScopeMember(scopeId, { uid: "u-1", email: "old@example.com", roles: ["member"] });
    }
    return store;
  }

  it("updates the user's email on every scope membership, not just the global record", async () => {
    const store = await setup();
    const server = createLanyardServer({ adminAuth, store, policy, authService: tokenWithEmail("new@example.com") });
    try {
      expect(await checkAuth(server)).toBe(true);
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
      expect((await store.getScopeMember("org-a", "u-1"))?.email).toBe("new@example.com");
      expect((await store.getScopeMember("org-b", "u-1"))?.email).toBe("new@example.com");
      expect(await store.listUserMembershipScopeIds("u-1")).toEqual(["org-a", "org-b"]);
    } finally {
      server.close();
    }
  });

  it("a failed membership update doesn't call onVerifiedEmailChange, so retries don't re-fire it", async () => {
    const store = await setup();
    const realPatch = store.patchScopeMember.bind(store);
    let failures = 2;
    store.patchScopeMember = async (scopeId, uid, fields) => {
      if (scopeId === "org-b" && failures > 0) {
        failures--;
        throw new Error("transient outage");
      }
      return realPatch(scopeId, uid, fields);
    };
    const onVerifiedEmailChange = vi.fn();
    const server = createLanyardServer({
      adminAuth,
      store,
      policy,
      authService: tokenWithEmail("new@example.com"),
      onVerifiedEmailChange
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await checkAuth(server);
      await checkAuth(server);
      expect(onVerifiedEmailChange).not.toHaveBeenCalled();
      await checkAuth(server);
      expect(onVerifiedEmailChange).toHaveBeenCalledTimes(1);
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
    } finally {
      warn.mockRestore();
      server.close();
    }
  });

  it("while the hook keeps failing, retries call it again without re-listing or re-writing memberships", async () => {
    const store = await setup();
    const listSpy = vi.spyOn(store, "listUserMembershipScopeIds");
    const patchSpy = vi.spyOn(store, "patchScopeMember");
    let hookFailures = 2;
    const onVerifiedEmailChange = vi.fn(async () => {
      if (hookFailures-- > 0) throw new Error("newsletter service down");
    });
    const server = createLanyardServer({
      adminAuth,
      store,
      policy,
      authService: tokenWithEmail("new@example.com"),
      onVerifiedEmailChange
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (let i = 0; i < 3; i++) await checkAuth(server);
      expect(onVerifiedEmailChange).toHaveBeenCalledTimes(3);
      expect(listSpy).toHaveBeenCalledTimes(1);
      expect(patchSpy).toHaveBeenCalledTimes(2); // org-a and org-b, once each
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
    } finally {
      warn.mockRestore();
      server.close();
    }
  });

  it("changing back to an earlier address while the hook is failing still updates the memberships", async () => {
    const store = await setup();
    let email = "b@example.com";
    const authService: AuthService = {
      async verifyToken() {
        const t = nowSeconds();
        return {
          uid: "u-1",
          email,
          emailVerified: true,
          adminClaim: false,
          issuedAtSeconds: t,
          authTimeSeconds: t - 60
        };
      }
    };
    let hookDown = true;
    const onVerifiedEmailChange = vi.fn(async () => {
      if (hookDown) throw new Error("newsletter service down");
    });
    const server = createLanyardServer({ adminAuth, store, policy, authService, onVerifiedEmailChange });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await checkAuth(server); // memberships -> b
      email = "c@example.com";
      await checkAuth(server); // memberships -> c
      email = "b@example.com";
      await checkAuth(server); // memberships must go back to b
      expect((await store.getScopeMember("org-a", "u-1"))?.email).toBe("b@example.com");
      hookDown = false;
      await checkAuth(server);
      expect((await store.getUser("u-1"))?.email).toBe("b@example.com");
      expect((await store.getScopeMember("org-b", "u-1"))?.email).toBe("b@example.com");
    } finally {
      warn.mockRestore();
      server.close();
    }
  });

  it("a server whose hook failed earlier still updates memberships when the email later changes back on it", async () => {
    const store = await setup();
    let email = "b@example.com";
    const authService: AuthService = {
      async verifyToken() {
        const t = nowSeconds();
        return {
          uid: "u-1",
          email,
          emailVerified: true,
          adminClaim: false,
          issuedAtSeconds: t,
          authTimeSeconds: t - 60
        };
      }
    };
    let hookDown = true;
    const failingHook = vi.fn(async (): Promise<void> => {
      if (hookDown) throw new Error("newsletter service down on this instance");
    });
    const one = createLanyardServer({ adminAuth, store, policy, authService, onVerifiedEmailChange: failingHook });
    const two = createLanyardServer({ adminAuth, store, policy, authService, onVerifiedEmailChange: async () => {} });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await checkAuth(one); // old -> b: memberships written, hook fails, so instance one remembers the pass
      await checkAuth(two); // instance two finishes old -> b
      email = "c@example.com";
      await checkAuth(two); // b -> c, fully
      email = "b@example.com";
      // c -> b back on instance one (its hook works again): its leftover note is for old -> b, not c -> b
      hookDown = false;
      await checkAuth(one);
      expect((await store.getUser("u-1"))?.email).toBe("b@example.com");
      expect((await store.getScopeMember("org-a", "u-1"))?.email).toBe("b@example.com");
    } finally {
      warn.mockRestore();
      one.close();
      two.close();
    }
  });

  it("if checking whether a failed membership still exists also fails, reports the original write error", async () => {
    const store = await setup();
    const writeError = new Error("membership write failed");
    store.patchScopeMember = async () => {
      throw writeError;
    };
    store.getScopeMember = async () => {
      throw new Error("lookup failed too");
    };
    const server = createLanyardServer({ adminAuth, store, policy, authService: tokenWithEmail("new@example.com") });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await checkAuth(server);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining("will retry"), writeError);
    } finally {
      warn.mockRestore();
      server.close();
    }
  });

  it("skips a membership that's removed while the sync runs, instead of failing every request", async () => {
    const store = await setup();
    const realPatch = store.patchScopeMember.bind(store);
    store.patchScopeMember = async (scopeId, uid, fields) => {
      if (scopeId === "org-b") await store.deleteScopeMember("org-b", uid); // left the scope meanwhile
      return realPatch(scopeId, uid, fields);
    };
    const server = createLanyardServer({ adminAuth, store, policy, authService: tokenWithEmail("new@example.com") });
    try {
      await checkAuth(server);
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
      expect((await store.getScopeMember("org-a", "u-1"))?.email).toBe("new@example.com");
    } finally {
      server.close();
    }
  });

  it("createLanyardServer refuses a store that can't list a user's memberships", () => {
    const store = new InMemoryLanyardStore({ policy });
    (store as any).listUserMembershipScopeIds = undefined;
    expect(() => createLanyardServer({ adminAuth, store, policy })).toThrow(/listUserMembershipScopeIds/);
  });

  it("if a membership can't be updated, leaves the global record unchanged so the next request retries", async () => {
    const store = await setup();
    const realPatch = store.patchScopeMember.bind(store);
    let failOnce = true;
    store.patchScopeMember = async (scopeId, uid, fields) => {
      if (scopeId === "org-b" && failOnce) {
        failOnce = false;
        throw new Error("transient outage");
      }
      return realPatch(scopeId, uid, fields);
    };
    const server = createLanyardServer({ adminAuth, store, policy, authService: tokenWithEmail("new@example.com") });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await checkAuth(server);
      expect((await store.getUser("u-1"))?.email).toBe("old@example.com");
      expect(warn).toHaveBeenCalled();

      await checkAuth(server);
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
      expect((await store.getScopeMember("org-b", "u-1"))?.email).toBe("new@example.com");
    } finally {
      warn.mockRestore();
      server.close();
    }
  });
});

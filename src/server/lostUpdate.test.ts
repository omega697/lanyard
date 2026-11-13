import { describe, expect, it, vi } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, createPermissionPolicy } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter, type AuthService } from "./index.js";

/**
 * Lost updates: a request reads a user's record, an admin changes their roles (or admin directory entry) meanwhile,
 * and the request then writes back what it read. Syncs (avatar, verified email) and profile edits must write only the
 * fields they change, so they can't undo a revocation that happened in between.
 */

type Role = "member" | "manager";
type Cap = "edit";
const policy = createPermissionPolicy<Role, Cap>({
  roles: { member: { capabilities: [] }, manager: { inherits: ["member"], capabilities: ["edit"] } }
});

const nowSeconds = () => Math.floor(Date.now() / 1000);

function tokenFor(uid: string, email: string, photoUrl: string): AuthService {
  return {
    async verifyToken() {
      const t = nowSeconds();
      return {
        uid,
        email,
        emailVerified: true,
        photoUrl,
        isAdmin: false,
        tokenIssuedAtSeconds: t,
        authTimeSeconds: t - 60
      };
    }
  };
}

const adminAuth: AdminAuthAdapter = {
  verifyIdToken: async () => {
    throw new Error("not used");
  },
  getUserByEmail: async () => {
    throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
  },
  createUser: async () => ({ uid: "unused" }),
  setCustomUserClaims: async () => {},
  getUser: async (uid: string) => ({ uid, customClaims: {} })
};

async function run(middleware: (req: any, res: any, next: () => void) => unknown, req: any) {
  const res: any = { statusCode: 200, status: (c: number) => ((res.statusCode = c), res), json: () => res };
  let nextCalled = false;
  await middleware(req, res, () => {
    nextCalled = true;
  });
  return { req, res, nextCalled };
}

/** Makes the next `method` read return what it read, after running `interleave` (the concurrent admin change). */
function interleaveAfterNextRead(store: any, method: "getUser" | "getScopeMember", interleave: () => Promise<void>) {
  const original = store[method].bind(store);
  vi.spyOn(store, method).mockImplementationOnce(async (...args: any[]) => {
    const snapshot = await original(...args);
    await interleave();
    return snapshot;
  });
}

describe("syncs and profile edits never write back stale roles or admin flags", () => {
  it("global avatar sync in requireCapability doesn't restore a role revoked mid-request", async () => {
    const store = new InMemoryLanyardStore<Role, Cap>();
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: ["manager"], photoUrl: null });
    const server = createLanyardServer({
      adminAuth,
      store,
      policy,
      authService: tokenFor("u-1", "u1@example.com", "https://example.com/new.png")
    });
    try {
      const { req } = await run(server.checkAuth, { headers: { authorization: "Bearer t" } });
      interleaveAfterNextRead(store, "getUser", () => store.revokeUserRoles("u-1", ["manager"]));
      await run(server.requireCapability("edit", GLOBAL_SCOPE), req);

      const after = await store.getUser("u-1");
      expect(after?.photoUrl).toBe("https://example.com/new.png");
      expect(after?.roles).toEqual([]);
    } finally {
      server.close();
    }
  });

  it("scoped avatar sync in requireRole doesn't restore a scope role revoked mid-request", async () => {
    const store = new InMemoryLanyardStore<Role, Cap>();
    await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: ["manager"], photoUrl: null });
    const server = createLanyardServer({
      adminAuth,
      store,
      policy,
      authService: tokenFor("u-1", "u1@example.com", "https://example.com/new.png")
    });
    try {
      const { req } = await run(server.checkAuth, { headers: { authorization: "Bearer t" } });
      req.params = { scopeId: "ws-1" };
      interleaveAfterNextRead(store, "getScopeMember", () => store.revokeScopeRoles("ws-1", "u-1", ["manager"]));
      await run(server.requireRole("member"), req);

      const after = await store.getScopeMember("ws-1", "u-1");
      expect(after?.photoUrl).toBe("https://example.com/new.png");
      expect(after?.roles).toEqual([]);
    } finally {
      server.close();
    }
  });

  it("the verified-email sync in checkAuth doesn't restore a role or admin flag removed mid-request", async () => {
    const store = new InMemoryLanyardStore<Role, Cap>();
    await store.upsertUser({ uid: "u-1", email: "old@example.com", roles: ["manager"], isSystemAdmin: true });
    const server = createLanyardServer({
      adminAuth,
      store,
      policy,
      authService: tokenFor("u-1", "new@example.com", "")
    });
    try {
      interleaveAfterNextRead(store, "getUser", async () => {
        await store.revokeUserRoles("u-1", ["manager"]);
        await store.deleteSystemAdmin("u-1");
      });
      await run(server.checkAuth, { headers: { authorization: "Bearer t" } });

      const after = await store.getUser("u-1");
      expect(after?.email).toBe("new@example.com");
      expect(after?.roles).toEqual([]);
      expect(after?.isSystemAdmin).not.toBe(true);
    } finally {
      server.close();
    }
  });

  it("updateUserProfile (global and scoped) doesn't restore roles revoked mid-request", async () => {
    const store = new InMemoryLanyardStore<Role, Cap>();
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: ["manager"] });
    await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: ["manager"] });
    const server = createLanyardServer({ adminAuth, store, policy });
    try {
      // The global path reads the actor's record and then the target's: revoke between the target read and the write
      const original = store.getUser.bind(store);
      let reads = 0;
      vi.spyOn(store, "getUser").mockImplementation(async (uid: string) => {
        const snapshot = await original(uid);
        if (++reads === 2) await store.revokeUserRoles("u-1", ["manager"]);
        return snapshot;
      });
      await server.updateUserProfile({
        scopeId: GLOBAL_SCOPE,
        actor: { uid: "u-1" },
        targetUid: "u-1",
        patch: { firstName: "Uno" }
      });
      vi.mocked(store.getUser).mockRestore();
      expect(await store.getUser("u-1")).toMatchObject({ firstName: "Uno", roles: [] });

      // Scoped: the actor's member read comes first, then the target's
      const originalMember = store.getScopeMember.bind(store);
      let memberReads = 0;
      vi.spyOn(store, "getScopeMember").mockImplementation(async (scopeId: string, uid: string) => {
        const snapshot = await originalMember(scopeId, uid);
        if (++memberReads === 2) await store.revokeScopeRoles("ws-1", "u-1", ["manager"]);
        return snapshot;
      });
      await server.updateUserProfile({
        scopeId: "ws-1",
        actor: { uid: "u-1" },
        targetUid: "u-1",
        patch: { firstName: "Uno" }
      });
      vi.mocked(store.getScopeMember).mockRestore();
      expect(await store.getScopeMember("ws-1", "u-1")).toMatchObject({ firstName: "Uno", roles: [] });
    } finally {
      server.close();
    }
  });
});

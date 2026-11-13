import { describe, expect, it, vi } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, type VerifiedEmailChangeEvent } from "./core/index.js";
import { createLanyardClient } from "./client/index.js";
import { createLanyardServer, type AdminAuthAdapter, type AuthService } from "./server/index.js";

/**
 * Email is server-owned: only provisioning (`upsertUserByEmail`) and the server's verified-email sync in `checkAuth`
 * write it. These tests reproduce what happened when clients and profile patches could write it too.
 */

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Tokens are keys into `users`; each carries the (verified) email it was issued with. */
function tokenTable(users: Record<string, { uid: string; email: string }>): AuthService {
  return {
    async verifyToken(authHeader) {
      const entry = users[(authHeader || "").replace(/^Bearer /, "")];
      if (!entry) return null;
      const t = nowSeconds();
      return {
        uid: entry.uid,
        email: entry.email,
        emailVerified: true,
        adminClaim: false,
        issuedAtSeconds: t,
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

async function runCheckAuth(server: ReturnType<typeof createLanyardServer>, token: string) {
  const req: any = { headers: { authorization: `Bearer ${token}` } };
  const res: any = { status: () => res, json: () => res };
  let nextCalled = false;
  await server.checkAuth(req, res, () => {
    nextCalled = true;
  });
  return { req, nextCalled };
}

describe("email is server-owned", () => {
  it("the server hook fires for a verified email change even while the user's browser is signed in (no client write races it)", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "old@example.com", roles: [], photoUrl: null });
    const events: VerifiedEmailChangeEvent[] = [];
    const server = createLanyardServer({
      adminAuth,
      store,
      authService: tokenTable({ newToken: { uid: "u-1", email: "new@example.com" } }),
      onVerifiedEmailChange: (event) => void events.push(event)
    });
    const client = createLanyardClient({ store, defaultPreferences: {} });
    const updateUserProfile = vi.spyOn(store, "updateUserProfile");
    const syncAvatar = vi.spyOn(store, "syncAvatar");
    try {
      // The user verified a new address in Firebase Auth; their browser loads first and sees the mismatch
      client.setActiveUser({
        uid: "u-1",
        email: "new@example.com",
        emailVerified: true,
        displayName: "User One",
        photoUrl: "https://example.com/u1.png",
        isAdmin: false,
        providerIds: ["google.com"]
      });
      await new Promise((resolve) => setTimeout(resolve, 0));

      // The browser wrote nothing about email...
      expect(updateUserProfile).not.toHaveBeenCalled();
      for (const [params] of syncAvatar.mock.calls) expect(params).not.toHaveProperty("email");
      expect((await store.getUser("u-1"))?.email).toBe("old@example.com");

      // ...so the server's hook sees the change and fires, exactly once
      await runCheckAuth(server, "newToken");
      expect(events).toEqual([{ uid: "u-1", email: "new@example.com", previousEmail: "old@example.com" }]);
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
    } finally {
      client.destroy();
      server.close();
    }
  });

  it("updateUserProfile refuses to change a stored email, so nobody can plant a fake previousEmail", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-attacker", email: "attacker@example.com", roles: [] });
    const events: VerifiedEmailChangeEvent[] = [];
    const server = createLanyardServer({
      adminAuth,
      store,
      authService: tokenTable({ attackerToken: { uid: "u-attacker", email: "attacker@example.com" } }),
      onVerifiedEmailChange: (event) => void events.push(event)
    });
    try {
      // Plant the victim's address as "previous email": a hook that migrates data keyed by the old email would then
      // hand the victim's data to the attacker on their next request
      await expect(
        server.updateUserProfile({
          scopeId: GLOBAL_SCOPE,
          actor: { uid: "u-attacker" },
          targetUid: "u-attacker",
          patch: { email: "victim@example.com" } as any
        })
      ).rejects.toThrow(/email/i);
      expect((await store.getUser("u-attacker"))?.email).toBe("attacker@example.com");

      await runCheckAuth(server, "attackerToken");
      expect(events).toEqual([]);
    } finally {
      server.close();
    }
  });

  it("the client store and in-memory store refuse email in profile patches", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "me@example.com", roles: [] });
    await store.upsertScopeMember("ws-1", { uid: "u-1", email: "me@example.com", roles: [] });
    await expect(store.updateUserProfile("u-1", { email: "other@example.com" } as any)).rejects.toThrow(/email/i);
    await expect(store.updateScopeMemberProfile("ws-1", "u-1", { email: "other@example.com" } as any)).rejects.toThrow(
      /email/i
    );
    expect((await store.getUser("u-1"))?.email).toBe("me@example.com");
    expect((await store.getScopeMember("ws-1", "u-1"))?.email).toBe("me@example.com");
  });

  it("checkAuth fills in a missing stored email from the verified token without calling the change hook", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "", roles: [] });
    const onVerifiedEmailChange = vi.fn();
    const server = createLanyardServer({
      adminAuth,
      store,
      authService: tokenTable({ token: { uid: "u-1", email: "first@example.com" } }),
      onVerifiedEmailChange
    });
    try {
      await runCheckAuth(server, "token");
      expect((await store.getUser("u-1"))?.email).toBe("first@example.com");
      expect(onVerifiedEmailChange).not.toHaveBeenCalled();
    } finally {
      server.close();
    }
  });

  it("a failing email sync is reported instead of swallowed, and is retried on the next request", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "old@example.com", roles: [] });
    const onVerifiedEmailChange = vi.fn().mockRejectedValueOnce(new Error("newsletter API down"));
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const server = createLanyardServer({
      adminAuth,
      store,
      authService: tokenTable({ token: { uid: "u-1", email: "new@example.com" } }),
      onVerifiedEmailChange
    });
    try {
      const first = await runCheckAuth(server, "token");
      expect(first.nextCalled).toBe(true);
      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/verified email/i), expect.any(Error));
      expect((await store.getUser("u-1"))?.email).toBe("old@example.com");

      await runCheckAuth(server, "token");
      expect(onVerifiedEmailChange).toHaveBeenCalledTimes(2);
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
    } finally {
      warn.mockRestore();
      server.close();
    }
  });
});

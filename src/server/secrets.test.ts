import { describe, expect, it, vi } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, createPermissionPolicy } from "../core/index.js";
import { withoutUndeclaredSecretKeys } from "../core/tierDocs.js";
import { createLanyardServer, type AdminAuthAdapter } from "./index.js";

/**
 * Secrets are closed-world: a key exists only if the policy declares it, and declaring it says exactly who may write
 * it. Self-writing is opt-in. Server code (and stores) refuse undeclared keys, so a route that forwards a patch can't
 * plant values that other server code later trusts.
 */

type Role = "member" | "billing";
type Cap = "manage_billing";
const roles = {
  member: { capabilities: [] as Cap[] },
  billing: { inherits: ["member"] as Role[], capabilities: ["manage_billing"] as Cap[] }
};
const secretCapabilities = {
  geminiKey: { self: true }, // the user's own API key
  orgApiKey: "manage_billing" as Cap, // billing staff only (shorthand)
  gmailRefreshToken: {} // trusted server code only (e.g. an OAuth callback)
};

function fakeAdminAuth(admins: string[] = []) {
  return {
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async () => {
      throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
    },
    createUser: async () => ({ uid: "unused" }),
    setCustomUserClaims: async () => {},
    getUser: async (uid: string) => ({ uid, customClaims: admins.includes(uid) ? { admin: true } : {} })
  } satisfies AdminAuthAdapter;
}

describe("secret rules", () => {
  const policy = createPermissionPolicy<Role, Cap>({ roles, secretCapabilities });
  const member = { roles: ["member"] as Role[] };
  const billing = { roles: ["billing"] as Role[] };

  it("refuse undeclared keys to everyone, even system admins", () => {
    for (const options of [{ isSelf: true }, { isSystemAdmin: true }, { isSelf: true, isSystemAdmin: true }]) {
      expect(policy.canWriteSecret(billing, "gmailAccessToken", options)).toBe(false);
    }
  });

  it("make self-writing opt-in: a capability rule doesn't let users write their own copy", () => {
    expect(policy.canWriteSecret(member, "orgApiKey", { isSelf: true })).toBe(false);
    expect(policy.canWriteSecret(billing, "orgApiKey", { isSelf: false })).toBe(true);
    expect(policy.canWriteSecret(member, "geminiKey", { isSelf: true })).toBe(true);
    expect(policy.canWriteSecret(billing, "geminiKey", { isSelf: false })).toBe(false);
    // {} = admins and trusted server code only
    expect(policy.canWriteSecret(member, "gmailRefreshToken", { isSelf: true })).toBe(false);
    expect(policy.canWriteSecret(billing, "gmailRefreshToken", { isSystemAdmin: true })).toBe(true);
    expect(policy.secretKeys).toEqual(["geminiKey", "orgApiKey", "gmailRefreshToken"]);
  });

  it("reject the legacy write/allowSelfWrite shape instead of silently flipping its default", () => {
    expect(() =>
      createPermissionPolicy<Role, Cap>({ roles, secretCapabilities: { k: { write: "manage_billing" } as any } })
    ).toThrow(/secretCapabilities\.k.*'write'.*'allowSelfWrite'/);
    expect(() =>
      createPermissionPolicy<Role, Cap>({ roles, secretCapabilities: { k: { allowSelfWrite: true } as any } })
    ).toThrow(/secretCapabilities\.k/);
  });
});

describe("server and store enforcement", () => {
  const policy = createPermissionPolicy<Role, Cap>({ roles, secretCapabilities });

  it("a user can't plant an undeclared secret through updateUserSecrets", async () => {
    const store = new InMemoryLanyardStore<Role, Cap>({ policy });
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: ["member"] });
    const server = createLanyardServer({ adminAuth: fakeAdminAuth(), store, policy });
    try {
      await expect(
        server.updateUserSecrets({
          scopeId: GLOBAL_SCOPE,
          actor: { uid: "u-1" },
          targetUid: "u-1",
          patch: { gmailRefreshToken: "attacker-token" } as any
        })
      ).rejects.toThrow(/Forbidden/);
      await expect(
        server.updateUserSecrets({
          scopeId: GLOBAL_SCOPE,
          actor: { uid: "u-1" },
          targetUid: "u-1",
          patch: { someUndeclaredKey: "x" } as any
        })
      ).rejects.toThrow(/Forbidden/);
      expect(await store.getUserSecrets("u-1")).toEqual({});

      // Their own declared key works
      await server.updateUserSecrets({
        scopeId: GLOBAL_SCOPE,
        actor: { uid: "u-1" },
        targetUid: "u-1",
        patch: { geminiKey: "mine" }
      });
      expect(await store.getUserSecrets("u-1")).toEqual({ geminiKey: "mine" });
    } finally {
      server.close();
    }
  });

  it("stores refuse undeclared keys even when called directly, and refuse all secrets without a policy", async () => {
    const store = new InMemoryLanyardStore<Role, Cap>({ policy });
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [] });
    await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: [] });
    await expect(store.updateUserSecrets("u-1", { notDeclared: "x" } as any)).rejects.toThrow(/not declared/);
    await expect(store.updateScopeMemberSecrets("ws-1", "u-1", { notDeclared: "x" } as any)).rejects.toThrow(
      /not declared/
    );
    // Declared keys, including server-only ones, are writable by trusted server code
    await store.updateScopeMemberSecrets("ws-1", "u-1", { gmailRefreshToken: "server-token" });
    expect(await store.getScopeMemberSecrets("ws-1", "u-1")).toEqual({ gmailRefreshToken: "server-token" });

    const noPolicy = new InMemoryLanyardStore();
    await noPolicy.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [] });
    await expect(noPolicy.updateUserSecrets("u-1", { geminiKey: "x" })).rejects.toThrow(/policy/);
  });

  it("createLanyardServer refuses a store whose declared secret keys differ from the policy's", () => {
    const store = new InMemoryLanyardStore<Role, Cap>({
      policy: createPermissionPolicy<Role, Cap>({ roles, secretCapabilities: { geminiKey: { self: true } } })
    });
    expect(() => createLanyardServer({ adminAuth: fakeAdminAuth(), store, policy })).toThrow(/secret keys/);
  });
});

describe("undeclared stored keys", () => {
  it("are dropped on every read but warned about only once per location and key", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (let i = 0; i < 3; i++) {
        expect(withoutUndeclaredSecretKeys(["geminiKey"], { geminiKey: "a", stray: "b" }, "users/u-warn")).toEqual({
          geminiKey: "a"
        });
      }
      expect(warn).toHaveBeenCalledTimes(1);
      withoutUndeclaredSecretKeys(["geminiKey"], { stray: "b" }, "users/u-other");
      expect(warn).toHaveBeenCalledTimes(2);

      // Memory stays bounded: after 1000 more distinct locations, the record of what was warned about starts over
      for (let i = 0; i < 1000; i++) withoutUndeclaredSecretKeys([], { stray: "b" }, `users/u-many-${i}`);
      warn.mockClear();
      withoutUndeclaredSecretKeys(["geminiKey"], { stray: "b" }, "users/u-warn");
      expect(warn).toHaveBeenCalledTimes(1);
    } finally {
      warn.mockRestore();
    }
  });
});

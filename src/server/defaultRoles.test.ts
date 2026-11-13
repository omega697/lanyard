import { describe, expect, it, vi } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, createPermissionPolicy } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter } from "./index.js";

/**
 * Default roles are a provisioning convenience: they fill in an omitted `roles` when a record is created, and nothing
 * else. Revoking every role must leave a user with no roles, and nothing may re-grant defaults later.
 */

type Role = "member" | "staff";
type Cap = "edit";
const roles = {
  member: { capabilities: [] as Cap[] },
  staff: { inherits: ["member"] as Role[], capabilities: ["edit"] as Cap[] }
};

function fakeAdminAuth() {
  const accounts = new Map<string, string>();
  let n = 0;
  return {
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async (email: string) => {
      const uid = accounts.get(email);
      if (!uid) throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
      return { uid, email, emailVerified: true };
    },
    createUser: async (props: { email: string }) => {
      const uid = `u-${++n}`;
      accounts.set(props.email, uid);
      return { uid, email: props.email, emailVerified: true };
    },
    setCustomUserClaims: async () => {},
    getUser: async (uid: string) => ({ uid, customClaims: {} })
  } satisfies AdminAuthAdapter;
}

describe("policy defaultRoles", () => {
  it("are empty unless listed, and an unknown role name is an error instead of a silent fallback", () => {
    expect(createPermissionPolicy<Role, Cap>({ roles }).defaultRoles).toEqual([]);
    expect(createPermissionPolicy<Role, Cap>({ roles, defaultRoles: ["member"] }).defaultRoles).toEqual(["member"]);
    expect(() => createPermissionPolicy<Role, Cap>({ roles, defaultRoles: ["mmeber" as Role] })).toThrow(
      /Invalid defaultRoles 'mmeber'/
    );
  });

  it("aren't assumed for a record without roles when deciding presence tracking", () => {
    const policy = createPermissionPolicy<Role, Cap>({
      roles: { member: { capabilities: [], trackPresence: true }, staff: { capabilities: ["edit"] } },
      defaultRoles: ["member"]
    });
    expect(policy.shouldTrackPresence({ roles: undefined } as any)).toBe(false);
    expect(policy.shouldTrackPresence({ roles: ["member"] })).toBe(true);
  });
});

describe("upsertUserByEmail applies defaults only when it creates a record", () => {
  it("gives a new user the defaults, but leaves an existing user's roles alone, even when they're empty", async () => {
    const policy = createPermissionPolicy<Role, Cap>({ roles, defaultRoles: ["member"] });
    const store = new InMemoryLanyardStore<Role, Cap>();
    const server = createLanyardServer({ adminAuth: fakeAdminAuth(), store, policy });
    try {
      const created = await server.upsertUserByEmail({ scopeId: GLOBAL_SCOPE, email: "new@example.com" });
      expect(created.roles).toEqual(["member"]);
      const member = await server.upsertUserByEmail({ scopeId: "ws-1", email: "new@example.com" });
      expect(member.roles).toEqual(["member"]);

      // Every role revoked: a later profile upsert must not hand the defaults back
      await store.revokeUserRoles(created.uid, ["member"]);
      await store.revokeScopeRoles("ws-1", created.uid, ["member"]);
      await server.upsertUserByEmail({ scopeId: GLOBAL_SCOPE, email: "new@example.com", firstName: "Nu" });
      await server.upsertUserByEmail({ scopeId: "ws-1", email: "new@example.com", firstName: "Nu" });
      expect(await store.getUser(created.uid)).toMatchObject({ firstName: "Nu", roles: [] });
      expect(await store.getScopeMember("ws-1", created.uid)).toMatchObject({ firstName: "Nu", roles: [] });
    } finally {
      server.close();
    }
  });

  it("grants never add defaults, even to a new member", async () => {
    const policy = createPermissionPolicy<Role, Cap>({ roles, defaultRoles: ["staff"] });
    const store = new InMemoryLanyardStore<Role, Cap>();
    const server = createLanyardServer({ adminAuth: fakeAdminAuth(), store, policy });
    try {
      const volunteer = await server.grantRolesByEmail({ scopeId: "ws-1", email: "volunteer@example.com", roles: [] });
      expect((await store.getScopeMember("ws-1", volunteer.uid))?.roles).toEqual([]);
    } finally {
      server.close();
    }
  });

  it("doesn't write back roles or admin status it read, so a concurrent revocation or demotion sticks", async () => {
    const policy = createPermissionPolicy<Role, Cap>({ roles, defaultRoles: ["member"] });
    const store = new InMemoryLanyardStore<Role, Cap>();
    const server = createLanyardServer({ adminAuth: fakeAdminAuth(), store, policy });
    try {
      const user = await server.upsertUserByEmail({ scopeId: GLOBAL_SCOPE, email: "u@example.com", roles: ["staff"] });
      await store.upsertSystemAdmin({ uid: user.uid, email: "u@example.com", isSystemAdmin: true });
      const original = store.getUser.bind(store);
      vi.spyOn(store, "getUser").mockImplementationOnce(async (uid: string) => {
        const snapshot = await original(uid);
        await store.revokeUserRoles(uid, ["staff"]);
        await store.deleteSystemAdmin(uid);
        return snapshot;
      });
      await server.upsertUserByEmail({ scopeId: GLOBAL_SCOPE, email: "u@example.com", lastName: "Later" });
      vi.mocked(store.getUser).mockRestore();
      const after = await store.getUser(user.uid);
      expect(after).toMatchObject({ lastName: "Later", roles: [] });
      expect(after?.isSystemAdmin).not.toBe(true);
    } finally {
      server.close();
    }
  });

  it("filling defaults into a card that never had roles doesn't overwrite a role granted at the same moment", async () => {
    const policy = createPermissionPolicy<Role, Cap>({ roles, defaultRoles: ["member"] });
    const store = new InMemoryLanyardStore<Role, Cap>();
    const adminAuth = fakeAdminAuth();
    const server = createLanyardServer({ adminAuth, store, policy });
    try {
      // A bare card the user created for themselves (no roles field), for an existing account
      const { uid } = await adminAuth.createUser({ email: "stub@example.com" });
      await store.upsertUser({ uid, email: "stub@example.com" } as any);
      expect((await store.getUser(uid))?.roles).toBeUndefined();

      const original = store.getUser.bind(store);
      vi.spyOn(store, "getUser").mockImplementationOnce(async (id: string) => {
        const snapshot = await original(id);
        await store.grantUserRoles(id, ["staff"]); // e.g. an admin's grant, between the read and the write
        return snapshot;
      });
      await server.upsertUserByEmail({ scopeId: GLOBAL_SCOPE, email: "stub@example.com", firstName: "Stub" });
      vi.mocked(store.getUser).mockRestore();
      expect((await store.getUser(uid))?.roles).toEqual(expect.arrayContaining(["staff", "member"]));
    } finally {
      server.close();
    }
  });
});

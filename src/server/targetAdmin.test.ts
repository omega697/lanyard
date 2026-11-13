import { describe, expect, it, vi } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, createPermissionPolicy } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter } from "./index.js";

/**
 * A non-admin with user-management capabilities must never be able to edit, re-role, or delete a system admin. Admin
 * status is the Firebase claim, so these guards must check the target's claim, not the store's directory flag (which
 * an admin promoted through the console or a script never got).
 */

type Role = "member" | "staff";
type Cap = "manage";
const policy = createPermissionPolicy<Role, Cap>({
  roles: { member: { capabilities: [] }, staff: { inherits: ["member"], capabilities: ["manage"] } },
  userCapabilities: { write: "manage", assignRoles: "manage" }
});

function fakeAdminAuth(claims: Record<string, Record<string, any>>) {
  return {
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async () => {
      throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
    },
    createUser: async () => ({ uid: "unused" }),
    setCustomUserClaims: async () => {},
    deleteUser: vi.fn(async () => {}),
    getUser: vi.fn(async (uid: string) => {
      if (!(uid in claims)) throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
      return { uid, customClaims: claims[uid] };
    })
  } satisfies AdminAuthAdapter;
}

async function setup(claims: Record<string, Record<string, any>>) {
  const store = new InMemoryLanyardStore<Role, Cap>();
  // The staff member manages users globally and in ws-1
  await store.upsertUser({ uid: "u-staff", email: "staff@example.com", roles: ["staff"] });
  await store.upsertScopeMember("ws-1", { uid: "u-staff", email: "staff@example.com", roles: ["staff"] });
  // An admin known only by their Firebase claim: no isSystemAdmin flag on their record
  await store.upsertUser({ uid: "u-admin", email: "admin@example.com", roles: ["member"], firstName: "Ada" });
  await store.upsertScopeMember("ws-1", { uid: "u-admin", email: "admin@example.com", roles: ["member"] });
  // An ordinary user
  await store.upsertUser({ uid: "u-plain", email: "plain@example.com", roles: ["member"] });
  await store.upsertScopeMember("ws-1", { uid: "u-plain", email: "plain@example.com", roles: ["member"] });
  const adminAuth = fakeAdminAuth(claims);
  const server = createLanyardServer({ adminAuth, store, policy });
  return { store, adminAuth, server };
}

const staff = { uid: "u-staff" };

describe("non-admins can't edit, re-role, or delete a system admin (by claim)", () => {
  it("is refused globally and in a scope, even when the admin's record has no isSystemAdmin flag", async () => {
    const { store, adminAuth, server } = await setup({ "u-staff": {}, "u-admin": { admin: true }, "u-plain": {} });
    try {
      for (const scopeId of [GLOBAL_SCOPE, "ws-1"] as const) {
        await expect(
          server.updateUserProfile({ scopeId, actor: staff, targetUid: "u-admin", patch: { firstName: "Pwned" } })
        ).rejects.toThrow(/Forbidden/);
        await expect(
          server.updateUserRoles({ scopeId, actor: staff, targetUid: "u-admin", roles: [] })
        ).rejects.toThrow(/Forbidden/);
        await expect(
          server.deleteUser({ scopeId, actor: staff, targetUid: "u-admin", confirmTargetEmail: "admin@example.com" })
        ).rejects.toThrow(/Forbidden/);
      }
      expect(adminAuth.deleteUser).not.toHaveBeenCalled();
      expect(await store.getUser("u-admin")).toMatchObject({ firstName: "Ada", roles: ["member"] });
      expect(await store.getScopeMember("ws-1", "u-admin")).toMatchObject({ roles: ["member"] });
    } finally {
      server.close();
    }
  });

  it("fails closed: if the target's claim can't be checked, they're treated as an admin", async () => {
    const { adminAuth, server } = await setup({ "u-staff": {}, "u-admin": {}, "u-plain": {} });
    adminAuth.getUser.mockImplementation(async (uid: string) => {
      if (uid === "u-plain") throw new Error("Firebase unavailable");
      return { uid, customClaims: {} };
    });
    try {
      await expect(
        server.deleteUser({
          scopeId: GLOBAL_SCOPE,
          actor: staff,
          targetUid: "u-plain",
          confirmTargetEmail: "plain@example.com"
        })
      ).rejects.toThrow(/Forbidden/);
      expect(adminAuth.deleteUser).not.toHaveBeenCalled();
    } finally {
      server.close();
    }
  });

  it("still lets staff manage ordinary users, including ones with no Firebase account yet", async () => {
    const { store, server } = await setup({ "u-staff": {}, "u-admin": { admin: true } });
    try {
      // u-plain has no Firebase account in this fake (user-not-found): they can't hold the admin claim
      await server.updateUserProfile({
        scopeId: "ws-1",
        actor: staff,
        targetUid: "u-plain",
        patch: { firstName: "P" }
      });
      await server.updateUserRoles({ scopeId: GLOBAL_SCOPE, actor: staff, targetUid: "u-plain", roles: ["staff"] });
      expect((await store.getUser("u-plain"))?.roles).toEqual(["staff"]);
      await server.deleteUser({
        scopeId: "ws-1",
        actor: staff,
        targetUid: "u-plain",
        confirmTargetEmail: "plain@example.com"
      });
      expect(await store.getScopeMember("ws-1", "u-plain")).toBeNull();
    } finally {
      server.close();
    }
  });

  it("admins can still manage other admins", async () => {
    const { store, server } = await setup({ "u-staff": {}, "u-admin": { admin: true }, "u-root": { admin: true } });
    try {
      await server.updateUserProfile({
        scopeId: GLOBAL_SCOPE,
        actor: { uid: "u-root" },
        targetUid: "u-admin",
        patch: { firstName: "Adaline" }
      });
      expect((await store.getUser("u-admin"))?.firstName).toBe("Adaline");
    } finally {
      server.close();
    }
  });
});

describe("adminAuth.getUser", () => {
  it("is required, so admin checks never silently treat every actor as a non-admin and every target as an admin", () => {
    const { getUser: _omitted, ...withoutGetUser } = fakeAdminAuth({});
    expect(() =>
      createLanyardServer({ adminAuth: withoutGetUser as any, store: new InMemoryLanyardStore<Role, Cap>(), policy })
    ).toThrow(/adminAuth\.getUser/);
  });
});

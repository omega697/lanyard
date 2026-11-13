import { describe, expect, it } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, createPermissionPolicy, type ScopeId } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter } from "./index.js";

/**
 * Deleting someone is irreversible (the global delete removes their Firebase account and all their data; a scoped one
 * removes their membership and that scope's private data), so it has its own capability, userCapabilities.delete,
 * which nobody but admins holds unless the app grants it. Like every capability it's checked against the actor's roles
 * in that scope, so a role that may remove members from a campaign doesn't thereby delete accounts.
 */

type Role = "member" | "editor" | "coordinator";
type Cap = "edit_users" | "remove_members";
const roles = {
  member: { capabilities: [] as Cap[] },
  editor: { inherits: ["member"] as Role[], capabilities: ["edit_users"] as Cap[] },
  coordinator: { inherits: ["editor"] as Role[], capabilities: ["edit_users", "remove_members"] as Cap[] }
};

function fakeAdminAuth(admins: string[] = []) {
  const deleted: string[] = [];
  return {
    deleted,
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async () => {
      throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
    },
    createUser: async () => ({ uid: "unused" }),
    setCustomUserClaims: async () => {},
    getUser: async (uid: string) => ({ uid, customClaims: admins.includes(uid) ? { admin: true } : {} }),
    deleteUser: async (uid: string) => {
      deleted.push(uid);
    }
  } satisfies AdminAuthAdapter & { deleted: string[] };
}

async function setup(policyConfig: Parameters<typeof createPermissionPolicy<Role, Cap>>[0], admins: string[] = []) {
  const policy = createPermissionPolicy<Role, Cap>(policyConfig);
  const store = new InMemoryLanyardStore<Role, Cap>({ policy });
  const people: Record<string, { global: Role[]; scoped: Role[] }> = {
    staff: { global: ["editor"], scoped: ["coordinator"] },
    editor: { global: ["editor"], scoped: ["editor"] },
    target: { global: ["member"], scoped: ["member"] },
    root: { global: [], scoped: [] }
  };
  for (const [uid, r] of Object.entries(people)) {
    await store.upsertUser({ uid, email: `${uid}@example.com`, roles: r.global });
    await store.upsertScopeMember("org-1", { uid, email: `${uid}@example.com`, roles: r.scoped });
  }
  const adminAuth = fakeAdminAuth(admins);
  const server = createLanyardServer({ adminAuth, store, policy });
  const remove = (actor: string, targetUid: string, scopeId: ScopeId) =>
    server.deleteUser({ scopeId, actor: { uid: actor }, targetUid, confirmTargetEmail: `${targetUid}@example.com` });
  return { store, server, adminAuth, remove };
}

describe("userCapabilities.delete", () => {
  it("being able to edit users doesn't let staff delete accounts or remove members", async () => {
    const { store, server, adminAuth, remove } = await setup({ roles, userCapabilities: { write: "edit_users" } });
    try {
      await expect(remove("editor", "target", GLOBAL_SCOPE)).rejects.toThrow(/Insufficient permissions to delete/);
      await expect(remove("editor", "target", "org-1")).rejects.toThrow(/Insufficient permissions to delete/);
      expect(adminAuth.deleted).toEqual([]);
      expect(await store.getUser("target")).not.toBeNull();
      expect(await store.getScopeMember("org-1", "target")).not.toBeNull();
    } finally {
      server.close();
    }
  });

  it("is admin-only unless configured, and admins can always delete", async () => {
    const { store, server, adminAuth, remove } = await setup({ roles, userCapabilities: { write: "edit_users" } }, [
      "root"
    ]);
    try {
      await remove("root", "target", "org-1");
      expect(await store.getScopeMember("org-1", "target")).toBeNull();
      await remove("root", "target", GLOBAL_SCOPE);
      expect(adminAuth.deleted).toEqual(["target"]);
    } finally {
      server.close();
    }
  });

  it("granted through a scope role, it removes members from that scope but doesn't delete accounts", async () => {
    const { store, server, adminAuth, remove } = await setup({
      roles,
      userCapabilities: { write: "edit_users", delete: "remove_members" }
    });
    try {
      // staff is a coordinator (remove_members) in org-1, but only an editor globally
      await remove("staff", "target", "org-1");
      expect(await store.getScopeMember("org-1", "target")).toBeNull();
      await expect(remove("staff", "target", GLOBAL_SCOPE)).rejects.toThrow(/Insufficient permissions to delete/);
      expect(adminAuth.deleted).toEqual([]);
      expect(await store.getUser("target")).not.toBeNull();
    } finally {
      server.close();
    }
  });

  it("deleting yourself or leaving a scope needs no capability", async () => {
    const { store, server, adminAuth, remove } = await setup({ roles });
    try {
      await remove("target", "target", "org-1");
      expect(await store.getScopeMember("org-1", "target")).toBeNull();
      await remove("target", "target", GLOBAL_SCOPE);
      expect(adminAuth.deleted).toEqual(["target"]);
    } finally {
      server.close();
    }
  });

  it("isn't granted by the string shorthand, which covers read, write and assignRoles only", () => {
    const policy = createPermissionPolicy<Role, Cap>({ roles, userCapabilities: "edit_users" });
    expect(policy.canWriteUser({ roles: ["editor"] })).toBe(true);
    expect(policy.canDeleteUser({ roles: ["editor"] })).toBe(false);
    expect(policy.canDeleteUser(null, true)).toBe(true);
    expect(policy.userCapabilities.delete).toBeUndefined();
  });
});

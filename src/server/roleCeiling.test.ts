import { describe, expect, it } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, createPermissionPolicy, type ScopeId } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter } from "./index.js";

/**
 * Role assignment has a ceiling: a non-admin who holds the assign-roles capability may add or remove only roles within
 * their rank (the roles they hold plus everything those inherit), and may change only targets whose current roles are
 * all within it. Nobody changes their own roles. Peers of equal rank may manage each other. System-managed roles are
 * owned by trusted server code: updateUserRoles never adds them, keeps the ones a user holds, and ignores them when
 * checking rank.
 */

type Role = "volunteer" | "scanner" | "greeter" | "lead" | "coordinator" | "owner";
type Cap = "scan" | "assign_roles" | "manage";
const capabilities: Cap[] = ["scan", "assign_roles", "manage"];
const roles = {
  // Kept in sync with a roster by server code
  volunteer: { systemManaged: true, capabilities: [] as Cap[] },
  scanner: { capabilities: ["scan"] as Cap[] },
  // Same capabilities as scanner, but a different role
  greeter: { capabilities: ["scan"] as Cap[] },
  // Manages greeters only
  lead: { inherits: ["greeter"] as Role[], capabilities: ["assign_roles"] as Cap[] },
  coordinator: { inherits: ["scanner"] as Role[], capabilities: ["assign_roles", "manage"] as Cap[] },
  owner: { inherits: ["coordinator", "greeter", "lead"] as Role[], capabilities: "*" as const }
};
const userCapabilities = { assignRoles: "assign_roles" as Cap, write: "manage" as Cap };

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

describe("role ceiling in the policy", () => {
  const policy = createPermissionPolicy<Role, Cap>({ capabilities, roles, userCapabilities });

  it("lists only the roles an actor may assign: within their rank, concrete, and not system-managed", () => {
    expect(policy.getAssignableRoles({ roles: ["coordinator"] })).toEqual(["scanner", "coordinator"]);
    expect(policy.getAssignableRoles({ roles: ["lead"] })).toEqual(["greeter", "lead"]);
    expect(policy.getAssignableRoles({ roles: ["owner"] })).toEqual([
      "scanner",
      "greeter",
      "lead",
      "coordinator",
      "owner"
    ]);
    // Holding roles isn't enough without the assign-roles capability
    expect(policy.getAssignableRoles({ roles: ["scanner"] })).toEqual([]);
    expect(policy.getAssignableRoles(null)).toEqual([]);
    // Admins may assign every concrete role except system-managed ones
    expect(policy.getAssignableRoles(null, true)).toEqual(["scanner", "greeter", "lead", "coordinator", "owner"]);
    expect(policy.isSystemManagedRole("volunteer")).toBe(true);
    expect(policy.isSystemManagedRole("scanner")).toBe(false);
  });

  it("rank comes from inherits, not from matching capabilities", () => {
    // greeter has exactly scanner's capabilities, yet a coordinator (who inherits scanner) can't assign it
    expect(policy.canAssignRole({ roles: ["coordinator"] }, "scanner")).toBe(true);
    expect(policy.canAssignRole({ roles: ["coordinator"] }, "greeter")).toBe(false);
    expect(policy.canAssignRole({ roles: ["lead"] }, "scanner")).toBe(false);
    expect(policy.canAssignRole({ roles: ["owner"] }, "volunteer")).toBe(false);
    expect(policy.canAssignRole(null, "volunteer", true)).toBe(false);
  });

  it("refuses a wildcard role that can't assign or manage every other role, when non-admins can do either", () => {
    const flatOwner = {
      member: { capabilities: [] as Cap[] },
      owner: { capabilities: "*" as const }
    };
    expect(() =>
      createPermissionPolicy<"member" | "owner", Cap>({ capabilities, roles: flatOwner, userCapabilities })
    ).toThrow(/Role 'owner' has every capability but can't assign or manage 'member'.*inherits/);
    // Managing users (write) is held to rank too, so the same applies without assign-roles
    expect(() =>
      createPermissionPolicy<"member" | "owner", Cap>({
        capabilities,
        roles: flatOwner,
        userCapabilities: { write: "manage" }
      })
    ).toThrow(/can't assign or manage 'member'/);
    // Without assign-roles or write, only admins manage users and roles, so rank doesn't matter
    expect(() => createPermissionPolicy<"member" | "owner", Cap>({ capabilities, roles: flatOwner })).not.toThrow();
    // System-managed roles don't need to be reachable (canvus's owner doesn't inherit volunteer)
    expect(() =>
      createPermissionPolicy<"volunteer" | "owner", Cap>({
        capabilities,
        roles: { volunteer: { systemManaged: true }, owner: { capabilities: "*" } },
        userCapabilities
      })
    ).not.toThrow();
  });

  it("accepts a role ranked above a wildcard role (a protected founder), and ranks it above owners", () => {
    type Ranked = "member" | "owner" | "superowner";
    const ranked = createPermissionPolicy<Ranked, Cap>({
      capabilities,
      roles: {
        member: { capabilities: [] },
        owner: { inherits: ["member"], capabilities: "*" },
        // Every capability (through owner), and outranks owners
        superowner: { inherits: ["owner"] }
      },
      userCapabilities
    });
    expect(ranked.getAssignableRoles({ roles: ["superowner"] })).toEqual(["member", "owner", "superowner"]);
    expect(ranked.getAssignableRoles({ roles: ["owner"] })).toEqual(["member", "owner"]);
    expect(ranked.canAssignRole({ roles: ["owner"] }, "superowner")).toBe(false);
  });

  it("rejects a role that is both systemManaged and abstract", () => {
    expect(() =>
      createPermissionPolicy<"base" | "member", Cap>({
        roles: { base: { abstract: true, systemManaged: true }, member: { inherits: ["base"] } }
      })
    ).toThrow(/'base'.*abstract.*systemManaged/);
  });
});

describe("role ceiling in updateUserRoles", () => {
  const policy = createPermissionPolicy<Role, Cap>({ capabilities, roles, userCapabilities });
  const scopeId = "campaign-1";

  async function setup(members: Record<string, Role[]>, admins: string[] = []) {
    const store = new InMemoryLanyardStore<Role, Cap>({ policy });
    for (const [uid, memberRoles] of Object.entries(members)) {
      await store.upsertUser({ uid, email: `${uid}@example.com`, roles: memberRoles });
      await store.upsertScopeMember(scopeId, { uid, email: `${uid}@example.com`, roles: memberRoles });
    }
    const server = createLanyardServer({ adminAuth: fakeAdminAuth(admins), store, policy });
    const update = (actor: string, targetUid: string, nextRoles: Role[], scope: ScopeId = scopeId) =>
      server.updateUserRoles({ scopeId: scope, actor: { uid: actor }, targetUid, roles: nextRoles });
    const rolesOf = async (uid: string, scope: ScopeId = scopeId) =>
      scope === GLOBAL_SCOPE ? (await store.getUser(uid))?.roles : (await store.getScopeMember(scope, uid))?.roles;
    return { store, server, update, rolesOf };
  }

  it("a coordinator can't make anyone an owner, in a scope or globally", async () => {
    const { server, update, rolesOf } = await setup({ coord: ["coordinator"], friend: ["scanner"] });
    try {
      await expect(update("coord", "friend", ["owner"])).rejects.toThrow(/Forbidden.*'owner'/);
      await expect(update("coord", "friend", ["owner"], GLOBAL_SCOPE)).rejects.toThrow(/Forbidden.*'owner'/);
      expect(await rolesOf("friend")).toEqual(["scanner"]);
      expect(await rolesOf("friend", GLOBAL_SCOPE)).toEqual(["scanner"]);
    } finally {
      server.close();
    }
  });

  it("a coordinator can't change the roles of someone who outranks them", async () => {
    const { server, update, rolesOf } = await setup({ coord: ["coordinator"], boss: ["owner"] });
    try {
      // Not even by adding a role within their own rank
      await expect(update("coord", "boss", ["owner", "scanner"])).rejects.toThrow(/Forbidden/);
      await expect(update("coord", "boss", ["scanner"])).rejects.toThrow(/Forbidden/);
      expect(await rolesOf("boss")).toEqual(["owner"]);
    } finally {
      server.close();
    }
  });

  it("sibling roles with the same capabilities can't assign each other", async () => {
    const { server, update } = await setup({ coord: ["coordinator"], lead: ["lead"], someone: [] });
    try {
      await expect(update("coord", "someone", ["greeter"])).rejects.toThrow(/Forbidden.*'greeter'/);
      await expect(update("lead", "someone", ["scanner"])).rejects.toThrow(/Forbidden.*'scanner'/);
      // Each can assign what's under them
      await update("coord", "someone", ["scanner"]);
      await expect(update("lead", "someone", ["greeter"])).rejects.toThrow(/Forbidden.*'scanner'/); // target outranks lead now
    } finally {
      server.close();
    }
  });

  it("nobody but an admin changes their own roles", async () => {
    const { server, update, rolesOf } = await setup({ coord: ["coordinator"], root: [] }, ["root"]);
    try {
      await expect(update("coord", "coord", ["coordinator", "scanner"])).rejects.toThrow(/Forbidden.*own roles/);
      await expect(update("coord", "coord", [])).rejects.toThrow(/Forbidden.*own roles/);
      expect(await rolesOf("coord")).toEqual(["coordinator"]);
      await update("root", "root", ["owner"]);
      expect(await rolesOf("root")).toEqual(["owner"]);
    } finally {
      server.close();
    }
  });

  it("peers of equal rank may grant and remove each other's role", async () => {
    const { server, update, rolesOf } = await setup({ a: ["coordinator"], b: ["coordinator"], c: ["scanner"] });
    try {
      await update("a", "c", ["coordinator"]);
      expect(await rolesOf("c")).toEqual(["coordinator"]);
      await update("a", "b", ["scanner"]);
      expect(await rolesOf("b")).toEqual(["scanner"]);
    } finally {
      server.close();
    }
  });

  it("an owner can assign every role, including ones only reachable through inherits", async () => {
    const { server, update, rolesOf } = await setup({ boss: ["owner"], x: [] });
    try {
      await update("boss", "x", ["greeter", "lead", "coordinator"]);
      expect(await rolesOf("x")).toEqual(["greeter", "lead", "coordinator"]);
      await update("boss", "x", ["owner"]);
      expect(await rolesOf("x")).toEqual(["owner"]);
    } finally {
      server.close();
    }
  });

  it("system-managed roles are kept when someone is promoted, and nobody can add one", async () => {
    const { server, update, rolesOf } = await setup(
      { coord: ["coordinator"], vol: ["volunteer"], other: [], root: [] },
      ["root"]
    );
    try {
      // A coordinator promotes a volunteer; a picker built from getAssignableRoles doesn't include volunteer
      await update("coord", "vol", ["scanner"]);
      expect(await rolesOf("vol")).toEqual(["volunteer", "scanner"]);
      // Echoing a held system-managed role is fine too
      await update("coord", "vol", ["volunteer"]);
      expect(await rolesOf("vol")).toEqual(["volunteer"]);
      // Nobody adds one, not even an admin: the roster sync owns it
      await expect(update("coord", "other", ["volunteer"])).rejects.toThrow(/'volunteer' is system-managed/);
      await expect(update("root", "other", ["volunteer"])).rejects.toThrow(/'volunteer' is system-managed/);
      expect(await rolesOf("other")).toEqual([]);
    } finally {
      server.close();
    }
  });

  it("rank is per scope: an owner in one campaign is only what they hold in another, and nothing globally", async () => {
    const store = new InMemoryLanyardStore<Role, Cap>({ policy });
    await store.upsertUser({ uid: "multi", email: "multi@example.com", roles: [] });
    await store.upsertUser({ uid: "target", email: "target@example.com", roles: [] });
    for (const [scope, multiRoles] of [
      ["campaign-a", ["owner"]],
      ["campaign-b", ["scanner"]]
    ] as const) {
      await store.upsertScopeMember(scope, { uid: "multi", email: "multi@example.com", roles: [...multiRoles] });
      await store.upsertScopeMember(scope, { uid: "target", email: "target@example.com", roles: [] });
    }
    const server = createLanyardServer({ adminAuth: fakeAdminAuth(), store, policy });
    const update = (scope: ScopeId, nextRoles: Role[]) =>
      server.updateUserRoles({ scopeId: scope, actor: { uid: "multi" }, targetUid: "target", roles: nextRoles });
    try {
      await update("campaign-a", ["coordinator"]);
      expect((await store.getScopeMember("campaign-a", "target"))?.roles).toEqual(["coordinator"]);
      await expect(update("campaign-b", ["coordinator"])).rejects.toThrow(/Forbidden/);
      await expect(update(GLOBAL_SCOPE, ["coordinator"])).rejects.toThrow(/Forbidden/);
      // Not a member at all
      await expect(update("campaign-c", ["scanner"])).rejects.toThrow(/Forbidden.*not a member/);
      expect((await store.getScopeMember("campaign-b", "target"))?.roles).toEqual([]);
      expect((await store.getUser("target"))?.roles).toEqual([]);
    } finally {
      server.close();
    }
  });

  it("staff who can manage users can't remove or edit someone who outranks them either", async () => {
    const { store, server } = await setup({
      coord: ["coordinator"],
      boss: ["owner"],
      peer: ["coordinator"],
      s: ["scanner"]
    });
    const remove = (targetUid: string, scope: ScopeId = scopeId) =>
      server.deleteUser({
        scopeId: scope,
        actor: { uid: "coord" },
        targetUid,
        confirmTargetEmail: `${targetUid}@example.com`
      });
    const rename = (targetUid: string, scope: ScopeId = scopeId) =>
      server.updateUserProfile({ scopeId: scope, actor: { uid: "coord" }, targetUid, patch: { firstName: "Renamed" } });
    try {
      // Removing an owner from the campaign would revoke every role they hold
      await expect(remove("boss")).rejects.toThrow(/Forbidden: Target holds 'owner'/);
      await expect(remove("boss", GLOBAL_SCOPE)).rejects.toThrow(/Forbidden: Target holds 'owner'/);
      await expect(rename("boss")).rejects.toThrow(/Forbidden: Target holds 'owner'/);
      await expect(rename("boss", GLOBAL_SCOPE)).rejects.toThrow(/Forbidden: Target holds 'owner'/);
      expect(await store.getScopeMember(scopeId, "boss")).not.toBeNull();
      expect(await store.getUser("boss")).toMatchObject({ roles: ["owner"] });

      // Peers and people below them are fine
      await rename("peer");
      await rename("s", GLOBAL_SCOPE);
      await remove("s");
      expect(await store.getScopeMember(scopeId, "s")).toBeNull();
    } finally {
      server.close();
    }
  });

  it("writes only roles, so a concurrent demotion or profile edit isn't undone", async () => {
    const { store, server, update } = await setup({ coord: ["coordinator"], target: ["scanner"] });
    try {
      await store.upsertUser({ uid: "target", email: "target@example.com", roles: ["scanner"], isSystemAdmin: true });
      // Between updateUserRoles reading the target and writing, another request demotes them and renames them
      const realGetUser = store.getUser.bind(store);
      let raced = false;
      store.getUser = async (uid: string) => {
        const snapshot = await realGetUser(uid);
        if (uid === "target" && !raced) {
          raced = true;
          await store.patchUser("target", { firstName: "Renamed" } as any);
          await store.deleteSystemAdmin("target");
        }
        return snapshot;
      };
      await update("coord", "target", ["coordinator"], GLOBAL_SCOPE);
      store.getUser = realGetUser;
      const after = await store.getUser("target");
      expect(raced).toBe(true);
      expect(after).toMatchObject({ roles: ["coordinator"], firstName: "Renamed", isSystemAdmin: false });
    } finally {
      server.close();
    }
  });
});

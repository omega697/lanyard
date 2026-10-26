import { describe, it, expect, vi } from "vitest";
import { GLOBAL_SCOPE, createPermissionPolicy, InMemoryLanyardStore } from "../core/index.js";
import {
  createLanyardServer,
  createSecretCipher,
  decryptSecret,
  encryptSecret,
  GoogleAuthService,
  isEncryptedSecretData,
  type AdminAuthAdapter
} from "./index.js";
import { FirestoreServerStore } from "./firestore.js";

type TestRole = "owner" | "manager" | "member";
type TestCap = "edit_content" | "invite_members" | "billing";

const TEST_POLICY = createPermissionPolicy<TestRole, TestCap>({
  roles: {
    owner: {
      inherits: ["manager"],
      capabilities: "*",
      trackPresence: true
    },
    manager: {
      inherits: ["member"],
      capabilities: ["edit_content", "invite_members"],
      trackPresence: true
    },
    member: {
      capabilities: [],
      trackPresence: false
    }
  }
});

function createFakeAdminAuth(): AdminAuthAdapter & {
  claimsByUid: Map<string, Record<string, any> | null>;
  deletedUids: Set<string>;
  updatedUsersByUid: Map<string, { displayName?: string | null; photoURL?: string | null }>;
} {
  const usersByEmail = new Map<string, { uid: string; email: string; displayName?: string }>();
  const claimsByUid = new Map<string, Record<string, any> | null>();
  const deletedUids = new Set<string>();
  const updatedUsersByUid = new Map<string, { displayName?: string | null; photoURL?: string | null }>();
  let counter = 1;

  return {
    claimsByUid,
    deletedUids,
    updatedUsersByUid,
    async verifyIdToken(idToken: string) {
      if (idToken === "valid-token") {
        return {
          uid: "u-verified",
          email: "Verified@Example.com",
          email_verified: true,
          name: "Verified User",
          picture: "https://example.com/p.png",
          admin: false
        };
      }
      if (idToken === "unverified-token") {
        return {
          uid: "u-unverified",
          email: "unverified@example.com",
          email_verified: false
        };
      }
      if (idToken === "no-email-token") {
        return {
          uid: "u-no-email"
        };
      }
      if (idToken === "inviter-token") {
        return {
          uid: "u-inviter",
          email: "inviter@example.com",
          email_verified: true,
          picture: "https://example.com/inviter-oauth.png"
        };
      }
      if (idToken === "mgr-token") {
        return {
          uid: "u-mgr",
          email: "mgr@example.com",
          email_verified: true,
          picture: "https://example.com/mgr-oauth.png"
        };
      }
      throw new Error("Invalid token");
    },
    async getUserByEmail(email: string) {
      const clean = email.toLowerCase().trim();
      if (clean === "boom@example.com") {
        throw new Error("Unexpected Firebase Admin outage");
      }
      const found = usersByEmail.get(clean);
      if (!found) {
        const err: any = new Error("User not found");
        err.code = "auth/user-not-found";
        throw err;
      }
      return {
        ...found,
        customClaims: claimsByUid.get(found.uid) || undefined
      };
    },
    async createUser(props) {
      const clean = props.email.toLowerCase().trim();
      const rec = {
        uid: `provisioned-uid-${counter++}`,
        email: clean,
        displayName: props.displayName
      };
      usersByEmail.set(clean, rec);
      return rec;
    },
    async setCustomUserClaims(uid, claims) {
      claimsByUid.set(uid, claims);
    },
    async updateUser(uid, properties) {
      updatedUsersByUid.set(uid, properties);
    },
    async deleteUser(uid) {
      deletedUids.add(uid);
      for (const [email, rec] of usersByEmail.entries()) {
        if (rec.uid === uid) {
          usersByEmail.delete(email);
        }
      }
    }
  };
}

function createMockRes() {
  const res: any = {
    statusCode: 200,
    body: null,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: any) {
      res.body = payload;
      return res;
    },
    send(payload?: any) {
      if (payload !== undefined) {
        res.body = payload;
      }
      return res;
    }
  };
  return res;
}

describe("lanyard/server unit tests", () => {
  it("verifies tokens and enforces email_verified and email presence in GoogleAuthService", async () => {
    const adminAuth = createFakeAdminAuth();
    const authService = new GoogleAuthService(adminAuth);

    expect(await authService.verifyToken(undefined)).toBeNull();
    expect(await authService.verifyToken("Basic abc")).toBeNull();
    expect(await authService.verifyToken("Bearer    ")).toBeNull();

    const user = await authService.verifyToken("Bearer valid-token");
    expect(user).toEqual({
      uid: "u-verified",
      email: "verified@example.com",
      emailVerified: true,
      name: "Verified User",
      photoUrl: "https://example.com/p.png",
      isAdmin: false
    });

    await expect(authService.verifyToken("Bearer unverified-token")).rejects.toThrow("Token email must be verified");
    await expect(authService.verifyToken("Bearer no-email-token")).rejects.toThrow("Token must contain an email claim");

    // requireVerifiedEmail = false allows unverified email tokens
    const lenientAuth = new GoogleAuthService(adminAuth, false);
    const unverifiedUser = await lenientAuth.verifyToken("Bearer unverified-token");
    expect(unverifiedUser?.emailVerified).toBe(false);
  });

  it("provisions UIDs by email, manages system admins, and grants/revokes multi-capabilities", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });

    await expect(server.getOrProvisionUidByEmail({ email: "not-an-email" })).rejects.toThrow(/Valid email/);
    await expect(server.getOrProvisionUidByEmail({ email: "boom@example.com" })).rejects.toThrow(
      /Unexpected Firebase Admin outage/
    );

    // 1. Pre-provision a user by email before they have ever logged in
    const firstProvision = await server.getOrProvisionUidByEmail({
      email: "NewMember@Example.com",
      displayName: "New Member"
    });
    expect(firstProvision.created).toBe(true);
    expect(firstProvision.uid).toBe("provisioned-uid-1");

    // Second call resolves the existing UID without creating a duplicate
    const secondProvision = await server.getOrProvisionUidByEmail({
      email: "newmember@example.com"
    });
    expect(secondProvision.created).toBe(false);
    expect(secondProvision.uid).toBe("provisioned-uid-1");

    // 2. Grant multiple roles incrementally by email
    await server.grantRolesByEmail({
      scopeId: "ws-1",
      email: "newmember@example.com",
      roles: ["member"],
      firstName: "New",
      lastName: "Member"
    });
    const afterSecondGrant = await server.grantRolesByEmail({
      scopeId: "ws-1",
      email: "newmember@example.com",
      roles: ["manager"]
    });
    expect(afterSecondGrant.uid).toBe("provisioned-uid-1");
    expect(afterSecondGrant.roles).toEqual(["member", "manager"]);

    // Revoke role
    await server.revokeRoles("ws-1", "provisioned-uid-1", ["member"]);
    expect((await store.getScopeMember("ws-1", "provisioned-uid-1"))?.roles).toEqual(["manager"]);

    // Upsert full member by email
    const upsertedManager = await server.upsertUserByEmail({
      scopeId: "ws-1",
      email: "lead@example.com",
      firstName: "Lead",
      lastName: "Manager",
      roles: ["manager"]
    });
    expect(upsertedManager.roles).toEqual(["manager"]);

    // 3. Promote and demote system admin
    const adminProfile = await server.setSystemAdminStatus({
      email: "boss@example.com",
      isAdmin: true,
      firstName: "Boss",
      lastName: "Admin",
      actor: { uid: "root-admin", isAdmin: true }
    });
    expect(adminProfile?.uid).toBe("provisioned-uid-3");
    expect(adminAuth.claimsByUid.get("provisioned-uid-3")).toEqual({ admin: true });

    // Prevent self-demotion
    await expect(
      server.setSystemAdminStatus({
        email: "boss@example.com",
        isAdmin: false,
        actor: adminProfile!
      })
    ).rejects.toThrow(/Cannot remove yourself/);

    // Demote by a different admin succeeds
    const demoted = await server.setSystemAdminStatus({
      email: "boss@example.com",
      isAdmin: false,
      actor: { uid: "root-admin", isAdmin: true }
    });
    expect(demoted).toBeNull();
    expect(adminAuth.claimsByUid.get("provisioned-uid-3")).toEqual({ admin: false });
    expect(await store.getSystemAdmin("provisioned-uid-3")).toBeNull();
  });

  it("enforces middleware (401/400/403/500), role-implied capabilities, and syncs OAuth avatars", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });

    // Unauthenticated checkAuth -> 401
    const resUnauth = createMockRes();
    await server.checkAuth({ headers: {} } as any, resUnauth, () => {});
    expect(resUnauth.statusCode).toBe(401);

    // Invalid token in checkAuth -> 401
    const resBadHeader = createMockRes();
    await server.checkAuth({ headers: { authorization: "Bearer invalid-token" } } as any, resBadHeader, () => {});
    expect(resBadHeader.statusCode).toBe(401);

    // requireAdmin rejects non-admin (403) and auto-seeds brand-new admin
    const resNonAdmin = createMockRes();
    await server.requireAdmin(
      { user: { uid: "u1", email: "u1@example.com", isAdmin: false } } as any,
      resNonAdmin,
      () => {}
    );
    expect(resNonAdmin.statusCode).toBe(403);

    let adminNext = false;
    await server.requireAdmin(
      {
        user: {
          uid: "u-new-admin",
          email: "newadmin@example.com",
          name: "New Admin",
          photoUrl: "https://example.com/newadmin.png",
          isAdmin: true
        }
      } as any,
      createMockRes(),
      () => {
        adminNext = true;
      }
    );
    expect(adminNext).toBe(true);
    expect((await store.getSystemAdmin("u-new-admin"))?.photoUrl).toBe("https://example.com/newadmin.png");

    // Pre-existing admin gets photoUrl updated on requireAdmin
    await store.upsertSystemAdmin({
      uid: "u-pre-admin",
      email: "preadmin@example.com",
      displayName: "Pre Admin",
      photoUrl: null
    });
    await server.requireAdmin(
      {
        user: {
          uid: "u-pre-admin",
          email: "preadmin@example.com",
          photoUrl: "https://example.com/admin-oauth.png",
          isAdmin: true
        }
      } as any,
      createMockRes(),
      () => {}
    );
    expect((await store.getSystemAdmin("u-pre-admin"))?.photoUrl).toBe("https://example.com/admin-oauth.png");

    await store.upsertScopeMember("ws-1", {
      uid: "u-inviter",
      email: "inviter@example.com",
      roles: ["manager"],
      photoUrl: null
    });

    await store.upsertScopeMember("ws-1", {
      uid: "u-mgr",
      email: "mgr@example.com",
      roles: ["manager"],
      photoUrl: null
    });

    // Missing user (401) and missing scope param (400) in requireRole & requireCapability
    const requireManager = server.requireRole("manager");
    const requireInvite = server.requireCapability("invite_members");
    const requireAnyCap = server.requireCapability(["edit_content", "invite_members"]);

    const resRole401 = createMockRes();
    await requireManager({ params: { scopeId: "ws-1" } } as any, resRole401, () => {});
    expect(resRole401.statusCode).toBe(401);

    const resRole400 = createMockRes();
    await requireManager({ user: { uid: "u-mgr", email: "c@example.com" }, params: {} } as any, resRole400, () => {});
    expect(resRole400.statusCode).toBe(400);

    const resCap401 = createMockRes();
    await requireInvite({ params: { scopeId: "ws-1" } } as any, resCap401, () => {});
    expect(resCap401.statusCode).toBe(401);

    const resCap400 = createMockRes();
    await requireInvite({ user: { uid: "u-inviter", email: "s@example.com" }, params: {} } as any, resCap400, () => {});
    expect(resCap400.statusCode).toBe(400);

    // u-inviter passes requireScopeCapability("invite_members") and array ["edit_content", "invite_members"], and syncs photoUrl
    const reqInviter: any = {
      headers: {
        authorization: "Bearer inviter-token"
      },
      params: { scopeId: "ws-1" }
    };
    await server.checkAuth(reqInviter, createMockRes(), () => {});

    let inviterAllowed = false;
    await requireAnyCap(reqInviter, createMockRes(), () => {
      inviterAllowed = true;
    });
    expect(inviterAllowed).toBe(true);
    expect((await store.getScopeMember("ws-1", "u-inviter"))?.photoUrl).toBe("https://example.com/inviter-oauth.png");

    // u-mgr passes requireScopeRole("manager") and syncs photoUrl
    const reqMgr: any = {
      headers: {
        authorization: "Bearer mgr-token"
      },
      params: { scopeId: "ws-1" }
    };
    await server.checkAuth(reqMgr, createMockRes(), () => {});
    let mgrRoleAllowed = false;
    await requireManager(reqMgr, createMockRes(), () => {
      mgrRoleAllowed = true;
    });
    expect(mgrRoleAllowed).toBe(true);
    expect((await store.getScopeMember("ws-1", "u-mgr"))?.photoUrl).toBe("https://example.com/mgr-oauth.png");

    // Store error returns 500
    vi.spyOn(store, "getScopeMember").mockRejectedValueOnce(new Error("DB offline"));
    const res500 = createMockRes();
    await requireManager(reqMgr, res500, () => {});
    expect(res500.statusCode).toBe(500);
  });

  it("tests FirestoreServerStore CRUD and additive/subtractive roles", async () => {
    const docs = new Map<string, Record<string, any>>();

    const fakeDb: any = {
      doc(path: string) {
        return {
          path,
          async get() {
            const data = docs.get(path);
            return {
              id: path.split("/").pop()!,
              exists: Boolean(data),
              data: () => (data ? { ...data } : undefined)
            };
          },
          async set(payload: Record<string, any>, options?: { merge?: boolean }) {
            const current = options?.merge ? docs.get(path) || {} : {};
            docs.set(path, { ...current, ...payload });
          },
          async update(patch: Record<string, any>) {
            const current = docs.get(path) || {};
            const updated = { ...current };
            for (const [k, v] of Object.entries(patch)) {
              if (v && typeof v === "object" && "elements" in (v as any)) {
                const elems: any[] = (v as any).elements || [];
                const opName = v.constructor?.name || "";
                const existingArr: any[] = Array.isArray(updated[k]) ? [...updated[k]] : [];
                if (opName.includes("ArrayRemove")) {
                  updated[k] = existingArr.filter((item) => !elems.includes(item));
                } else {
                  updated[k] = Array.from(new Set([...existingArr, ...elems]));
                }
              } else {
                updated[k] = v;
              }
            }
            docs.set(path, updated);
          },
          async delete() {
            docs.delete(path);
          }
        };
      },
      collection(path: string) {
        return {
          async get() {
            const prefix = `${path}/`;
            const matching: any[] = [];
            for (const [k, v] of docs.entries()) {
              if (k.startsWith(prefix) && !k.slice(prefix.length).includes("/")) {
                matching.push({
                  id: k.slice(prefix.length),
                  data: () => ({ ...v })
                });
              }
            }
            return { docs: matching };
          }
        };
      }
    };

    const store = new FirestoreServerStore<TestRole, TestCap>({
      db: fakeDb,
      defaultRole: "member"
    });

    // 1. System Admin CRUD
    expect(await store.getSystemAdmin("admin-1")).toBeNull();
    await store.upsertSystemAdmin({
      uid: "admin-1",
      email: "admin1@example.com",
      displayName: "Admin 1",
      photoUrl: "https://example.com/a1.png"
    });
    expect((await store.getSystemAdmin("admin-1"))?.email).toBe("admin1@example.com");
    expect(await store.listSystemAdmins()).toHaveLength(1);
    await store.deleteSystemAdmin("admin-1");
    expect(await store.getSystemAdmin("admin-1")).toBeNull();

    // 2. Scoped Member CRUD + grant/revoke/delete
    await expect(store.grantScopeRoles("ws-1", "missing", ["member"])).rejects.toThrow(/does not exist/);

    const created = await store.grantScopeRoles("ws-1", "u-1", ["member"], {
      uid: "u-1",
      email: "u1@example.com"
    });
    expect(created.roles).toEqual(["member"]);
    expect((await store.getScopeMember("ws-1", "u-1"))?.roles).toEqual(["member"]);

    // Additive grant on existing member uses FieldValue.arrayUnion
    const updatedGrant = await store.grantScopeRoles("ws-1", "u-1", ["manager"]);
    expect(updatedGrant.roles).toEqual(["member", "manager"]);

    // Subtractive revoke on existing member uses FieldValue.arrayRemove
    await store.revokeScopeRoles("ws-1", "u-1", ["member"]);
    expect((await store.getScopeMember("ws-1", "u-1"))?.roles).toEqual(["manager"]);

    // No-op revokes (empty array or non-existent member)
    await store.revokeScopeRoles("ws-1", "u-1", []);
    await store.revokeScopeRoles("ws-1", "non-existent", ["manager"]);

    // Doc without roles field resolves to [defaultRole]
    docs.set("workspaces/ws-1/members/u-default", {
      uid: "u-default",
      email: "default@example.com"
    });
    expect((await store.getScopeMember("ws-1", "u-default"))?.roles).toEqual(["member"]);
    expect(await store.listScopeMembers("ws-1")).toHaveLength(2);

    await store.deleteScopeMember("ws-1", "u-1");
    expect(await store.getScopeMember("ws-1", "u-1")).toBeNull();
  });

  it("enforces no-op avatar write guards in requireAdmin, requireScopeRole, and requireScopeCapability when photoUrl already matches", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });

    await store.upsertSystemAdmin({
      uid: "u-admin",
      email: "admin@example.com",
      displayName: "Admin",
      photoUrl: "https://example.com/same-admin.png"
    });
    await store.upsertScopeMember("ws-1", {
      uid: "u-mgr",
      email: "mgr@example.com",
      roles: ["manager"],
      photoUrl: "https://example.com/same-mgr.png"
    });

    const upsertAdminSpy = vi.spyOn(store, "upsertSystemAdmin");
    const upsertMemberSpy = vi.spyOn(store, "upsertScopeMember");

    // 1. requireAdmin with already-matching photoUrl -> zero store writes
    await server.requireAdmin(
      {
        user: {
          uid: "u-admin",
          email: "admin@example.com",
          photoUrl: "https://example.com/same-admin.png",
          isAdmin: true
        }
      } as any,
      createMockRes(),
      () => {}
    );
    expect(upsertAdminSpy).not.toHaveBeenCalled();

    // 2. requireRole with already-matching photoUrl -> zero store writes
    const requireManager = server.requireRole("manager");
    await requireManager(
      {
        user: {
          uid: "u-mgr",
          email: "mgr@example.com",
          photoUrl: "https://example.com/same-mgr.png",
          isAdmin: false
        },
        params: { scopeId: "ws-1" }
      } as any,
      createMockRes(),
      () => {}
    );
    expect(upsertMemberSpy).not.toHaveBeenCalled();

    // 3. requireCapability with already-matching photoUrl -> zero store writes
    const requireEdit = server.requireCapability("edit_content");
    await requireEdit(
      {
        user: {
          uid: "u-mgr",
          email: "mgr@example.com",
          photoUrl: "https://example.com/same-mgr.png",
          isAdmin: false
        },
        params: { scopeId: "ws-1" }
      } as any,
      createMockRes(),
      () => {}
    );
    expect(upsertMemberSpy).not.toHaveBeenCalled();
  });

  it("handles concurrent UID provisioning races, multi-scope provisioning, and preserves existing photoUrl/lastSeen/capabilities on role promotion", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });

    // 1. Simulate concurrent getOrProvisionUidByEmail race where getUserByEmail initially throws user-not-found,
    // another request creates the user first, and createUser throws auth/email-already-exists
    const origCreateUser = adminAuth.createUser.bind(adminAuth);
    vi.spyOn(adminAuth, "createUser").mockImplementationOnce(async (props) => {
      await origCreateUser(props);
      const raceErr: any = new Error("The email address is already in use by another account.");
      raceErr.code = "auth/email-already-exists";
      throw raceErr;
    });

    const raceResult = await server.getOrProvisionUidByEmail({
      email: "  Race.Condition@Example.COM  ",
      displayName: "Race User"
    });
    expect(raceResult).toEqual({
      uid: "provisioned-uid-1",
      email: "race.condition@example.com",
      created: false
    });

    // 2. Multi-scope pre-provisioning for the same email across ws-1 and ws-2 resolves the exact same UID
    const m1 = await server.grantRolesByEmail({
      scopeId: "ws-1",
      email: "  Multi.Scope@Example.com ",
      roles: ["member"],
      firstName: "Multi",
      lastName: "Scope"
    });
    const m2 = await server.upsertUserByEmail({
      scopeId: "ws-2",
      email: "multi.scope@example.com",
      roles: ["owner"]
    });
    expect(m1.uid).toBe(m2.uid);

    // 3. Simulate user signing in to ws-1 (populating photoUrl and lastSeen), then getting promoted to 'manager'
    await store.syncAvatar({
      uid: m1.uid,
      scopeId: "ws-1",
      photoUrl: "https://example.com/multi-avatar.png"
    });
    await store.recordPresenceHeartbeat({
      uid: m1.uid,
      scopeId: "ws-1",
      lastSeenIso: "2026-10-19T15:00:00.000Z"
    });

    const promoted = await server.upsertUserByEmail({
      scopeId: "ws-1",
      email: "multi.scope@example.com",
      roles: ["manager"]
    });
    expect(promoted.roles).toEqual(["manager"]);
    expect(promoted.photoUrl).toBe("https://example.com/multi-avatar.png");
    expect(promoted.lastSeen).toBe("2026-10-19T15:00:00.000Z");
  });

  it("enforces cross-scope authorization isolation, capability revocation, and custom scopeParamName", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });

    // User is 'owner' in ws-A, but only 'manager' in ws-B, and not a member of ws-C
    await store.upsertScopeMember("ws-A", {
      uid: "u-scoped",
      email: "scoped@example.com",
      roles: ["owner"]
    });
    await store.upsertScopeMember("ws-B", {
      uid: "u-scoped",
      email: "scoped@example.com",
      roles: ["manager"]
    });

    const requireOwnerOnProject = server.requireRole("owner", "projectId");
    const requireInviteOnProject = server.requireCapability("invite_members", "projectId");

    // 1. Allowed as owner in ws-A
    let allowedInA = false;
    await requireOwnerOnProject(
      {
        user: { uid: "u-scoped", email: "scoped@example.com", isAdmin: false },
        params: { projectId: "ws-A" }
      } as any,
      createMockRes(),
      () => {
        allowedInA = true;
      }
    );
    expect(allowedInA).toBe(true);

    // 2. Rejected (403) when attempting owner actions in ws-B or ws-C (cross-scope isolation)
    const resB = createMockRes();
    await requireOwnerOnProject(
      {
        user: { uid: "u-scoped", email: "scoped@example.com", isAdmin: false },
        params: { projectId: "ws-B" }
      } as any,
      resB,
      () => {}
    );
    expect(resB.statusCode).toBe(403);

    const resC = createMockRes();
    await requireInviteOnProject(
      {
        user: { uid: "u-scoped", email: "scoped@example.com", isAdmin: false },
        params: { projectId: "ws-C" }
      } as any,
      resC,
      () => {}
    );
    expect(resC.statusCode).toBe(403);

    // 3. In ws-B, user has 'manager' (which implies 'invite_members')
    let inviteInB = false;
    await requireInviteOnProject(
      {
        user: { uid: "u-scoped", email: "scoped@example.com", isAdmin: false },
        params: { projectId: "ws-B" }
      } as any,
      createMockRes(),
      () => {
        inviteInB = true;
      }
    );
    expect(inviteInB).toBe(true);

    // 4. Revoke 'manager' role in ws-B -> immediately blocked (403), while global system admin still passes
    await server.revokeRoles("ws-B", "u-scoped", ["manager"]);
    const resAfterRevoke = createMockRes();
    await requireInviteOnProject(
      {
        user: { uid: "u-scoped", email: "scoped@example.com", isAdmin: false },
        params: { projectId: "ws-B" }
      } as any,
      resAfterRevoke,
      () => {}
    );
    expect(resAfterRevoke.statusCode).toBe(403);

    let sysAdminAllowed = false;
    await requireInviteOnProject(
      {
        user: { uid: "u-sysadmin", email: "sys@example.com", isAdmin: true },
        params: { projectId: "ws-B" }
      } as any,
      createMockRes(),
      () => {
        sysAdminAllowed = true;
      }
    );
    expect(sysAdminAllowed).toBe(true);
  });

  it("enforces server security guards: default GoogleAuthService, runtime assertNotProduction, checkRevoked, path traversal rejection, and sanitized 500 errors", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();

    // 1. createLanyardServer defaults to GoogleAuthService even if FIRESTORE_EMULATOR_HOST is set
    const origFsEmulator = process.env.FIRESTORE_EMULATOR_HOST;
    process.env.FIRESTORE_EMULATOR_HOST = "127.0.0.1:8080";
    try {
      const defaultServer = createLanyardServer<TestRole, TestCap>({
        adminAuth,
        store,
        policy: TEST_POLICY
      });
      expect(defaultServer.authService).toBeInstanceOf(GoogleAuthService);
    } finally {
      if (origFsEmulator !== undefined) process.env.FIRESTORE_EMULATOR_HOST = origFsEmulator;
      else delete process.env.FIRESTORE_EMULATOR_HOST;
    }

    // 2. GoogleAuthService with checkRevoked = true passes true to adminAuth.verifyIdToken
    const verifySpy = vi.spyOn(adminAuth, "verifyIdToken");
    const strictAuth = new GoogleAuthService(adminAuth, true, true);
    await strictAuth.verifyToken("Bearer valid-token");
    expect(verifySpy).toHaveBeenCalledWith("valid-token", true);

    // 3. requireRole and requireCapability reject path-traversal scopeId with 400
    // and never leak internal database error details in 500 responses
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });
    const requireMgr = server.requireRole("manager");
    const requireEdit = server.requireCapability("edit_content");

    for (const traversalScopeId of ["ws-1/../../system_admins", "..", ".", "ws\\bad"]) {
      const resRole = createMockRes();
      await requireMgr(
        { user: { uid: "u-1", email: "u1@example.com" }, params: { scopeId: traversalScopeId } } as any,
        resRole,
        () => {}
      );
      expect(resRole.statusCode).toBe(400);

      const resCap = createMockRes();
      await requireEdit(
        { user: { uid: "u-1", email: "u1@example.com" }, params: { scopeId: traversalScopeId } } as any,
        resCap,
        () => {}
      );
      expect(resCap.statusCode).toBe(400);
    }

    vi.spyOn(store, "getScopeMember").mockRejectedValueOnce(
      new Error("SENSITIVE_DB_CONNECTION_STRING_LEAK://internal-host:5432")
    );
    const res500 = createMockRes();
    await requireMgr(
      { user: { uid: "u-1", email: "u1@example.com" }, params: { scopeId: "ws-1" } } as any,
      res500,
      () => {}
    );
    expect(res500.statusCode).toBe(500);
    expect(JSON.stringify(res500.body)).not.toContain("SENSITIVE_DB_CONNECTION_STRING_LEAK");

    // 5. FirestoreServerStore rejects path traversal and reserved __.*__ document IDs
    const fsServerStore = new FirestoreServerStore<TestRole, TestCap>({
      db: {} as any,
      defaultRole: "member"
    });
    await expect(fsServerStore.getScopeMember("ws-1/../../system_admins", "u-1")).rejects.toThrow(/Invalid scopeId/);
    await expect(fsServerStore.getScopeMember("ws-1", "__reserved__")).rejects.toThrow(
      /reserved Firestore document ID/
    );
    await expect(fsServerStore.getSystemAdmin("../other")).rejects.toThrow(/Invalid uid/);

    // 6. setSystemAdminStatus preserves pre-existing customClaims and validates actor.uid
    await expect(
      server.setSystemAdminStatus({
        email: "boss@example.com",
        isAdmin: true,
        actor: { uid: "../bad-actor" }
      })
    ).rejects.toThrow(/Invalid actor\.uid/);

    const provisionedBoss = await server.getOrProvisionUidByEmail({ email: "boss@example.com" });
    adminAuth.claimsByUid.set(provisionedBoss.uid, { tenantTier: "enterprise" });
    await server.setSystemAdminStatus({
      email: "boss@example.com",
      isAdmin: true,
      actor: { uid: "root-admin", isAdmin: true }
    });
    expect(adminAuth.claimsByUid.get(provisionedBoss.uid)).toEqual({
      tenantTier: "enterprise",
      admin: true
    });

    // 7. checkAuth does not leak internal Firebase Admin exception details in 401 responses
    const prodServer = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });
    vi.spyOn(adminAuth, "verifyIdToken").mockRejectedValueOnce(
      new Error("INTERNAL_GCP_METADATA_ENDPOINT_FAILURE://169.254.169.254")
    );
    const res401 = createMockRes();
    await prodServer.checkAuth({ headers: { authorization: "Bearer bad-jwt" } } as any, res401, () => {});
    expect(res401.statusCode).toBe(401);
    expect(JSON.stringify(res401.body)).not.toContain("169.254.169.254");
    expect(res401.body.error).toBe("Unauthorized: Invalid or expired authentication token");

    // 8. upsertUserByEmail and grantRolesByEmail reject unknown/prototype roles
    await expect(
      server.upsertUserByEmail({
        scopeId: "ws-1",
        email: "alice@example.com",
        roles: ["__proto__" as any]
      })
    ).rejects.toThrow(/role is not defined in policy\.roles/);
    await expect(
      server.grantRolesByEmail({
        scopeId: "ws-1",
        email: "alice@example.com",
        roles: ["superadmin" as any]
      })
    ).rejects.toThrow(/role is not defined in policy\.roles/);
  });

  it("covers non-fatal requireAdmin store errors, requireCapability 500 sanitization, and FirestoreServerStore photoUrl sanitization", async () => {
    // 1. requireAdmin continues (calls next()) even if the backing directory store throws a transient error
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });

    vi.spyOn(store, "getSystemAdmin").mockRejectedValueOnce(new Error("Transient directory outage"));
    let adminProceeded = false;
    await server.requireAdmin(
      { user: { uid: "u-admin", email: "admin@example.com", isAdmin: true } } as any,
      createMockRes(),
      () => {
        adminProceeded = true;
      }
    );
    expect(adminProceeded).toBe(true);

    // 4. requireCapability returns 500 with sanitized error when store.getScopeMember rejects
    const requireEdit = server.requireCapability("edit_content");
    vi.spyOn(store, "getScopeMember").mockRejectedValueOnce(new Error("INTERNAL_SQL_STATE_ERROR_999"));
    const resCap500 = createMockRes();
    await requireEdit(
      { user: { uid: "u-1", email: "u1@example.com" }, params: { scopeId: "ws-1" } } as any,
      resCap500,
      () => {}
    );
    expect(resCap500.statusCode).toBe(500);
    expect(JSON.stringify(resCap500.body)).not.toContain("INTERNAL_SQL_STATE_ERROR_999");

    // 5. FirestoreServerStore custom collection names and photoUrl sanitization on write & read
    const docs = new Map<string, Record<string, any>>();
    const fakeDb: any = {
      doc(path: string) {
        return {
          path,
          async get() {
            const data = docs.get(path);
            return {
              id: path.split("/").pop()!,
              exists: Boolean(data),
              data: () => (data ? { ...data } : undefined)
            };
          },
          async set(payload: Record<string, any>) {
            docs.set(path, { ...payload });
          }
        };
      }
    };

    const fsStore = new FirestoreServerStore<TestRole, TestCap>({
      db: fakeDb,
      defaultRole: "member",
      usersCollection: "custom_users",
      scopeCollection: "custom_orgs",
      membersSubcollection: "custom_members"
    });

    await fsStore.upsertSystemAdmin({
      uid: "a-1",
      email: "a1@example.com",
      photoUrl: "data:image/svg+xml;base64,PHN2Zz4="
    });
    expect((await fsStore.getSystemAdmin("a-1"))?.photoUrl).toBeNull();

    await fsStore.upsertScopeMember("org-1", {
      uid: "u-1",
      email: "u1@example.com",
      roles: ["member"],
      photoUrl: "javascript:alert(1)"
    });
    expect((await fsStore.getScopeMember("org-1", "u-1"))?.photoUrl).toBeNull();
  });

  it("blocks stale 1-hour admin JWTs immediately after demotion without re-seeding or wiping user attributes/preferences", async () => {
    interface Prefs {
      leaderboardOptIn: boolean;
    }
    interface Attrs {
      pointsAllTime: number;
    }
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap, Prefs, Attrs>();
    const server = createLanyardServer<TestRole, TestCap, Prefs, Attrs>({
      adminAuth,
      store,
      policy: TEST_POLICY
    });

    // 1. Provision user who is both an attendee (with points & preferences) and promoted to system admin
    const user = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "hybrid.admin@example.com",
      firstName: "Testy",
      lastName: "McTest",
      roles: ["member"],
      preferences: { leaderboardOptIn: true },
      attributes: { pointsAllTime: 350 }
    });
    await server.setSystemAdminStatus({
      email: "hybrid.admin@example.com",
      isAdmin: true,
      actor: { uid: "root-admin", isAdmin: true }
    });
    expect((await store.getSystemAdmin(user.uid))?.isSystemAdmin).toBe(true);

    // 2. Root admin demotes hybrid.admin@example.com
    await server.setSystemAdminStatus({
      email: "hybrid.admin@example.com",
      isAdmin: false,
      actor: { uid: "root-admin", isAdmin: true }
    });

    // User's attendee attributes and preferences on users/{uid} are 100% preserved!
    const preservedRecord = await store.getUser(user.uid);
    expect(preservedRecord?.isSystemAdmin).toBe(false);
    expect(preservedRecord?.attributes).toEqual({ pointsAllTime: 350 });
    expect(preservedRecord?.preferences).toEqual({ leaderboardOptIn: true });

    // 3. Stale JWT attack: demoted admin still holds a Firebase ID token with `isAdmin: true` (valid for up to 1 hour)
    const staleAdminReq: any = {
      user: {
        uid: user.uid,
        email: "hybrid.admin@example.com",
        isAdmin: true // Stale claim from unexpired JWT!
      },
      params: { scopeId: "ws-1" }
    };

    // requireAdmin blocks with 403 and does NOT auto-seed them back into system_admins!
    const resAdmin = createMockRes();
    await server.requireAdmin(staleAdminReq, resAdmin, () => {});
    expect(resAdmin.statusCode).toBe(403);
    expect(await store.getSystemAdmin(user.uid)).toBeNull();

    // requireRole("owner") in scope also strips the stale admin bypass and blocks with 403!
    const resScope = createMockRes();
    await server.requireRole("owner")(
      { ...staleAdminReq, user: { ...staleAdminReq.user, isAdmin: true } },
      resScope,
      () => {}
    );
    expect(resScope.statusCode).toBe(403);

    // requireRole("owner", GLOBAL_SCOPE) also strips the stale admin bypass and blocks with 403!
    const resUserRole = createMockRes();
    await server.requireRole("owner", GLOBAL_SCOPE)(
      { ...staleAdminReq, user: { ...staleAdminReq.user, isAdmin: true } },
      resUserRole,
      () => {}
    );
    expect(resUserRole.statusCode).toBe(403);
  });

  it("enforces single-tenant roles/capabilities, field-level attributes/hiddenAttributes/secrets permissions, and strict cross-tenant isolation", async () => {
    type AppRole = "attendee" | "scanner" | "auditor" | "moderator" | "tenant_owner";
    type AppCap =
      | "write:points"
      | "write:badges"
      | "read:tier"
      | "write:tier"
      | "read:notes"
      | "write:notes"
      | "write:ai_keys";

    interface AppPrefs {
      optIn: boolean;
    }
    interface AppAttrs {
      pointsAllTime: number;
      awardedBadges: string[];
      vipTier: string;
    }
    interface AppHiddenAttrs {
      moderatorNotes: string;
      superAdminSecret: string;
    }
    interface AppSecrets {
      geminiKey: string;
      openaiKey: string;
    }

    const policy = createPermissionPolicy<AppRole, AppCap>({
      roles: {
        attendee: { capabilities: [] },
        scanner: { inherits: ["attendee"], capabilities: ["write:points"] },
        auditor: { inherits: ["attendee"], capabilities: ["read:tier", "read:notes"] },
        moderator: {
          inherits: ["scanner", "auditor"],
          capabilities: ["write:badges", "write:tier", "write:notes", "write:ai_keys"]
        },
        tenant_owner: {
          inherits: ["moderator"],
          capabilities: "*"
        }
      },
      attributeCapabilities: {
        pointsAllTime: "write:points",
        awardedBadges: "write:badges",
        vipTier: { read: "read:tier", write: "write:tier" }
      },
      hiddenAttributeCapabilities: {
        moderatorNotes: { read: "read:notes", write: "write:notes" }
      },
      secretCapabilities: {
        geminiKey: { allowSelfWrite: true },
        openaiKey: { write: "write:ai_keys", allowSelfWrite: false }
      }
    });

    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<AppRole, AppCap, AppPrefs, AppAttrs, AppHiddenAttrs, AppSecrets>();
    const server = createLanyardServer<AppRole, AppCap, AppPrefs, AppAttrs, AppHiddenAttrs, AppSecrets>({
      adminAuth,
      store,
      policy
    });

    // Provision single-tenant users
    const attendee = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "attendee@example.com",
      firstName: "Testy",
      lastName: "McTest",
      roles: ["attendee"],
      attributes: { pointsAllTime: 10, awardedBadges: [], vipTier: "silver" }
    });
    const scanner = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "scanner@example.com",
      firstName: "Scanny",
      lastName: "McScanner",
      roles: ["scanner"]
    });
    const auditor = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "auditor@example.com",
      firstName: "Audity",
      lastName: "McAuditor",
      roles: ["auditor"]
    });
    const moderator = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "moderator@example.com",
      firstName: "Moddy",
      lastName: "McModerator",
      roles: ["moderator"]
    });

    // 1. Single-tenant middleware: requireRole(role, GLOBAL_SCOPE) & requireCapability(cap, GLOBAL_SCOPE) (including inherited capabilities!)
    const reqMod: any = {
      user: {
        uid: moderator.uid,
        email: moderator.email,
        photoUrl: "https://example.com/mod.png",
        isAdmin: false
      }
    };
    let modPassedRole = false;
    await server.requireRole("scanner", GLOBAL_SCOPE)(reqMod, createMockRes(), () => {
      modPassedRole = true;
    });
    expect(modPassedRole).toBe(true);
    expect((await store.getUser(moderator.uid))?.photoUrl).toBe("https://example.com/mod.png");

    let modPassedInheritedCap = false;
    await server.requireCapability("write:points", GLOBAL_SCOPE)(reqMod, createMockRes(), () => {
      modPassedInheritedCap = true;
    });
    expect(modPassedInheritedCap).toBe(true);

    // Attendee fails requireRole("scanner", GLOBAL_SCOPE) and requireCapability("write:points", GLOBAL_SCOPE)
    const resAttRole = createMockRes();
    await server.requireRole("scanner", GLOBAL_SCOPE)(
      { user: { uid: attendee.uid, email: attendee.email, isAdmin: false } } as any,
      resAttRole,
      () => {}
    );
    expect(resAttRole.statusCode).toBe(403);

    // 2. Global User Attributes:
    // - Self can read ALL own attributes (including vipTier), but CANNOT write own attributes!
    expect(
      await server.readUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid
      })
    ).toEqual({ pointsAllTime: 10, awardedBadges: [], vipTier: "silver" });

    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 9999 }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Scanner can read public attributes (pointsAllTime, awardedBadges) but NOT vipTier, and can ONLY write pointsAllTime
    expect(
      await server.readUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid
      })
    ).toEqual({ pointsAllTime: 10, awardedBadges: [] });

    await server.updateUserAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: scanner,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 50 }
    });
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(50);

    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { awardedBadges: ["cheater-badge"] }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Moderator inherits scanner's write:points AND has write:badges + write:tier
    await server.updateUserAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: moderator,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 100, awardedBadges: ["centurion"], vipTier: "gold" }
    });
    expect((await store.getUser(attendee.uid))?.attributes).toEqual({
      pointsAllTime: 100,
      awardedBadges: ["centurion"],
      vipTier: "gold"
    });

    // 3. Global User HiddenAttributes:
    // - Moderator writes moderatorNotes; SystemAdmin writes superAdminSecret
    await server.updateUserHiddenAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: moderator,
      targetUid: attendee.uid,
      patch: { moderatorNotes: "Verified ID at booth" }
    });
    await server.updateUserHiddenAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: { uid: "root-admin", isAdmin: true },
      targetUid: attendee.uid,
      patch: { superAdminSecret: "classified-flag" }
    });

    // - Self (`attendee`) CANNOT read or write their own hiddenAttributes!
    await expect(
      server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "I am totally trustworthy" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Auditor can read `moderatorNotes` (redacting `superAdminSecret`), and CANNOT write `moderatorNotes`
    expect(
      await server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: auditor,
        targetUid: attendee.uid
      })
    ).toEqual({ moderatorNotes: "Verified ID at booth" });

    await expect(
      server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: auditor,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "Tampered by auditor" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - System Admin reads all hiddenAttributes unredacted
    expect(
      await server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: { uid: "root-admin", isAdmin: true },
        targetUid: attendee.uid
      })
    ).toEqual({
      moderatorNotes: "Verified ID at booth",
      superAdminSecret: "classified-flag"
    });

    // 4. Write-Only Encrypted User Secrets:
    // - Self (`attendee`) CAN write `geminiKey` (`allowSelfWrite: true`), receives boolean status, and server decrypts it
    const userSecretStatus = await server.updateUserSecrets({
      scopeId: GLOBAL_SCOPE,
      actor: attendee,
      targetUid: attendee.uid,
      patch: { geminiKey: "AIzaSyPersonal123" }
    });
    expect(userSecretStatus).toEqual({ geminiKey: true });
    expect(
      await server.getUserSecretsStatus({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid
      })
    ).toEqual({ geminiKey: true });
    expect(await server.getDecryptedUserSecrets(GLOBAL_SCOPE, attendee.uid)).toEqual({
      geminiKey: "AIzaSyPersonal123"
    });

    // - Self (`attendee`) CANNOT write `openaiKey` because `allowSelfWrite: false` and they lack `write:ai_keys`
    await expect(
      server.updateUserSecrets({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        patch: { openaiKey: "sk-proj-unauthorized" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Moderator (holding `write:ai_keys`) CAN write `openaiKey` and clear `geminiKey` with ""
    expect(
      await server.updateUserSecrets({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid,
        patch: { openaiKey: "sk-proj-mod123" }
      })
    ).toEqual({ geminiKey: true, openaiKey: true });
    expect(
      await server.updateUserSecrets({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        patch: { geminiKey: "" }
      })
    ).toEqual({ openaiKey: true });
    expect(await server.getDecryptedUserSecrets(GLOBAL_SCOPE, attendee.uid)).toEqual({ openaiKey: "sk-proj-mod123" });

    // 5. STRICT CROSS-TENANT ISOLATION:
    // Make `tenantOwnerA` a `tenant_owner` (with wildcard capabilities: "*") in `tenant-A` ONLY.
    const tenantOwnerA = await server.upsertUserByEmail({
      scopeId: "tenant-A",
      email: "owner.a@example.com",
      firstName: "Owner",
      lastName: "Alpha",
      roles: ["tenant_owner"]
    });
    await server.upsertUserByEmail({
      scopeId: "tenant-A",
      email: "attendee@example.com",
      roles: ["attendee"]
    });
    await server.upsertUserByEmail({
      scopeId: "tenant-B",
      email: "attendee@example.com",
      roles: ["attendee"],
      attributes: { pointsAllTime: 10, awardedBadges: [], vipTier: "bronze" }
    });
    await store.updateScopeMemberHiddenAttributes("tenant-B", attendee.uid, {
      moderatorNotes: "Tenant B confidential note"
    });
    await store.updateScopeMemberSecrets("tenant-B", attendee.uid, {
      openaiKey: "sk-tenant-B-key"
    });

    // (a) `tenantOwnerA` can update attributes, hiddenAttributes, and member secrets inside `tenant-A`:
    await server.updateUserAttributes({
      scopeId: "tenant-A",
      actor: tenantOwnerA,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 500 }
    });
    await server.updateUserHiddenAttributes({
      scopeId: "tenant-A",
      actor: tenantOwnerA,
      targetUid: attendee.uid,
      patch: { moderatorNotes: "Tenant A note" }
    });
    expect(
      await server.readUserHiddenAttributes({
        scopeId: "tenant-A",
        actor: tenantOwnerA,
        targetUid: attendee.uid
      })
    ).toEqual({ moderatorNotes: "Tenant A note" });

    expect(
      await server.updateUserSecrets({
        scopeId: "tenant-A",
        actor: tenantOwnerA,
        targetUid: attendee.uid,
        patch: { openaiKey: "sk-tenant-A-key" }
      })
    ).toEqual({ openaiKey: true });
    expect(
      await server.getUserSecretsStatus({
        scopeId: "tenant-A",
        actor: attendee,
        targetUid: attendee.uid
      })
    ).toEqual({ openaiKey: true });
    expect(await server.getDecryptedUserSecrets("tenant-A", attendee.uid)).toEqual({ openaiKey: "sk-tenant-A-key" });

    // (b) `tenantOwnerA` CANNOT monkey with `tenant-B` attributes, hiddenAttributes, or secrets!
    await expect(
      server.updateUserAttributes({
        scopeId: "tenant-B",
        actor: tenantOwnerA,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 0 }
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.readUserHiddenAttributes({
        scopeId: "tenant-B",
        actor: tenantOwnerA,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.updateUserHiddenAttributes({
        scopeId: "tenant-B",
        actor: tenantOwnerA,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "Cross-tenant sabotage" }
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.getUserSecretsStatus({
        scopeId: "tenant-B",
        actor: tenantOwnerA,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.updateUserSecrets({
        scopeId: "tenant-B",
        actor: tenantOwnerA,
        targetUid: attendee.uid,
        patch: { openaiKey: "sk-sabotage" }
      })
    ).rejects.toThrow(/Forbidden/);

    // (c) `tenantOwnerA` CANNOT monkey with global `users/{attendee.uid}` attributes, hiddenAttributes, or secrets!
    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: tenantOwnerA,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 0 }
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: tenantOwnerA,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: tenantOwnerA,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "Global sabotage" }
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.updateUserSecrets({
        scopeId: GLOBAL_SCOPE,
        actor: tenantOwnerA,
        targetUid: attendee.uid,
        patch: { openaiKey: "sk-global-sabotage" }
      })
    ).rejects.toThrow(/Forbidden/);
  });

  it("tests FirestoreServerStore unified users/{uid}, private/hiddenAttributes, AES-256-GCM encrypted private/secrets, and admin demotion preservation", async () => {
    const docs = new Map<string, Record<string, any>>();
    const fakeDb: any = {
      doc(path: string) {
        return {
          path,
          async get() {
            const data = docs.get(path);
            return {
              id: path.split("/").pop()!,
              exists: Boolean(data),
              data: () => (data ? { ...data } : undefined)
            };
          },
          async set(payload: Record<string, any>, options?: { merge?: boolean }) {
            const current = options?.merge ? { ...(docs.get(path) || {}) } : {};
            for (const [k, v] of Object.entries(payload)) {
              if (v && typeof v === "object" && v.constructor?.name?.includes("Delete")) {
                delete current[k];
              } else {
                current[k] = v;
              }
            }
            docs.set(path, current);
          },
          async delete() {
            docs.delete(path);
          }
        };
      },
      collection(path: string) {
        return {
          where(field: string, _op: string, val: any) {
            return {
              async get() {
                const prefix = `${path}/`;
                const matching: any[] = [];
                for (const [k, v] of docs.entries()) {
                  if (k.startsWith(prefix) && !k.slice(prefix.length).includes("/") && v[field] === val) {
                    matching.push({
                      id: k.slice(prefix.length),
                      data: () => ({ ...v })
                    });
                  }
                }
                return { docs: matching };
              }
            };
          },
          async get() {
            const prefix = `${path}/`;
            const matching: any[] = [];
            for (const [k, v] of docs.entries()) {
              if (k.startsWith(prefix) && !k.slice(prefix.length).includes("/")) {
                matching.push({
                  id: k.slice(prefix.length),
                  data: () => ({ ...v })
                });
              }
            }
            return { docs: matching };
          }
        };
      }
    };

    const fsStore = new FirestoreServerStore<
      TestRole,
      TestCap,
      { theme: string },
      { pointsAllTime: number },
      { note: string },
      { geminiKey: string; openaiKey: string }
    >({
      db: fakeDb,
      defaultRole: "member",
      encryptionKey: "test-master-encryption-key-for-lanyard"
    });

    // 1. Direct AES-256-GCM cipher helper verification
    const cipher = createSecretCipher("test-master-encryption-key-for-lanyard");
    const encrypted = encryptSecret("AIzaSyDirectTest", "test-master-encryption-key-for-lanyard");
    expect(isEncryptedSecretData(encrypted)).toBe(true);
    expect(encrypted.ciphertext).not.toContain("AIzaSyDirectTest");
    expect(decryptSecret(encrypted, "test-master-encryption-key-for-lanyard")).toBe("AIzaSyDirectTest");
    expect(() => createSecretCipher("   ")).toThrow(/non-empty master encryption key/);
    expect(() => decryptSecret({ ciphertext: "bad" } as any, "test-master-encryption-key-for-lanyard")).toThrow(
      /Invalid encrypted secret payload/
    );
    expect(cipher.decrypt(cipher.encrypt("roundtrip-secret"))).toBe("roundtrip-secret");

    // 2. UserRecord + attributes + hiddenAttributes + encrypted secrets on users/{uid}, private/hiddenAttributes, and private/secrets
    await fsStore.upsertUser({
      uid: "u-1",
      email: "u1@example.com",
      firstName: "Testy",
      lastName: "McTest",
      isSystemAdmin: true,
      preferences: { theme: "dark" },
      attributes: { pointsAllTime: 100 }
    });
    await fsStore.updateUserAttributes("u-1", { pointsAllTime: 250 });
    await fsStore.updateUserHiddenAttributes("u-1", { note: "Top secret" });
    const statusAfterWrite = await fsStore.updateUserSecrets("u-1", {
      geminiKey: "AIzaSyLiveKey999",
      openaiKey: "sk-proj-live999"
    });

    expect(docs.get("users/u-1")?.attributes).toEqual({ pointsAllTime: 250 });
    expect(docs.get("users/u-1")?.note).toBeUndefined();
    expect(docs.get("users/u-1")?.geminiKey).toBeUndefined();
    expect(docs.get("users/u-1/private/hiddenAttributes")).toEqual({ note: "Top secret" });
    expect(await fsStore.getUserHiddenAttributes("u-1")).toEqual({ note: "Top secret" });

    // Verify raw Firestore `users/u-1/private/secrets` document stores AES-256-GCM `{ ciphertext, iv, tag }`, NEVER plaintext!
    const rawUserSecretsDoc = docs.get("users/u-1/private/secrets");
    expect(isEncryptedSecretData(rawUserSecretsDoc?.geminiKey)).toBe(true);
    expect(JSON.stringify(rawUserSecretsDoc)).not.toContain("AIzaSyLiveKey999");
    expect(statusAfterWrite).toEqual({ geminiKey: true, openaiKey: true });
    expect(await fsStore.getUserSecretsStatus("u-1")).toEqual({ geminiKey: true, openaiKey: true });
    expect(await fsStore.getUserSecrets("u-1")).toEqual({
      geminiKey: "AIzaSyLiveKey999",
      openaiKey: "sk-proj-live999"
    });

    // Clearing `openaiKey` with `""` deletes the field via FieldValue.delete()
    expect(await fsStore.updateUserSecrets("u-1", { openaiKey: "" })).toEqual({ geminiKey: true });
    expect(await fsStore.getUserSecrets("u-1")).toEqual({ geminiKey: "AIzaSyLiveKey999" });
    expect(await fsStore.listSystemAdmins()).toHaveLength(1);

    // 3. Demoting admin via deleteSystemAdmin sets isSystemAdmin: false on users/u-1 while keeping attributes & preferences
    await fsStore.deleteSystemAdmin("u-1");
    expect(await fsStore.getSystemAdmin("u-1")).toBeNull();
    expect(await fsStore.listSystemAdmins()).toHaveLength(0);
    const afterDemote = await fsStore.getUser("u-1");
    expect(afterDemote?.isSystemAdmin).toBe(false);
    expect(afterDemote?.attributes).toEqual({ pointsAllTime: 250 });
    expect(afterDemote?.preferences).toEqual({ theme: "dark" });

    // 4. Scoped member attributes, private/hiddenAttributes, and private/secrets lifecycle
    await fsStore.upsertScopeMember("ws-1", {
      uid: "u-1",
      email: "u1@example.com",
      roles: ["manager"]
    });
    await fsStore.updateScopeMemberAttributes("ws-1", "u-1", { pointsAllTime: 77 });
    await fsStore.updateScopeMemberHiddenAttributes("ws-1", "u-1", { note: "Workspace note" });
    await fsStore.updateScopeMemberSecrets("ws-1", "u-1", { geminiKey: "AIzaSyMemberSecret" });

    expect(docs.get("workspaces/ws-1/members/u-1")?.attributes).toEqual({ pointsAllTime: 77 });
    expect(docs.get("workspaces/ws-1/members/u-1/private/hiddenAttributes")).toEqual({ note: "Workspace note" });
    expect(await fsStore.getScopeMemberHiddenAttributes("ws-1", "u-1")).toEqual({ note: "Workspace note" });
    expect(isEncryptedSecretData(docs.get("workspaces/ws-1/members/u-1/private/secrets")?.geminiKey)).toBe(true);
    expect(await fsStore.getScopeMemberSecretsStatus("ws-1", "u-1")).toEqual({ geminiKey: true });
    expect(await fsStore.getScopeMemberSecrets("ws-1", "u-1")).toEqual({ geminiKey: "AIzaSyMemberSecret" });

    // Deleting scoped member also deletes both its private/hiddenAttributes and private/secrets subdocuments
    await fsStore.deleteScopeMember("ws-1", "u-1");
    expect(docs.has("workspaces/ws-1/members/u-1")).toBe(false);
    expect(docs.has("workspaces/ws-1/members/u-1/private/hiddenAttributes")).toBe(false);
    expect(docs.has("workspaces/ws-1/members/u-1/private/secrets")).toBe(false);

    // FirestoreServerStore without encryptionKey throws a clear error if encrypted secrets are read/written
    const unconfiguredCipherStore = new FirestoreServerStore({
      db: fakeDb,
      defaultRole: "member"
    });
    await expect(unconfiguredCipherStore.updateUserSecrets("u-1", { geminiKey: "fail" })).rejects.toThrow(
      /configure 'encryptionKey', 'cipher', or MASTER_ENCRYPTION_KEY/
    );
  });

  it("enforces single-tenant sibling role isolation, per-user capability overrides, atomic multi-key patch rejection, and role demotion on users/{uid}", async () => {
    type SingleTenantRole = "attendee" | "scanner" | "merch_seller" | "moderator";
    type SingleTenantCap =
      | "write:points"
      | "read:merch"
      | "write:merch"
      | "write:badges"
      | "read:scanner_log"
      | "write:scanner_log"
      | "read:merch_Pin"
      | "write:merch_Pin"
      | "write:audit_hash";

    interface SingleTenantAttrs {
      pointsAllTime: number;
      merchCreditBalance: number;
      awardedBadges: string[];
      readonlySystemBadge: string;
    }

    interface SingleTenantHiddenAttrs {
      scannerAuditLog: string;
      merchPosPin: string;
      blindAuditHash: string;
    }

    const policy = createPermissionPolicy<SingleTenantRole, SingleTenantCap>({
      roles: {
        attendee: { capabilities: [] },
        // Sibling role A: scanner (handles points + scannerAuditLog)
        scanner: {
          inherits: ["attendee"],
          capabilities: ["write:points", "read:scanner_log", "write:scanner_log"]
        },
        // Sibling role B: merch_seller (handles merchCreditBalance + merchPosPin; does NOT inherit scanner!)
        merch_seller: {
          inherits: ["attendee"],
          capabilities: ["read:merch", "write:merch", "read:merch_Pin", "write:merch_Pin"]
        },
        // Moderator inherits BOTH scanner and merch_seller, plus badges and write-only blindAuditHash
        moderator: {
          inherits: ["scanner", "merch_seller"],
          capabilities: ["write:badges", "write:audit_hash"]
        }
      },
      attributeCapabilities: {
        pointsAllTime: "write:points",
        merchCreditBalance: { read: "read:merch", write: "write:merch" },
        awardedBadges: "write:badges",
        // Read-only for merch/moderator, writable ONLY by system admin (no write capability configured)
        readonlySystemBadge: { read: "read:merch" }
      },
      hiddenAttributeCapabilities: {
        scannerAuditLog: { read: "read:scanner_log", write: "write:scanner_log" },
        merchPosPin: { read: "read:merch_Pin", write: "write:merch_Pin" },
        // Write-only hiddenAttribute for moderator; readable ONLY by system admin
        blindAuditHash: { write: "write:audit_hash" }
      }
    });

    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<
      SingleTenantRole,
      SingleTenantCap,
      Record<string, unknown>,
      SingleTenantAttrs,
      SingleTenantHiddenAttrs
    >();
    const server = createLanyardServer<
      SingleTenantRole,
      SingleTenantCap,
      Record<string, unknown>,
      SingleTenantAttrs,
      SingleTenantHiddenAttrs
    >({
      adminAuth,
      store,
      policy
    });

    const attendee = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "attendee@example.com",
      firstName: "Testy",
      lastName: "McTest",
      roles: ["attendee"],
      attributes: {
        pointsAllTime: 25,
        merchCreditBalance: 150,
        awardedBadges: ["welcome"],
        readonlySystemBadge: "founding-member"
      }
    });
    const scanner = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "scanner@example.com",
      firstName: "Scanny",
      lastName: "McScanner",
      roles: ["scanner"]
    });
    const merchSeller = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "merch@example.com",
      firstName: "Merchy",
      lastName: "McMerch",
      roles: ["merch_seller"]
    });
    const moderator = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "mod@example.com",
      firstName: "Moddy",
      lastName: "McModerator",
      roles: ["moderator"]
    });

    // 1. Mutual sibling role isolation on users/{uid}:
    // - Scanner can update pointsAllTime & scannerAuditLog, but CANNOT read/write merchCreditBalance or merchPosPin
    await server.updateUserAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: scanner,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 40 }
    });
    await server.updateUserHiddenAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: scanner,
      targetUid: attendee.uid,
      patch: { scannerAuditLog: "Scanned booth #4" }
    });
    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { merchCreditBalance: 999 }
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { merchPosPin: "0000" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Merch seller can read/write merchCreditBalance & merchPosPin, but CANNOT write pointsAllTime or read scannerAuditLog
    await server.updateUserAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: merchSeller,
      targetUid: attendee.uid,
      patch: { merchCreditBalance: 120 }
    });
    await server.updateUserHiddenAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: merchSeller,
      targetUid: attendee.uid,
      patch: { merchPosPin: "4821" }
    });
    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: merchSeller,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 999 }
      })
    ).rejects.toThrow(/Forbidden/);

    // Reading attributes & hiddenAttributes redacts each sibling's restricted fields:
    expect(
      await server.readUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 40,
      awardedBadges: ["welcome"]
      // merchCreditBalance and readonlySystemBadge are redacted for scanner!
    });
    expect(
      await server.readUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: merchSeller,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 40,
      merchCreditBalance: 120,
      awardedBadges: ["welcome"],
      readonlySystemBadge: "founding-member"
    });
    expect(
      await server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid
      })
    ).toEqual({ scannerAuditLog: "Scanned booth #4" });
    expect(
      await server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: merchSeller,
        targetUid: attendee.uid
      })
    ).toEqual({ merchPosPin: "4821" });

    // Sibling middleware check: scanner fails requireRole("merch_seller", GLOBAL_SCOPE) and vice versa
    const resScannerAsMerch = createMockRes();
    await server.requireRole("merch_seller", GLOBAL_SCOPE)(
      { user: { uid: scanner.uid, email: scanner.email, isAdmin: false } } as any,
      resScannerAsMerch,
      () => {}
    );
    expect(resScannerAsMerch.statusCode).toBe(403);

    // 2. Write-only hiddenAttribute & Read-only attribute enforcement:
    // Moderator can write `blindAuditHash`, but CANNOT read `blindAuditHash` back (only systemAdmin can read it)
    await server.updateUserHiddenAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: moderator,
      targetUid: attendee.uid,
      patch: { blindAuditHash: "sha256:abcdef" }
    });
    expect(
      await server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid
      })
    ).toEqual({
      scannerAuditLog: "Scanned booth #4",
      merchPosPin: "4821"
      // blindAuditHash is redacted for non-system-admins!
    });
    expect(
      await server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: { uid: "sys-admin", isAdmin: true },
        targetUid: attendee.uid
      })
    ).toEqual({
      scannerAuditLog: "Scanned booth #4",
      merchPosPin: "4821",
      blindAuditHash: "sha256:abcdef"
    });

    // Moderator CANNOT write `readonlySystemBadge` (only systemAdmin can)
    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid,
        patch: { readonlySystemBadge: "forged-founder" }
      })
    ).rejects.toThrow(/Forbidden/);

    // 3. All-or-nothing atomic multi-key patch rejection on users/{uid}:
    // Scanner attempts to patch BOTH `pointsAllTime` (allowed) and `awardedBadges` (forbidden) in one call.
    // Must reject with 403 and leave `pointsAllTime` untouched at 40!
    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 9999, awardedBadges: ["injected-badge"] }
      })
    ).rejects.toThrow(/Forbidden/);
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(40);
    expect((await store.getUser(attendee.uid))?.attributes?.awardedBadges).toEqual(["welcome"]);

    // Same atomic guarantee for hiddenAttributes on users/{uid}/private/hiddenAttributes:
    await expect(
      server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { scannerAuditLog: "Valid", merchPosPin: "9999" }
      })
    ).rejects.toThrow(/Forbidden/);
    expect(await store.getUserHiddenAttributes(attendee.uid)).toEqual({
      scannerAuditLog: "Scanned booth #4",
      merchPosPin: "4821",
      blindAuditHash: "sha256:abcdef"
    });

    // 4. Multi-role grant & revoke on users/{uid} using atomic grantRolesByEmail & revokeRoles:
    // Grant `attendee` the `scanner` role (so they now hold `["attendee", "scanner"]`)
    await server.grantRolesByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "attendee@example.com",
      roles: ["scanner"]
    });
    expect((await store.getUser(attendee.uid))?.roles).toEqual(["attendee", "scanner"]);
    await server.updateUserAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: attendee,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 55 }
    });
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(55);

    // Revoke the `scanner` role on `attendee` -> immediately blocked again
    await server.revokeRoles(GLOBAL_SCOPE, attendee.uid, ["scanner"]);
    expect((await store.getUser(attendee.uid))?.roles).toEqual(["attendee"]);
    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 70 }
      })
    ).rejects.toThrow(/Forbidden/);

    // Also verify scoped `readUserAttributes` enforces scope membership and field-level read rules
    await server.upsertUserByEmail({
      scopeId: "event-2026",
      email: "attendee@example.com",
      roles: ["attendee"],
      attributes: {
        pointsAllTime: 88,
        awardedBadges: ["scoped-badge"],
        merchCreditBalance: 35,
        readonlySystemBadge: "vip"
      }
    });
    await server.upsertUserByEmail({
      scopeId: "event-2026",
      email: "scanner@example.com",
      roles: ["scanner"]
    });
    await server.upsertUserByEmail({
      scopeId: "event-2026",
      email: "mod@example.com",
      roles: ["moderator"]
    });

    // Self in scope can read all their own attributes (`isSelf: true`)
    expect(
      await server.readUserAttributes({
        scopeId: "event-2026",
        actor: attendee,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 88,
      awardedBadges: ["scoped-badge"],
      merchCreditBalance: 35,
      readonlySystemBadge: "vip"
    });

    // Scanner in scope can read attributes without restricted `read` capability (`pointsAllTime`, `awardedBadges`),
    // whereas Moderator in scope also inherits `read:merch` and can read `merchCreditBalance` & `readonlySystemBadge`!
    expect(
      await server.readUserAttributes({
        scopeId: "event-2026",
        actor: scanner,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 88,
      awardedBadges: ["scoped-badge"]
    });
    expect(
      await server.readUserAttributes({
        scopeId: "event-2026",
        actor: moderator,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 88,
      awardedBadges: ["scoped-badge"],
      merchCreditBalance: 35,
      readonlySystemBadge: "vip"
    });

    // Non-member of `event-2026` (`merchSeller`) is rejected with Forbidden
    await expect(
      server.readUserAttributes({
        scopeId: "event-2026",
        actor: merchSeller,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden: Caller is not a member of scope/);

    // 5. Role demotion on users/{uid}:
    // Demote `moderator` down to `scanner` -> immediately loses access to `merchPosPin` and `awardedBadges`,
    // while retaining `scanner` access to `pointsAllTime` and `scannerAuditLog`
    await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "mod@example.com",
      roles: ["scanner"]
    });
    await expect(
      server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid,
        patch: { awardedBadges: ["demoted-mod-badge"] }
      })
    ).rejects.toThrow(/Forbidden/);
    expect(
      await server.readUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid
      })
    ).toEqual({
      scannerAuditLog: "Scanned booth #4"
      // merchPosPin is no longer visible after demotion from moderator to scanner!
    });
    await server.updateUserAttributes({
      scopeId: GLOBAL_SCOPE,
      actor: moderator,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 65 }
    });
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(65);
  });

  it("enforces per-member scoped secrets (updateUserSecrets, getUserSecretsStatus, getDecryptedUserSecrets) for self and delegated writers", async () => {
    type ScopeRole = "coordinator" | "lead";
    type ScopeCap = "manage:oauth_secrets";
    interface ScopeMemberSecrets {
      gmailRefreshToken: string;
      calendarRefreshToken: string;
      managedBotToken: string;
    }

    const policy = createPermissionPolicy<ScopeRole, ScopeCap>({
      roles: {
        coordinator: { capabilities: [] },
        lead: { inherits: ["coordinator"], capabilities: ["manage:oauth_secrets"] }
      },
      secretCapabilities: {
        // Coordinator can connect/disconnect their own Gmail/Calendar OAuth tokens, and a lead can also manage them
        gmailRefreshToken: { write: "manage:oauth_secrets", allowSelfWrite: true },
        calendarRefreshToken: { write: "manage:oauth_secrets", allowSelfWrite: true },
        // Only a lead with manage:oauth_secrets (not self-coordinator) can set managedBotToken
        managedBotToken: { write: "manage:oauth_secrets", allowSelfWrite: false }
      }
    });

    const store = new InMemoryLanyardStore<
      ScopeRole,
      ScopeCap,
      Record<string, any>,
      Record<string, any>,
      Record<string, any>,
      ScopeMemberSecrets
    >();
    const adminAuth = createFakeAdminAuth();
    const server = createLanyardServer<
      ScopeRole,
      ScopeCap,
      Record<string, any>,
      Record<string, any>,
      Record<string, any>,
      ScopeMemberSecrets
    >({
      adminAuth,
      store,
      policy
    });

    const coordA = await server.upsertUserByEmail({
      scopeId: "camp-1",
      email: "coord-a@example.com",
      roles: ["coordinator"]
    });
    const coordB = await server.upsertUserByEmail({
      scopeId: "camp-1",
      email: "coord-b@example.com",
      roles: ["coordinator"]
    });
    const lead = await server.upsertUserByEmail({
      scopeId: "camp-1",
      email: "lead@example.com",
      roles: ["lead"]
    });

    // 1. Coordinator A can write and clear their own `gmailRefreshToken` (`allowSelfWrite: true`)
    const statusAfterSelfWrite = await server.updateUserSecrets({
      scopeId: "camp-1",
      actor: coordA,
      targetUid: coordA.uid,
      patch: { gmailRefreshToken: "1//0g-refresh-token-a" }
    });
    expect(statusAfterSelfWrite).toEqual({ gmailRefreshToken: true });
    expect(
      await server.getUserSecretsStatus({
        scopeId: "camp-1",
        actor: coordA,
        targetUid: coordA.uid
      })
    ).toEqual({ gmailRefreshToken: true });
    expect(await server.getDecryptedUserSecrets("camp-1", coordA.uid)).toEqual({
      gmailRefreshToken: "1//0g-refresh-token-a"
    });

    // 2. Coordinator A CANNOT write `managedBotToken` on themselves (`allowSelfWrite: false`)
    await expect(
      server.updateUserSecrets({
        scopeId: "camp-1",
        actor: coordA,
        targetUid: coordA.uid,
        patch: { managedBotToken: "bot-secret-xyz" }
      })
    ).rejects.toThrow(/Forbidden/);

    // 3. Peer Coordinator B CANNOT write or check status of Coordinator A's secrets (`isSelf: false`, lacks capability)
    await expect(
      server.updateUserSecrets({
        scopeId: "camp-1",
        actor: coordB,
        targetUid: coordA.uid,
        patch: { gmailRefreshToken: "hijacked-token" }
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.getUserSecretsStatus({
        scopeId: "camp-1",
        actor: coordB,
        targetUid: coordA.uid
      })
    ).rejects.toThrow(/Forbidden/);

    // 4. Lead (`manage:oauth_secrets`) CAN write `managedBotToken` and `calendarRefreshToken` on Coordinator A (`isSelf: false`)
    await server.updateUserSecrets({
      scopeId: "camp-1",
      actor: lead,
      targetUid: coordA.uid,
      patch: {
        calendarRefreshToken: "1//0g-cal-token-a",
        managedBotToken: "bot-secret-123"
      }
    });
    expect(await server.getDecryptedUserSecrets("camp-1", coordA.uid)).toEqual({
      gmailRefreshToken: "1//0g-refresh-token-a",
      calendarRefreshToken: "1//0g-cal-token-a",
      managedBotToken: "bot-secret-123"
    });

    // 5. Coordinator A can clear their own `gmailRefreshToken` by passing `""` or `null`
    await server.updateUserSecrets({
      scopeId: "camp-1",
      actor: coordA,
      targetUid: coordA.uid,
      patch: { gmailRefreshToken: null }
    });
    expect(await server.getDecryptedUserSecrets("camp-1", coordA.uid)).toEqual({
      calendarRefreshToken: "1//0g-cal-token-a",
      managedBotToken: "bot-secret-123"
    });
  });

  it("validates AES-256-GCM encryption edge cases (missing key, key mismatch, tampered ciphertext/tag)", async () => {
    // 1. Empty or whitespace master key throws a clear error
    expect(() => createSecretCipher("")).toThrow(/non-empty master encryption key is required/);
    expect(() => createSecretCipher("   ")).toThrow(/non-empty master encryption key is required/);
    expect(() => encryptSecret("secret", "")).toThrow(/non-empty master encryption key is required/);

    // 2. Round-trip encryption produces unique IVs for identical plaintexts
    const cipherA = createSecretCipher("master-key-alpha");
    const enc1 = cipherA.encrypt("same-plaintext");
    const enc2 = cipherA.encrypt("same-plaintext");
    expect(isEncryptedSecretData(enc1)).toBe(true);
    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
    expect(cipherA.decrypt(enc1)).toBe("same-plaintext");
    expect(cipherA.decrypt(enc2)).toBe("same-plaintext");

    // 3. Decrypting with a different key (e.g. wrong key) fails GCM authentication
    const cipherB = createSecretCipher("master-key-beta");
    expect(() => cipherB.decrypt(enc1)).toThrow();
    expect(() => decryptSecret(enc1, "master-key-beta")).toThrow();

    // 4. Tampering with ciphertext or auth tag fails GCM verification
    const tamperedCiphertext = {
      ...enc1,
      ciphertext: enc1.ciphertext.slice(0, -2) + (enc1.ciphertext.endsWith("ff") ? "00" : "ff")
    };
    expect(() => cipherA.decrypt(tamperedCiphertext)).toThrow();

    const tamperedTag = {
      ...enc1,
      tag: enc1.tag.slice(0, -2) + (enc1.tag.endsWith("ff") ? "00" : "ff")
    };
    expect(() => cipherA.decrypt(tamperedTag)).toThrow();

    // 5. Malformed payloads are rejected by isEncryptedSecretData and decrypt()
    expect(isEncryptedSecretData(null)).toBe(false);
    expect(isEncryptedSecretData("plaintext")).toBe(false);
    expect(isEncryptedSecretData({ ciphertext: "abc", iv: "", tag: "def" })).toBe(false);
    expect(() => cipherA.decrypt({ ciphertext: "abc", iv: "", tag: "" })).toThrow(/Invalid encrypted secret payload/);

    // 6. FirestoreServerStore without encryptionKey or MASTER_ENCRYPTION_KEY throws when writing secrets
    const prevMasterKey = process.env.MASTER_ENCRYPTION_KEY;
    delete process.env.MASTER_ENCRYPTION_KEY;
    try {
      const storeWithoutKey = new FirestoreServerStore({
        db: {
          doc: () => ({
            get: async () => ({ exists: false, data: () => ({}) }),
            set: async () => {}
          })
        } as any,
        defaultRole: "member"
      });
      await expect(storeWithoutKey.updateUserSecrets("u-1", { apiKey: "secret-val" })).rejects.toThrow(
        /Cannot encrypt or decrypt secrets/
      );
    } finally {
      if (prevMasterKey !== undefined) {
        process.env.MASTER_ENCRYPTION_KEY = prevMasterKey;
      }
    }
  });

  it("enforces userCapabilities (read, write, assignRoles), abstract roles, multi-role assignment (getUser, listUsers, updateUserProfile, updateUserRoles), and anti-footgun deletion safeguards (deleteUser) across GLOBAL_SCOPE and tenant scopeId", async () => {
    type UserRole =
      | "user_reader_base"
      | "user_writer_base"
      | "attendee"
      | "scanner"
      | "merch_seller"
      | "write_only_registrar"
      | "role_manager"
      | "moderator"
      | "director";
    type UserCap =
      | "read:users"
      | "write:users"
      | "assign:roles"
      | "read:vip_tier"
      | "write:merch"
      | "director:nuclear_launch";

    interface UserAttrs {
      points: number;
      vipTier: string;
    }

    const policy = createPermissionPolicy<UserRole, UserCap>({
      roles: {
        // Abstract capability-grouping roles (never directly assignable, never defaultRole)
        user_reader_base: {
          abstract: true,
          capabilities: ["read:users"]
        },
        user_writer_base: {
          abstract: true,
          capabilities: ["write:users"]
        },
        attendee: { capabilities: [] },
        scanner: {
          inherits: ["attendee", "user_reader_base"],
          capabilities: []
        },
        // Sibling role to scanner/moderator
        merch_seller: {
          inherits: ["attendee"],
          capabilities: ["write:merch"]
        },
        // Write-only user role: has `write:users` via `user_writer_base` and inherits `attendee`, but lacks `read:users` and `assign:roles`
        write_only_registrar: {
          inherits: ["attendee", "user_writer_base"],
          capabilities: []
        },
        // Role manager: has `read:users` + `assign:roles`, but lacks `write:users`
        role_manager: {
          inherits: ["attendee", "user_reader_base"],
          capabilities: ["assign:roles"]
        },
        // Moderator inherits `scanner` and `user_writer_base` (so holds `read:users` + `write:users` + `read:vip_tier`),
        // but does NOT hold `assign:roles`!
        moderator: {
          inherits: ["scanner", "user_writer_base"],
          capabilities: ["read:vip_tier"]
        },
        // Director inherits `moderator`, `merch_seller`, and `role_manager`
        director: {
          inherits: ["moderator", "merch_seller", "role_manager"],
          capabilities: ["director:nuclear_launch"]
        }
      },
      userCapabilities: {
        read: "read:users",
        write: "write:users",
        assignRoles: "assign:roles"
      },
      attributeCapabilities: {
        points: "write:users",
        vipTier: { read: "read:vip_tier", write: "write:users" }
      }
    });

    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<
      UserRole,
      UserCap,
      Record<string, any>,
      UserAttrs,
      { note: string },
      { apiKey: string }
    >();
    const server = createLanyardServer<
      UserRole,
      UserCap,
      Record<string, any>,
      UserAttrs,
      { note: string },
      { apiKey: string }
    >({
      adminAuth,
      store,
      policy
    });

    // 0. Abstract Role Assignment & Middleware Verification:
    // - Assigning an abstract role directly via upsertUserByEmail or grantRolesByEmail (in GLOBAL_SCOPE or tenant scopeId) is rejected!
    await expect(
      server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "bad-abstract@example.com",
        roles: ["user_reader_base"]
      })
    ).rejects.toThrow(/abstract roles cannot be directly assigned to a user/);
    await expect(
      server.grantRolesByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "bad-abstract@example.com",
        roles: ["user_writer_base"]
      })
    ).rejects.toThrow(/abstract roles cannot be directly assigned to a user/);
    await expect(
      server.upsertUserByEmail({
        scopeId: "ws-1",
        email: "bad-abstract@example.com",
        roles: ["user_reader_base"]
      })
    ).rejects.toThrow(/abstract roles cannot be directly assigned to a user/);
    await expect(
      server.grantRolesByEmail({
        scopeId: "ws-1",
        email: "bad-abstract@example.com",
        roles: ["user_writer_base"]
      })
    ).rejects.toThrow(/abstract roles cannot be directly assigned to a user/);

    const attendee = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "attendee@example.com",
      firstName: "Testy",
      lastName: "McTest",
      roles: ["attendee"],
      preferences: { theme: "dark" },
      attributes: { points: 50, vipTier: "gold" }
    });
    const scanner = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "scanner@example.com",
      firstName: "Scanny",
      lastName: "McScanner",
      roles: ["scanner"],
      attributes: { points: 10, vipTier: "silver" }
    });
    const merchSeller = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "merch@example.com",
      firstName: "Merchy",
      lastName: "McMerch",
      roles: ["merch_seller"]
    });
    const registrar = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "registrar@example.com",
      firstName: "Reggie",
      lastName: "Registrar",
      roles: ["write_only_registrar"]
    });
    const roleManager = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "rolemanager@example.com",
      firstName: "Roley",
      lastName: "Manager",
      roles: ["role_manager"]
    });
    const moderator = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "moderator@example.com",
      firstName: "Moddy",
      lastName: "McModerator",
      roles: ["moderator"]
    });
    const moderator2 = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "moderator2@example.com",
      firstName: "Second",
      lastName: "Moderator",
      roles: ["moderator"]
    });
    const director = await server.upsertUserByEmail({
      scopeId: GLOBAL_SCOPE,
      email: "director@example.com",
      firstName: "Dirk",
      lastName: "Director",
      roles: ["director"]
    });
    const sysAdmin = await server.setSystemAdminStatus({
      email: "sysadmin@example.com",
      isAdmin: true,
      firstName: "Root",
      lastName: "Admin",
      actor: { uid: "bootstrap", isAdmin: true }
    });

    // - Middleware `requireRole("user_reader_base", GLOBAL_SCOPE)` passes for `scanner` and `moderator` (who inherit `user_reader_base`),
    //   and fails for `attendee` and `merch_seller`!
    let scannerPassedAbstractRole = false;
    await server.requireRole("user_reader_base", GLOBAL_SCOPE)(
      { user: { uid: scanner.uid, email: scanner.email, isAdmin: false } } as any,
      createMockRes(),
      () => {
        scannerPassedAbstractRole = true;
      }
    );
    expect(scannerPassedAbstractRole).toBe(true);

    const resMerchAbstract = createMockRes();
    await server.requireRole("user_reader_base", GLOBAL_SCOPE)(
      { user: { uid: merchSeller.uid, email: merchSeller.email, isAdmin: false } } as any,
      resMerchAbstract,
      () => {}
    );
    expect(resMerchAbstract.statusCode).toBe(403);

    // 1. Viewing users (`getUser` and `listUsers`):
    await store.updateUserHiddenAttributes(attendee.uid, { note: "Confidential staff note" });
    await store.updateUserSecrets(attendee.uid, { apiKey: "AIzaSySecret123" });

    // - Attendee can read their own profile (including restricted `vipTier`), but CANNOT read another user's profile or list users
    const selfRead = await server.getUser({
      scopeId: GLOBAL_SCOPE,
      actor: attendee,
      targetUid: attendee.uid
    });
    expect(selfRead?.attributes).toEqual({ points: 50, vipTier: "gold" });
    // `hiddenAttributes` and `secrets` never leak onto `getUser`!
    expect((selfRead as any)?.note).toBeUndefined();
    expect((selfRead as any)?.apiKey).toBeUndefined();

    await expect(
      server.getUser({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: scanner.uid
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.listUsers({
        scopeId: GLOBAL_SCOPE,
        actor: attendee
      })
    ).rejects.toThrow(/Forbidden/);

    // - Write-only registrar (has `write:users`, lacks `read:users`) CANNOT read another user or list users!
    await expect(
      server.getUser({
        scopeId: GLOBAL_SCOPE,
        actor: registrar,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.listUsers({
        scopeId: GLOBAL_SCOPE,
        actor: registrar
      })
    ).rejects.toThrow(/Forbidden/);

    // - Scanner (inherits `read:users` from abstract `user_reader_base`, lacks `read:vip_tier`) CAN read another user's profile and list users;
    //   restricted attributes (`vipTier`) are redacted on OTHER users (`attendee`), while remaining UNREDACTED on `scanner`'s own record in `listUsers`!
    const scannerReadAttendee = await server.getUser({
      scopeId: GLOBAL_SCOPE,
      actor: scanner,
      targetUid: attendee.uid
    });
    expect(scannerReadAttendee?.email).toBe("attendee@example.com");
    expect(scannerReadAttendee?.attributes).toEqual({ points: 50 });

    const scannerListed = await server.listUsers({ scopeId: GLOBAL_SCOPE, actor: scanner });
    expect(scannerListed).toHaveLength(9);
    expect(scannerListed.find((u) => u.uid === attendee.uid)?.attributes).toEqual({ points: 50 });
    expect(scannerListed.find((u) => u.uid === scanner.uid)?.attributes).toEqual({ points: 10, vipTier: "silver" });

    // - Multi-role grant (`scanner`) to `merchSeller` (`roles: ["merch_seller", "scanner"]`) then revoked:
    await server.grantRolesByEmail({
      scopeId: GLOBAL_SCOPE,
      email: merchSeller.email,
      roles: ["scanner"]
    });
    expect((await server.getUser({ scopeId: GLOBAL_SCOPE, actor: merchSeller, targetUid: attendee.uid }))?.uid).toBe(
      attendee.uid
    );
    await server.revokeRoles(GLOBAL_SCOPE, merchSeller.uid, ["scanner"]);
    await expect(
      server.getUser({ scopeId: GLOBAL_SCOPE, actor: merchSeller, targetUid: attendee.uid })
    ).rejects.toThrow(/Forbidden/);

    // - Moderator (holds `read:users` + `read:vip_tier`) sees unredacted `vipTier`, and `note`/`apiKey` still never leak onto UserRecord
    const modReadAttendee = await server.getUser({
      scopeId: GLOBAL_SCOPE,
      actor: moderator,
      targetUid: attendee.uid
    });
    expect(modReadAttendee?.attributes).toEqual({ points: 50, vipTier: "gold" });
    expect((modReadAttendee as any)?.note).toBeUndefined();
    expect((modReadAttendee as any)?.apiKey).toBeUndefined();

    // 2. Editing User Profiles (`updateUserProfile`):
    // - Self profile edit (`actor.uid === targetUid`) by `attendee` (who lacks `write:users`) is ALLOWED,
    //   and preserves `roles`, `preferences`, and `attributes`!
    const selfEdited = await server.updateUserProfile({
      scopeId: GLOBAL_SCOPE,
      actor: attendee,
      targetUid: attendee.uid,
      patch: {
        firstName: "SelfRenamed",
        lastName: "Attendee",
        photoUrl: "javascript:alert(1)" // sanitized to null!
      }
    });
    expect(selfEdited.displayName).toBe("SelfRenamed Attendee");
    expect(selfEdited.photoUrl).toBeNull();
    expect(selfEdited.roles).toEqual(["attendee"]);
    expect(selfEdited.preferences).toEqual({ theme: "dark" });
    expect(selfEdited.attributes).toEqual({ points: 50, vipTier: "gold" });

    // - No-permission user (`attendee`) trying to edit another user -> Forbidden
    await expect(
      server.updateUserProfile({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: scanner.uid,
        patch: { firstName: "Hacked" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Read-only user (`scanner` with `read:users`, lacking `write:users`) trying to edit another user -> Forbidden
    await expect(
      server.updateUserProfile({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { firstName: "HackedByScanner" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Role-assigner (`roleManager` with `assign:roles`, lacking `write:users`) trying to edit another user's profile -> Forbidden
    await expect(
      server.updateUserProfile({
        scopeId: GLOBAL_SCOPE,
        actor: roleManager,
        targetUid: attendee.uid,
        patch: { firstName: "HackedByRoleManager" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Write-only user (`registrar` with `write:users`, lacking `read:users`) CAN edit another non-admin user's profile
    const registrarEdited = await server.updateUserProfile({
      scopeId: GLOBAL_SCOPE,
      actor: registrar,
      targetUid: attendee.uid,
      patch: { firstName: "ReggieUpdated" }
    });
    expect(registrarEdited.firstName).toBe("ReggieUpdated");

    // - Moderator (with `write:users`) CAN edit `attendee` or `merchSeller`, and syncs `displayName` to `adminAuth.updateUser`
    const updatedProfile = await server.updateUserProfile({
      scopeId: GLOBAL_SCOPE,
      actor: moderator,
      targetUid: attendee.uid,
      patch: { firstName: "Renamed", lastName: "Attendee" }
    });
    expect(updatedProfile?.displayName).toBe("Renamed Attendee");
    expect(adminAuth.updatedUsersByUid.get(attendee.uid)).toEqual({
      displayName: "Renamed Attendee"
    });

    // - Non-existent target user throws not-found and never creates a phantom user doc
    await expect(
      server.updateUserProfile({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: "non-existent-uid",
        patch: { firstName: "Ghost" }
      })
    ).rejects.toThrow(/Target user 'non-existent-uid' not found/);
    expect(await store.getUser("non-existent-uid")).toBeNull();

    // - Non-system-admin Moderator CANNOT edit a `systemAdmin`!
    await expect(
      server.updateUserProfile({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: sysAdmin!.uid,
        patch: { firstName: "HijackedAdmin" }
      })
    ).rejects.toThrow(/Non-system administrators cannot modify a system administrator/);

    // 3. Updating User Roles (`updateUserRoles` gated by `userCapabilities.assignRoles`):
    // - No-permission user (`attendee`), read-only user (`scanner`), and `write:users`-only user (`moderator`) CANNOT call `updateUserRoles`!
    await expect(
      server.updateUserRoles({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        roles: ["scanner"]
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.updateUserRoles({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        roles: ["scanner"]
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.updateUserRoles({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid,
        roles: ["scanner"]
      })
    ).rejects.toThrow(/Forbidden: Insufficient permissions to assign user roles/);

    // - Abstract role cannot be assigned via `updateUserRoles` (even by `roleManager` or `systemAdmin`!)
    await expect(
      server.updateUserRoles({
        scopeId: GLOBAL_SCOPE,
        actor: sysAdmin!,
        targetUid: attendee.uid,
        roles: ["user_writer_base"]
      })
    ).rejects.toThrow(/abstract roles cannot be directly assigned to a user/);

    // - Non-system-admin `roleManager` (who holds `assign:roles`) CANNOT modify a `systemAdmin`!
    await expect(
      server.updateUserRoles({
        scopeId: GLOBAL_SCOPE,
        actor: roleManager,
        targetUid: sysAdmin!.uid,
        roles: ["attendee"]
      })
    ).rejects.toThrow(/Non-system administrators cannot modify a system administrator/);

    // - Trusted `roleManager` (who holds `assign:roles`) CAN assign multiple concrete roles (e.g. `["scanner", "merch_seller"]`)
    //   to `attendee`, even though `roleManager` does not personally hold `scanner` or `merch_seller`!
    const updatedRoles = await server.updateUserRoles({
      scopeId: GLOBAL_SCOPE,
      actor: roleManager,
      targetUid: attendee.uid,
      roles: ["scanner", "merch_seller"]
    });
    expect(updatedRoles.roles).toEqual(["scanner", "merch_seller"]);
    expect(policy.hasAllRoles(updatedRoles, ["attendee", "user_reader_base", "scanner", "merch_seller"])).toBe(true);
    expect(policy.hasAllCapabilities(updatedRoles, ["read:users", "write:merch"])).toBe(true);

    // 4. Unified User Deletion Safeguards (`deleteUser` in `GLOBAL_SCOPE` and tenant `scopeId`):
    // Safeguard A1: Swapped UIDs when target lacks `write:users` (`actor: attendee, targetUid: moderator.uid`) -> Rejected by permission check!
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: attendee, // Swapped!
        targetUid: moderator.uid,
        confirmTargetEmail: "attendee@example.com"
      })
    ).rejects.toThrow(/Forbidden/);
    expect(await store.getUser(moderator.uid)).not.toBeNull();

    // Safeguard A2: Swapped UIDs when BOTH users have `write:users` (`actor: moderator2, targetUid: moderator.uid`)
    // or when `moderator` accidentally passes their own UID as `targetUid` while trying to delete `attendee@example.com`!
    // `confirmTargetEmail` ("attendee@example.com") does NOT match `moderator.email` ("moderator@example.com"), so deletion is aborted before any data is touched!
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: moderator.uid, // ACCIDENTALLY PASSED OWN UID!
        confirmTargetEmail: "attendee@example.com"
      })
    ).rejects.toThrow(/confirmTargetEmail 'attendee@example\.com' does not match target user's email/);
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: moderator2,
        targetUid: moderator.uid, // ACCIDENTALLY SWAPPED!
        confirmTargetEmail: "attendee@example.com"
      })
    ).rejects.toThrow(/confirmTargetEmail 'attendee@example\.com' does not match target user's email/);
    expect(await store.getUser(moderator.uid)).not.toBeNull();
    expect(adminAuth.deletedUids.has(moderator.uid)).toBe(false);

    // Safeguard B: Empty or whitespace `confirmTargetEmail` is rejected
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid,
        confirmTargetEmail: "   "
      })
    ).rejects.toThrow(/confirmTargetEmail is required/);

    // Safeguard C: Role without `write:users` (`scanner`, `roleManager`, or `attendee`) cannot delete OTHER users
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        confirmTargetEmail: "attendee@example.com"
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: roleManager,
        targetUid: attendee.uid,
        confirmTargetEmail: "attendee@example.com"
      })
    ).rejects.toThrow(/Forbidden/);

    // Safeguard D: Non-system-admin Moderator cannot delete a `systemAdmin` even with matching email!
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: sysAdmin!.uid,
        confirmTargetEmail: "sysadmin@example.com"
      })
    ).rejects.toThrow(/Non-system administrators cannot delete a system administrator/);

    // Safeguard E: Stale 1-hour admin JWT after demotion cannot delete or modify users
    const tempAdmin = await server.setSystemAdminStatus({
      email: "tempadmin@example.com",
      isAdmin: true,
      actor: sysAdmin!
    });
    await server.setSystemAdminStatus({
      email: "tempadmin@example.com",
      isAdmin: false,
      actor: sysAdmin!
    });
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: { uid: tempAdmin!.uid, isAdmin: true }, // Stale JWT claim!
        targetUid: attendee.uid,
        confirmTargetEmail: "attendee@example.com"
      })
    ).rejects.toThrow(/Forbidden/);

    // 5. Tenant-Scoped User Management (`getUser`, `listUsers`, `updateUserProfile`, `updateUserRoles`, `deleteUser` with `scopeId: "ws-scoped"`):
    await server.upsertUserByEmail({
      scopeId: "ws-scoped",
      email: "attendee@example.com",
      firstName: "Scoped",
      lastName: "Attendee",
      roles: ["attendee"],
      attributes: { points: 77, vipTier: "platinum" }
    });
    await server.upsertUserByEmail({
      scopeId: "ws-scoped",
      email: "scanner@example.com",
      roles: ["scanner"]
    });
    await server.upsertUserByEmail({
      scopeId: "ws-scoped",
      email: "rolemanager@example.com",
      roles: ["role_manager"]
    });
    await server.upsertUserByEmail({
      scopeId: "ws-scoped",
      email: "moderator@example.com",
      roles: ["moderator"]
    });

    // Scoped `getUser` & `listUsers` enforce scope membership and attribute redaction
    const scopedReadByScanner = await server.getUser({
      scopeId: "ws-scoped",
      actor: scanner,
      targetUid: attendee.uid
    });
    expect(scopedReadByScanner?.attributes).toEqual({ points: 77 }); // vipTier redacted for scanner!
    const scopedListedByScanner = await server.listUsers({
      scopeId: "ws-scoped",
      actor: scanner
    });
    expect(scopedListedByScanner).toHaveLength(4);

    // Scoped `updateUserProfile` & `updateUserRoles`
    const scopedEdited = await server.updateUserProfile({
      scopeId: "ws-scoped",
      actor: moderator,
      targetUid: attendee.uid,
      patch: { firstName: "ScopedRenamed" }
    });
    expect(scopedEdited.displayName).toBe("ScopedRenamed Attendee");

    const scopedRolesUpdated = await server.updateUserRoles({
      scopeId: "ws-scoped",
      actor: roleManager,
      targetUid: attendee.uid,
      roles: ["scanner"]
    });
    expect(scopedRolesUpdated.roles).toEqual(["scanner"]);

    // Scoped `deleteUser` removes the member from `"ws-scoped"` with `confirmTargetEmail` verification,
    // WITHOUT deleting the global `users/{attendee.uid}` record or Firebase Auth user!
    await expect(
      server.deleteUser({
        scopeId: "ws-scoped",
        actor: moderator,
        targetUid: attendee.uid,
        confirmTargetEmail: "wrong@example.com"
      })
    ).rejects.toThrow(/does not match target member's email/);

    await server.deleteUser({
      scopeId: "ws-scoped",
      actor: moderator,
      targetUid: attendee.uid,
      confirmTargetEmail: "attendee@example.com"
    });
    expect(await store.getScopeMember("ws-scoped", attendee.uid)).toBeNull();
    expect(await store.getUser(attendee.uid)).not.toBeNull();
    expect(adminAuth.deletedUids.has(attendee.uid)).toBe(false);

    // Safeguard F: Authorized Moderator deleting `attendee` in `GLOBAL_SCOPE` with matching `confirmTargetEmail`
    // succeeds and cleans up store + hiddenAttributes + secrets + Auth
    await server.deleteUser({
      scopeId: GLOBAL_SCOPE,
      actor: moderator,
      targetUid: attendee.uid,
      confirmTargetEmail: "  ATTENDEE@example.com "
    });
    expect(await store.getUser(attendee.uid)).toBeNull();
    expect(await store.getUserHiddenAttributes(attendee.uid)).toEqual({});
    expect(await store.getUserSecrets(attendee.uid)).toEqual({});
    expect(adminAuth.deletedUids.has(attendee.uid)).toBe(true);

    // Director (who holds `write:users`) CAN delete `merch_seller`
    await server.deleteUser({
      scopeId: GLOBAL_SCOPE,
      actor: director,
      targetUid: merchSeller.uid,
      confirmTargetEmail: "merch@example.com"
    });
    expect(await store.getUser(merchSeller.uid)).toBeNull();

    // Safeguard G: Self-deletion (`actor.uid === targetUid` on `deleteUser`) works without `write:users`,
    // requires non-empty matching `confirmTargetEmail`, and cleans up store + Auth
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: scanner.uid,
        confirmTargetEmail: "   "
      })
    ).rejects.toThrow(/confirmTargetEmail is required/);
    await expect(
      server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: scanner.uid,
        confirmTargetEmail: "wrong@example.com"
      })
    ).rejects.toThrow(/confirmTargetEmail 'wrong@example\.com' does not match target user's email/);
    expect(await store.getUser(scanner.uid)).not.toBeNull();

    await server.deleteUser({
      scopeId: GLOBAL_SCOPE,
      actor: scanner,
      targetUid: scanner.uid,
      confirmTargetEmail: "scanner@example.com"
    });
    expect(await store.getUser(scanner.uid)).toBeNull();
    expect(adminAuth.deletedUids.has(scanner.uid)).toBe(true);
  });

  it("invokes onVerifiedEmailChange and updates users/{uid}.email in checkAuth when verified token email changes", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    await store.upsertUser({
      uid: "u-verified",
      email: "old-verified@example.com",
      roles: ["member"]
    });

    const onVerifiedEmailChange = vi
      .fn()
      .mockRejectedValueOnce(new Error("Transient Beehiiv outage"))
      .mockResolvedValue(undefined);

    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY,
      onVerifiedEmailChange
    });

    // 1. First checkAuth call: onVerifiedEmailChange rejects -> request still succeeds, and users/{uid}.email stays 'old-verified@example.com' for retry
    const req1: any = { headers: { authorization: "Bearer valid-token" } };
    let next1 = false;
    await server.checkAuth(req1, createMockRes(), () => {
      next1 = true;
    });
    expect(next1).toBe(true);
    expect(onVerifiedEmailChange).toHaveBeenCalledTimes(1);
    expect(onVerifiedEmailChange).toHaveBeenCalledWith({
      uid: "u-verified",
      email: "verified@example.com",
      previousEmail: "old-verified@example.com"
    });
    expect((await store.getUser("u-verified"))?.email).toBe("old-verified@example.com");

    // 2. Second checkAuth call: onVerifiedEmailChange resolves -> users/{uid}.email is updated to 'verified@example.com'
    const req2: any = { headers: { authorization: "Bearer valid-token" } };
    await server.checkAuth(req2, createMockRes(), () => {});
    expect(onVerifiedEmailChange).toHaveBeenCalledTimes(2);
    expect((await store.getUser("u-verified"))?.email).toBe("verified@example.com");
    expect(req2.userRecord?.email).toBe("verified@example.com");

    // 3. Subsequent checkAuth call with already-synced email does not invoke onVerifiedEmailChange again
    const req3: any = { headers: { authorization: "Bearer valid-token" } };
    await server.checkAuth(req3, createMockRes(), () => {});
    expect(onVerifiedEmailChange).toHaveBeenCalledTimes(2);
  });
});

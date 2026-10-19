import { describe, it, expect, vi } from "vitest";
import { createPermissionPolicy, InMemoryLanyardStore } from "../core/index.js";
import {
  assertNotProduction,
  createLanyardServer,
  FakeAuthService,
  GoogleAuthService,
  type AdminAuthAdapter
} from "./index.js";
import { FirestoreServerStore } from "./firestore.js";

type TestRole = "owner" | "manager" | "member";
type TestCap = "edit_content" | "invite_members" | "billing";

const TEST_POLICY = createPermissionPolicy<TestRole, TestCap>({
  roles: {
    owner: {
      weight: 30,
      capabilities: "*",
      trackPresence: true
    },
    manager: {
      weight: 20,
      capabilities: ["edit_content", "invite_members"],
      trackPresence: true
    },
    member: {
      weight: 10,
      capabilities: [],
      trackPresence: false
    }
  }
});

function createFakeAdminAuth(): AdminAuthAdapter & {
  claimsByUid: Map<string, Record<string, any> | null>;
} {
  const usersByEmail = new Map<string, { uid: string; email: string; displayName?: string }>();
  const claimsByUid = new Map<string, Record<string, any> | null>();
  let counter = 1;

  return {
    claimsByUid,
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

  it("enforces FakeAuthService production guards, Bearer header requirements, and adminAuth fallback", async () => {
    const origNodeEnv = process.env.NODE_ENV;
    const origKService = process.env.K_SERVICE;
    try {
      process.env.NODE_ENV = "production";
      expect(() => assertNotProduction("FakeAuthService")).toThrow(/SECURITY VIOLATION/);

      process.env.NODE_ENV = "development";
      process.env.K_SERVICE = "my-prod-service";
      expect(() => assertNotProduction("FakeAuthService")).toThrow(/SECURITY VIOLATION/);
    } finally {
      process.env.NODE_ENV = origNodeEnv;
      if (origKService) process.env.K_SERVICE = origKService;
      else delete process.env.K_SERVICE;
    }

    const adminAuth = createFakeAdminAuth();
    const fakeAuth = new FakeAuthService(adminAuth);

    // Rejects x-mock-user-email if Authorization: Bearer header is missing
    await expect(fakeAuth.verifyToken(undefined, { "x-mock-user-email": "alice@example.com" })).rejects.toThrow(
      /Missing Authorization header/
    );
    await expect(fakeAuth.verifyToken("Bearer   ", { "x-mock-user-email": "alice@example.com" })).rejects.toThrow(
      /Missing Authorization header/
    );

    // Default mock-uid-<email> when x-mock-user-uid is omitted
    const mockUser = await fakeAuth.verifyToken("Bearer mock", {
      "x-mock-user-email": "  Alice@Example.com "
    });
    expect(mockUser?.uid).toBe("mock-uid-alice@example.com");

    // Falls back to GoogleAuthService when no x-mock-user-email header is provided
    const fallbackUser = await fakeAuth.verifyToken("Bearer valid-token", {});
    expect(fallbackUser?.uid).toBe("u-verified");
  });

  it("provisions UIDs by email, manages system admins, and grants/revokes multi-capabilities", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY,
      authService: new FakeAuthService()
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

    // 2. Grant multiple capabilities incrementally by email (defaults to policy.defaultRole = 'member')
    await server.grantScopeCapabilitiesByEmail({
      scopeId: "ws-1",
      email: "newmember@example.com",
      capabilities: ["edit_content"],
      firstName: "New",
      lastName: "Member"
    });
    const afterSecondGrant = await server.grantScopeCapabilitiesByEmail({
      scopeId: "ws-1",
      email: "newmember@example.com",
      capabilities: ["invite_members"]
    });
    expect(afterSecondGrant.uid).toBe("provisioned-uid-1");
    expect(afterSecondGrant.role).toBe("member");
    expect(afterSecondGrant.capabilities).toEqual(["edit_content", "invite_members"]);

    // Revoke capability
    await server.revokeScopeCapabilities("ws-1", "provisioned-uid-1", ["edit_content"]);
    expect((await store.getScopeMember("ws-1", "provisioned-uid-1"))?.capabilities).toEqual(["invite_members"]);

    // Upsert full member by email
    const upsertedManager = await server.upsertScopeMemberByEmail({
      scopeId: "ws-1",
      email: "lead@example.com",
      firstName: "Lead",
      lastName: "Manager",
      role: "manager",
      capabilities: ["edit_content"]
    });
    expect(upsertedManager.role).toBe("manager");

    // 3. Promote and demote system admin
    const adminProfile = await server.setSystemAdminStatus({
      email: "boss@example.com",
      isAdmin: true,
      firstName: "Boss",
      lastName: "Admin",
      actorUid: "root-admin"
    });
    expect(adminProfile?.uid).toBe("provisioned-uid-3");
    expect(adminAuth.claimsByUid.get("provisioned-uid-3")).toEqual({ admin: true });

    // Prevent self-demotion
    await expect(
      server.setSystemAdminStatus({
        email: "boss@example.com",
        isAdmin: false,
        actorUid: "provisioned-uid-3"
      })
    ).rejects.toThrow(/Cannot remove yourself/);

    // Demote by a different admin succeeds
    const demoted = await server.setSystemAdminStatus({
      email: "boss@example.com",
      isAdmin: false,
      actorUid: "root-admin"
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
      policy: TEST_POLICY,
      authService: new FakeAuthService()
    });

    // Unauthenticated checkAuth -> 401
    const resUnauth = createMockRes();
    await server.checkAuth({ headers: {} } as any, resUnauth, () => {});
    expect(resUnauth.statusCode).toBe(401);

    // Invalid credentials throw in checkAuth -> 401
    const resBadHeader = createMockRes();
    await server.checkAuth({ headers: { "x-mock-user-email": "x@example.com" } } as any, resBadHeader, () => {});
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
      role: "member",
      capabilities: ["invite_members"],
      photoUrl: null
    });

    await store.upsertScopeMember("ws-1", {
      uid: "u-mgr",
      email: "mgr@example.com",
      role: "manager",
      capabilities: [],
      photoUrl: null
    });

    // Missing user (401) and missing scope param (400) in requireScopeRole & requireScopeCapability
    const requireManager = server.requireScopeRole("manager");
    const requireInvite = server.requireScopeCapability("invite_members");
    const requireAnyCap = server.requireScopeCapability(["edit_content", "invite_members"]);

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
        authorization: "Bearer mock",
        "x-mock-user-email": "inviter@example.com",
        "x-mock-user-uid": "u-inviter",
        "x-mock-user-photo-url": "https://example.com/inviter-oauth.png"
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
        authorization: "Bearer mock",
        "x-mock-user-email": "mgr@example.com",
        "x-mock-user-uid": "u-mgr",
        "x-mock-user-photo-url": "https://example.com/mgr-oauth.png"
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

  it("tests FirestoreServerStore CRUD, custom resolveRole, and additive/subtractive capabilities", async () => {
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
      defaultRole: "member",
      resolveRole: (data) => (data.role as TestRole) || (data.isCreator ? "owner" : "member")
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

    // 2. Scoped Member CRUD + custom resolveRole + grant/revoke/delete
    await expect(store.grantScopeCapabilities("ws-1", "missing", ["edit_content"])).rejects.toThrow(/does not exist/);

    const created = await store.grantScopeCapabilities("ws-1", "u-1", ["edit_content"], {
      uid: "u-1",
      email: "u1@example.com",
      role: "member"
    });
    expect(created.capabilities).toEqual(["edit_content"]);
    expect((await store.getScopeMember("ws-1", "u-1"))?.capabilities).toEqual(["edit_content"]);

    // Additive grant on existing member uses FieldValue.arrayUnion
    const updatedGrant = await store.grantScopeCapabilities("ws-1", "u-1", ["invite_members"]);
    expect(updatedGrant.capabilities).toEqual(["edit_content", "invite_members"]);

    // Subtractive revoke on existing member uses FieldValue.arrayRemove
    await store.revokeScopeCapabilities("ws-1", "u-1", ["edit_content"]);
    expect((await store.getScopeMember("ws-1", "u-1"))?.capabilities).toEqual(["invite_members"]);

    // No-op revokes (empty array or non-existent member)
    await store.revokeScopeCapabilities("ws-1", "u-1", []);
    await store.revokeScopeCapabilities("ws-1", "non-existent", ["invite_members"]);

    // Legacy doc with isCreator: true resolves to 'owner' via resolveRole
    docs.set("workspaces/ws-1/members/u-legacy", {
      uid: "u-legacy",
      email: "legacy@example.com",
      isCreator: true
    });
    expect((await store.getScopeMember("ws-1", "u-legacy"))?.role).toBe("owner");
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
      policy: TEST_POLICY,
      authService: new FakeAuthService()
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
      role: "manager",
      capabilities: ["edit_content"],
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

    // 2. requireScopeRole with already-matching photoUrl -> zero store writes
    const requireManager = server.requireScopeRole("manager");
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

    // 3. requireScopeCapability with already-matching photoUrl -> zero store writes
    const requireEdit = server.requireScopeCapability("edit_content");
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
      policy: TEST_POLICY,
      authService: new FakeAuthService()
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
    const m1 = await server.grantScopeCapabilitiesByEmail({
      scopeId: "ws-1",
      email: "  Multi.Scope@Example.com ",
      capabilities: ["edit_content"],
      firstName: "Multi",
      lastName: "Scope"
    });
    const m2 = await server.upsertScopeMemberByEmail({
      scopeId: "ws-2",
      email: "multi.scope@example.com",
      role: "owner"
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

    const promoted = await server.upsertScopeMemberByEmail({
      scopeId: "ws-1",
      email: "multi.scope@example.com",
      role: "manager"
    });
    expect(promoted.role).toBe("manager");
    expect(promoted.photoUrl).toBe("https://example.com/multi-avatar.png");
    expect(promoted.lastSeen).toBe("2026-10-19T15:00:00.000Z");
    expect(promoted.capabilities).toEqual(["edit_content"]);
  });

  it("enforces cross-scope authorization isolation, capability revocation, and custom scopeParamName", async () => {
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY,
      authService: new FakeAuthService()
    });

    // User is 'owner' in ws-A, but only 'member' with ['invite_members'] in ws-B, and not a member of ws-C
    await store.upsertScopeMember("ws-A", {
      uid: "u-scoped",
      email: "scoped@example.com",
      role: "owner",
      capabilities: []
    });
    await store.upsertScopeMember("ws-B", {
      uid: "u-scoped",
      email: "scoped@example.com",
      role: "member",
      capabilities: ["invite_members"]
    });

    const requireOwnerOnProject = server.requireScopeRole("owner", "projectId");
    const requireInviteOnProject = server.requireScopeCapability("invite_members", "projectId");
    const requireEditOnProject = server.requireScopeCapability("edit_content", "projectId");

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

    // 3. In ws-B, user has 'invite_members' but not 'edit_content'
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

    const resNoEditB = createMockRes();
    await requireEditOnProject(
      {
        user: { uid: "u-scoped", email: "scoped@example.com", isAdmin: false },
        params: { projectId: "ws-B" }
      } as any,
      resNoEditB,
      () => {}
    );
    expect(resNoEditB.statusCode).toBe(403);

    // 4. Revoke 'invite_members' in ws-B -> immediately blocked (403), while global system admin still passes
    await server.revokeScopeCapabilities("ws-B", "u-scoped", ["invite_members"]);
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

    // 3. FakeAuthService.verifyToken re-checks assertNotProduction on every invocation (including FUNCTION_TARGET)
    const fakeAuth = new FakeAuthService(adminAuth);
    const origFnTarget = process.env.FUNCTION_TARGET;
    try {
      process.env.FUNCTION_TARGET = "apiHandler";
      await expect(fakeAuth.verifyToken("Bearer mock", { "x-mock-user-email": "alice@example.com" })).rejects.toThrow(
        /SECURITY VIOLATION/
      );
    } finally {
      if (origFnTarget !== undefined) process.env.FUNCTION_TARGET = origFnTarget;
      else delete process.env.FUNCTION_TARGET;
    }

    // FakeAuthService rejects path-traversal x-mock-user-uid
    await expect(
      fakeAuth.verifyToken("Bearer mock", {
        "x-mock-user-email": "alice@example.com",
        "x-mock-user-uid": "../system_admins/root"
      })
    ).rejects.toThrow(/Invalid x-mock-user-uid/);

    // 4. requireScopeRole and requireScopeCapability reject path-traversal scopeId with 400
    // and never leak internal database error details in 500 responses
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY,
      authService: fakeAuth
    });
    const requireMgr = server.requireScopeRole("manager");
    const requireEdit = server.requireScopeCapability("edit_content");

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

    // 6. setSystemAdminStatus preserves pre-existing customClaims and validates actorUid
    await expect(
      server.setSystemAdminStatus({
        email: "boss@example.com",
        isAdmin: true,
        actorUid: "../bad-actor"
      })
    ).rejects.toThrow(/Invalid actorUid/);

    const provisionedBoss = await server.getOrProvisionUidByEmail({ email: "boss@example.com" });
    adminAuth.claimsByUid.set(provisionedBoss.uid, { tenantTier: "enterprise" });
    await server.setSystemAdminStatus({
      email: "boss@example.com",
      isAdmin: true,
      actorUid: "root-admin"
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

    // 8. upsertScopeMemberByEmail and grantScopeCapabilitiesByEmail reject unknown/prototype roles
    await expect(
      server.upsertScopeMemberByEmail({
        scopeId: "ws-1",
        email: "alice@example.com",
        role: "__proto__" as any
      })
    ).rejects.toThrow(/role is not defined in policy\.roles/);
    await expect(
      server.grantScopeCapabilitiesByEmail({
        scopeId: "ws-1",
        email: "alice@example.com",
        capabilities: ["edit_content"],
        role: "superadmin" as any
      })
    ).rejects.toThrow(/role is not defined in policy\.roles/);
  });
});

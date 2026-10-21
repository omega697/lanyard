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

  it("covers FIREBASE_CONFIG emulator interplay, non-fatal requireAdmin store errors, requireScopeCapability 500 sanitization, and FirestoreServerStore photoUrl sanitization", async () => {
    // 1. FIREBASE_CONFIG without FIREBASE_AUTH_EMULATOR_HOST throws SECURITY VIOLATION, but succeeds when emulator host is set
    const origFbConfig = process.env.FIREBASE_CONFIG;
    const origAuthEmu = process.env.FIREBASE_AUTH_EMULATOR_HOST;
    try {
      process.env.FIREBASE_CONFIG = '{"projectId":"prod-proj"}';
      delete process.env.FIREBASE_AUTH_EMULATOR_HOST;
      expect(() => assertNotProduction("FakeAuthService")).toThrow(/SECURITY VIOLATION/);

      process.env.FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099";
      expect(() => assertNotProduction("FakeAuthService")).not.toThrow();
    } finally {
      if (origFbConfig !== undefined) process.env.FIREBASE_CONFIG = origFbConfig;
      else delete process.env.FIREBASE_CONFIG;
      if (origAuthEmu !== undefined) process.env.FIREBASE_AUTH_EMULATOR_HOST = origAuthEmu;
      else delete process.env.FIREBASE_AUTH_EMULATOR_HOST;
    }

    // 2. FakeAuthService without adminAuth fallback returns null when no x-mock-user-email header is present
    const standaloneFakeAuth = new FakeAuthService();
    expect(await standaloneFakeAuth.verifyToken("Bearer some-token", {})).toBeNull();

    // 3. requireAdmin continues (calls next()) even if the backing directory store throws a transient error
    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<TestRole, TestCap>();
    const server = createLanyardServer<TestRole, TestCap>({
      adminAuth,
      store,
      policy: TEST_POLICY,
      authService: standaloneFakeAuth
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

    // 4. requireScopeCapability returns 500 with sanitized error when store.getScopeMember rejects
    const requireEdit = server.requireScopeCapability("edit_content");
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
      role: "member",
      capabilities: [],
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
      policy: TEST_POLICY,
      authService: new FakeAuthService()
    });

    // 1. Provision user who is both an attendee (with points & preferences) and promoted to system admin
    const user = await server.upsertUserByEmail({
      email: "hybrid.admin@example.com",
      firstName: "Testy",
      lastName: "McTest",
      role: "member",
      preferences: { leaderboardOptIn: true },
      attributes: { pointsAllTime: 350 }
    });
    await server.setSystemAdminStatus({
      email: "hybrid.admin@example.com",
      isAdmin: true,
      actorUid: "root-admin"
    });
    expect((await store.getSystemAdmin(user.uid))?.isSystemAdmin).toBe(true);

    // 2. Root admin demotes hybrid.admin@example.com
    await server.setSystemAdminStatus({
      email: "hybrid.admin@example.com",
      isAdmin: false,
      actorUid: "root-admin"
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

    // requireScopeRole("owner") also strips the stale admin bypass and blocks with 403!
    const resScope = createMockRes();
    await server.requireScopeRole("owner")(
      { ...staleAdminReq, user: { ...staleAdminReq.user, isAdmin: true } },
      resScope,
      () => {}
    );
    expect(resScope.statusCode).toBe(403);

    // requireUserRole("owner") also strips the stale admin bypass and blocks with 403!
    const resUserRole = createMockRes();
    await server.requireUserRole("owner")(
      { ...staleAdminReq, user: { ...staleAdminReq.user, isAdmin: true } },
      resUserRole,
      () => {}
    );
    expect(resUserRole.statusCode).toBe(403);
  });

  it("enforces single-tenant roles/capabilities, field-level attributes/secrets permissions, and strict cross-tenant isolation", async () => {
    type AppRole = "attendee" | "scanner" | "auditor" | "moderator" | "tenant_owner";
    type AppCap = "write:points" | "write:badges" | "read:tier" | "write:tier" | "read:notes" | "write:notes";

    interface AppPrefs {
      optIn: boolean;
    }
    interface AppAttrs {
      pointsAllTime: number;
      awardedBadges: string[];
      vipTier: string;
    }
    interface AppSecrets {
      moderatorNotes: string;
      superAdminSecret: string;
    }

    const policy = createPermissionPolicy<AppRole, AppCap>({
      roles: {
        attendee: { weight: 10, capabilities: [] },
        scanner: { weight: 20, inherits: ["attendee"], capabilities: ["write:points"] },
        auditor: { weight: 20, inherits: ["attendee"], capabilities: ["read:tier", "read:notes"] },
        moderator: {
          weight: 30,
          inherits: ["scanner", "auditor"],
          capabilities: ["write:badges", "write:tier", "write:notes"]
        },
        tenant_owner: {
          weight: 40,
          inherits: ["moderator"],
          capabilities: "*"
        }
      },
      attributeCapabilities: {
        pointsAllTime: "write:points",
        awardedBadges: "write:badges",
        vipTier: { read: "read:tier", write: "write:tier" }
      },
      secretCapabilities: {
        moderatorNotes: { read: "read:notes", write: "write:notes" }
      }
    });

    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<AppRole, AppCap, AppPrefs, AppAttrs, AppSecrets>();
    const server = createLanyardServer<AppRole, AppCap, AppPrefs, AppAttrs, AppSecrets>({
      adminAuth,
      store,
      policy,
      authService: new FakeAuthService()
    });

    // Provision single-tenant users
    const attendee = await server.upsertUserByEmail({
      email: "attendee@example.com",
      firstName: "Testy",
      lastName: "McTest",
      role: "attendee",
      attributes: { pointsAllTime: 10, awardedBadges: [], vipTier: "silver" }
    });
    const scanner = await server.upsertUserByEmail({
      email: "scanner@example.com",
      firstName: "Scanny",
      lastName: "McScanner",
      role: "scanner"
    });
    const auditor = await server.upsertUserByEmail({
      email: "auditor@example.com",
      firstName: "Audity",
      lastName: "McAuditor",
      role: "auditor"
    });
    const moderator = await server.upsertUserByEmail({
      email: "moderator@example.com",
      firstName: "Moddy",
      lastName: "McModerator",
      role: "moderator"
    });

    // 1. Single-tenant middleware: requireUserRole & requireUserCapability (including inherited capabilities!)
    const reqMod: any = {
      user: {
        uid: moderator.uid,
        email: moderator.email,
        photoUrl: "https://example.com/mod.png",
        isAdmin: false
      }
    };
    let modPassedRole = false;
    await server.requireUserRole("scanner")(reqMod, createMockRes(), () => {
      modPassedRole = true;
    });
    expect(modPassedRole).toBe(true);
    expect((await store.getUser(moderator.uid))?.photoUrl).toBe("https://example.com/mod.png");

    let modPassedInheritedCap = false;
    await server.requireUserCapability("write:points")(reqMod, createMockRes(), () => {
      modPassedInheritedCap = true;
    });
    expect(modPassedInheritedCap).toBe(true);

    // Attendee fails requireUserRole("scanner") and requireUserCapability("write:points")
    const resAttRole = createMockRes();
    await server.requireUserRole("scanner")(
      { user: { uid: attendee.uid, email: attendee.email, isAdmin: false } } as any,
      resAttRole,
      () => {}
    );
    expect(resAttRole.statusCode).toBe(403);

    // 2. Global User Attributes:
    // - Self can read ALL own attributes (including vipTier), but CANNOT write own attributes!
    expect(
      await server.readUserAttributesAs({
        actorUid: attendee.uid,
        targetUid: attendee.uid
      })
    ).toEqual({ pointsAllTime: 10, awardedBadges: [], vipTier: "silver" });

    await expect(
      server.updateUserAttributesAs({
        actorUid: attendee.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 9999 }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Scanner can read public attributes (pointsAllTime, awardedBadges) but NOT vipTier, and can ONLY write pointsAllTime
    expect(
      await server.readUserAttributesAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid
      })
    ).toEqual({ pointsAllTime: 10, awardedBadges: [] });

    await server.updateUserAttributesAs({
      actorUid: scanner.uid,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 50 }
    });
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(50);

    await expect(
      server.updateUserAttributesAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid,
        patch: { awardedBadges: ["cheater-badge"] }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Moderator inherits scanner's write:points AND has write:badges + write:tier
    await server.updateUserAttributesAs({
      actorUid: moderator.uid,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 100, awardedBadges: ["centurion"], vipTier: "gold" }
    });
    expect((await store.getUser(attendee.uid))?.attributes).toEqual({
      pointsAllTime: 100,
      awardedBadges: ["centurion"],
      vipTier: "gold"
    });

    // 3. Global User Secrets:
    // - Moderator writes moderatorNotes; SystemAdmin writes superAdminSecret
    await server.updateUserSecretsAs({
      actorUid: moderator.uid,
      targetUid: attendee.uid,
      patch: { moderatorNotes: "Verified ID at booth" }
    });
    await server.updateUserSecretsAs({
      actorUid: "root-admin",
      isSystemAdmin: true,
      targetUid: attendee.uid,
      patch: { superAdminSecret: "classified-flag" }
    });

    // - Self (`attendee`) CANNOT read or write their own secrets!
    await expect(
      server.readUserSecretsAs({
        actorUid: attendee.uid,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.updateUserSecretsAs({
        actorUid: attendee.uid,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "I am totally trustworthy" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Auditor can read `moderatorNotes` (redacting `superAdminSecret`), and CANNOT write `moderatorNotes`
    expect(
      await server.readUserSecretsAs({
        actorUid: auditor.uid,
        targetUid: attendee.uid
      })
    ).toEqual({ moderatorNotes: "Verified ID at booth" });

    await expect(
      server.updateUserSecretsAs({
        actorUid: auditor.uid,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "Tampered by auditor" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - System Admin reads all secrets unredacted
    expect(
      await server.readUserSecretsAs({
        actorUid: "root-admin",
        isSystemAdmin: true,
        targetUid: attendee.uid
      })
    ).toEqual({
      moderatorNotes: "Verified ID at booth",
      superAdminSecret: "classified-flag"
    });

    // 4. STRICT CROSS-TENANT ISOLATION:
    // Make `tenantOwnerA` a `tenant_owner` (with wildcard capabilities: "*") in `tenant-A` ONLY.
    const tenantOwnerA = await server.upsertScopeMemberByEmail({
      scopeId: "tenant-A",
      email: "owner.a@example.com",
      firstName: "Owner",
      lastName: "Alpha",
      role: "tenant_owner"
    });
    await server.upsertScopeMemberByEmail({
      scopeId: "tenant-A",
      email: "attendee@example.com",
      role: "attendee"
    });
    await server.upsertScopeMemberByEmail({
      scopeId: "tenant-B",
      email: "attendee@example.com",
      role: "attendee",
      attributes: { pointsAllTime: 10, awardedBadges: [], vipTier: "bronze" }
    });
    await store.updateScopeMemberSecrets("tenant-B", attendee.uid, {
      moderatorNotes: "Tenant B confidential note"
    });

    // (a) `tenantOwnerA` can update attributes & secrets inside `tenant-A`:
    await server.updateScopeMemberAttributesAs({
      scopeId: "tenant-A",
      actorUid: tenantOwnerA.uid,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 500 }
    });
    await server.updateScopeMemberSecretsAs({
      scopeId: "tenant-A",
      actorUid: tenantOwnerA.uid,
      targetUid: attendee.uid,
      patch: { moderatorNotes: "Tenant A note" }
    });
    expect(
      await server.readScopeMemberSecretsAs({
        scopeId: "tenant-A",
        actorUid: tenantOwnerA.uid,
        targetUid: attendee.uid
      })
    ).toEqual({ moderatorNotes: "Tenant A note" });

    // (b) `tenantOwnerA` CANNOT monkey with `tenant-B` attributes or secrets!
    await expect(
      server.updateScopeMemberAttributesAs({
        scopeId: "tenant-B",
        actorUid: tenantOwnerA.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 0 }
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.readScopeMemberSecretsAs({
        scopeId: "tenant-B",
        actorUid: tenantOwnerA.uid,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.updateScopeMemberSecretsAs({
        scopeId: "tenant-B",
        actorUid: tenantOwnerA.uid,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "Cross-tenant sabotage" }
      })
    ).rejects.toThrow(/Forbidden/);

    // (c) `tenantOwnerA` CANNOT monkey with global `users/{attendee.uid}` attributes or secrets!
    await expect(
      server.updateUserAttributesAs({
        actorUid: tenantOwnerA.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 0 }
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.readUserSecretsAs({
        actorUid: tenantOwnerA.uid,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden/);

    await expect(
      server.updateUserSecretsAs({
        actorUid: tenantOwnerA.uid,
        targetUid: attendee.uid,
        patch: { moderatorNotes: "Global sabotage" }
      })
    ).rejects.toThrow(/Forbidden/);
  });

  it("tests FirestoreServerStore unified users/{uid}, private/secrets subdocuments, and admin demotion preservation", async () => {
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
      { note: string }
    >({
      db: fakeDb,
      defaultRole: "member"
    });

    // 1. UserRecord + attributes + secrets + admin status on users/{uid} and users/{uid}/private/secrets
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
    await fsStore.updateUserSecrets("u-1", { note: "Top secret" });

    expect(docs.get("users/u-1")?.attributes).toEqual({ pointsAllTime: 250 });
    expect(docs.get("users/u-1")?.note).toBeUndefined(); // Secrets are NEVER stored on users/{uid}!
    expect(docs.get("users/u-1/private/secrets")).toEqual({ note: "Top secret" });
    expect(await fsStore.getUserSecrets("u-1")).toEqual({ note: "Top secret" });
    expect(await fsStore.listSystemAdmins()).toHaveLength(1);

    // 2. Demoting admin via deleteSystemAdmin sets isSystemAdmin: false on users/u-1 while keeping attributes & preferences
    await fsStore.deleteSystemAdmin("u-1");
    expect(await fsStore.getSystemAdmin("u-1")).toBeNull();
    expect(await fsStore.listSystemAdmins()).toHaveLength(0);
    const afterDemote = await fsStore.getUser("u-1");
    expect(afterDemote?.isSystemAdmin).toBe(false);
    expect(afterDemote?.attributes).toEqual({ pointsAllTime: 250 });
    expect(afterDemote?.preferences).toEqual({ theme: "dark" });

    // 3. Scoped member attributes & private/secrets subdocument lifecycle
    await fsStore.upsertScopeMember("ws-1", {
      uid: "u-1",
      email: "u1@example.com",
      role: "manager",
      capabilities: []
    });
    await fsStore.updateScopeMemberAttributes("ws-1", "u-1", { pointsAllTime: 77 });
    await fsStore.updateScopeMemberSecrets("ws-1", "u-1", { note: "Workspace secret" });

    expect(docs.get("workspaces/ws-1/members/u-1")?.attributes).toEqual({ pointsAllTime: 77 });
    expect(docs.get("workspaces/ws-1/members/u-1/private/secrets")).toEqual({ note: "Workspace secret" });
    expect(await fsStore.getScopeMemberSecrets("ws-1", "u-1")).toEqual({ note: "Workspace secret" });

    // Deleting scoped member also deletes its private/secrets subdocument
    await fsStore.deleteScopeMember("ws-1", "u-1");
    expect(docs.has("workspaces/ws-1/members/u-1")).toBe(false);
    expect(docs.has("workspaces/ws-1/members/u-1/private/secrets")).toBe(false);
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

    interface SingleTenantSecrets {
      scannerAuditLog: string;
      merchPosPin: string;
      blindAuditHash: string;
    }

    const policy = createPermissionPolicy<SingleTenantRole, SingleTenantCap>({
      roles: {
        attendee: { weight: 10, capabilities: [] },
        // Sibling role A: scanner (handles points + scannerAuditLog)
        scanner: {
          weight: 20,
          inherits: ["attendee"],
          capabilities: ["write:points", "read:scanner_log", "write:scanner_log"]
        },
        // Sibling role B: merch_seller (handles merchCreditBalance + merchPosPin; does NOT inherit scanner!)
        merch_seller: {
          weight: 20,
          inherits: ["attendee"],
          capabilities: ["read:merch", "write:merch", "read:merch_Pin", "write:merch_Pin"]
        },
        // Moderator inherits BOTH scanner and merch_seller, plus badges and write-only blindAuditHash
        moderator: {
          weight: 30,
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
      secretCapabilities: {
        scannerAuditLog: { read: "read:scanner_log", write: "write:scanner_log" },
        merchPosPin: { read: "read:merch_Pin", write: "write:merch_Pin" },
        // Write-only secret for moderator; readable ONLY by system admin
        blindAuditHash: { write: "write:audit_hash" }
      }
    });

    const adminAuth = createFakeAdminAuth();
    const store = new InMemoryLanyardStore<
      SingleTenantRole,
      SingleTenantCap,
      Record<string, unknown>,
      SingleTenantAttrs,
      SingleTenantSecrets
    >();
    const server = createLanyardServer<
      SingleTenantRole,
      SingleTenantCap,
      Record<string, unknown>,
      SingleTenantAttrs,
      SingleTenantSecrets
    >({
      adminAuth,
      store,
      policy,
      authService: new FakeAuthService()
    });

    const attendee = await server.upsertUserByEmail({
      email: "attendee@example.com",
      firstName: "Testy",
      lastName: "McTest",
      role: "attendee",
      attributes: {
        pointsAllTime: 25,
        merchCreditBalance: 150,
        awardedBadges: ["welcome"],
        readonlySystemBadge: "founding-member"
      }
    });
    const scanner = await server.upsertUserByEmail({
      email: "scanner@example.com",
      firstName: "Scanny",
      lastName: "McScanner",
      role: "scanner"
    });
    const merchSeller = await server.upsertUserByEmail({
      email: "merch@example.com",
      firstName: "Merchy",
      lastName: "McMerch",
      role: "merch_seller"
    });
    const moderator = await server.upsertUserByEmail({
      email: "mod@example.com",
      firstName: "Moddy",
      lastName: "McModerator",
      role: "moderator"
    });

    // 1. Mutual sibling role isolation on users/{uid}:
    // - Scanner can update pointsAllTime & scannerAuditLog, but CANNOT read/write merchCreditBalance or merchPosPin
    await server.updateUserAttributesAs({
      actorUid: scanner.uid,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 40 }
    });
    await server.updateUserSecretsAs({
      actorUid: scanner.uid,
      targetUid: attendee.uid,
      patch: { scannerAuditLog: "Scanned booth #4" }
    });
    await expect(
      server.updateUserAttributesAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid,
        patch: { merchCreditBalance: 999 }
      })
    ).rejects.toThrow(/Forbidden/);
    await expect(
      server.updateUserSecretsAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid,
        patch: { merchPosPin: "0000" }
      })
    ).rejects.toThrow(/Forbidden/);

    // - Merch seller can read/write merchCreditBalance & merchPosPin, but CANNOT write pointsAllTime or read scannerAuditLog
    await server.updateUserAttributesAs({
      actorUid: merchSeller.uid,
      targetUid: attendee.uid,
      patch: { merchCreditBalance: 120 }
    });
    await server.updateUserSecretsAs({
      actorUid: merchSeller.uid,
      targetUid: attendee.uid,
      patch: { merchPosPin: "4821" }
    });
    await expect(
      server.updateUserAttributesAs({
        actorUid: merchSeller.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 999 }
      })
    ).rejects.toThrow(/Forbidden/);

    // Reading attributes & secrets redacts each sibling's restricted fields:
    expect(
      await server.readUserAttributesAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 40,
      awardedBadges: ["welcome"]
      // merchCreditBalance and readonlySystemBadge are redacted for scanner!
    });
    expect(
      await server.readUserAttributesAs({
        actorUid: merchSeller.uid,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 40,
      merchCreditBalance: 120,
      awardedBadges: ["welcome"],
      readonlySystemBadge: "founding-member"
    });
    expect(
      await server.readUserSecretsAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid
      })
    ).toEqual({ scannerAuditLog: "Scanned booth #4" });
    expect(
      await server.readUserSecretsAs({
        actorUid: merchSeller.uid,
        targetUid: attendee.uid
      })
    ).toEqual({ merchPosPin: "4821" });

    // Sibling middleware check: scanner fails requireUserRole("merch_seller") and vice versa
    const resScannerAsMerch = createMockRes();
    await server.requireUserRole("merch_seller")(
      { user: { uid: scanner.uid, email: scanner.email, isAdmin: false } } as any,
      resScannerAsMerch,
      () => {}
    );
    expect(resScannerAsMerch.statusCode).toBe(403);

    // 2. Write-only secret & Read-only attribute enforcement:
    // Moderator can write `blindAuditHash`, but CANNOT read `blindAuditHash` back (only systemAdmin can read it)
    await server.updateUserSecretsAs({
      actorUid: moderator.uid,
      targetUid: attendee.uid,
      patch: { blindAuditHash: "sha256:abcdef" }
    });
    expect(
      await server.readUserSecretsAs({
        actorUid: moderator.uid,
        targetUid: attendee.uid
      })
    ).toEqual({
      scannerAuditLog: "Scanned booth #4",
      merchPosPin: "4821"
      // blindAuditHash is redacted for non-system-admins!
    });
    expect(
      await server.readUserSecretsAs({
        actorUid: "sys-admin",
        isSystemAdmin: true,
        targetUid: attendee.uid
      })
    ).toEqual({
      scannerAuditLog: "Scanned booth #4",
      merchPosPin: "4821",
      blindAuditHash: "sha256:abcdef"
    });

    // Moderator CANNOT write `readonlySystemBadge` (only systemAdmin can)
    await expect(
      server.updateUserAttributesAs({
        actorUid: moderator.uid,
        targetUid: attendee.uid,
        patch: { readonlySystemBadge: "forged-founder" }
      })
    ).rejects.toThrow(/Forbidden/);

    // 3. All-or-nothing atomic multi-key patch rejection on users/{uid}:
    // Scanner attempts to patch BOTH `pointsAllTime` (allowed) and `awardedBadges` (forbidden) in one call.
    // Must reject with 403 and leave `pointsAllTime` untouched at 40!
    await expect(
      server.updateUserAttributesAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 9999, awardedBadges: ["injected-badge"] }
      })
    ).rejects.toThrow(/Forbidden/);
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(40);
    expect((await store.getUser(attendee.uid))?.attributes?.awardedBadges).toEqual(["welcome"]);

    // Same atomic guarantee for secrets on users/{uid}/private/secrets:
    await expect(
      server.updateUserSecretsAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid,
        patch: { scannerAuditLog: "Valid", merchPosPin: "9999" }
      })
    ).rejects.toThrow(/Forbidden/);
    expect(await store.getUserSecrets(attendee.uid)).toEqual({
      scannerAuditLog: "Scanned booth #4",
      merchPosPin: "4821",
      blindAuditHash: "sha256:abcdef"
    });

    // 4. Per-user ad-hoc capability overrides on users/{uid} using atomic grantUserCapabilitiesByEmail & revokeUserCapabilities:
    // Grant `attendee` an individual `write:points` capability without promoting their role from `attendee`
    await server.grantUserCapabilitiesByEmail({
      email: "attendee@example.com",
      capabilities: ["write:points"]
    });
    await server.updateUserAttributesAs({
      actorUid: attendee.uid,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 55 }
    });
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(55);

    // Revoke the ad-hoc capability on `attendee` -> immediately blocked again
    await server.revokeUserCapabilities(attendee.uid, ["write:points"]);
    await expect(
      server.updateUserAttributesAs({
        actorUid: attendee.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 70 }
      })
    ).rejects.toThrow(/Forbidden/);

    // Also verify scoped `readScopeMemberAttributesAs` enforces scope membership and field-level read rules
    await server.upsertScopeMemberByEmail({
      scopeId: "event-2026",
      email: "attendee@example.com",
      role: "attendee",
      attributes: {
        pointsAllTime: 88,
        awardedBadges: ["scoped-badge"],
        merchCreditBalance: 35,
        readonlySystemBadge: "vip"
      }
    });
    await server.upsertScopeMemberByEmail({
      scopeId: "event-2026",
      email: "scanner@example.com",
      role: "scanner"
    });
    await server.upsertScopeMemberByEmail({
      scopeId: "event-2026",
      email: "mod@example.com",
      role: "moderator"
    });

    // Self in scope can read all their own attributes (`isSelf: true`)
    expect(
      await server.readScopeMemberAttributesAs({
        scopeId: "event-2026",
        actorUid: attendee.uid,
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
      await server.readScopeMemberAttributesAs({
        scopeId: "event-2026",
        actorUid: scanner.uid,
        targetUid: attendee.uid
      })
    ).toEqual({
      pointsAllTime: 88,
      awardedBadges: ["scoped-badge"]
    });
    expect(
      await server.readScopeMemberAttributesAs({
        scopeId: "event-2026",
        actorUid: moderator.uid,
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
      server.readScopeMemberAttributesAs({
        scopeId: "event-2026",
        actorUid: merchSeller.uid,
        targetUid: attendee.uid
      })
    ).rejects.toThrow(/Forbidden: Caller is not a member of scope/);

    // 5. Role demotion on users/{uid}:
    // Demote `moderator` down to `scanner` -> immediately loses access to `merchPosPin` and `awardedBadges`,
    // while retaining `scanner` access to `pointsAllTime` and `scannerAuditLog`
    await server.upsertUserByEmail({
      email: "mod@example.com",
      role: "scanner"
    });
    await expect(
      server.updateUserAttributesAs({
        actorUid: moderator.uid,
        targetUid: attendee.uid,
        patch: { awardedBadges: ["demoted-mod-badge"] }
      })
    ).rejects.toThrow(/Forbidden/);
    expect(
      await server.readUserSecretsAs({
        actorUid: moderator.uid,
        targetUid: attendee.uid
      })
    ).toEqual({
      scannerAuditLog: "Scanned booth #4"
      // merchPosPin is no longer visible after demotion from moderator to scanner!
    });
    await server.updateUserAttributesAs({
      actorUid: moderator.uid,
      targetUid: attendee.uid,
      patch: { pointsAllTime: 65 }
    });
    expect((await store.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(65);
  });
});

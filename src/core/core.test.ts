import { describe, it, expect, vi } from "vitest";
import * as rootBarrel from "../index.js";
import {
  assertValidResourceId,
  createPermissionPolicy,
  createWritableStore,
  formatExistingAccountError,
  formatLastSeen,
  formatMemberDisplayName,
  getAvatarInitials,
  getProviderNameLabel,
  getSocialProviderId,
  InMemoryLanyardStore,
  isValidEmail,
  isValidResourceId,
  resolveAvatar,
  resolveAvatarUrl,
  sanitizeAvatarUrl,
  type ScopedMember
} from "./index.js";

type TestRole = "owner" | "manager" | "member";
type TestCapability = "edit_content" | "invite_members" | "billing";

const TEST_POLICY = createPermissionPolicy<TestRole, TestCapability>({
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

describe("lanyard/core unit tests", () => {
  describe("Custom PermissionPolicy (Generic TRole & TCapability)", () => {
    it("throws if roles configuration is empty and respects explicit or root defaultRole", () => {
      expect(() => createPermissionPolicy({ roles: {} as any })).toThrow(/at least one role/);
      expect(TEST_POLICY.defaultRole).toBe("member");

      const explicitDefault = createPermissionPolicy<TestRole, TestCapability>({
        roles: {
          owner: { inherits: ["manager"] },
          manager: { inherits: ["member"] },
          member: {}
        },
        defaultRole: "manager"
      });
      expect(explicitDefault.defaultRole).toBe("manager");
    });

    it("evaluates custom role hierarchies and edge cases via policy.hasRole, hasAnyRole, and hasAllRoles", () => {
      const owner: ScopedMember<TestRole, TestCapability> = {
        uid: "u1",
        email: "owner@example.com",
        roles: ["owner"]
      };
      const manager: ScopedMember<TestRole, TestCapability> = {
        uid: "u2",
        email: "manager@example.com",
        roles: ["manager"]
      };
      const member: ScopedMember<TestRole, TestCapability> = {
        uid: "u3",
        email: "member@example.com",
        roles: ["member"]
      };
      const unknownRoleMember = {
        uid: "u4",
        email: "unknown@example.com",
        roles: ["guest" as TestRole]
      };

      expect(TEST_POLICY.hasRole(owner, "owner")).toBe(true);
      expect(TEST_POLICY.hasRole(owner, "manager")).toBe(true);
      expect(TEST_POLICY.hasRole(owner, "member")).toBe(true);
      expect(TEST_POLICY.hasRole(manager, "owner")).toBe(false);
      expect(TEST_POLICY.hasRole(manager, "manager")).toBe(true);
      expect(TEST_POLICY.hasRole(manager, "member")).toBe(true);
      expect(TEST_POLICY.hasRole(member, "manager")).toBe(false);
      expect(TEST_POLICY.hasRole(member, "member")).toBe(true);
      expect(TEST_POLICY.hasRole(unknownRoleMember, "member")).toBe(false);
      expect(TEST_POLICY.hasRole(member, "unknown" as TestRole)).toBe(false);
      expect(TEST_POLICY.hasRole(null, "member")).toBe(false);
      expect(TEST_POLICY.hasRole(undefined, "member")).toBe(false);
      expect(TEST_POLICY.hasRole(null, "owner", true)).toBe(true); // System Admin override

      expect(TEST_POLICY.hasAnyRole(manager, ["owner", "manager"])).toBe(true);
      expect(TEST_POLICY.hasAnyRole(member, ["owner", "manager"])).toBe(false);
      expect(TEST_POLICY.hasAnyRole(manager, [])).toBe(false);
      expect(TEST_POLICY.hasAnyRole(null, ["member"], true)).toBe(true);

      expect(TEST_POLICY.hasAllRoles(owner, ["owner", "manager", "member"])).toBe(true);
      expect(TEST_POLICY.hasAllRoles(manager, ["owner", "manager"])).toBe(false);
      expect(TEST_POLICY.hasAllRoles(null, ["member"], true)).toBe(true);
    });

    it("evaluates role-implied capabilities across single and multiple roles", () => {
      const owner: ScopedMember<TestRole, TestCapability> = {
        uid: "u-owner",
        email: "owner@example.com",
        roles: ["owner"]
      };
      const manager: ScopedMember<TestRole, TestCapability> = {
        uid: "u-mgr",
        email: "manager@example.com",
        roles: ["manager"]
      };
      const multiMember: ScopedMember<TestRole, TestCapability> = {
        uid: "u-mem",
        email: "member@example.com",
        roles: ["member", "manager"]
      };

      // Owner has "*" -> implies all capabilities including "billing"
      expect(TEST_POLICY.hasCapability(owner, "edit_content")).toBe(true);
      expect(TEST_POLICY.hasCapability(owner, "invite_members")).toBe(true);
      expect(TEST_POLICY.hasCapability(owner, "billing")).toBe(true);

      // Manager has ["edit_content", "invite_members"] implied by role, but NOT "billing"
      expect(TEST_POLICY.hasCapability(manager, "edit_content")).toBe(true);
      expect(TEST_POLICY.hasCapability(manager, "invite_members")).toBe(true);
      expect(TEST_POLICY.hasCapability(manager, "billing")).toBe(false);

      // Member holding both ["member", "manager"] gets capabilities from the union of their roles
      expect(TEST_POLICY.hasCapability(multiMember, "edit_content")).toBe(true);
      expect(TEST_POLICY.hasCapability(multiMember, "invite_members")).toBe(true);
      expect(TEST_POLICY.hasCapability(multiMember, "billing")).toBe(false);

      // Null/undefined member and System Admin override
      expect(TEST_POLICY.hasCapability(null, "edit_content")).toBe(false);
      expect(TEST_POLICY.hasCapability(null, "billing", true)).toBe(true);
    });

    it("evaluates policy.hasAnyCapability, policy.hasAllCapabilities, and policy.shouldTrackPresence", () => {
      const manager: ScopedMember<TestRole, TestCapability> = {
        uid: "u-mgr",
        email: "manager@example.com",
        roles: ["manager"]
      };
      const member: ScopedMember<TestRole, TestCapability> = {
        uid: "u-mem",
        email: "mem@example.com",
        roles: ["member"]
      };

      expect(TEST_POLICY.hasAnyCapability(manager, ["invite_members", "billing"])).toBe(true);
      expect(TEST_POLICY.hasAnyCapability(manager, [])).toBe(false);
      expect(TEST_POLICY.hasAnyCapability(null, ["invite_members"])).toBe(false);
      expect(TEST_POLICY.hasAnyCapability(null, ["invite_members"], true)).toBe(true);

      expect(TEST_POLICY.hasAllCapabilities(manager, ["edit_content", "invite_members"])).toBe(true);
      expect(TEST_POLICY.hasAllCapabilities(manager, ["edit_content", "billing"])).toBe(false);
      expect(TEST_POLICY.hasAllCapabilities(null, ["edit_content"])).toBe(false);
      expect(TEST_POLICY.hasAllCapabilities(null, ["edit_content"], true)).toBe(true);

      // Presence tracking is configured per role level, and always enabled for system admins
      expect(TEST_POLICY.shouldTrackPresence(manager, false)).toBe(true);
      expect(TEST_POLICY.shouldTrackPresence(member, false)).toBe(false);
      expect(TEST_POLICY.shouldTrackPresence(member, true)).toBe(true);
      expect(TEST_POLICY.shouldTrackPresence(null, true)).toBe(true);
      expect(TEST_POLICY.shouldTrackPresence(null, false)).toBe(false);

      // Object.prototype key injection ("toString", "constructor", "__proto__") must never match or throw
      for (const protoKey of ["toString", "valueOf", "constructor", "__proto__"] as any[]) {
        const protoMember = { uid: "u-proto", email: "p@example.com", roles: [protoKey] };
        expect(TEST_POLICY.hasRole(protoMember, "member")).toBe(false);
        expect(TEST_POLICY.hasRole(member, protoKey)).toBe(false);
        expect(TEST_POLICY.isAssignableRole(protoKey)).toBe(false);
        expect(TEST_POLICY.hasCapability(protoMember, "edit_content")).toBe(false);
        expect(TEST_POLICY.hasAnyCapability(protoMember, ["edit_content"])).toBe(false);
        expect(TEST_POLICY.hasAllCapabilities(protoMember, ["edit_content"])).toBe(false);
        expect(TEST_POLICY.shouldTrackPresence(protoMember, false)).toBe(false);
      }
    });
  });

  describe("Formatters, Resource ID Validation & Smart Avatar Resolution", () => {
    it("validates storage-agnostic resource IDs and rejects path-traversal or control characters", () => {
      expect(isValidResourceId("ws-1")).toBe(true);
      expect(isValidResourceId("user_123:abc@example.com")).toBe(true);
      expect(assertValidResourceId("ws-1", "scopeId")).toBe("ws-1");

      for (const badId of [
        "",
        "   ",
        ".",
        "..",
        "ws-1/members",
        "ws-1\\members",
        "ws-1/../admin",
        "id with space",
        "id\0null",
        "id\nnewline",
        "id\u200Bzerowidth",
        "id\u202Ebidi",
        "id\u0085c1control",
        "a".repeat(513),
        null,
        undefined
      ]) {
        expect(isValidResourceId(badId as any)).toBe(false);
        expect(() => assertValidResourceId(badId as any, "scopeId")).toThrow(/Invalid scopeId/);
      }

      // Linear-time ReDoS-safe email validation
      expect(isValidEmail("alice@example.com")).toBe(true);
      expect(isValidEmail("  accenty.mceccent+tag@sub.example.co.uk ")).toBe(true);
      for (const badEmail of [
        "",
        "not-an-email",
        "@example.com",
        "alice@",
        "alice@example",
        "alice@.example.com",
        "alice@example.com.",
        "alice@exa..mple.com",
        "alice@bob@example.com",
        `${"a".repeat(65)}@example.com`,
        `a@${"b.".repeat(130)}com`,
        `a@${"b.".repeat(5000)} `,
        null,
        undefined
      ]) {
        expect(isValidEmail(badEmail as any)).toBe(false);
      }
    });

    it("formats relative lastSeen timestamps across ISO strings, Dates, numbers, and Timestamp-like objects", () => {
      const now = 1_700_000_000_000;
      vi.spyOn(Date, "now").mockReturnValue(now);

      expect(formatLastSeen(null)).toBe("Never");
      expect(formatLastSeen(undefined)).toBe("Never");
      expect(formatLastSeen("invalid-date")).toBe("Never");
      expect(formatLastSeen(new Date(now + 10_000).toISOString())).toBe("just now"); // future clock skew
      expect(formatLastSeen(new Date(now - 15_000))).toBe("just now");
      expect(formatLastSeen(now - 5 * 60_000)).toBe("5m ago");
      expect(formatLastSeen({ toDate: () => new Date(now - 3 * 3600_000) })).toBe("3h ago");
      expect(formatLastSeen(new Date(now - 2 * 86400_000).toISOString())).toBe("2d ago");

      vi.restoreAllMocks();
    });

    it("formats existing account error messages and provider helpers for all providers", () => {
      expect(getSocialProviderId("google")).toBe("google.com");
      expect(getSocialProviderId("microsoft")).toBe("microsoft.com");
      expect(getSocialProviderId("github")).toBe("github.com");

      expect(getProviderNameLabel("google")).toBe("Google");
      expect(getProviderNameLabel("microsoft")).toBe("Microsoft");
      expect(getProviderNameLabel("github")).toBe("GitHub");

      const msgWithMethods = formatExistingAccountError("alice@example.com", ["google.com", "github.com"]);
      expect(msgWithMethods).toContain("alice@example.com");
      expect(msgWithMethods).toContain("Google, GitHub");

      const msgWithoutMethods = formatExistingAccountError("  ", []);
      expect(msgWithoutMethods).toContain("this email address");
      expect(msgWithoutMethods).toContain("different sign-in method");
    });

    it("sanitizes avatar URLs and prevents activeUser avatar bleed when viewing other users", () => {
      expect(sanitizeAvatarUrl("  https://example.com/a.png  ")).toBe("https://example.com/a.png");
      expect(sanitizeAvatarUrl("http://example.com/a.png")).toBe("http://example.com/a.png");
      expect(sanitizeAvatarUrl("data:image/png;base64,AAAA")).toBe("data:image/png;base64,AAAA");
      expect(sanitizeAvatarUrl("data:image/webp;base64,UklGRg==")).toBe("data:image/webp;base64,UklGRg==");
      expect(sanitizeAvatarUrl("/avatars/default.png")).toBe("/avatars/default.png");
      expect(sanitizeAvatarUrl("")).toBeNull();
      expect(sanitizeAvatarUrl("null")).toBeNull();
      expect(sanitizeAvatarUrl("undefined")).toBeNull();
      expect(sanitizeAvatarUrl("javascript:alert(1)")).toBeNull();
      expect(sanitizeAvatarUrl("ftp://example.com/file")).toBeNull();
      // Security hardening: block SVG data URIs (XSS), protocol-relative URLs, HTML injection, and >2048 char URLs
      expect(sanitizeAvatarUrl("data:image/svg+xml;utf8,<svg onload=alert(1)>")).toBeNull();
      expect(sanitizeAvatarUrl("data:image/svg+xml;base64,PHN2Zz4=")).toBeNull();
      expect(sanitizeAvatarUrl("//evil.com/phish.png")).toBeNull();
      expect(sanitizeAvatarUrl("/\\evil.com/phish.png")).toBeNull();
      expect(sanitizeAvatarUrl('https://example.com/a.png" onerror="alert(1)')).toBeNull();
      expect(sanitizeAvatarUrl("https://example.com/a.png\nheader:injected")).toBeNull();
      expect(sanitizeAvatarUrl(`https://example.com/${"a".repeat(2050)}.png`)).toBeNull();

      const activeAdmin = { uid: "u-admin", photoUrl: "https://example.com/admin.png" };
      const otherMemberNoPhoto = { uid: "u-other", firstName: "Accenty", lastName: "McÉccent", photoUrl: null };
      const otherMemberWithPhoto = {
        uid: "u-other",
        firstName: "Accenty",
        lastName: "McÉccent",
        photoUrl: "https://example.com/accenty.png"
      };
      const selfMemberNoPhoto = { uid: "u-admin", firstName: "Admin", lastName: "User", photoUrl: null };

      // Viewing another member with a photo returns their photo
      expect(resolveAvatarUrl(otherMemberWithPhoto, activeAdmin)).toBe("https://example.com/accenty.png");
      // Viewing another member with no photoUrl must NOT fall back to activeAdmin.photoUrl
      expect(resolveAvatarUrl(otherMemberNoPhoto, activeAdmin)).toBeNull();
      // Viewing self before member.photoUrl is synced falls back to activeAdmin.photoUrl
      expect(resolveAvatarUrl(selfMemberNoPhoto, activeAdmin)).toBe("https://example.com/admin.png");
      expect(resolveAvatarUrl(null, activeAdmin)).toBe("https://example.com/admin.png");

      const resolvedOther = resolveAvatar(otherMemberNoPhoto, activeAdmin);
      expect(resolvedOther).toEqual({
        photoUrl: null,
        initials: "AM",
        displayName: "Accenty McÉccent",
        colorIndex: expect.any(Number)
      });
      expect(resolvedOther.colorIndex).toBeGreaterThanOrEqual(0);
      expect(resolvedOther.colorIndex).toBeLessThan(8);

      // Initials edge cases
      expect(getAvatarInitials("Testy McTest")).toBe("TM");
      expect(getAvatarInitials("Mononymy")).toBe("M");
      expect(getAvatarInitials({ email: "alice@example.com" })).toBe("A");
      expect(getAvatarInitials(null, "?")).toBe("?");
      expect(getAvatarInitials("   ", "U")).toBe("U");

      // Display name fallback order: firstName + lastName -> displayName -> name -> email -> fallback
      expect(
        formatMemberDisplayName({ firstName: "Accenty", lastName: "McÉccent", email: "accenty@example.com" })
      ).toBe("Accenty McÉccent");
      expect(formatMemberDisplayName({ displayName: "Accenty M." })).toBe("Accenty M.");
      expect(formatMemberDisplayName({ name: "Accenty Name" })).toBe("Accenty Name");
      expect(formatMemberDisplayName({ email: "accenty@example.com" })).toBe("accenty@example.com");
      expect(formatMemberDisplayName(null, "Anonymous")).toBe("Anonymous");
    });
  });

  describe("Svelte-Compatible Observable Store", () => {
    it("notifies subscribers immediately and on updates, and safely handles mid-notification unsubscribes", () => {
      const store = createWritableStore({ count: 0 });
      const observedA: number[] = [];
      const observedB: number[] = [];

      let unsubB: (() => void) | null = null;
      const unsubA = store.subscribe((v) => {
        observedA.push(v.count);
        if (v.count === 2 && unsubB) {
          unsubB();
        }
      });
      unsubB = store.subscribe((v) => observedB.push(v.count));

      store.update((v) => ({ count: v.count + 1 }));
      store.set({ count: 2 }); // A unsubscribes B during this notification!
      unsubA();
      store.set({ count: 99 });

      expect(observedA).toEqual([0, 1, 2]);
      expect(observedB).toEqual([0, 1]); // B was unsubscribed before receiving 2
      expect(store.get()).toEqual({ count: 99 });
    });
  });

  describe("InMemoryLanyardStore (Storage-Agnostic Reference Implementation)", () => {
    it("supports multi-tenant memberships, scope subscriptions, and capability grants/revocations", async () => {
      const store = new InMemoryLanyardStore<TestRole, TestCapability, { theme: string }>();
      const scopeSnapshots: ScopedMember<TestRole, TestCapability>[][] = [];

      const unsubScope = store.subscribeToScopeMembers("ws-1", (members) => {
        scopeSnapshots.push(members);
      });

      // Throws if granting roles to a non-existent member without fallbackMember
      await expect(store.grantScopeRoles("ws-1", "missing-uid", ["member"])).rejects.toThrow(/does not exist/);

      await store.grantScopeRoles("ws-1", "uid-1", ["member"], {
        uid: "uid-1",
        email: "accenty@example.com",
        firstName: "Accenty",
        lastName: "McÉccent"
      });

      const afterSecondGrant = await store.grantScopeRoles("ws-1", "uid-1", ["manager"]);
      expect(afterSecondGrant.roles).toEqual(["member", "manager"]);

      await store.revokeScopeRoles("ws-1", "uid-1", ["member"]);
      const afterRevoke = await store.getScopeMember("ws-1", "uid-1");
      expect(afterRevoke?.roles).toEqual(["manager"]);

      // Revoking on non-existent member is a safe no-op
      await store.revokeScopeRoles("ws-1", "non-existent", ["manager"]);

      expect(await store.listScopeMembers("ws-1")).toHaveLength(1);
      await store.deleteScopeMember("ws-1", "uid-1");
      expect(await store.listScopeMembers("ws-1")).toHaveLength(0);

      unsubScope();
      expect(scopeSnapshots.length).toBeGreaterThanOrEqual(4);
    });

    it("supports system admins, preferences, avatar syncing, and presence heartbeats", async () => {
      const store = new InMemoryLanyardStore<TestRole, TestCapability, { theme: string }>();
      const updates: Partial<{ theme: string }>[] = [];

      const unsubPrefs = store.subscribeToPreferences("uid-1", (prefs) => updates.push(prefs));
      await store.savePreferences("uid-1", { theme: "dark" });
      unsubPrefs();

      expect(updates).toEqual([{}, { theme: "dark" }]);

      // System Admin CRUD + avatar & heartbeat sync
      await store.syncAvatar({
        uid: "admin-1",
        email: "admin@example.com",
        displayName: "Admin One",
        photoUrl: "https://example.com/admin1.png"
      });
      expect((await store.getSystemAdmin("admin-1"))?.photoUrl).toBe("https://example.com/admin1.png");

      await store.recordPresenceHeartbeat({
        uid: "admin-1",
        lastSeenIso: "2026-10-19T11:00:00.000Z",
        photoUrl: "https://example.com/admin1-v2.png"
      });
      const admins = await store.listSystemAdmins();
      expect(admins).toHaveLength(1);
      expect(admins[0].lastSeen).toBe("2026-10-19T11:00:00.000Z");
      expect(admins[0].photoUrl).toBe("https://example.com/admin1-v2.png");

      await store.deleteSystemAdmin("admin-1");
      expect(await store.getSystemAdmin("admin-1")).toBeNull();

      // Scoped Member avatar & heartbeat sync
      await store.upsertScopeMember("ws-1", {
        uid: "uid-1",
        email: "accenty@example.com",
        roles: ["manager"]
      });

      await store.syncAvatar({
        uid: "uid-1",
        scopeId: "ws-1",
        photoUrl: "https://example.com/accenty.png"
      });
      expect((await store.getScopeMember("ws-1", "uid-1"))?.photoUrl).toBe("https://example.com/accenty.png");

      await store.recordPresenceHeartbeat({
        uid: "uid-1",
        scopeId: "ws-1",
        lastSeenIso: "2026-10-19T12:00:00.000Z"
      });

      const updated = await store.getScopeMember("ws-1", "uid-1");
      expect(updated?.lastSeen).toBe("2026-10-19T12:00:00.000Z");
    });

    it("enforces no-op write guards on syncAvatar when photoUrl already matches or scoped member does not exist", async () => {
      const store = new InMemoryLanyardStore<TestRole, TestCapability>();
      await store.upsertScopeMember("ws-1", {
        uid: "uid-1",
        email: "accenty@example.com",
        roles: ["manager"],
        photoUrl: "https://example.com/same.png"
      });
      await store.upsertSystemAdmin({
        uid: "admin-1",
        email: "admin@example.com",
        displayName: "Admin One",
        photoUrl: "https://example.com/admin-same.png"
      });

      const upsertMemberSpy = vi.spyOn(store, "upsertScopeMember");
      const upsertAdminSpy = vi.spyOn(store, "upsertSystemAdmin");

      // 1. Scoped member with already-matching photoUrl -> zero writes
      await store.syncAvatar({
        uid: "uid-1",
        scopeId: "ws-1",
        photoUrl: "https://example.com/same.png"
      });
      expect(upsertMemberSpy).not.toHaveBeenCalled();

      // 2. Non-existent scoped member -> zero writes (never creates a phantom member doc)
      await store.syncAvatar({
        uid: "non-existent-uid",
        scopeId: "ws-1",
        photoUrl: "https://example.com/ghost.png"
      });
      expect(upsertMemberSpy).not.toHaveBeenCalled();
      expect(await store.getScopeMember("ws-1", "non-existent-uid")).toBeNull();

      // 3. System admin with already-matching photoUrl -> zero writes
      await store.syncAvatar({
        uid: "admin-1",
        photoUrl: "https://example.com/admin-same.png"
      });
      expect(upsertAdminSpy).not.toHaveBeenCalled();

      // 4. Rejects unsafe photoUrl (e.g. javascript: or SVG) in syncAvatar & upsertScopeMember, and rejects invalid IDs
      await store.syncAvatar({
        uid: "uid-1",
        scopeId: "ws-1",
        photoUrl: "javascript:alert(1)"
      });
      expect((await store.getScopeMember("ws-1", "uid-1"))?.photoUrl).toBe("https://example.com/same.png");

      await store.upsertScopeMember("ws-1", {
        uid: "uid-1",
        email: "accenty@example.com",
        roles: ["manager"],
        photoUrl: "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="
      });
      expect((await store.getScopeMember("ws-1", "uid-1"))?.photoUrl).toBeNull();

      await expect(store.getScopeMember("../bad", "uid-1")).rejects.toThrow(/Invalid scopeId/);
      await expect(store.getSystemAdmin("uid/bad")).rejects.toThrow(/Invalid uid/);
    });

    it("covers root barrel exports, defaultRole/quantifier edge cases, URL parse catch, punctuation initials, and store no-ops", async () => {
      // 1. Root barrel re-exports core APIs
      expect(rootBarrel.createPermissionPolicy).toBe(createPermissionPolicy);
      expect(rootBarrel.InMemoryLanyardStore).toBe(InMemoryLanyardStore);

      // 2. Explicit defaultRole vs unrecognized defaultRole fallback + omitted capabilities
      const customDefaultPolicy = createPermissionPolicy<"lead" | "viewer", "read">({
        roles: {
          lead: { inherits: ["viewer"], capabilities: "*" },
          viewer: {}
        },
        defaultRole: "lead"
      });
      expect(customDefaultPolicy.defaultRole).toBe("lead");

      const fallbackDefaultPolicy = createPermissionPolicy<"lead" | "viewer", "read">({
        roles: {
          lead: { inherits: ["viewer"] },
          viewer: {}
        },
        defaultRole: "nonexistent" as any
      });
      expect(fallbackDefaultPolicy.defaultRole).toBe("viewer");

      // hasAllCapabilities quantifier semantics on empty array vs null member
      const viewerMember: ScopedMember<"lead" | "viewer", "read"> = {
        uid: "u-v",
        email: "v@example.com",
        roles: ["viewer"]
      };
      expect(fallbackDefaultPolicy.hasAllCapabilities(viewerMember, [])).toBe(true);
      expect(fallbackDefaultPolicy.hasAllCapabilities(null, [])).toBe(false);
      expect(fallbackDefaultPolicy.hasAnyCapability(viewerMember, [])).toBe(false);

      // 3. Malformed URL starting with https:// triggers URL constructor catch block
      expect(sanitizeAvatarUrl("https://[invalid-ipv6")).toBeNull();

      // 4. Initials with leading punctuation, punctuation-only strings, and resolveAvatar(null)
      expect(getAvatarInitials(" (Alice)   [Bob] ")).toBe("AB");
      expect(getAvatarInitials("--- ***", "?")).toBe("?");
      expect(getAvatarInitials("@", "?")).toBe("@");
      expect(resolveAvatar(null)).toEqual({
        photoUrl: null,
        initials: "?",
        displayName: "User",
        colorIndex: expect.any(Number)
      });

      // 5. InMemoryLanyardStore edge cases: non-object patch, existing admin syncAvatar update, and non-existent member/admin heartbeats
      const store = new InMemoryLanyardStore<TestRole, TestCapability>();
      await store.savePreferences("u-1", null as any);
      await store.savePreferences("u-1", ["bad"] as any);

      await store.upsertSystemAdmin({
        uid: "admin-1",
        email: "admin@example.com",
        photoUrl: "https://example.com/old.png"
      });
      await store.syncAvatar({
        uid: "admin-1",
        photoUrl: "https://example.com/new.png"
      });
      expect((await store.getSystemAdmin("admin-1"))?.photoUrl).toBe("https://example.com/new.png");

      // Heartbeat & revoke on non-existent member/admin are safe no-ops
      await store.recordPresenceHeartbeat({
        uid: "ghost-user",
        scopeId: "ws-ghost",
        lastSeenIso: "2026-10-20T00:00:00.000Z"
      });
      await store.recordPresenceHeartbeat({
        uid: "ghost-admin",
        lastSeenIso: "2026-10-20T00:00:00.000Z"
      });
      await store.revokeScopeRoles("ws-ghost", "ghost-user", ["member"]);
      expect(await store.getScopeMember("ws-ghost", "ghost-user")).toBeNull();
    });

    it("resolves explicit role inheritance (DAGs, abstract roles, sibling roles, wildcard propagation, trackPresence override) and rejects cycles or unknown roles", () => {
      type EventRole =
        | "staff_base"
        | "attendee"
        | "scanner"
        | "merch_seller"
        | "moderator"
        | "director"
        | "quiet_director";
      type EventCap =
        | "view:events"
        | "staff:radio"
        | "manage:points"
        | "manage:merch"
        | "manage:badges"
        | "view:notes"
        | "manage:notes";

      const dagPolicy = createPermissionPolicy<EventRole, EventCap>({
        roles: {
          // Abstract role at the very top of the map: must NOT be picked as defaultRole or listed in assignableRoles!
          staff_base: {
            abstract: true,
            capabilities: ["staff:radio"],
            trackPresence: true
          },
          attendee: {
            capabilities: ["view:events"],
            trackPresence: false
          },
          scanner: {
            inherits: ["attendee", "staff_base"],
            capabilities: ["manage:points"]
            // trackPresence inherited from staff_base -> true!
          },
          merch_seller: {
            inherits: ["attendee", "staff_base"],
            capabilities: ["manage:merch"],
            trackPresence: false // explicitly overrides staff_base trackPresence -> false
          },
          // Diamond inheritance: moderator inherits from both sibling roles (scanner & merch_seller)
          moderator: {
            inherits: ["scanner", "merch_seller"],
            capabilities: ["manage:badges"]
            // trackPresence omitted -> inherits true from scanner!
          },
          director: {
            inherits: ["moderator"],
            capabilities: "*"
          },
          quiet_director: {
            inherits: ["director"],
            trackPresence: false // Explicitly overrides inherited trackPresence: true -> false
          }
        }
      });

      // Abstract role `staff_base` is skipped when selecting `defaultRole` and excluded from `assignableRoles`
      expect(dagPolicy.defaultRole).toBe("attendee");
      expect(dagPolicy.assignableRoles).toEqual([
        "attendee",
        "scanner",
        "merch_seller",
        "moderator",
        "director",
        "quiet_director"
      ]);
      expect(dagPolicy.isAssignableRole("staff_base")).toBe(false);
      expect(dagPolicy.isAssignableRole("scanner")).toBe(true);

      const scannerSubj = { roles: ["scanner"] as const };
      const merchSubj = { roles: ["merch_seller"] as const };
      const dualSubj = { roles: ["scanner", "merch_seller"] as const };
      const modSubj = { roles: ["moderator"] as const };
      const quietDirSubj = { roles: ["quiet_director"] as const };

      // Multi-role subject holding ["scanner", "merch_seller"] gets capabilities of both roles + inherited staff_base/attendee
      expect(dagPolicy.hasAllRoles(dualSubj, ["scanner", "merch_seller", "staff_base", "attendee"])).toBe(true);
      expect(dagPolicy.hasRole(dualSubj, "moderator")).toBe(false);
      expect(
        dagPolicy.hasAllCapabilities(dualSubj, ["view:events", "staff:radio", "manage:points", "manage:merch"])
      ).toBe(true);

      // Sibling isolation + abstract role inheritance:
      // Both scanner and merch_seller inherit abstract `staff_base` (passing `hasRole(..., "staff_base")` and getting `staff:radio`),
      // while scanner cannot manage:merch and merch_seller cannot manage:points!
      expect(dagPolicy.hasRole(scannerSubj, "staff_base")).toBe(true);
      expect(dagPolicy.hasRole(merchSubj, "staff_base")).toBe(true);
      expect(dagPolicy.hasCapability(scannerSubj, "staff:radio")).toBe(true);
      expect(dagPolicy.hasCapability(merchSubj, "staff:radio")).toBe(true);
      expect(dagPolicy.hasCapability(scannerSubj, "view:events")).toBe(true);
      expect(dagPolicy.hasCapability(scannerSubj, "manage:points")).toBe(true);
      expect(dagPolicy.hasCapability(scannerSubj, "manage:merch")).toBe(false);
      expect(dagPolicy.hasRole(scannerSubj, "merch_seller")).toBe(false);
      expect(dagPolicy.hasRole(merchSubj, "scanner")).toBe(false);

      expect(dagPolicy.hasCapability(merchSubj, "view:events")).toBe(true);
      expect(dagPolicy.hasCapability(merchSubj, "manage:merch")).toBe(true);
      expect(dagPolicy.hasCapability(merchSubj, "manage:points")).toBe(false);

      // Diamond convergence: moderator has attendee + staff_base + scanner + merch_seller + moderator capabilities
      expect(
        dagPolicy.hasAllCapabilities(modSubj, [
          "view:events",
          "staff:radio",
          "manage:points",
          "manage:merch",
          "manage:badges"
        ])
      ).toBe(true);
      expect(dagPolicy.hasCapability(modSubj, "manage:notes")).toBe(false);
      expect(dagPolicy.hasRole(modSubj, "attendee")).toBe(true);
      expect(dagPolicy.hasRole(modSubj, "staff_base")).toBe(true);
      expect(dagPolicy.hasRole(modSubj, "scanner")).toBe(true);
      expect(dagPolicy.hasRole(modSubj, "merch_seller")).toBe(true);
      expect(dagPolicy.hasRole(modSubj, "director")).toBe(false);
      expect(dagPolicy.shouldTrackPresence(modSubj)).toBe(true); // inherited from scanner/staff_base

      // quiet_director inherits wildcard "*" from director and passes hasRole("director")
      expect(dagPolicy.hasCapability(quietDirSubj, "manage:notes")).toBe(true);
      expect(dagPolicy.hasRole(quietDirSubj, "director")).toBe(true);
      expect(dagPolicy.shouldTrackPresence(quietDirSubj)).toBe(false); // explicit override

      // Abstract role validation errors (all roles abstract, or explicit defaultRole is abstract)
      expect(() =>
        createPermissionPolicy({
          roles: {
            onlyAbstract: { abstract: true, capabilities: [] }
          }
        })
      ).toThrow(/requires at least one concrete \(non-abstract\) role/);

      expect(() =>
        createPermissionPolicy<"abstractBase" | "concreteRole", never>({
          roles: {
            abstractBase: { abstract: true, capabilities: [] },
            concreteRole: { inherits: ["abstractBase"] }
          },
          defaultRole: "abstractBase"
        })
      ).toThrow(/abstract roles cannot be used as defaultRole/);

      // Cycle detection & validation errors
      expect(() =>
        createPermissionPolicy({
          roles: {
            selfLoop: { inherits: ["selfLoop"] }
          }
        })
      ).toThrow(/Circular role inheritance detected: selfLoop -> selfLoop/);

      expect(() =>
        createPermissionPolicy({
          roles: {
            a: { inherits: ["b"] },
            b: { inherits: ["c"] },
            c: { inherits: ["a"] }
          }
        })
      ).toThrow(/Circular role inheritance detected: a -> b -> c -> a/);

      expect(() =>
        createPermissionPolicy({
          roles: {
            a: { inherits: ["nonexistent" as any] }
          }
        })
      ).toThrow(/inherits from unknown role 'nonexistent'/);

      expect(() =>
        createPermissionPolicy({
          roles: {
            a: { inherits: ["__proto__" as any] }
          }
        })
      ).toThrow(/inherits from unknown role '__proto__'/);
    });

    it("enforces independent read/write capabilities on userCapabilities, attributes, hiddenAttributes, and write-only secrets with strict self/admin/prototype invariants", () => {
      type Role = "attendee" | "scanner" | "auditor" | "moderator" | "role_manager";
      type Cap =
        | "read:users"
        | "write:users"
        | "assign:roles"
        | "write:points"
        | "read:internal_tier"
        | "write:internal_tier"
        | "read:notes"
        | "write:notes"
        | "full:risk"
        | "write:ai_keys";

      const policy = createPermissionPolicy<Role, Cap>({
        roles: {
          attendee: { capabilities: [] },
          scanner: { inherits: ["attendee"], capabilities: ["read:users", "write:points"] },
          auditor: { inherits: ["attendee"], capabilities: ["read:users", "read:internal_tier", "read:notes"] },
          moderator: {
            inherits: ["scanner", "auditor"],
            capabilities: ["write:users", "write:internal_tier", "write:notes", "full:risk", "write:ai_keys"]
          },
          role_manager: {
            inherits: ["attendee"],
            capabilities: ["read:users", "assign:roles"]
          }
        },
        userCapabilities: {
          read: "read:users",
          write: "write:users",
          assignRoles: "assign:roles"
        },
        attributeCapabilities: {
          // String shorthand: anyone (including self) can read, only 'write:points' can write
          pointsAllTime: "write:points",
          // Object syntax: self or 'read:internal_tier' can read; 'write:internal_tier' can write
          internalTier: { read: "read:internal_tier", write: "write:internal_tier" },
          // Read-only attribute with no non-admin writer
          systemFlag: { read: "read:internal_tier" }
        },
        hiddenAttributeCapabilities: {
          // Object syntax: independent read and write capabilities; self NEVER gets access
          moderatorNotes: { read: "read:notes", write: "write:notes" },
          // String shorthand on hiddenAttributes: gates BOTH read and write
          riskScore: "full:risk",
          // Write-only hiddenAttribute for non-admins (no read capability configured)
          auditTrailHash: { write: "write:notes" }
        },
        secretCapabilities: {
          // User/member-owned secret (allowSelfWrite defaults to true)
          personalGeminiKey: { allowSelfWrite: true },
          // Role-gated secret where self cannot write unless they hold 'write:ai_keys'
          sharedOpenaiKey: { write: "write:ai_keys", allowSelfWrite: false },
          // String shorthand on secretCapabilities: self OR 'write:ai_keys' can write
          hybridAnthropicKey: "write:ai_keys"
        }
      });

      const attendee = { roles: ["attendee"] as const };
      const scanner = { roles: ["scanner"] as const };
      const auditor = { roles: ["auditor"] as const };
      const moderator = { roles: ["moderator"] as const };
      const roleManager = { roles: ["role_manager"] as const };

      // 0. User records (canReadUser, canWriteUser, canAssignRoles):
      // Self can always read own user record; reading other users requires `read:users` or systemAdmin;
      // writing/deleting other users requires `write:users` or systemAdmin; assigning roles requires `assign:roles` or systemAdmin.
      expect(policy.canReadUser(attendee, { isSelf: true })).toBe(true);
      expect(policy.canReadUser(attendee, { isSelf: false })).toBe(false);
      expect(policy.canReadUser(scanner, { isSelf: false })).toBe(true);
      expect(policy.canReadUser(auditor, { isSelf: false })).toBe(true);
      expect(policy.canReadUser(null, { isSystemAdmin: true })).toBe(true);

      expect(policy.canWriteUser(attendee)).toBe(false);
      expect(policy.canWriteUser(scanner)).toBe(false);
      expect(policy.canWriteUser(auditor)).toBe(false);
      expect(policy.canWriteUser(roleManager)).toBe(false);
      expect(policy.canWriteUser(moderator)).toBe(true);
      expect(policy.canWriteUser(null, true)).toBe(true);

      expect(policy.canAssignRoles(attendee)).toBe(false);
      expect(policy.canAssignRoles(scanner)).toBe(false);
      expect(policy.canAssignRoles(moderator)).toBe(false); // moderator has write:users, NOT assign:roles!
      expect(policy.canAssignRoles(roleManager)).toBe(true);
      expect(policy.canAssignRoles(null, true)).toBe(true);

      // 1. Attributes: self can ALWAYS read their own attributes, but can NEVER write attributes without capability
      expect(policy.canReadAttribute(attendee, "pointsAllTime", { isSelf: true })).toBe(true);
      expect(policy.canReadAttribute(attendee, "internalTier", { isSelf: true })).toBe(true);
      expect(policy.canReadAttribute(attendee, "internalTier", { isSelf: false })).toBe(false);
      expect(policy.canReadAttribute(auditor, "internalTier", { isSelf: false })).toBe(true);

      expect(policy.canWriteAttribute(attendee, "pointsAllTime")).toBe(false);
      expect(policy.canWriteAttribute(scanner, "pointsAllTime")).toBe(true);
      expect(policy.canWriteAttribute(scanner, "internalTier")).toBe(false);
      expect(policy.canWriteAttribute(moderator, "internalTier")).toBe(true);
      // Unconfigured or write-omitted attribute key is default-deny for non-admins, allowed for system admins
      expect(policy.canWriteAttribute(moderator, "systemFlag")).toBe(false);
      expect(policy.canWriteAttribute(moderator, "unconfiguredAttr")).toBe(false);
      expect(policy.canWriteAttribute(null, "unconfiguredAttr", true)).toBe(true);

      // filterReadableAttributes redacts restricted attributes for non-self callers lacking read capability
      const sampleAttrs = { pointsAllTime: 100, internalTier: "gold", systemFlag: true };
      expect(policy.filterReadableAttributes(attendee, sampleAttrs, { isSelf: false })).toEqual({
        pointsAllTime: 100
      });
      expect(policy.filterReadableAttributes(attendee, sampleAttrs, { isSelf: true })).toEqual(sampleAttrs);
      expect(policy.filterReadableAttributes(auditor, sampleAttrs, { isSelf: false })).toEqual(sampleAttrs);

      // 2. HiddenAttributes: self NEVER gets read or write access; only explicit capability holders or systemAdmin
      expect(policy.canReadHiddenAttribute(attendee, "moderatorNotes")).toBe(false);
      expect(policy.canReadHiddenAttribute(scanner, "moderatorNotes")).toBe(false);
      expect(policy.canReadHiddenAttribute(auditor, "moderatorNotes")).toBe(true);
      expect(policy.canWriteHiddenAttribute(auditor, "moderatorNotes")).toBe(false); // auditor has read:notes, NOT write:notes!
      expect(policy.canWriteHiddenAttribute(moderator, "moderatorNotes")).toBe(true);

      expect(policy.canReadHiddenAttribute(auditor, "riskScore")).toBe(false);
      expect(policy.canReadHiddenAttribute(moderator, "riskScore")).toBe(true);
      expect(policy.canWriteHiddenAttribute(moderator, "riskScore")).toBe(true);

      // HiddenAttribute with write capability but no read capability cannot be read by non-admins
      expect(policy.canWriteHiddenAttribute(moderator, "auditTrailHash")).toBe(true);
      expect(policy.canReadHiddenAttribute(moderator, "auditTrailHash")).toBe(false);
      expect(policy.canReadHiddenAttribute(null, "auditTrailHash", true)).toBe(true);

      const sampleHidden = { moderatorNotes: "Trusted", riskScore: 0, superAdminOnly: "top-secret" };
      expect(policy.filterReadableHiddenAttributes(attendee, sampleHidden)).toEqual({});
      expect(policy.filterReadableHiddenAttributes(auditor, sampleHidden)).toEqual({ moderatorNotes: "Trusted" });
      expect(policy.filterReadableHiddenAttributes(moderator, sampleHidden)).toEqual({
        moderatorNotes: "Trusted",
        riskScore: 0
      });
      expect(policy.filterReadableHiddenAttributes(null, sampleHidden, true)).toEqual(sampleHidden);

      // 3. Write-only Secrets:
      // - personalGeminiKey (allowSelfWrite: true) -> self can write; non-self without capability cannot
      expect(policy.canWriteSecret(attendee, "personalGeminiKey", { isSelf: true })).toBe(true);
      expect(policy.canWriteSecret(attendee, "personalGeminiKey", { isSelf: false })).toBe(false);
      // - Unconfigured secret key also defaults to allowSelfWrite: true when isSelf is true
      expect(policy.canWriteSecret(attendee, "unconfiguredUserApiKey", { isSelf: true })).toBe(true);
      expect(policy.canWriteSecret(attendee, "unconfiguredUserApiKey", { isSelf: false })).toBe(false);
      // - sharedOpenaiKey (allowSelfWrite: false, write: "write:ai_keys") -> self cannot write unless holding write:ai_keys
      expect(policy.canWriteSecret(attendee, "sharedOpenaiKey", { isSelf: true })).toBe(false);
      expect(policy.canWriteSecret(moderator, "sharedOpenaiKey", { isSelf: false })).toBe(true);
      // - hybridAnthropicKey ("write:ai_keys") -> self OR holder of write:ai_keys can write
      expect(policy.canWriteSecret(attendee, "hybridAnthropicKey", { isSelf: true })).toBe(true);
      expect(policy.canWriteSecret(moderator, "hybridAnthropicKey", { isSelf: false })).toBe(true);
      expect(policy.canWriteSecret(scanner, "hybridAnthropicKey", { isSelf: false })).toBe(false);

      // - canWriteSecretsPatch validates every key in a multi-key secret patch
      expect(
        policy.canWriteSecretsPatch(
          attendee,
          { personalGeminiKey: "AIza1", hybridAnthropicKey: "sk-ant-1" },
          { isSelf: true }
        )
      ).toBe(true);
      expect(
        policy.canWriteSecretsPatch(
          attendee,
          { personalGeminiKey: "AIza1", sharedOpenaiKey: "sk-proj-1" },
          { isSelf: true }
        )
      ).toBe(false);
      expect(
        policy.canWriteSecretsPatch(
          moderator,
          { sharedOpenaiKey: "sk-proj-1", hybridAnthropicKey: null },
          { isSelf: false }
        )
      ).toBe(true);
      expect(policy.canWriteSecretsPatch(moderator, { personalGeminiKey: "AIza1" }, { isSelf: false })).toBe(false);
      expect(policy.canWriteSecretsPatch(moderator, {}, { isSelf: true })).toBe(false);

      // 4. Patch validation & prototype-pollution defenses (even for systemAdmin!)
      expect(policy.canWriteAttributesPatch(scanner, { pointsAllTime: 50 })).toBe(true);
      expect(policy.canWriteAttributesPatch(scanner, { pointsAllTime: 50, internalTier: "vip" })).toBe(false);
      expect(policy.canWriteAttributesPatch(scanner, {})).toBe(false);
      expect(policy.canWriteAttributesPatch(scanner, null as any)).toBe(false);
      expect(policy.canWriteAttributesPatch(scanner, [] as any)).toBe(false);

      const protoPatch = Object.defineProperty({}, "__proto__", {
        value: { polluted: true },
        enumerable: true
      });
      expect(policy.canWriteAttributesPatch(null, protoPatch, true)).toBe(false);
      expect(policy.canWriteHiddenAttributesPatch(null, protoPatch, true)).toBe(false);
      expect(policy.canWriteSecretsPatch(null, protoPatch, true)).toBe(false);
      expect(policy.canWriteAttribute(null, "__proto__", true)).toBe(false);
      expect(policy.canReadHiddenAttribute(null, "constructor", true)).toBe(false);
      expect(policy.canWriteSecret(null, "__proto__", true)).toBe(false);
    });

    it("preserves user preferences, attributes, hiddenAttributes, encrypted secrets, and profile when demoting a system admin in InMemoryLanyardStore", async () => {
      interface Prefs {
        leaderboardOptIn: boolean;
      }
      interface Attrs {
        pointsAllTime: number;
      }
      interface HiddenAttrs {
        internalNotes: string;
      }
      interface Secrets {
        geminiKey: string;
      }

      const store = new InMemoryLanyardStore<TestRole, TestCapability, Prefs, Attrs, HiddenAttrs, Secrets>();
      const observedUsers: any[] = [];
      const unsubUser = store.subscribeToUser("u-hybrid", (u) => observedUsers.push(u));

      // User is both a system admin and an attendee with preferences, attributes, hiddenAttributes, and secrets
      await store.upsertSystemAdmin({
        uid: "u-hybrid",
        email: "hybrid@example.com",
        firstName: "Testy",
        lastName: "McTest",
        displayName: "Testy McTest"
      });
      await store.savePreferences("u-hybrid", { leaderboardOptIn: true });
      await store.updateUserAttributes("u-hybrid", { pointsAllTime: 250 });
      await store.updateUserHiddenAttributes("u-hybrid", { internalNotes: "Great volunteer" });
      await store.updateUserSecrets("u-hybrid", { geminiKey: "AIzaSyTest123" });
      await store.updateUserProfile("u-hybrid", {
        firstName: "UpdatedTesty",
        photoUrl: "https://example.com/testy.png"
      });

      expect(await store.getSystemAdmin("u-hybrid")).not.toBeNull();
      expect(await store.listSystemAdmins()).toHaveLength(1);

      // Demote from system admin -> getSystemAdmin returns null, but UserRecord preserves points, prefs, and profile!
      await store.deleteSystemAdmin("u-hybrid");
      expect(await store.getSystemAdmin("u-hybrid")).toBeNull();
      expect(await store.listSystemAdmins()).toHaveLength(0);

      const userAfterDemotion = await store.getUser("u-hybrid");
      expect(userAfterDemotion).toMatchObject({
        uid: "u-hybrid",
        email: "hybrid@example.com",
        firstName: "UpdatedTesty",
        lastName: "McTest",
        photoUrl: "https://example.com/testy.png",
        isSystemAdmin: false,
        preferences: { leaderboardOptIn: true },
        attributes: { pointsAllTime: 250 }
      });
      expect(await store.getUserHiddenAttributes("u-hybrid")).toEqual({ internalNotes: "Great volunteer" });
      expect(await store.getUserSecretsStatus("u-hybrid")).toEqual({ geminiKey: true });
      expect(await store.getUserSecrets("u-hybrid")).toEqual({ geminiKey: "AIzaSyTest123" });

      // Scoped member attributes, hiddenAttributes, and secrets lifecycle
      await expect(store.updateScopeMemberAttributes("ws-1", "missing-uid", { pointsAllTime: 10 })).rejects.toThrow(
        /does not exist/
      );
      await store.upsertScopeMember("ws-1", {
        uid: "u-hybrid",
        email: "hybrid@example.com",
        roles: ["member"]
      });
      await store.updateScopeMemberAttributes("ws-1", "u-hybrid", { pointsAllTime: 99 });
      await store.updateScopeMemberHiddenAttributes("ws-1", "u-hybrid", { internalNotes: "Scoped note" });
      await store.updateScopeMemberSecrets("ws-1", "u-hybrid", { geminiKey: "AIzaSyScoped456" });
      expect((await store.getScopeMember("ws-1", "u-hybrid"))?.attributes).toEqual({ pointsAllTime: 99 });
      expect(await store.getScopeMemberHiddenAttributes("ws-1", "u-hybrid")).toEqual({ internalNotes: "Scoped note" });
      expect(await store.getScopeMemberSecretsStatus("ws-1", "u-hybrid")).toEqual({ geminiKey: true });
      expect(await store.getScopeMemberSecrets("ws-1", "u-hybrid")).toEqual({ geminiKey: "AIzaSyScoped456" });

      // Clearing a secret with "" or null removes it from status & decrypted secrets
      await store.updateScopeMemberSecrets("ws-1", "u-hybrid", { geminiKey: "" });
      expect(await store.getScopeMemberSecretsStatus("ws-1", "u-hybrid")).toEqual({});
      expect(await store.getScopeMemberSecrets("ws-1", "u-hybrid")).toEqual({});

      // Deleting scope member also cleans up scope hiddenAttributes and secrets
      await store.updateScopeMemberSecrets("ws-1", "u-hybrid", { geminiKey: "AIzaSyScoped789" });
      await store.deleteScopeMember("ws-1", "u-hybrid");
      expect(await store.getScopeMemberHiddenAttributes("ws-1", "u-hybrid")).toEqual({});
      expect(await store.getScopeMemberSecrets("ws-1", "u-hybrid")).toEqual({});

      // Scope-wide secrets lifecycle (e.g. BYOK workspace keys)
      await store.updateScopeSecrets("ws-1", { geminiKey: "AIzaSyWorkspaceByok" });
      expect(await store.getScopeSecretsStatus("ws-1")).toEqual({ geminiKey: true });
      expect(await store.getScopeSecrets("ws-1")).toEqual({ geminiKey: "AIzaSyWorkspaceByok" });
      await store.updateScopeSecrets("ws-1", { geminiKey: null });
      expect(await store.getScopeSecretsStatus("ws-1")).toEqual({});
      expect(await store.getScopeSecrets("ws-1")).toEqual({});

      unsubUser();
      expect(observedUsers.length).toBeGreaterThanOrEqual(5);
    });
  });
});

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
    it("supports empty roles configuration and respects explicit or root defaultRoles", () => {
      const emptyRolesPolicy = createPermissionPolicy({ roles: {} as any });
      expect(emptyRolesPolicy.defaultRoles).toEqual([]);
      expect(emptyRolesPolicy.assignableRoles).toEqual([]);
      expect(TEST_POLICY.defaultRoles).toEqual(["member"]);

      const explicitDefault = createPermissionPolicy<TestRole, TestCapability>({
        roles: {
          owner: { inherits: ["manager"] },
          manager: { inherits: ["member"] },
          member: {}
        },
        defaultRoles: ["manager"]
      });
      expect(explicitDefault.defaultRoles).toEqual(["manager"]);

      const explicitEmptyDefault = createPermissionPolicy<TestRole, TestCapability>({
        roles: {
          owner: { inherits: ["manager"] },
          manager: { inherits: ["member"] },
          member: {}
        },
        defaultRoles: []
      });
      expect(explicitEmptyDefault.defaultRoles).toEqual([]);
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

    it("stores preferences in a separate tier: card subscriptions omit them, server reads merge them, and deletes clear them", async () => {
      type Prefs = { theme: string; compact: boolean };
      const store = new InMemoryLanyardStore<TestRole, TestCapability, Prefs>();
      await store.upsertUser({
        uid: "u-1",
        email: "u1@example.com",
        roles: ["member"],
        preferences: { theme: "dark" }
      });
      await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: ["member"] });
      await store.saveScopePreferences("ws-1", "u-1", { compact: true });

      // Client-facing card subscriptions never include preferences
      const userEvents: any[] = [];
      const directoryEvents: any[][] = [];
      const membershipEvents: any[][] = [];
      const rosterEvents: any[][] = [];
      const unsubs = [
        store.subscribeToUser("u-1", (u) => userEvents.push(u)),
        store.subscribeToUsers((users) => directoryEvents.push(users)),
        store.subscribeToUserMemberships("u-1", (m) => membershipEvents.push(m)),
        store.subscribeToScopeMembers("ws-1", (m) => rosterEvents.push(m))
      ];
      expect(userEvents.at(-1)).not.toHaveProperty("preferences");
      expect(directoryEvents.at(-1)?.[0]).not.toHaveProperty("preferences");
      expect(membershipEvents.at(-1)?.[0]).not.toHaveProperty("preferences");
      expect(rosterEvents.at(-1)?.[0]).not.toHaveProperty("preferences");

      // Server reads merge the preferences tier back in
      expect((await store.getUser("u-1"))?.preferences).toEqual({ theme: "dark" });
      expect((await store.listUsers())[0].preferences).toEqual({ theme: "dark" });
      expect((await store.getScopeMember("ws-1", "u-1"))?.preferences).toEqual({ compact: true });
      expect((await store.listScopeMembers("ws-1"))[0].preferences).toEqual({ compact: true });

      // Preference writes notify only preference listeners, not card listeners
      const globalPrefEvents: Partial<Prefs>[] = [];
      const scopePrefEvents: Partial<Prefs>[] = [];
      unsubs.push(store.subscribeToPreferences("u-1", (p) => globalPrefEvents.push(p)));
      unsubs.push(store.subscribeToScopePreferences("ws-1", "u-1", (p) => scopePrefEvents.push(p)));
      const userEventCount = userEvents.length;
      const rosterEventCount = rosterEvents.length;
      await store.savePreferences("u-1", { compact: false });
      await store.saveScopePreferences("ws-1", "u-1", { theme: "light" });
      expect(globalPrefEvents).toEqual([{ theme: "dark" }, { theme: "dark", compact: false }]);
      expect(scopePrefEvents).toEqual([{ compact: true }, { compact: true, theme: "light" }]);
      expect(userEvents).toHaveLength(userEventCount);
      expect(rosterEvents).toHaveLength(rosterEventCount);

      // Upserting a card without preferences keeps the existing preferences
      await store.upsertUser({ uid: "u-1", email: "u1@example.com", firstName: "Uno" });
      expect((await store.getUser("u-1"))?.preferences).toEqual({ theme: "dark", compact: false });

      // The reserved tier metadata key is rejected on every write path and nothing is written
      for (const key of ["_lanyard"]) {
        const bad = { [key]: "x" } as any;
        await expect(store.savePreferences("u-1", bad)).rejects.toThrow(`Invalid preferences key '${key}'`);
        await expect(store.saveScopePreferences("ws-1", "u-1", bad)).rejects.toThrow(
          `Invalid preferences key '${key}'`
        );
        await expect(store.upsertUser({ uid: "u-1", email: "u1@example.com", preferences: bad })).rejects.toThrow(
          `Invalid preferences key '${key}'`
        );
        await expect(
          store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: [], preferences: bad })
        ).rejects.toThrow(`Invalid preferences key '${key}'`);
      }
      expect((await store.getUser("u-1"))?.preferences).toEqual({ theme: "dark", compact: false });
      expect((await store.getScopeMember("ws-1", "u-1"))?.roles).toEqual(["member"]);

      // Scoped preferences require an existing membership
      await expect(store.saveScopePreferences("ws-2", "u-1", { theme: "x" })).rejects.toThrow(/does not exist/);

      // Deleting the user/member deletes their preferences and notifies listeners with empty preferences
      await store.deleteScopeMember("ws-1", "u-1");
      expect(scopePrefEvents.at(-1)).toEqual({});
      await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: ["member"] });
      expect((await store.getScopeMember("ws-1", "u-1"))?.preferences).toBeUndefined();
      await store.deleteUser("u-1");
      expect(globalPrefEvents.at(-1)).toEqual({});
      await store.upsertUser({ uid: "u-1", email: "u1@example.com" });
      expect((await store.getUser("u-1"))?.preferences).toBeUndefined();

      unsubs.forEach((unsub) => unsub());
    });

    it("routes attributes to the card or the attributes tier by the policy's cardFields", async () => {
      type Attrs = { badges: string[]; points: number; tier: string };
      const policy = createPermissionPolicy<TestRole, TestCapability>({ cardFields: { attributes: ["badges"] } });
      const store = new InMemoryLanyardStore<TestRole, TestCapability, Record<string, any>, Attrs>({ policy });
      expect(store.cardFields).toBe(policy.cardFields);
      expect(new InMemoryLanyardStore().cardFields).toEqual({ email: false, attributes: [] });

      await store.upsertUser({ uid: "u-1", email: "u1@example.com", attributes: { badges: ["a"], points: 1 } });
      await store.upsertScopeMember("ws-1", {
        uid: "u-1",
        email: "u1@example.com",
        roles: ["member"],
        attributes: { badges: ["b"], points: 2, tier: "gold" }
      });

      // Cards carry only card-placed keys; ordinary keys like `tier` are allowed in the attributes tier
      const userEvents: any[] = [];
      const rosterEvents: any[][] = [];
      const globalAttrEvents: Partial<Attrs>[] = [];
      const scopeAttrEvents: Partial<Attrs>[] = [];
      const unsubs = [
        store.subscribeToUser("u-1", (u) => userEvents.push(u)),
        store.subscribeToScopeMembers("ws-1", (m) => rosterEvents.push(m)),
        store.subscribeToAttributes("u-1", (a) => globalAttrEvents.push(a)),
        store.subscribeToScopeAttributes("ws-1", "u-1", (a) => scopeAttrEvents.push(a))
      ];
      expect(userEvents.at(-1)?.attributes).toEqual({ badges: ["a"] });
      expect(rosterEvents.at(-1)?.[0].attributes).toEqual({ badges: ["b"] });
      expect(globalAttrEvents.at(-1)).toEqual({ points: 1 });
      expect(scopeAttrEvents.at(-1)).toEqual({ points: 2, tier: "gold" });

      // Server reads merge both locations back into one shape
      expect((await store.getUser("u-1"))?.attributes).toEqual({ badges: ["a"], points: 1 });
      expect((await store.getScopeMember("ws-1", "u-1"))?.attributes).toEqual({
        badges: ["b"],
        points: 2,
        tier: "gold"
      });

      // Updates are routed per key: a tier-only update doesn't touch the card, and vice versa
      const userEventCount = userEvents.length;
      expect(await store.updateUserAttributes("u-1", { points: 5 })).toMatchObject({
        attributes: { badges: ["a"], points: 5 }
      });
      expect(globalAttrEvents.at(-1)).toEqual({ points: 5 });
      await store.updateUserAttributes("u-1", { badges: ["a", "c"] });
      expect(userEvents.at(-1)?.attributes).toEqual({ badges: ["a", "c"] });
      expect(globalAttrEvents.at(-1)).toEqual({ points: 5 });
      expect(userEvents.length).toBeGreaterThan(userEventCount);
      const scopeAttrEventCount = scopeAttrEvents.length;
      await store.updateScopeMemberAttributes("ws-1", "u-1", { badges: ["b", "d"] });
      expect(scopeAttrEvents).toHaveLength(scopeAttrEventCount);
      expect(rosterEvents.at(-1)?.[0].attributes).toEqual({ badges: ["b", "d"] });

      // Card-only updates (presence, roles) don't re-emit the private tiers
      const globalAttrEventCount = globalAttrEvents.length;
      await store.recordPresenceHeartbeat({ uid: "u-1", scopeId: "ws-1", lastSeenIso: "2026-01-01T00:00:00.000Z" });
      await store.grantScopeRoles("ws-1", "u-1", ["manager"]);
      expect(scopeAttrEvents).toHaveLength(scopeAttrEventCount);
      expect(globalAttrEvents).toHaveLength(globalAttrEventCount);

      // `_lanyard` is rejected as an attribute key, even when the patch also has card-placed keys
      await expect(store.updateUserAttributes("u-1", { badges: ["x"], _lanyard: {} } as any)).rejects.toThrow(
        "Invalid attributes key '_lanyard'"
      );
      expect((await store.getUser("u-1"))?.attributes).toEqual({ badges: ["a", "c"], points: 5 });

      // Deleting removes both locations
      await store.deleteScopeMember("ws-1", "u-1");
      expect(scopeAttrEvents.at(-1)).toEqual({});
      await store.deleteUser("u-1");
      expect(globalAttrEvents.at(-1)).toEqual({});

      unsubs.forEach((unsub) => unsub());
    });

    it("keeps email private in the attributes tier by default, or on the card with cardFields.email", async () => {
      expect(() => createPermissionPolicy({ cardFields: { attributes: ["email"] } })).toThrow(/use cardFields.email/);

      // Default: email is private
      const store = new InMemoryLanyardStore<TestRole, TestCapability>();
      await store.upsertUser({ uid: "u-1", email: "u1@example.com", attributes: { points: 1 } });
      await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1-ws@example.com", roles: ["member"] });
      await store.upsertSystemAdmin({ uid: "admin-1", email: "admin@example.com", isSystemAdmin: true });

      const cards: any[] = [];
      const rosters: any[][] = [];
      const attrs: Array<{ attrs: any; email?: string }> = [];
      const scopeAttrs: Array<{ attrs: any; email?: string }> = [];
      const unsubs = [
        store.subscribeToUser("u-1", (u) => cards.push(u)),
        store.subscribeToScopeMembers("ws-1", (m) => rosters.push(m)),
        store.subscribeToAttributes("u-1", (a, email) => attrs.push({ attrs: a, email })),
        store.subscribeToScopeAttributes("ws-1", "u-1", (a, email) => scopeAttrs.push({ attrs: a, email }))
      ];
      expect(cards.at(-1)?.email).toBe("");
      expect(rosters.at(-1)?.[0].email).toBe("");
      expect(attrs.at(-1)).toEqual({ attrs: { points: 1 }, email: "u1@example.com" });
      expect(scopeAttrs.at(-1)).toEqual({ attrs: {}, email: "u1-ws@example.com" });
      expect((await store.getUser("u-1"))?.email).toBe("u1@example.com");
      expect((await store.getUser("u-1"))?.attributes).toEqual({ points: 1 });
      expect((await store.getScopeMember("ws-1", "u-1"))?.email).toBe("u1-ws@example.com");
      expect((await store.getSystemAdmin("admin-1"))?.email).toBe("admin@example.com");
      expect((await store.listSystemAdmins()).map((a) => a.email)).toEqual(["admin@example.com"]);

      // Self-service email updates route to the tier; card-only read-modify-write paths can't erase it
      await store.updateUserProfile("u-1", { email: "New@Example.com" });
      expect(attrs.at(-1)?.email).toBe("new@example.com");
      await store.recordPresenceHeartbeat({ uid: "u-1", lastSeenIso: "2026-01-01T00:00:00.000Z" });
      await store.upsertUser({ uid: "u-1", email: "" });
      await store.grantScopeRoles("ws-1", "u-1", ["manager"]);
      expect((await store.getUser("u-1"))?.email).toBe("new@example.com");
      expect((await store.getScopeMember("ws-1", "u-1"))?.email).toBe("u1-ws@example.com");

      // `email` is reserved as an attribute key
      await expect(store.updateUserAttributes("u-1", { email: "x@example.com" } as any)).rejects.toThrow(
        "Invalid attributes key 'email'"
      );
      unsubs.forEach((unsub) => unsub());

      // cardFields.email: email lives on the card and never in the tier
      const cardPolicy = createPermissionPolicy<TestRole, TestCapability>({ cardFields: { email: true } });
      const cardStore = new InMemoryLanyardStore<TestRole, TestCapability>({ policy: cardPolicy });
      await cardStore.upsertUser({ uid: "u-2", email: "u2@example.com", attributes: { points: 2 } });
      await cardStore.updateUserProfile("u-2", { email: "u2-new@example.com" });
      const cardEvents: any[] = [];
      const cardAttrEvents: Array<{ attrs: any; email?: string }> = [];
      cardStore.subscribeToUser("u-2", (u) => cardEvents.push(u))();
      cardStore.subscribeToAttributes("u-2", (a, email) => cardAttrEvents.push({ attrs: a, email }))();
      expect(cardEvents.at(-1)?.email).toBe("u2-new@example.com");
      expect(cardAttrEvents.at(-1)).toEqual({ attrs: { points: 2 }, email: undefined });
      expect((await cardStore.getUser("u-2"))?.email).toBe("u2-new@example.com");
    });

    it("merges the attributes tier into list subscriptions only when included, and re-emits on tier changes", async () => {
      const store = new InMemoryLanyardStore<TestRole, TestCapability>();
      await store.upsertScopeMember("ws-1", {
        uid: "u-1",
        email: "u1@example.com",
        roles: ["member"],
        attributes: { a: 1 }
      });
      await store.upsertUser({ uid: "u-1", email: "u1@example.com", attributes: { g: 1 } });

      const plain: any[][] = [];
      const included: any[][] = [];
      const plainUsers: any[][] = [];
      const includedUsers: any[][] = [];
      const unsubs = [
        store.subscribeToScopeMembers("ws-1", (m) => plain.push(m)),
        store.subscribeToScopeMembers("ws-1", (m) => included.push(m), { include: ["attributes"] }),
        store.subscribeToUsers((u) => plainUsers.push(u)),
        store.subscribeToUsers((u) => includedUsers.push(u), { include: ["attributes"] })
      ];
      expect(plain.at(-1)?.[0]).toMatchObject({ email: "" });
      expect(plain.at(-1)?.[0].attributes).toBeUndefined();
      expect(included.at(-1)?.[0]).toMatchObject({ email: "u1@example.com", attributes: { a: 1 } });
      expect(plainUsers.at(-1)?.[0].email).toBe("");
      expect(includedUsers.at(-1)?.[0]).toMatchObject({ email: "u1@example.com", attributes: { g: 1 } });

      // Tier changes re-emit subscriptions that include the tier; plain subscriptions never see tier values
      await store.updateScopeMemberAttributes("ws-1", "u-1", { a: 2 });
      await store.updateUserAttributes("u-1", { g: 2 });
      expect(plain.at(-1)?.[0].attributes).toBeUndefined();
      expect(included.at(-1)?.[0].attributes).toEqual({ a: 2 });
      expect(includedUsers.at(-1)?.[0].attributes).toEqual({ g: 2 });

      // Unsubscribed include listeners stop receiving tier changes
      unsubs.forEach((unsub) => unsub());
      const includedCount = included.length;
      await store.updateScopeMemberAttributes("ws-1", "u-1", { a: 3 });
      expect(included).toHaveLength(includedCount);
    });

    it("queries member uids by card-placed or attributes-tier values, and validates filters", async () => {
      const policy = createPermissionPolicy<TestRole, TestCapability>({ cardFields: { attributes: ["team"] } });
      const store = new InMemoryLanyardStore<TestRole, TestCapability, Record<string, any>, Record<string, any>>({
        policy
      });
      await store.upsertScopeMember("ws-1", {
        uid: "a",
        email: "a@example.com",
        roles: [],
        attributes: { team: "blue", level: 2, tags: ["x"] }
      });
      await store.upsertScopeMember("ws-1", {
        uid: "b",
        email: "b@example.com",
        roles: [],
        attributes: { team: "red", level: 2 }
      });
      await store.upsertScopeMember("ws-2", {
        uid: "c",
        email: "c@example.com",
        roles: [],
        attributes: { team: "blue", level: 2 }
      });
      await store.upsertUser({ uid: "g", email: "g@example.com", attributes: { level: 9 } });

      expect(await store.queryMemberUids("ws-1", { team: "blue" })).toEqual(["a"]);
      expect((await store.queryMemberUids("ws-1", { level: 2 })).sort()).toEqual(["a", "b"]);
      expect(await store.queryMemberUids("ws-1", { level: 2, tags: ["x"] })).toEqual(["a"]);
      expect(await store.queryMemberUids("ws-1", { level: "2" })).toEqual([]);
      expect(await store.queryMemberUids(null, { level: 9 })).toEqual(["g"]);
      expect(await store.queryMemberUids("ws-none", { level: 2 })).toEqual([]);

      await expect(store.queryMemberUids("ws-1", {})).rejects.toThrow(/at least one attribute/);
      await expect(store.queryMemberUids("ws-1", { team: "blue", level: 2 })).rejects.toThrow(/can't be combined/);
      await expect(store.queryMemberUids("ws-1", { email: "a@example.com" })).rejects.toThrow(/filter key 'email'/);
      await expect(store.queryMemberUids("ws-1", { _lanyard: {} })).rejects.toThrow(/filter key '_lanyard'/);
      await expect(store.queryMemberUids("ws-1", { level: undefined })).rejects.toThrow(/'level' is undefined/);
    });

    it("rejects the reserved _lanyard key in hiddenAttributes and secrets", async () => {
      const store = new InMemoryLanyardStore<TestRole, TestCapability>();
      await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: [] });
      await expect(store.updateUserHiddenAttributes("u-1", { _lanyard: {} } as any)).rejects.toThrow(
        "Invalid hiddenAttributes key '_lanyard'"
      );
      await expect(store.updateScopeMemberHiddenAttributes("ws-1", "u-1", { _lanyard: {} } as any)).rejects.toThrow(
        "Invalid hiddenAttributes key '_lanyard'"
      );
      await expect(store.updateUserSecrets("u-1", { _lanyard: "x" } as any)).rejects.toThrow(
        "Invalid secrets key '_lanyard'"
      );
      await expect(store.updateScopeMemberSecrets("ws-1", "u-1", { _lanyard: "x" } as any)).rejects.toThrow(
        "Invalid secrets key '_lanyard'"
      );
      expect(await store.getUserHiddenAttributes("u-1")).toEqual({});
    });

    it("stores custom documents per user and scope, with live updates, validation, and delete cleanup", async () => {
      const store = new InMemoryLanyardStore<TestRole, TestCapability>();
      await store.upsertScopeMember("ws-1", { uid: "u-1", email: "u1@example.com", roles: ["member"] });
      await store.upsertUser({ uid: "u-1", email: "u1@example.com" });

      const events: Record<string, any>[] = [];
      const unsub = store.subscribeToCustomDoc("shiftNotes", "u-1", "ws-1", (v) => events.push(v));
      expect(events).toEqual([{}]);
      await store.updateCustomDoc("shiftNotes", "u-1", "ws-1", { note: "great" });
      await store.updateCustomDoc("shiftNotes", "u-1", "ws-1", { rating: 5 });
      expect(events.at(-1)).toEqual({ note: "great", rating: 5 });
      expect(await store.getCustomDoc("shiftNotes", "u-1", "ws-1")).toEqual({ note: "great", rating: 5 });
      // Global and other scopes are separate documents
      expect(await store.getCustomDoc("shiftNotes", "u-1", null)).toEqual({});
      expect(await store.getCustomDoc("shiftNotes", "u-1", "ws-2")).toEqual({});

      await expect(store.updateCustomDoc("shiftNotes", "u-1", "ws-1", { _lanyard: {} })).rejects.toThrow(
        "Invalid shiftNotes key '_lanyard'"
      );
      await expect(store.getCustomDoc("attributes", "u-1", "ws-1")).rejects.toThrow(/reserved for a built-in/);
      await expect(store.getCustomDoc("bad/name", "u-1", "ws-1")).rejects.toThrow(/Invalid custom doc name/);

      // Deleting the member deletes their custom documents in that scope only
      await store.updateCustomDoc("shiftNotes", "u-1", null, { note: "global" });
      await store.deleteScopeMember("ws-1", "u-1");
      expect(events.at(-1)).toEqual({});
      expect(await store.getCustomDoc("shiftNotes", "u-1", "ws-1")).toEqual({});
      expect(await store.getCustomDoc("shiftNotes", "u-1", null)).toEqual({ note: "global" });
      await store.deleteUser("u-1");
      expect(await store.getCustomDoc("shiftNotes", "u-1", null)).toEqual({});
      unsub();
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

      // 2. Explicit defaultRoles vs unrecognized defaultRoles fallback + omitted capabilities
      const customDefaultPolicy = createPermissionPolicy<"lead" | "viewer", "read">({
        roles: {
          lead: { inherits: ["viewer"], capabilities: "*" },
          viewer: {}
        },
        defaultRoles: ["lead"]
      });
      expect(customDefaultPolicy.defaultRoles).toEqual(["lead"]);

      const fallbackDefaultPolicy = createPermissionPolicy<"lead" | "viewer", "read">({
        roles: {
          lead: { inherits: ["viewer"] },
          viewer: {}
        },
        defaultRoles: ["nonexistent" as any]
      });
      expect(fallbackDefaultPolicy.defaultRoles).toEqual(["viewer"]);

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

      // Abstract role `staff_base` is skipped when selecting `defaultRoles` and excluded from `assignableRoles`
      expect(dagPolicy.defaultRoles).toEqual(["attendee"]);
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
          defaultRoles: ["abstractBase"]
        })
      ).toThrow(/abstract roles cannot be used in defaultRoles/);

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

    it("enforces tier-based reads with per-key writes on userCapabilities, attributes, hiddenAttributes, and write-only secrets with strict self/admin/prototype invariants", () => {
      type Role = "attendee" | "scanner" | "auditor" | "moderator" | "role_manager";
      type Cap =
        | "read:users"
        | "write:users"
        | "assign:roles"
        | "write:points"
        | "view:member_private"
        | "write:internal_tier"
        | "write:notes"
        | "full:risk"
        | "write:ai_keys";

      const policy = createPermissionPolicy<Role, Cap>({
        roles: {
          attendee: { capabilities: [] },
          scanner: { inherits: ["attendee"], capabilities: ["read:users", "write:points"] },
          auditor: { inherits: ["attendee"], capabilities: ["read:users", "view:member_private"] },
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
        // Holders of 'view:member_private' are scope staff: they can read the attributes and hiddenAttributes tiers
        staffCapability: "view:member_private",
        attributeCapabilities: {
          // String shorthand: only 'write:points' can write
          pointsAllTime: "write:points",
          // Object syntax: 'write:internal_tier' can write
          internalTier: { write: "write:internal_tier" },
          // Attribute with no non-admin writer
          systemFlag: {}
        },
        hiddenAttributeCapabilities: {
          moderatorNotes: { write: "write:notes" },
          // String shorthand on hiddenAttributes gates writes (reads are governed by the staff tier)
          riskScore: "full:risk",
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

      // 1. Attributes tier: readable by self, scope staff, and system admins; self can NEVER write without capability
      expect(policy.canReadAttribute(attendee, "pointsAllTime", { isSelf: true })).toBe(true);
      expect(policy.canReadAttribute(attendee, "internalTier", { isSelf: true })).toBe(true);
      expect(policy.canReadAttribute(attendee, "internalTier", { isSelf: false })).toBe(false);
      expect(policy.canReadAttribute(attendee, "pointsAllTime", { isSelf: false })).toBe(false);
      expect(policy.canReadAttribute(scanner, "pointsAllTime", { isSelf: false })).toBe(false); // writer, but not staff
      expect(policy.canReadAttribute(auditor, "internalTier", { isSelf: false })).toBe(true);
      expect(policy.canReadAttribute(null, "internalTier", { isSystemAdmin: true })).toBe(true);

      expect(policy.canWriteAttribute(attendee, "pointsAllTime")).toBe(false);
      expect(policy.canWriteAttribute(scanner, "pointsAllTime")).toBe(true);
      expect(policy.canWriteAttribute(scanner, "internalTier")).toBe(false);
      expect(policy.canWriteAttribute(moderator, "internalTier")).toBe(true);
      // Unconfigured or write-omitted attribute key is default-deny for non-admins, allowed for system admins
      expect(policy.canWriteAttribute(moderator, "systemFlag")).toBe(false);
      expect(policy.canWriteAttribute(moderator, "unconfiguredAttr")).toBe(false);
      expect(policy.canWriteAttribute(null, "unconfiguredAttr", true)).toBe(true);

      // filterReadableAttributes returns the whole tier to self/staff/admins and nothing to other callers
      const sampleAttrs = { pointsAllTime: 100, internalTier: "gold", systemFlag: true };
      expect(policy.filterReadableAttributes(attendee, sampleAttrs, { isSelf: false })).toEqual({});
      expect(policy.filterReadableAttributes(attendee, sampleAttrs, { isSelf: true })).toEqual(sampleAttrs);
      expect(policy.filterReadableAttributes(auditor, sampleAttrs, { isSelf: false })).toEqual(sampleAttrs);

      // 2. HiddenAttributes tier: self NEVER gets read or write access; scope staff and system admins can read
      expect(policy.canReadHiddenAttribute(attendee, "moderatorNotes")).toBe(false);
      expect(policy.canReadHiddenAttribute(scanner, "moderatorNotes")).toBe(false);
      expect(policy.canReadHiddenAttribute(auditor, "moderatorNotes")).toBe(true);
      expect(policy.canWriteHiddenAttribute(auditor, "moderatorNotes")).toBe(false); // staff can read, NOT write:notes!
      expect(policy.canWriteHiddenAttribute(moderator, "moderatorNotes")).toBe(true);

      expect(policy.canReadHiddenAttribute(auditor, "riskScore")).toBe(true);
      expect(policy.canWriteHiddenAttribute(auditor, "riskScore")).toBe(false);
      expect(policy.canReadHiddenAttribute(moderator, "riskScore")).toBe(true);
      expect(policy.canWriteHiddenAttribute(moderator, "riskScore")).toBe(true);

      expect(policy.canWriteHiddenAttribute(moderator, "auditTrailHash")).toBe(true);
      expect(policy.canReadHiddenAttribute(moderator, "auditTrailHash")).toBe(true);
      expect(policy.canReadHiddenAttribute(null, "auditTrailHash", true)).toBe(true);

      const sampleHidden = { moderatorNotes: "Trusted", riskScore: 0, superAdminOnly: "top-secret" };
      expect(policy.filterReadableHiddenAttributes(attendee, sampleHidden)).toEqual({});
      expect(policy.filterReadableHiddenAttributes(scanner, sampleHidden)).toEqual({});
      expect(policy.filterReadableHiddenAttributes(auditor, sampleHidden)).toEqual(sampleHidden);
      expect(policy.filterReadableHiddenAttributes(moderator, sampleHidden)).toEqual(sampleHidden);
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

    it("evaluates storage-tier reads, staff status, scoped card visibility, card field placement, and custom docs", () => {
      type Role = "volunteer" | "coordinator" | "creator";
      type Cap = "manage_members" | "view_roster" | "view_shift_notes" | "edit_shift_notes";

      const basePolicyConfig = {
        roles: {
          volunteer: { capabilities: [] as Cap[] },
          coordinator: {
            inherits: ["volunteer"] as Role[],
            capabilities: ["view_roster", "view_shift_notes"] as Cap[]
          },
          creator: { inherits: ["coordinator"] as Role[], capabilities: "*" as const }
        },
        staffCapability: "manage_members" as const
      };

      const policy = createPermissionPolicy<Role, Cap>({
        ...basePolicyConfig,
        cardFields: { attributes: ["badges", "badges", "__proto__"] },
        customDocs: {
          shiftNotes: {
            read: { capability: "view_shift_notes", self: true },
            write: { capability: "edit_shift_notes" }
          },
          auditLog: { read: { staff: true }, write: {} }
        }
      });

      const volunteer = { roles: ["volunteer"] as const };
      const coordinator = { roles: ["coordinator"] as const };
      const creator = { roles: ["creator"] as const };

      // Normalized configuration
      expect(policy.staffCapability).toBe("manage_members");
      expect(policy.cardVisibility).toBe("members");
      expect(policy.cardFields).toEqual({ email: false, attributes: ["badges"] });
      expect(Object.keys(policy.customDocs)).toEqual(["shiftNotes", "auditLog"]);

      // Staff = holders of staffCapability (creator via "*") or system admins
      expect(policy.isStaff(volunteer)).toBe(false);
      expect(policy.isStaff(coordinator)).toBe(false);
      expect(policy.isStaff(creator)).toBe(true);
      expect(policy.isStaff(null, true)).toBe(true);

      // preferences: self + system admins only
      expect(policy.canReadTier(creator, "preferences")).toBe(false);
      expect(policy.canReadTier(volunteer, "preferences", { isSelf: true })).toBe(true);
      expect(policy.canReadTier(null, "preferences", { isSystemAdmin: true })).toBe(true);

      // attributes: self + staff + system admins
      expect(policy.canReadTier(coordinator, "attributes")).toBe(false);
      expect(policy.canReadTier(volunteer, "attributes", { isSelf: true })).toBe(true);
      expect(policy.canReadTier(creator, "attributes")).toBe(true);

      // hiddenAttributes: staff + system admins; never self
      expect(policy.canReadTier(volunteer, "hiddenAttributes", { isSelf: true })).toBe(false);
      expect(policy.canReadTier(creator, "hiddenAttributes")).toBe(true);
      expect(policy.canReadTier(null, "hiddenAttributes", { isSystemAdmin: true })).toBe(true);

      // secrets: never readable by any client
      expect(policy.canReadTier(null, "secrets", { isSystemAdmin: true, isSelf: true })).toBe(false);

      // card (default "members"): any scope member; global card follows userCapabilities.read (unset: self + admins)
      expect(policy.canReadTier(volunteer, "card", { isScopeMember: true })).toBe(true);
      expect(policy.canReadTier(volunteer, "card", { isScopeMember: false })).toBe(false);
      expect(policy.canReadTier(volunteer, "card", { isSelf: true })).toBe(true);
      expect(policy.canReadTier(creator, "card", { isGlobal: true })).toBe(false);
      expect(policy.canReadTier(creator, "card", { isGlobal: true, isSelf: true })).toBe(true);
      expect(policy.canReadTier(null, "card", { isGlobal: true, isSystemAdmin: true })).toBe(true);

      // Card-placed attributes are readable by card readers; tier attributes are not
      expect(policy.isCardAttribute("badges")).toBe(true);
      expect(policy.isCardAttribute("points")).toBe(false);
      expect(policy.canReadAttribute(volunteer, "badges", { canReadCard: true })).toBe(true);
      expect(policy.canReadAttribute(volunteer, "points", { canReadCard: true })).toBe(false);
      expect(policy.canReadAttribute(volunteer, "badges", { canReadCard: false })).toBe(false);
      expect(
        policy.filterReadableAttributes(volunteer, { badges: ["early-bird"], points: 10 }, { canReadCard: true })
      ).toEqual({ badges: ["early-bird"] });

      // Custom docs: app-defined audiences; system admins always allowed; unknown names denied
      expect(policy.canReadCustomDoc(volunteer, "shiftNotes")).toBe(false);
      expect(policy.canReadCustomDoc(volunteer, "shiftNotes", { isSelf: true })).toBe(true);
      expect(policy.canReadCustomDoc(coordinator, "shiftNotes")).toBe(true);
      expect(policy.canWriteCustomDoc(coordinator, "shiftNotes")).toBe(false);
      expect(policy.canWriteCustomDoc(creator, "shiftNotes")).toBe(true);
      expect(policy.canReadCustomDoc(coordinator, "auditLog")).toBe(false);
      expect(policy.canReadCustomDoc(creator, "auditLog")).toBe(true);
      expect(policy.canWriteCustomDoc(creator, "auditLog")).toBe(false); // empty rule: admins/server only
      expect(policy.canWriteCustomDoc(null, "auditLog", { isSystemAdmin: true })).toBe(true);
      expect(policy.canReadCustomDoc(creator, "unknownDoc")).toBe(false);
      expect(policy.canReadCustomDoc(null, "__proto__", { isSystemAdmin: true })).toBe(false);

      // Scoped card visibility modes
      const staffOnlyCards = createPermissionPolicy<Role, Cap>({ ...basePolicyConfig, cardVisibility: "staff" });
      expect(staffOnlyCards.canReadTier(coordinator, "card", { isScopeMember: true })).toBe(false);
      expect(staffOnlyCards.canReadTier(creator, "card", { isScopeMember: true })).toBe(true);

      const capabilityCards = createPermissionPolicy<Role, Cap>({
        ...basePolicyConfig,
        cardVisibility: { capability: "view_roster" }
      });
      expect(capabilityCards.canReadTier(volunteer, "card", { isScopeMember: true })).toBe(false);
      expect(capabilityCards.canReadTier(coordinator, "card", { isScopeMember: true })).toBe(true);

      // Without staffCapability, only system admins are staff
      const noStaff = createPermissionPolicy<Role, Cap>({ roles: basePolicyConfig.roles });
      expect(noStaff.staffCapability).toBeUndefined();
      expect(noStaff.isStaff(creator)).toBe(false);
      expect(noStaff.canReadTier(creator, "attributes")).toBe(false);
      expect(noStaff.canReadTier(null, "attributes", { isSystemAdmin: true })).toBe(true);
    });

    it("matches an independent reference model for every role x tier x cardVisibility x caller-flag combination", () => {
      type Role = "volunteer" | "coordinator" | "creator" | "auditor";
      type Cap = "manage_members" | "view_roster" | "view_directory";
      const roles = {
        volunteer: { capabilities: [] as Cap[] },
        coordinator: { inherits: ["volunteer"] as Role[], capabilities: ["view_roster"] as Cap[] },
        creator: { inherits: ["coordinator"] as Role[], capabilities: "*" as const },
        auditor: { capabilities: ["view_directory"] as Cap[] }
      };
      // Independent capability table (mirrors `roles` above without using the policy engine)
      const caps: Record<Role, readonly Cap[]> = {
        volunteer: [],
        coordinator: ["view_roster"],
        creator: ["manage_members", "view_roster", "view_directory"],
        auditor: ["view_directory"]
      };
      const subjects: { label: string; subject: { roles: readonly Role[] } | null }[] = [
        { label: "null", subject: null },
        { label: "no roles", subject: { roles: [] } },
        { label: "volunteer", subject: { roles: ["volunteer"] } },
        { label: "coordinator", subject: { roles: ["coordinator"] } },
        { label: "creator", subject: { roles: ["creator"] } },
        { label: "auditor", subject: { roles: ["auditor"] } },
        { label: "volunteer+auditor", subject: { roles: ["volunteer", "auditor"] } },
        { label: "unknown role", subject: { roles: ["ghost" as Role] } }
      ];
      const holds = (s: { roles: readonly Role[] } | null, cap: Cap) =>
        Boolean(s?.roles.some((r) => Object.hasOwn(caps, r) && caps[r].includes(cap)));

      const visibilityModes: { label: string; rule: "members" | "staff" | { capability: Cap } }[] = [
        { label: "members", rule: "members" },
        { label: "staff", rule: "staff" },
        { label: "capability", rule: { capability: "view_roster" } }
      ];
      const tiers = ["card", "preferences", "attributes", "hiddenAttributes", "secrets"] as const;
      const bools = [false, true];
      let checked = 0;

      for (const staffCapability of [undefined, "manage_members" as const]) {
        for (const userRead of [undefined, "view_directory" as const]) {
          for (const mode of visibilityModes) {
            const policy = createPermissionPolicy<Role, Cap>({
              roles,
              staffCapability,
              cardVisibility: mode.rule,
              ...(userRead ? { userCapabilities: { read: userRead } } : {})
            });
            for (const { label, subject } of subjects) {
              const isStaffRef = (admin: boolean) =>
                admin || (staffCapability !== undefined && holds(subject, staffCapability));
              for (const tier of tiers) {
                for (const isSystemAdmin of bools) {
                  for (const isSelf of bools) {
                    for (const isGlobal of bools) {
                      for (const isScopeMember of bools) {
                        let expected: boolean;
                        switch (tier) {
                          case "card":
                            if (isSystemAdmin || isSelf) expected = true;
                            else if (isGlobal) expected = userRead !== undefined && holds(subject, userRead);
                            else if (mode.rule === "members") expected = isScopeMember;
                            else if (mode.rule === "staff") expected = isStaffRef(false);
                            else expected = holds(subject, mode.rule.capability);
                            break;
                          case "preferences":
                            expected = isSystemAdmin || isSelf;
                            break;
                          case "attributes":
                            expected = isSystemAdmin || isSelf || isStaffRef(false);
                            break;
                          case "hiddenAttributes":
                            expected = isStaffRef(isSystemAdmin);
                            break;
                          case "secrets":
                            expected = false;
                            break;
                        }
                        const actual = policy.canReadTier(subject, tier, {
                          isSystemAdmin,
                          isSelf,
                          isGlobal,
                          isScopeMember
                        });
                        if (actual !== expected) {
                          throw new Error(
                            `canReadTier mismatch: staff=${staffCapability} userRead=${userRead} visibility=${mode.label} ` +
                              `subject=${label} tier=${tier} admin=${isSystemAdmin} self=${isSelf} global=${isGlobal} ` +
                              `member=${isScopeMember}: expected ${expected}, got ${actual}`
                          );
                        }
                        checked++;
                      }
                    }
                  }
                }
              }
              // hiddenAttributes reads never depend on self; attributes reads never depend on per-key config
              expect(policy.canReadHiddenAttribute(subject, "anyKey", false)).toBe(isStaffRef(false));
              expect(policy.canReadHiddenAttribute(subject, "anyKey", true)).toBe(true);
              expect(policy.canReadAttribute(subject, "anyKey", { isSelf: false })).toBe(isStaffRef(false));
              expect(policy.isStaff(subject)).toBe(isStaffRef(false));
            }
          }
        }
      }
      expect(checked).toBe(2 * 2 * 3 * 8 * 5 * 16);
    });

    it("never treats prototype keys, unsafe names, or mutated config as granting access", () => {
      type Cap = "manage_members" | "edit";
      const policy = createPermissionPolicy<"lead" | "member", Cap>({
        roles: { lead: { capabilities: ["manage_members", "edit"] }, member: { capabilities: [] } },
        staffCapability: "manage_members",
        cardFields: { attributes: ["badges", "", "  ", "__proto__", "constructor", "prototype", 42 as any] },
        customDocs: { notes: { read: { self: true }, write: { capability: "edit" } } }
      });
      const lead = { roles: ["lead"] as const };
      const member = { roles: ["member"] as const };

      // Unsafe card attribute names are dropped during normalization
      expect(policy.cardFields.attributes).toEqual(["badges"]);
      for (const key of ["__proto__", "constructor", "prototype", "", "  "]) {
        expect(policy.isCardAttribute(key)).toBe(false);
        expect(policy.canReadAttribute(lead, key, { isSystemAdmin: true, isSelf: true, canReadCard: true })).toBe(
          false
        );
        expect(policy.canReadHiddenAttribute(lead, key, true)).toBe(false);
        expect(policy.canReadCustomDoc(lead, key, { isSystemAdmin: true })).toBe(false);
        expect(policy.canWriteCustomDoc(lead, key, { isSystemAdmin: true })).toBe(false);
      }

      // Normalized configuration is deeply frozen: callers can't widen access after creation
      expect(Object.isFrozen(policy.cardFields)).toBe(true);
      expect(Object.isFrozen(policy.cardFields.attributes)).toBe(true);
      expect(Object.isFrozen(policy.customDocs)).toBe(true);
      expect(Object.isFrozen(policy.customDocs.notes)).toBe(true);
      expect(Object.isFrozen(policy.customDocs.notes.read)).toBe(true);
      expect(() => {
        (policy.cardFields.attributes as string[]).push("secretKey");
      }).toThrow();
      expect(() => {
        (policy.customDocs.notes.read as any).staff = true;
      }).toThrow();
      expect(() => {
        (policy as any).staffCapability = "edit";
      }).toThrow();
      expect(policy.isCardAttribute("secretKey")).toBe(false);
      expect(policy.canReadCustomDoc(lead, "notes")).toBe(false); // lead is staff, but notes.read is self-only
      expect(policy.isStaff(member)).toBe(false);

      // Mutating the input config after creation has no effect
      const input = {
        roles: { lead: { capabilities: ["manage_members"] as Cap[] } },
        staffCapability: "manage_members" as Cap,
        cardFields: { attributes: ["badges"] },
        customDocs: { notes: { read: { self: true } as { self?: boolean; staff?: boolean }, write: {} } }
      };
      const snapshotPolicy = createPermissionPolicy<"lead", Cap>(input);
      input.cardFields.attributes.push("points");
      input.customDocs.notes.read.staff = true;
      expect(snapshotPolicy.isCardAttribute("points")).toBe(false);
      expect(snapshotPolicy.canReadCustomDoc(lead, "notes")).toBe(false);

      // Unsafe staffCapability / customDoc capability values are ignored rather than matched
      const unsafe = createPermissionPolicy<"lead", string>({
        roles: { lead: { capabilities: "*" } },
        staffCapability: "__proto__",
        customDocs: { doc: { read: { capability: "constructor" }, write: {} } }
      });
      expect(unsafe.staffCapability).toBeUndefined();
      expect(unsafe.isStaff({ roles: ["lead"] })).toBe(false);
      expect(unsafe.canReadCustomDoc({ roles: ["lead"] }, "doc")).toBe(false);

      // Legacy string shorthand on hiddenAttributeCapabilities no longer grants READ (only write)
      const legacy = createPermissionPolicy<"mod", "full:risk">({
        roles: { mod: { capabilities: ["full:risk"] } },
        hiddenAttributeCapabilities: { riskScore: "full:risk" }
      });
      expect(legacy.canWriteHiddenAttribute({ roles: ["mod"] }, "riskScore")).toBe(true);
      expect(legacy.canReadHiddenAttribute({ roles: ["mod"] }, "riskScore")).toBe(false);
    });

    it("rejects legacy per-key read rules, reserved or invalid custom doc names, and invalid cardVisibility", () => {
      type Cap = "read:x" | "write:x";
      expect(() =>
        createPermissionPolicy<never, Cap>({
          attributeCapabilities: { tier: { read: "read:x", write: "write:x" } as any }
        })
      ).toThrow(/attributeCapabilities\.tier: per-key 'read' rules are not supported/);
      expect(() =>
        createPermissionPolicy<never, Cap>({
          hiddenAttributeCapabilities: { notes: { read: "read:x" } as any }
        })
      ).toThrow(/hiddenAttributeCapabilities\.notes: per-key 'read' rules are not supported/);
      expect(() =>
        createPermissionPolicy<never, Cap>({ customDocs: { preferences: { read: { self: true }, write: {} } } })
      ).toThrow(/reserved for a built-in storage tier/);
      expect(() =>
        createPermissionPolicy<never, Cap>({ customDocs: { "bad/name": { read: { self: true }, write: {} } } })
      ).toThrow(/Invalid customDocs name/);
      expect(() => createPermissionPolicy<never, Cap>({ cardVisibility: { capability: "" as Cap } })).toThrow(
        /Invalid cardVisibility/
      );
    });

    it("rejects malformed policy config loudly instead of falling back to defaults", () => {
      type Cap = "read:x" | "write:x";
      // A legacy `read` key throws even when its value is undefined
      expect(() =>
        createPermissionPolicy<never, Cap>({
          attributeCapabilities: { tier: { read: undefined, write: "write:x" } as any }
        })
      ).toThrow(/per-key 'read' rules are not supported/);
      // Custom doc definitions must be objects
      for (const definition of [null, "x", 42]) {
        expect(() => createPermissionPolicy<never, Cap>({ customDocs: { notes: definition as any } })).toThrow(
          /Invalid definition for customDocs 'notes'/
        );
      }
      // Typos or unsafe values in cardVisibility never fall back to a default visibility
      for (const cardVisibility of ["public", null, {}, { capability: "__proto__" }]) {
        expect(() => createPermissionPolicy<never, Cap>({ cardVisibility: cardVisibility as any })).toThrow(
          /Invalid cardVisibility/
        );
      }
    });

    it("grants custom doc writes to self only for the document's owner, and staff writes only with a staffCapability", () => {
      type Role = "admin" | "member";
      type Cap = "everything";
      const selfWrite = createPermissionPolicy<Role, Cap>({
        roles: { admin: { capabilities: "*" }, member: {} },
        customDocs: { notes: { read: {}, write: { self: true } } }
      });
      const member = { roles: ["member"] as Role[] };
      expect(selfWrite.canWriteCustomDoc(member, "notes", { isSelf: true })).toBe(true);
      expect(selfWrite.canWriteCustomDoc(member, "notes", { isSelf: false })).toBe(false);
      expect(selfWrite.canReadCustomDoc(member, "notes", { isSelf: true })).toBe(false);

      // Without a staffCapability nobody is staff, not even a "*" role; only system admins pass
      const staffWrite = createPermissionPolicy<Role, Cap>({
        roles: { admin: { capabilities: "*" }, member: {} },
        customDocs: { notes: { read: {}, write: { staff: true } } }
      });
      expect(staffWrite.canWriteCustomDoc({ roles: ["admin"] }, "notes")).toBe(false);
      expect(staffWrite.canWriteCustomDoc(member, "notes", { isSystemAdmin: true })).toBe(true);
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

      unsubUser();
      expect(observedUsers.length).toBeGreaterThanOrEqual(5);
    });

    it("supports role-less PermissionPolicy (empty or omitted roles) and filtered subscribeToUsers({ isSystemAdmin }) in InMemoryLanyardStore", async () => {
      // 1. Role-less PermissionPolicy (for apps where only isSystemAdmin has special privileges)
      const adminOnlyPolicy = createPermissionPolicy<never, never>({});
      expect(adminOnlyPolicy.defaultRoles).toEqual([]);
      expect(adminOnlyPolicy.assignableRoles).toEqual([]);
      expect(adminOnlyPolicy.isAssignableRole("any" as never)).toBe(false);
      expect(adminOnlyPolicy.hasRole({ roles: [] }, "any" as never, false)).toBe(false);
      expect(adminOnlyPolicy.hasRole({ roles: [] }, "any" as never, true)).toBe(true);
      expect(adminOnlyPolicy.hasCapability({ roles: [] }, "any" as never, false)).toBe(false);
      expect(adminOnlyPolicy.hasCapability({ roles: [] }, "any" as never, true)).toBe(true);
      expect(adminOnlyPolicy.shouldTrackPresence({}, false)).toBe(false);
      expect(adminOnlyPolicy.shouldTrackPresence({ roles: [] }, false)).toBe(false);
      expect(adminOnlyPolicy.shouldTrackPresence({ roles: [] }, true)).toBe(true);
      expect(adminOnlyPolicy.canReadUser({ roles: [] }, { isSelf: true, isSystemAdmin: false })).toBe(true);
      expect(adminOnlyPolicy.canReadUser({ roles: [] }, { isSelf: false, isSystemAdmin: false })).toBe(false);
      expect(adminOnlyPolicy.canWriteUser({ roles: [] }, false)).toBe(false);
      expect(adminOnlyPolicy.canWriteUser({ roles: [] }, true)).toBe(true);

      // 2. Filtered subscribeToUsers({ isSystemAdmin: true }) in InMemoryLanyardStore
      const store = new InMemoryLanyardStore<never, never>();
      await store.upsertUser({
        uid: "u-regular",
        email: "regular@example.com",
        roles: []
      });
      await store.upsertSystemAdmin({
        uid: "u-admin",
        email: "admin@example.com",
        displayName: "Admin User"
      });

      const allSnapshots: any[][] = [];
      const adminSnapshots: any[][] = [];
      const nonAdminSnapshots: any[][] = [];

      const unsubAll = store.subscribeToUsers((users) => allSnapshots.push(users));
      const unsubAdmins = store.subscribeToUsers((users) => adminSnapshots.push(users), { isSystemAdmin: true });
      const unsubNonAdmins = store.subscribeToUsers((users) => nonAdminSnapshots.push(users), { isSystemAdmin: false });

      expect(allSnapshots[0].map((u) => u.uid)).toEqual(["u-regular", "u-admin"]);
      expect(adminSnapshots[0].map((u) => u.uid)).toEqual(["u-admin"]);
      expect(nonAdminSnapshots[0].map((u) => u.uid)).toEqual(["u-regular"]);

      // Promote another admin -> adminSnapshots receives both admins
      await store.upsertSystemAdmin({
        uid: "u-admin-2",
        email: "admin2@example.com"
      });
      expect(adminSnapshots[adminSnapshots.length - 1].map((u) => u.uid)).toEqual(["u-admin", "u-admin-2"]);

      unsubAll();
      unsubAdmins();
      unsubNonAdmins();
    });
  });
});

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

describe("lanyard/core unit tests", () => {
  describe("Custom PermissionPolicy (Generic TRole & TCapability)", () => {
    it("throws if roles configuration is empty and respects explicit or lowest-weighted defaultRole", () => {
      expect(() => createPermissionPolicy({ roles: {} as any })).toThrow(/at least one role/);
      expect(TEST_POLICY.defaultRole).toBe("member");

      const explicitDefault = createPermissionPolicy<TestRole, TestCapability>({
        roles: {
          owner: { weight: 30 },
          manager: { weight: 20 },
          member: { weight: 10 }
        },
        defaultRole: "manager"
      });
      expect(explicitDefault.defaultRole).toBe("manager");
    });

    it("evaluates custom role hierarchies and edge cases via policy.hasMinimumRole", () => {
      const owner: ScopedMember<TestRole, TestCapability> = {
        uid: "u1",
        email: "owner@example.com",
        role: "owner",
        capabilities: []
      };
      const manager: ScopedMember<TestRole, TestCapability> = {
        uid: "u2",
        email: "manager@example.com",
        role: "manager",
        capabilities: []
      };
      const member: ScopedMember<TestRole, TestCapability> = {
        uid: "u3",
        email: "member@example.com",
        role: "member",
        capabilities: ["edit_content"]
      };
      const unknownRoleMember = {
        uid: "u4",
        email: "unknown@example.com",
        role: "guest" as TestRole,
        capabilities: []
      };

      expect(TEST_POLICY.hasMinimumRole(owner, "owner")).toBe(true);
      expect(TEST_POLICY.hasMinimumRole(owner, "manager")).toBe(true);
      expect(TEST_POLICY.hasMinimumRole(manager, "owner")).toBe(false);
      expect(TEST_POLICY.hasMinimumRole(manager, "manager")).toBe(true);
      expect(TEST_POLICY.hasMinimumRole(manager, "member")).toBe(true);
      expect(TEST_POLICY.hasMinimumRole(member, "manager")).toBe(false);
      expect(TEST_POLICY.hasMinimumRole(member, "member")).toBe(true);
      expect(TEST_POLICY.hasMinimumRole(unknownRoleMember, "member")).toBe(false);
      expect(TEST_POLICY.hasMinimumRole(member, "unknown" as TestRole)).toBe(false);
      expect(TEST_POLICY.hasMinimumRole(null, "member")).toBe(false);
      expect(TEST_POLICY.hasMinimumRole(undefined, "member")).toBe(false);
      expect(TEST_POLICY.hasMinimumRole(null, "owner", true)).toBe(true); // System Admin override
    });

    it("evaluates role-implied capabilities (e.g. all managers have invite_members) and explicit capabilities", () => {
      const owner: ScopedMember<TestRole, TestCapability> = {
        uid: "u-owner",
        email: "owner@example.com",
        role: "owner",
        capabilities: []
      };
      const manager: ScopedMember<TestRole, TestCapability> = {
        uid: "u-mgr",
        email: "manager@example.com",
        role: "manager",
        capabilities: []
      };
      const multiMember: ScopedMember<TestRole, TestCapability> = {
        uid: "u-mem",
        email: "member@example.com",
        role: "member",
        capabilities: ["edit_content", "invite_members"]
      };

      // Owner has "*" -> implies all capabilities including "billing"
      expect(TEST_POLICY.hasCapability(owner, "edit_content")).toBe(true);
      expect(TEST_POLICY.hasCapability(owner, "invite_members")).toBe(true);
      expect(TEST_POLICY.hasCapability(owner, "billing")).toBe(true);

      // Manager has ["edit_content", "invite_members"] implied by role, but NOT "billing" unless explicitly added
      expect(TEST_POLICY.hasCapability(manager, "edit_content")).toBe(true);
      expect(TEST_POLICY.hasCapability(manager, "invite_members")).toBe(true);
      expect(TEST_POLICY.hasCapability(manager, "billing")).toBe(false);

      // Member has no role-implied capabilities, only explicit member.capabilities
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
        role: "manager",
        capabilities: []
      };
      const member: ScopedMember<TestRole, TestCapability> = {
        uid: "u-mem",
        email: "mem@example.com",
        role: "member",
        capabilities: ["edit_content"]
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
        const protoMember = { uid: "u-proto", email: "p@example.com", role: protoKey, capabilities: [] };
        expect(TEST_POLICY.hasMinimumRole(protoMember, "member")).toBe(false);
        expect(TEST_POLICY.hasMinimumRole(member, protoKey)).toBe(false);
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
      expect(formatMemberDisplayName({ firstName: "Accenty", lastName: "McÉccent", email: "accenty@example.com" })).toBe(
        "Accenty McÉccent"
      );
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

      // Throws if granting capabilities to a non-existent member without fallbackMember
      await expect(store.grantScopeCapabilities("ws-1", "missing-uid", ["edit_content"])).rejects.toThrow(
        /does not exist/
      );

      await store.grantScopeCapabilities("ws-1", "uid-1", ["edit_content"], {
        uid: "uid-1",
        email: "accenty@example.com",
        firstName: "Accenty",
        lastName: "McÉccent",
        role: "member"
      });

      const afterSecondGrant = await store.grantScopeCapabilities("ws-1", "uid-1", ["invite_members"]);
      expect(afterSecondGrant.capabilities).toEqual(["edit_content", "invite_members"]);

      await store.revokeScopeCapabilities("ws-1", "uid-1", ["edit_content"]);
      const afterRevoke = await store.getScopeMember("ws-1", "uid-1");
      expect(afterRevoke?.capabilities).toEqual(["invite_members"]);

      // Revoking on non-existent member is a safe no-op
      await store.revokeScopeCapabilities("ws-1", "non-existent", ["invite_members"]);

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
        role: "manager",
        capabilities: []
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
        role: "manager",
        capabilities: [],
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
        role: "manager",
        capabilities: [],
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
          lead: { weight: 20, capabilities: "*" },
          viewer: { weight: 5 }
        },
        defaultRole: "lead"
      });
      expect(customDefaultPolicy.defaultRole).toBe("lead");

      const fallbackDefaultPolicy = createPermissionPolicy<"lead" | "viewer", "read">({
        roles: {
          lead: { weight: 20 },
          viewer: { weight: 5 }
        },
        defaultRole: "nonexistent" as any
      });
      expect(fallbackDefaultPolicy.defaultRole).toBe("viewer");

      // hasAllCapabilities quantifier semantics on empty array vs null member
      const viewerMember: ScopedMember<"lead" | "viewer", "read"> = {
        uid: "u-v",
        email: "v@example.com",
        role: "viewer",
        capabilities: []
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
      await store.revokeScopeCapabilities("ws-ghost", "ghost-user", ["edit_content"]);
      expect(await store.getScopeMember("ws-ghost", "ghost-user")).toBeNull();
    });
  });
});

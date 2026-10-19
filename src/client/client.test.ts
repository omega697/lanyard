import { describe, it, expect, beforeEach, vi } from "vitest";
import * as firebaseAuth from "firebase/auth";
import * as firebaseFirestore from "firebase/firestore";
import { createPermissionPolicy, InMemoryLanyardStore } from "../core/index.js";
import { createLanyardClient, getSocialProvider, HEARTBEAT_INTERVAL_MS, normalizeFirebaseUser } from "./index.js";
import { FirestoreClientStore } from "./firestore.js";

vi.mock("firebase/auth", async () => {
  return {
    GoogleAuthProvider: class {
      providerId = "google.com";
    },
    GithubAuthProvider: class {
      providerId = "github.com";
    },
    OAuthProvider: class {
      providerId: string;
      constructor(id: string) {
        this.providerId = id;
      }
    },
    signInWithPopup: vi.fn(),
    linkWithPopup: vi.fn(),
    unlink: vi.fn(),
    signInAnonymously: vi.fn(),
    signInWithCustomToken: vi.fn(),
    signOut: vi.fn(),
    onAuthStateChanged: vi.fn(),
    sendSignInLinkToEmail: vi.fn(),
    isSignInWithEmailLink: vi.fn(),
    signInWithEmailLink: vi.fn(),
    verifyBeforeUpdateEmail: vi.fn(),
    applyActionCode: vi.fn(),
    fetchSignInMethodsForEmail: vi.fn()
  };
});

vi.mock("firebase/firestore", async () => {
  return {
    doc: vi.fn((_db: any, ...segments: string[]) => ({
      path: segments.join("/"),
      id: segments[segments.length - 1],
      parent: { parent: { id: segments[1] } }
    })),
    collection: vi.fn((_db: any, ...segments: string[]) => ({
      path: segments.join("/")
    })),
    collectionGroup: vi.fn((_db: any, name: string) => ({
      group: name
    })),
    where: vi.fn((field: string, op: string, val: any) => ({ field, op, val })),
    query: vi.fn((target: any, ...constraints: any[]) => ({ target, constraints })),
    onSnapshot: vi.fn(),
    setDoc: vi.fn(),
    updateDoc: vi.fn()
  };
});

type TestRole = "owner" | "manager" | "member";
type TestCap = "edit_content" | "invite_members";

interface TestPrefs {
  theme: "light" | "dark" | "system";
  use12h: boolean;
}

const DEFAULT_PREFS: TestPrefs = {
  theme: "system",
  use12h: true
};

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

// Simple localStorage shim for Node test environment
class MemoryLocalStorage {
  private map = new Map<string, string>();
  getItem(k: string): string | null {
    return this.map.has(k) ? this.map.get(k)! : null;
  }
  setItem(k: string, v: string): void {
    this.map.set(k, String(v));
  }
  removeItem(k: string): void {
    this.map.delete(k);
  }
  clear(): void {
    this.map.clear();
  }
}

describe("lanyard/client unit tests", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("localStorage", new MemoryLocalStorage());
  });

  it("instantiates social providers and normalizes Firebase User objects with providerData fallback", () => {
    expect((getSocialProvider("google") as any).providerId).toBe("google.com");
    expect((getSocialProvider("microsoft") as any).providerId).toBe("microsoft.com");
    expect((getSocialProvider("github") as any).providerId).toBe("github.com");

    const fakeFbUser: any = {
      uid: "u-999",
      email: "  Alice@Example.COM ",
      emailVerified: true,
      displayName: "Alice",
      photoURL: null, // e.g., user first signed up via Magic Email Link and later linked Google
      isAnonymous: false,
      providerData: [
        { providerId: "password", photoURL: null },
        { providerId: "google.com", photoURL: "https://example.com/provider-avatar.png" }
      ]
    };

    const normalized = normalizeFirebaseUser(fakeFbUser, { admin: true });
    expect(normalized).toEqual({
      uid: "u-999",
      email: "alice@example.com",
      emailVerified: true,
      displayName: "Alice",
      photoUrl: "https://example.com/provider-avatar.png",
      isAnonymous: false,
      isAdmin: true,
      providerIds: ["password", "google.com"]
    });
  });

  it("wires reactive stores, syncs OAuth avatars, and retries avatar sync if store.syncAvatar fails once", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.savePreferences("u-1", { theme: "dark" });
    await store.upsertScopeMember("ws-1", {
      uid: "u-1",
      email: "u1@example.com",
      role: "member",
      capabilities: ["edit_content", "invite_members"],
      photoUrl: null
    });

    const syncSpy = vi.spyOn(store, "syncAvatar");
    syncSpy.mockRejectedValueOnce(new Error("Transient network failure"));

    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "testapp"
    });

    const authUsersObserved: (string | null)[] = [];
    const unsubAuthUser = client.subscribeToAuthUser((u) => authUsersObserved.push(u?.uid ?? null));

    // First attempt rejects -> syncedAvatars entry is rolled back so subsequent update retries
    client.setActiveUser({
      uid: "u-1",
      email: "u1@example.com",
      emailVerified: true,
      displayName: "User One",
      photoUrl: "https://example.com/u1-oauth.png",
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(1);
    expect((await store.getScopeMember("ws-1", "u-1"))?.photoUrl).toBeNull();

    // Trigger membership emission again -> retries and succeeds!
    await store.grantScopeCapabilities("ws-1", "u-1", ["edit_content"]);
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(2);
    expect((await store.getScopeMember("ws-1", "u-1"))?.photoUrl).toBe("https://example.com/u1-oauth.png");

    // Admin-only user signing in syncs avatar to system_admins (not ws-1)
    client.setActiveUser({
      uid: "u-admin",
      email: "admin@example.com",
      emailVerified: true,
      displayName: "Root Admin",
      photoUrl: "https://example.com/admin.png",
      isAnonymous: false,
      isAdmin: true,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect((await store.getSystemAdmin("u-admin"))?.photoUrl).toBe("https://example.com/admin.png");
    expect(await store.getScopeMember("ws-1", "u-admin")).toBeNull();

    // Update preferences with syncToStore = false and syncToStore = true
    await client.updatePreferences({ use12h: false }, false);
    expect(client.preferencesStore.get()).toEqual({ theme: "dark", use12h: false });
    await client.updatePreferences({ theme: "light" }, true);

    await client.signOut();
    unsubAuthUser();
    expect(authUsersObserved).toEqual([null, "u-1", "u-admin", null]);
  });

  it("handles OAuth login, anonymous login, magic email links, dev mode login, and account linking", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    const fakeAuth: any = {
      currentUser: {
        uid: "u-social",
        email: "social@example.com",
        emailVerified: true,
        displayName: "Social User",
        photoURL: "https://example.com/social.png",
        providerData: [{ providerId: "google.com" }],
        getIdTokenResult: vi.fn().mockResolvedValue({ claims: { admin: false } })
      }
    };

    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation((_auth, cb: any) => {
      cb(fakeAuth.currentUser);
      return () => {};
    });

    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "testapp"
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(client.authStore.get().user?.uid).toBe("u-social");

    // 1. Social login
    vi.mocked(firebaseAuth.signInWithPopup).mockResolvedValueOnce({
      user: fakeAuth.currentUser
    } as any);
    const socialRes = await client.loginWithSocialProvider("google");
    expect(socialRes?.uid).toBe("u-social");

    // 2. Anonymous login
    vi.mocked(firebaseAuth.signInAnonymously).mockResolvedValueOnce({
      user: { uid: "u-anon", isAnonymous: true, providerData: [] }
    } as any);
    const anonRes = await client.loginAnonymously();
    expect(anonRes?.isAnonymous).toBe(true);

    // 3. Passwordless Magic Email Link
    await expect(client.sendPasswordlessEmailLink("   ")).rejects.toThrow(/valid email/);
    await client.sendPasswordlessEmailLink("  Magic@Example.com ", "https://app.example.com/callback");
    expect(firebaseAuth.sendSignInLinkToEmail).toHaveBeenCalledWith(
      fakeAuth,
      "magic@example.com",
      expect.objectContaining({ url: "https://app.example.com/callback", handleCodeInApp: true })
    );
    expect(localStorage.getItem("testapp_emailForSignIn")).toBe("magic@example.com");

    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValueOnce(true);
    vi.mocked(firebaseAuth.signInWithEmailLink).mockResolvedValueOnce({
      user: {
        uid: "u-magic",
        email: "magic@example.com",
        emailVerified: true,
        providerData: [],
        getIdTokenResult: vi.fn().mockResolvedValue({ claims: {} })
      }
    } as any);
    const magicUser = await client.completePasswordlessSignIn(undefined, "https://app.example.com/?oobCode=123");
    expect(magicUser?.uid).toBe("u-magic");
    expect(localStorage.getItem("testapp_emailForSignIn")).toBeNull();

    // 4. Dev Mode Login (?loginAs=dev@test.com)
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: "custom-dev-token" })
      })
    );
    vi.mocked(firebaseAuth.signInWithCustomToken).mockResolvedValueOnce({
      user: {
        uid: "u-dev",
        email: "dev@test.com",
        emailVerified: true,
        providerData: [],
        getIdTokenResult: vi.fn().mockResolvedValue({ claims: { admin: true } })
      }
    } as any);
    const params = new URLSearchParams("loginAs=dev@test.com&tab=events");
    await client.handleDevModeLogin(params);
    expect(client.authStore.get().user?.uid).toBe("u-dev");
    expect(client.authStore.get().user?.isAdmin).toBe(true);

    // 5. Link / Unlink Social Provider, getSignInMethodsForEmail, sendEmailUpdateVerification
    vi.mocked(firebaseAuth.linkWithPopup).mockResolvedValueOnce({
      user: {
        ...fakeAuth.currentUser,
        providerData: [{ providerId: "google.com" }, { providerId: "github.com" }]
      }
    } as any);
    const linked = await client.linkSocialProvider("github");
    expect(linked?.providerIds).toEqual(["google.com", "github.com"]);

    vi.mocked(firebaseAuth.unlink).mockResolvedValueOnce({
      ...fakeAuth.currentUser,
      providerData: [{ providerId: "google.com" }]
    } as any);
    const unlinked = await client.unlinkSocialProvider("github.com");
    expect(unlinked?.providerIds).toEqual(["google.com"]);

    vi.mocked(firebaseAuth.fetchSignInMethodsForEmail).mockResolvedValueOnce(["google.com"]);
    expect(await client.getSignInMethodsForEmail("Alice@Example.com")).toEqual(["google.com"]);
    vi.mocked(firebaseAuth.fetchSignInMethodsForEmail).mockRejectedValueOnce(new Error("Network error"));
    expect(await client.getSignInMethodsForEmail("Alice@Example.com")).toEqual([]);

    await client.sendEmailUpdateVerification("NewEmail@Example.com", "https://app.example.com/verify");
    expect(firebaseAuth.verifyBeforeUpdateEmail).toHaveBeenCalledWith(
      fakeAuth.currentUser,
      "newemail@example.com",
      expect.objectContaining({ url: "https://app.example.com/verify" })
    );

    client.destroy();
  });

  it("throttles presence heartbeats, rolls back lastSynced on store failure, and cleans up startPresenceHeartbeat", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.upsertScopeMember("ws-1", {
      uid: "u-mgr",
      email: "mgr@example.com",
      role: "manager",
      capabilities: []
    });
    await store.upsertScopeMember("ws-1", {
      uid: "u-mem",
      email: "mem@example.com",
      role: "member",
      capabilities: ["edit_content"]
    });

    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "testapp"
    });

    // 1. Regular member ('member' has trackPresence: false in TEST_POLICY) does not emit presence writes
    client.setActiveUser({
      uid: "u-mem",
      email: "mem@example.com",
      emailVerified: true,
      displayName: "Member",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: []
    });

    client.recordActivity("ws-1");
    await client.syncPresence({ scopeId: "ws-1" });
    expect((await store.getScopeMember("ws-1", "u-mem"))?.lastSeen).toBeUndefined();

    // 2. Manager ('manager' has trackPresence: true)
    client.setActiveUser({
      uid: "u-mgr",
      email: "mgr@example.com",
      emailVerified: true,
      displayName: "Manager",
      photoUrl: "https://example.com/mgr.png",
      isAnonymous: false,
      isAdmin: false,
      providerIds: []
    });

    const baseTime = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(baseTime);

    // If store.recordPresenceHeartbeat rejects once, lastSynced is rolled back so next sync retries
    const hbSpy = vi.spyOn(store, "recordPresenceHeartbeat");
    hbSpy.mockRejectedValueOnce(new Error("Write failed"));
    client.recordActivity("ws-1");
    await client.syncPresence({ scopeId: "ws-1" });
    expect(client.getPresenceStatus("ws-1").lastSynced).toBe(0);

    // Next attempt succeeds
    await client.syncPresence({ scopeId: "ws-1" });
    expect(client.getPresenceStatus("ws-1").lastSynced).toBe(baseTime);

    // Activity 1 minute later is throttled (not written to store yet)
    vi.spyOn(Date, "now").mockReturnValue(baseTime + 60_000);
    client.recordActivity("ws-1");
    await client.syncPresence({ scopeId: "ws-1" });
    expect((await store.getScopeMember("ws-1", "u-mgr"))?.lastSeen).toBe(new Date(baseTime).toISOString());

    // Unless isUnloading: true is passed
    await client.syncPresence({ scopeId: "ws-1", isUnloading: true });
    expect((await store.getScopeMember("ws-1", "u-mgr"))?.lastSeen).toBe(new Date(baseTime + 60_000).toISOString());

    // startPresenceHeartbeat starts interval and cleans up cleanly
    const stopHeartbeat = client.startPresenceHeartbeat({ scopeId: "ws-1" });
    stopHeartbeat();

    vi.restoreAllMocks();
  });

  it("tests FirestoreClientStore subscriptions, custom resolveRole, avatar sync, and presence heartbeats", async () => {
    const fakeDb: any = {};
    const store = new FirestoreClientStore<TestRole, TestCap, TestPrefs>({
      db: fakeDb,
      defaultRole: "member",
      resolveRole: (data) => (data.role as TestRole) || (data.isCreator ? "owner" : "manager")
    });

    // 1. subscribeToPreferences + savePreferences
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      onNext({ exists: () => true, data: () => ({ theme: "dark" }) });
      return () => {};
    });
    const prefObserved: Partial<TestPrefs>[] = [];
    store.subscribeToPreferences("u-1", (p) => prefObserved.push(p));
    expect(prefObserved).toEqual([{ theme: "dark" }]);

    await store.savePreferences("u-1", { use12h: false });
    expect(firebaseFirestore.setDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "user_preferences/u-1" }),
      { use12h: false },
      { merge: true }
    );

    // 2. subscribeToUserMemberships with legacy isCreator resolved via resolveRole
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_q: any, onNext: any) => {
      onNext({
        forEach(cb: any) {
          cb({
            id: "u-1",
            ref: { parent: { parent: { id: "ws-legacy" } } },
            data: () => ({
              uid: "u-1",
              email: "u1@example.com",
              isCreator: true,
              scopeName: "Legacy Workspace"
            })
          });
        }
      });
      return () => {};
    });
    const userMembers: any[] = [];
    store.subscribeToUserMemberships("u-1", (m) => userMembers.push(...m));
    expect(userMembers).toHaveLength(1);
    expect(userMembers[0].role).toBe("owner");
    expect(userMembers[0].scopeId).toBe("ws-legacy");
    expect(userMembers[0].scopeName).toBe("Legacy Workspace");

    // 3. subscribeToScopeMembers
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      onNext({
        forEach(cb: any) {
          cb({
            id: "u-2",
            data: () => ({
              uid: "u-2",
              email: "u2@example.com",
              role: "member",
              capabilities: ["invite_members"]
            })
          });
        }
      });
      return () => {};
    });
    const scopeMembers: any[] = [];
    store.subscribeToScopeMembers("ws-1", (m) => scopeMembers.push(...m));
    expect(scopeMembers).toHaveLength(1);
    expect(scopeMembers[0].capabilities).toEqual(["invite_members"]);

    // 4. syncAvatar uses updateDoc for scoped members and setDoc for system_admins
    await store.syncAvatar({ uid: "u-1", scopeId: "ws-1", photoUrl: "https://example.com/u1.png" });
    expect(firebaseFirestore.updateDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "workspaces/ws-1/members/u-1" }),
      { photoUrl: "https://example.com/u1.png" }
    );

    await store.syncAvatar({
      uid: "u-admin",
      email: "admin@example.com",
      displayName: "Admin",
      photoUrl: "https://example.com/admin.png"
    });
    expect(firebaseFirestore.setDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "system_admins/u-admin" }),
      {
        uid: "u-admin",
        email: "admin@example.com",
        displayName: "Admin",
        photoUrl: "https://example.com/admin.png"
      },
      { merge: true }
    );

    // 5. recordPresenceHeartbeat
    await store.recordPresenceHeartbeat({
      uid: "u-1",
      scopeId: "ws-1",
      lastSeenIso: "2026-10-19T12:00:00.000Z",
      photoUrl: "https://example.com/u1.png"
    });
    expect(firebaseFirestore.updateDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "workspaces/ws-1/members/u-1" }),
      { lastSeen: "2026-10-19T12:00:00.000Z", photoUrl: "https://example.com/u1.png" }
    );

    await store.recordPresenceHeartbeat({
      uid: "u-admin",
      lastSeenIso: "2026-10-19T12:00:00.000Z"
    });
    expect(firebaseFirestore.setDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "system_admins/u-admin" }),
      { lastSeen: "2026-10-19T12:00:00.000Z" },
      { merge: true }
    );

    // 6. FirestoreClientStore error callbacks degrade gracefully to empty arrays / no-ops
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, _onNext: any, onError: any) => {
      onError(new Error("permission-denied"));
      return () => {};
    });
    let prefErrorTriggered = false;
    store.subscribeToPreferences("u-err", () => {
      prefErrorTriggered = true;
    });
    expect(prefErrorTriggered).toBe(false);

    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_q: any, _onNext: any, onError: any) => {
      onError(new Error("permission-denied"));
      return () => {};
    });
    let fallbackUserMembers: any = null;
    store.subscribeToUserMemberships("u-err", (m) => {
      fallbackUserMembers = m;
    });
    expect(fallbackUserMembers).toEqual([]);

    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_col: any, _onNext: any, onError: any) => {
      onError(new Error("permission-denied"));
      return () => {};
    });
    let fallbackScopeMembers: any = null;
    store.subscribeToScopeMembers("ws-err", (m) => {
      fallbackScopeMembers = m;
    });
    expect(fallbackScopeMembers).toEqual([]);
  });

  it("skips syncAvatar when member photoUrl already matches and deduplicates repeated emissions until photoUrl changes", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.upsertScopeMember("ws-1", {
      uid: "u-1",
      email: "u1@example.com",
      role: "manager",
      capabilities: [],
      photoUrl: "https://example.com/already-synced.png"
    });

    const syncSpy = vi.spyOn(store, "syncAvatar");
    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "testapp"
    });

    // 1. Member already has the exact same photoUrl -> zero syncAvatar calls
    client.setActiveUser({
      uid: "u-1",
      email: "u1@example.com",
      emailVerified: true,
      displayName: "User One",
      photoUrl: "https://example.com/already-synced.png",
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).not.toHaveBeenCalled();

    // 2. User updates OAuth avatar -> syncs once
    client.setActiveUser({
      uid: "u-1",
      email: "u1@example.com",
      emailVerified: true,
      displayName: "User One",
      photoUrl: "https://example.com/new-avatar.png",
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(1);

    // 3. Subsequent membership emissions with the same photoUrl do not trigger duplicate syncAvatar calls
    await store.grantScopeCapabilities("ws-1", "u-1", ["edit_content"]);
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(1);
  });

  it("auto-completes magic email link and mode=verifyEmail action codes on client boot", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    const fakeAuth: any = { currentUser: null };

    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});

    // 1. Boot with mode=verifyEmail&oobCode=VERIFY_CODE_123
    vi.stubGlobal("window", {
      location: {
        href: "https://app.example.com/?mode=verifyEmail&oobCode=VERIFY_CODE_123",
        search: "?mode=verifyEmail&oobCode=VERIFY_CODE_123",
        origin: "https://app.example.com",
        pathname: "/",
        hash: ""
      },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn()
    });
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValueOnce(false);
    vi.mocked(firebaseAuth.applyActionCode).mockResolvedValueOnce(undefined);

    const clientVerify = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      defaultPreferences: DEFAULT_PREFS
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(firebaseAuth.applyActionCode).toHaveBeenCalledWith(fakeAuth, "VERIFY_CODE_123");
    clientVerify.destroy();

    // 2. Boot with magic email link (?mode=signIn&oobCode=MAGIC_123&email=boot%40example.com)
    vi.stubGlobal("window", {
      location: {
        href: "https://app.example.com/?mode=signIn&oobCode=MAGIC_123&email=boot%40example.com",
        search: "?mode=signIn&oobCode=MAGIC_123&email=boot%40example.com",
        origin: "https://app.example.com",
        pathname: "/",
        hash: ""
      },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn()
    });
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValue(true);
    vi.mocked(firebaseAuth.signInWithEmailLink).mockResolvedValueOnce({
      user: {
        uid: "u-boot-magic",
        email: "boot@example.com",
        emailVerified: true,
        providerData: [],
        getIdTokenResult: vi.fn().mockResolvedValue({ claims: {} })
      }
    } as any);

    const clientMagic = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      defaultPreferences: DEFAULT_PREFS
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(firebaseAuth.signInWithEmailLink).toHaveBeenCalledWith(
      fakeAuth,
      "boot@example.com",
      "https://app.example.com/?mode=signIn&oobCode=MAGIC_123&email=boot%40example.com"
    );
    expect(clientMagic.authStore.get().user?.uid).toBe("u-boot-magic");
    clientMagic.destroy();
    vi.unstubAllGlobals();
  });

  it("enforces presence edge cases: no-new-activity guard, multi-user/multi-scope isolation, real-time role changes, and window activity listeners", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.upsertScopeMember("ws-1", {
      uid: "u-alice",
      email: "alice@example.com",
      role: "manager",
      capabilities: []
    });
    await store.upsertScopeMember("ws-2", {
      uid: "u-alice",
      email: "alice@example.com",
      role: "member", // untracked role in ws-2
      capabilities: []
    });
    await store.upsertScopeMember("ws-1", {
      uid: "u-bob",
      email: "bob@example.com",
      role: "owner",
      capabilities: []
    });

    const hbSpy = vi.spyOn(store, "recordPresenceHeartbeat");
    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "testapp"
    });

    const t0 = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(t0);

    // 1. Alice signs in: manager in ws-1 (tracked), member in ws-2 (untracked)
    client.setActiveUser({
      uid: "u-alice",
      email: "alice@example.com",
      emailVerified: true,
      displayName: "Alice",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: []
    });

    client.recordActivity("ws-1");
    client.recordActivity("ws-2");
    await client.syncPresence({ scopeId: "ws-1" });
    await client.syncPresence({ scopeId: "ws-2" });

    expect(hbSpy).toHaveBeenCalledTimes(1);
    expect((await store.getScopeMember("ws-1", "u-alice"))?.lastSeen).toBe(new Date(t0).toISOString());
    expect((await store.getScopeMember("ws-2", "u-alice"))?.lastSeen).toBeUndefined();

    // 2. No-new-activity guard: 10 minutes pass, but Alice has NOT triggered recordActivity since t0
    vi.spyOn(Date, "now").mockReturnValue(t0 + 10 * 60_000);
    await client.syncPresence({ scopeId: "ws-1" });
    expect(hbSpy).toHaveBeenCalledTimes(1); // still 1!

    // 3. Real-time role demotion mid-session: Alice is demoted from 'manager' to 'member' in ws-1
    await store.upsertScopeMember("ws-1", {
      uid: "u-alice",
      email: "alice@example.com",
      role: "member",
      capabilities: [],
      lastSeen: new Date(t0).toISOString()
    });
    client.recordActivity("ws-1");
    await client.syncPresence({ scopeId: "ws-1", isUnloading: true });
    expect(hbSpy).toHaveBeenCalledTimes(1); // blocked immediately upon demotion!

    // Real-time role promotion: Alice is promoted in ws-2 from 'member' to 'manager'
    await store.upsertScopeMember("ws-2", {
      uid: "u-alice",
      email: "alice@example.com",
      role: "manager",
      capabilities: []
    });
    client.recordActivity("ws-2");
    await client.syncPresence({ scopeId: "ws-2" });
    expect(hbSpy).toHaveBeenCalledTimes(2);
    expect((await store.getScopeMember("ws-2", "u-alice"))?.lastSeen).toBe(new Date(t0 + 10 * 60_000).toISOString());

    // 4. Multi-user isolation on the same browser: Alice signs out, Bob signs in
    await client.signOut();
    client.setActiveUser({
      uid: "u-bob",
      email: "bob@example.com",
      emailVerified: true,
      displayName: "Bob",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: []
    });

    // Bob's status starts clean at 0 despite Alice's localStorage keys existing
    expect(client.getPresenceStatus("ws-1")).toEqual({ lastActive: 0, lastSynced: 0 });

    // 5. Window pointerdown/keydown activity listener triggers sync when HEARTBEAT_INTERVAL_MS elapses
    const listeners = new Map<string, () => void>();
    vi.stubGlobal("window", {
      addEventListener: vi.fn((evt: string, cb: () => void) => listeners.set(evt, cb)),
      removeEventListener: vi.fn((evt: string) => listeners.delete(evt))
    });

    const stopBobHeartbeat = client.startPresenceHeartbeat({ scopeId: "ws-1" });
    await new Promise((r) => setTimeout(r, 0));
    expect(hbSpy).toHaveBeenCalledTimes(3); // initial tick synced Bob at t0 + 10m

    // Advance past HEARTBEAT_INTERVAL_MS and fire pointerdown
    vi.spyOn(Date, "now").mockReturnValue(t0 + 10 * 60_000 + HEARTBEAT_INTERVAL_MS + 1000);
    listeners.get("pointerdown")?.();
    await new Promise((r) => setTimeout(r, 0));
    expect(hbSpy).toHaveBeenCalledTimes(4);
    expect((await store.getScopeMember("ws-1", "u-bob"))?.lastSeen).toBe(
      new Date(t0 + 10 * 60_000 + HEARTBEAT_INTERVAL_MS + 1000).toISOString()
    );

    stopBobHeartbeat();
    expect(listeners.size).toBe(0);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("cleans up previous user subscriptions on user switch or sign-out so stale updates never bleed across users", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.savePreferences("u-alice", { theme: "dark" });
    await store.savePreferences("u-bob", { theme: "light" });
    await store.upsertScopeMember("ws-1", {
      uid: "u-alice",
      email: "alice@example.com",
      role: "owner",
      capabilities: []
    });

    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "testapp"
    });

    client.setActiveUser({
      uid: "u-alice",
      email: "alice@example.com",
      emailVerified: true,
      displayName: "Alice",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: []
    });
    expect(client.preferencesStore.get().theme).toBe("dark");
    expect(client.membershipsStore.get().memberships).toHaveLength(1);

    // Switch directly to Bob
    client.setActiveUser({
      uid: "u-bob",
      email: "bob@example.com",
      emailVerified: true,
      displayName: "Bob",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: []
    });
    expect(client.preferencesStore.get().theme).toBe("light");
    expect(client.membershipsStore.get().memberships).toHaveLength(0);

    // Mutate Alice's preferences and memberships in the store -> must NOT affect Bob's active stores
    await store.savePreferences("u-alice", { use12h: false });
    await store.upsertScopeMember("ws-2", {
      uid: "u-alice",
      email: "alice@example.com",
      role: "manager",
      capabilities: []
    });
    expect(client.preferencesStore.get()).toEqual({ theme: "light", use12h: true });
    expect(client.membershipsStore.get().memberships).toHaveLength(0);
  });

  it("enforces client security guards: localStorage prototype pollution, redirectUrl validation, dev-auth SSRF prevention, and Firestore path traversal", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    const fakeAuth: any = { currentUser: { uid: "u-sec", email: "sec@example.com" } };
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});

    // 1. Poison localStorage with __proto__ and non-object JSON before client boot
    localStorage.setItem(
      "secapp_user_preferences",
      '{"__proto__":{"pollutedProp":"yes"},"constructor":{"bad":1},"theme":"dark"}'
    );
    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "secapp"
    });
    expect(client.preferencesStore.get()).toEqual({ theme: "dark", use12h: true });
    expect(({} as any).pollutedProp).toBeUndefined();

    // Array or primitive in localStorage falls back cleanly to defaultPreferences
    localStorage.setItem("secapp_user_preferences", "[1, 2, 3]");
    const clientArrayCache = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "secapp"
    });
    expect(clientArrayCache.preferencesStore.get()).toEqual(DEFAULT_PREFS);

    // 2. Reject unsafe redirectUrl protocols in sendPasswordlessEmailLink & sendEmailUpdateVerification
    await expect(client.sendPasswordlessEmailLink("sec@example.com", "javascript:alert(1)")).rejects.toThrow(
      /protocol must be http: or https:/
    );
    await expect(client.sendPasswordlessEmailLink("sec@example.com", "not-a-url")).rejects.toThrow(
      /valid absolute http\(s\) URL/
    );
    await expect(client.sendEmailUpdateVerification("new@example.com", "javascript:alert(1)")).rejects.toThrow(
      /protocol must be http: or https:/
    );

    // 3. Reject external or protocol-relative endpoints and invalid emails in handleDevModeLogin
    await expect(
      client.handleDevModeLogin(new URLSearchParams("loginAs=dev@test.com"), "https://evil.example.com/steal")
    ).rejects.toThrow(/relative path/);
    await expect(
      client.handleDevModeLogin(new URLSearchParams("loginAs=dev@test.com"), "//evil.example.com/steal")
    ).rejects.toThrow(/relative path/);
    await expect(
      client.handleDevModeLogin(new URLSearchParams("loginAs=not-an-email"), "/api/dev/auth/token")
    ).rejects.toThrow(/Invalid loginAs email/);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce({ ok: true, json: async () => ({ token: "" }) }));
    await expect(
      client.handleDevModeLogin(new URLSearchParams("loginAs=dev@test.com"), "/api/dev/auth/token")
    ).rejects.toThrow(/missing valid token/);
    vi.unstubAllGlobals();

    // 4. FirestoreClientStore rejects path traversal and reserved __.*__ document IDs
    const fsStore = new FirestoreClientStore<TestRole, TestCap, TestPrefs>({
      db: {} as any,
      defaultRole: "member"
    });
    expect(() => fsStore.subscribeToScopeMembers("ws-1/../../system_admins", () => {})).toThrow(/Invalid scopeId/);
    expect(() => fsStore.subscribeToScopeMembers("__reserved__", () => {})).toThrow(/reserved Firestore document ID/);
    await expect(
      fsStore.syncAvatar({ uid: "u-1/../admin", scopeId: "ws-1", photoUrl: "https://example.com/a.png" })
    ).rejects.toThrow(/Invalid uid/);
    await expect(
      fsStore.recordPresenceHeartbeat({
        uid: "u-1",
        scopeId: "..",
        lastSeenIso: "2026-10-19T12:00:00.000Z"
      })
    ).rejects.toThrow(/Invalid scopeId/);

    // 5. In-flight onAuthStateChanged getIdTokenResult() does not resurrect a user if signOut() runs first
    let authStateCb: ((user: any) => Promise<void>) | null = null;
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementationOnce((_a: any, cb: any) => {
      authStateCb = cb;
      return () => {};
    });
    const raceClient = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      defaultPreferences: DEFAULT_PREFS
    });
    let resolveTokenResult!: (val: any) => void;
    const slowUser = {
      uid: "u-slow",
      email: "slow@example.com",
      emailVerified: true,
      providerData: [],
      getIdTokenResult: () =>
        new Promise((r) => {
          resolveTokenResult = r;
        })
    };
    const pendingAuthPromise = authStateCb!(slowUser);
    await raceClient.signOut();
    resolveTokenResult({ claims: { admin: true } });
    await pendingAuthPromise;
    expect(raceClient.authStore.get().user).toBeNull();
    raceClient.destroy();

    client.destroy();
    clientArrayCache.destroy();
  });
});

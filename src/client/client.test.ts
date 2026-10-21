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

    // 4. Link / Unlink Social Provider, getSignInMethodsForEmail, sendEmailUpdateVerification
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

    // 1. subscribeToPreferences + savePreferences on unified users/{uid}
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      onNext({ exists: () => true, data: () => ({ preferences: { theme: "dark" } }) });
      return () => {};
    });
    const prefObserved: Partial<TestPrefs>[] = [];
    const unsubPref1 = store.subscribeToPreferences("u-1", (p) => prefObserved.push(p));
    expect(prefObserved).toEqual([{ theme: "dark" }]);
    unsubPref1();

    await store.savePreferences("u-1", { use12h: false });
    expect(firebaseFirestore.setDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "users/u-1" }),
      expect.objectContaining({
        uid: "u-1",
        preferences: { use12h: false },
        updatedAt: expect.any(String)
      }),
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

    // 4. syncAvatar uses updateDoc for scoped members and setDoc for users/{uid}
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
      expect.objectContaining({ path: "users/u-admin" }),
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
      expect.objectContaining({ path: "users/u-admin" }),
      { lastSeen: "2026-10-19T12:00:00.000Z" },
      { merge: true }
    );

    // 6. FirestoreClientStore error callbacks degrade gracefully to empty arrays / no-ops
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, _onNext: any, onError: any) => {
      onError(new Error("permission-denied"));
      return () => {};
    });
    let prefErrorTriggered = false;
    const unsubErr = store.subscribeToPreferences("u-err", () => {
      prefErrorTriggered = true;
    });
    expect(prefErrorTriggered).toBe(false);
    unsubErr();

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

    // 3. FirestoreClientStore rejects path traversal and reserved __.*__ document IDs
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

  it("recovers from transient syncAvatar & recordPresenceHeartbeat errors, handles auth/policy fallbacks, and exercises FirestoreClientStore error callbacks", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.upsertScopeMember("ws-1", {
      uid: "u-retry",
      email: "retry@example.com",
      role: "manager",
      capabilities: [],
      photoUrl: null
    });

    // 1. Avatar sync failure clears syncedAvatars cache so next trigger retries both admin & scoped member sync
    const syncSpy = vi
      .spyOn(store, "syncAvatar")
      .mockRejectedValueOnce(new Error("Transient network failure"))
      .mockRejectedValueOnce(new Error("Transient member sync failure"));

    // Create client WITHOUT a policy to also exercise the policy-less shouldTrackPresence fallback
    const clientNoPolicy = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "retryapp"
    });

    clientNoPolicy.setActiveUser({
      uid: "u-retry",
      email: "retry@example.com",
      emailVerified: true,
      displayName: "Retry User",
      photoUrl: "https://example.com/retry.png",
      isAnonymous: false,
      isAdmin: true,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(2); // 1 admin attempt + 1 member attempt (both rejected)

    // Re-trigger setActiveUser: because .catch() deleted the keys from syncedAvatars, both retry and succeed!
    clientNoPolicy.setActiveUser({
      uid: "u-retry",
      email: "retry@example.com",
      emailVerified: true,
      displayName: "Retry User",
      photoUrl: "https://example.com/retry.png",
      isAnonymous: false,
      isAdmin: true,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(4);
    expect((await store.getSystemAdmin("u-retry"))?.photoUrl).toBe("https://example.com/retry.png");
    expect((await store.getScopeMember("ws-1", "u-retry"))?.photoUrl).toBe("https://example.com/retry.png");

    // 2. Presence heartbeat failure rolls back lastSynced in localStorage so the next sync retries immediately
    const t0 = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(t0);
    // Switch to non-admin to also verify policy-less shouldTrackPresence(scopeId) fallback
    clientNoPolicy.setActiveUser({
      uid: "u-retry",
      email: "retry@example.com",
      emailVerified: true,
      displayName: "Retry User",
      photoUrl: "https://example.com/retry.png",
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });

    // Without a policy, non-admin without scopeId or in non-member scopeId does not track presence
    clientNoPolicy.recordActivity();
    await clientNoPolicy.syncPresence();
    clientNoPolicy.recordActivity("ws-not-member");
    await clientNoPolicy.syncPresence({ scopeId: "ws-not-member" });
    expect(clientNoPolicy.getPresenceStatus("ws-1").lastSynced).toBe(0);

    // Reject first heartbeat write -> lastSynced rolls back to 0 so immediate retry succeeds!
    const hbSpy = vi.spyOn(store, "recordPresenceHeartbeat").mockRejectedValueOnce(new Error("Offline"));
    clientNoPolicy.recordActivity("ws-1");
    await clientNoPolicy.syncPresence({ scopeId: "ws-1" });
    expect(hbSpy).toHaveBeenCalledTimes(1);
    expect(clientNoPolicy.getPresenceStatus("ws-1").lastSynced).toBe(0); // rolled back!

    await clientNoPolicy.syncPresence({ scopeId: "ws-1" });
    expect(hbSpy).toHaveBeenCalledTimes(2);
    expect(clientNoPolicy.getPresenceStatus("ws-1").lastSynced).toBe(t0);

    // 3. Uninitialized auth guards & fallbacks
    await expect(clientNoPolicy.loginWithSocialProvider("google")).rejects.toThrow(/not initialized/);
    await expect(clientNoPolicy.loginAnonymously()).rejects.toThrow(/not initialized/);
    await expect(clientNoPolicy.sendPasswordlessEmailLink("a@b.com")).rejects.toThrow(/not initialized/);
    await expect(clientNoPolicy.completePasswordlessSignIn("a@b.com")).rejects.toThrow(/not initialized/);
    await expect(clientNoPolicy.linkSocialProvider("google")).rejects.toThrow(/No authenticated user/);
    await expect(clientNoPolicy.unlinkSocialProvider("google.com")).rejects.toThrow(/No authenticated user/);
    await expect(clientNoPolicy.sendEmailUpdateVerification("a@b.com")).rejects.toThrow(/No authenticated user/);
    expect(await clientNoPolicy.getSignInMethodsForEmail("a@b.com")).toEqual([]);

    // Auth with localStorage email fallback on completePasswordlessSignIn, failed fetchSignInMethodsForEmail, and failed dev login fetch
    const fakeAuth: any = { currentUser: null };
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});
    const clientWithAuth = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "retryapp"
    });

    // completePasswordlessSignIn when link is not a sign-in link or when no email is found anywhere -> null
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValueOnce(false);
    expect(await clientWithAuth.completePasswordlessSignIn(undefined, "https://app.example.com/")).toBeNull();

    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValue(true);
    localStorage.removeItem("retryapp_emailForSignIn");
    expect(
      await clientWithAuth.completePasswordlessSignIn(undefined, "https://app.example.com/?oobCode=123")
    ).toBeNull();

    // Stored email in localStorage is used when URL lacks ?email=
    localStorage.setItem("retryapp_emailForSignIn", "stored@example.com");
    vi.mocked(firebaseAuth.signInWithEmailLink).mockResolvedValueOnce({
      user: {
        uid: "u-stored",
        email: "stored@example.com",
        emailVerified: true,
        providerData: [],
        getIdTokenResult: vi.fn().mockResolvedValue({ claims: {} })
      }
    } as any);
    const completedStored = await clientWithAuth.completePasswordlessSignIn(
      undefined,
      "https://app.example.com/?oobCode=123"
    );
    expect(completedStored?.email).toBe("stored@example.com");
    expect(localStorage.getItem("retryapp_emailForSignIn")).toBeNull();

    // getSignInMethodsForEmail catches errors and returns []
    vi.mocked(firebaseAuth.fetchSignInMethodsForEmail).mockRejectedValueOnce(new Error("Network error"));
    expect(await clientWithAuth.getSignInMethodsForEmail("stored@example.com")).toEqual([]);

    // 4. FirestoreClientStore error callbacks, custom collection names, custom resolveRole, and unsafe photoUrl ignore
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementation((_ref: any, _onNext: any, onError?: any) => {
      if (onError) onError(new Error("permission-denied"));
      return () => {};
    });

    const fsStore = new FirestoreClientStore<TestRole, TestCap, TestPrefs>({
      db: { type: "custom-fs" } as any,
      defaultRole: "member",
      resolveRole: (d) => (d.isOwner ? "owner" : "member"),
      usersCollection: "custom_users",
      scopeCollection: "custom_scopes",
      membersSubcollection: "custom_members"
    });

    const prefErrCb = vi.fn();
    const userMemErrCb = vi.fn();
    const scopeMemErrCb = vi.fn();
    const unsubPrefErr = fsStore.subscribeToPreferences("u-1", prefErrCb);
    fsStore.subscribeToUserMemberships("u-1", userMemErrCb);
    fsStore.subscribeToScopeMembers("ws-1", scopeMemErrCb);

    expect(prefErrCb).not.toHaveBeenCalled();
    expect(userMemErrCb).toHaveBeenCalledWith([]);
    expect(scopeMemErrCb).toHaveBeenCalledWith([]);
    unsubPrefErr();

    // syncAvatar with unsafe URL is ignored without calling updateDoc or setDoc
    vi.mocked(firebaseFirestore.updateDoc).mockClear();
    vi.mocked(firebaseFirestore.setDoc).mockClear();
    await fsStore.syncAvatar({ uid: "u-1", scopeId: "ws-1", photoUrl: "javascript:alert(1)" });
    expect(firebaseFirestore.updateDoc).not.toHaveBeenCalled();
    expect(firebaseFirestore.setDoc).not.toHaveBeenCalled();

    clientNoPolicy.destroy();
    clientWithAuth.destroy();
    vi.restoreAllMocks();
  });

  it("multiplexes FirestoreClientStore users/{uid} listeners (1 onSnapshot per UID), strips unauthorized fields on updateUserProfile, and supports legacy top-level preferences", async () => {
    const fakeDb: any = {};
    const fsStore = new FirestoreClientStore<TestRole, TestCap, TestPrefs, { pointsAllTime: number }>({
      db: fakeDb,
      defaultRole: "member"
    });

    let emitSnapshot!: (snap: any) => void;
    const underlyingUnsub = vi.fn();
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      emitSnapshot = onNext;
      return underlyingUnsub;
    });

    const userEvents: any[] = [];
    const prefEvents: any[] = [];
    const latePrefEvents: any[] = [];

    // 1. Subscribing to BOTH subscribeToUser and subscribeToPreferences on 'u-mux' opens ONLY 1 Firestore listener!
    const unsubUser = fsStore.subscribeToUser("u-mux", (u) => userEvents.push(u));
    const unsubPref = fsStore.subscribeToPreferences("u-mux", (p) => prefEvents.push(p));
    expect(firebaseFirestore.onSnapshot).toHaveBeenCalledTimes(1);

    emitSnapshot({
      exists: () => true,
      data: () => ({
        uid: "u-mux",
        email: "mux@example.com",
        firstName: "Testy",
        lastName: "McTest",
        isSystemAdmin: false,
        role: "manager",
        preferences: { theme: "dark", use12h: false },
        attributes: { pointsAllTime: 420 }
      })
    });

    expect(userEvents).toHaveLength(1);
    expect(userEvents[0]).toMatchObject({
      uid: "u-mux",
      role: "manager",
      preferences: { theme: "dark", use12h: false },
      attributes: { pointsAllTime: 420 }
    });
    expect(prefEvents).toEqual([{ theme: "dark", use12h: false }]);

    // 2. Late subscriber immediately receives the latest cached snapshot without triggering a 2nd Firestore read!
    const unsubLatePref = fsStore.subscribeToPreferences("u-mux", (p) => latePrefEvents.push(p));
    expect(firebaseFirestore.onSnapshot).toHaveBeenCalledTimes(1);
    expect(latePrefEvents).toEqual([{ theme: "dark", use12h: false }]);

    // Non-existent doc snapshot emits null to userCallbacks
    emitSnapshot({ exists: () => false, data: () => undefined });
    expect(userEvents[userEvents.length - 1]).toBeNull();

    // 3. Ref-counted cleanup: underlying Firestore listener stays active until ALL 3 subscribers detach
    unsubUser();
    unsubPref();
    expect(underlyingUnsub).not.toHaveBeenCalled();
    unsubLatePref();
    expect(underlyingUnsub).toHaveBeenCalledTimes(1);

    // 4. Legacy top-level preferences fallback on users/{uid}
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      onNext({
        exists: () => true,
        data: () => ({
          uid: "u-legacy",
          email: "legacy@example.com",
          theme: "light",
          use12h: false
        })
      });
      return () => {};
    });
    const legacyPrefs: any[] = [];
    const unsubLegacy = fsStore.subscribeToPreferences("u-legacy", (p) => legacyPrefs.push(p));
    expect(legacyPrefs).toEqual([{ theme: "light", use12h: false }]);
    unsubLegacy();

    // 5. updateUserProfile strictly whitelists Tier-1 fields and strips malicious privilege escalation fields
    vi.mocked(firebaseFirestore.setDoc).mockClear();
    await fsStore.updateUserProfile("u-mux", {
      firstName: "  Testy  ",
      lastName: " McTest ",
      displayName: " Testy McTest ",
      photoUrl: "https://example.com/safe.png",
      // Malicious extra properties injected at runtime via `as any`
      isSystemAdmin: true,
      role: "owner",
      attributes: { pointsAllTime: 999999 }
    } as any);

    expect(firebaseFirestore.setDoc).toHaveBeenCalledTimes(1);
    const writtenPayload = vi.mocked(firebaseFirestore.setDoc).mock.calls[0][1] as Record<string, any>;
    expect(writtenPayload).toEqual({
      uid: "u-mux",
      firstName: "Testy",
      lastName: "McTest",
      displayName: "Testy McTest",
      photoUrl: "https://example.com/safe.png",
      updatedAt: expect.any(String)
    });
    expect(writtenPayload.isSystemAdmin).toBeUndefined();
    expect(writtenPayload.role).toBeUndefined();
    expect(writtenPayload.attributes).toBeUndefined();
  });

  it("wires userRecordStore, attributesStore, updateProfile, real-time isSystemAdmin sync, and single-tenant role presence tracking", async () => {
    interface CheckinAttrs {
      pointsAllTime: number;
      awardedBadges: string[];
    }
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs, CheckinAttrs>();
    await store.upsertUser({
      uid: "u-single",
      email: "single@example.com",
      firstName: "Testy",
      lastName: "McTest",
      role: "manager", // 'manager' has trackPresence: true in TEST_POLICY
      isSystemAdmin: false,
      preferences: { theme: "dark", use12h: false },
      attributes: { pointsAllTime: 120, awardedBadges: ["first-checkin"] }
    });

    const getIdTokenResultSpy = vi.fn().mockResolvedValue({ claims: { admin: true } });
    const fakeAuth: any = {
      currentUser: {
        uid: "u-single",
        email: "single@example.com",
        getIdTokenResult: getIdTokenResultSpy
      }
    };
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});

    const client = createLanyardClient<TestRole, TestCap, TestPrefs, CheckinAttrs>({
      auth: fakeAuth,
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "singleapp"
    });

    // Calling updateProfile before sign-in throws
    await expect(client.updateProfile({ firstName: "Anon" })).rejects.toThrow(/No authenticated user/);

    client.setActiveUser({
      uid: "u-single",
      email: "single@example.com",
      emailVerified: true,
      displayName: "Testy McTest",
      photoUrl: "https://example.com/oauth-single.png",
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));

    // 1. Single subscription populates preferencesStore, attributesStore, and userRecordStore, and syncs OAuth avatar to users/{uid}
    expect(client.preferencesStore.get()).toEqual({ theme: "dark", use12h: false });
    expect(client.attributesStore.get()).toEqual({ pointsAllTime: 120, awardedBadges: ["first-checkin"] });
    expect(client.userRecordStore.get()?.photoUrl).toBe("https://example.com/oauth-single.png");

    // 2. Self-service updateProfile updates firstName/lastName on users/{uid}
    await client.updateProfile({ firstName: "Formy", lastName: "McFormerson" });
    expect(client.userRecordStore.get()?.firstName).toBe("Formy");
    expect(client.userRecordStore.get()?.lastName).toBe("McFormerson");

    // 3. Server updates attributes -> client attributesStore updates reactively
    await store.updateUserAttributes("u-single", { pointsAllTime: 170 });
    expect(client.attributesStore.get().pointsAllTime).toBe(170);

    // 4. Real-time system admin promotion & demotion in users/{uid} updates authStore.user.isAdmin and refreshes ID token
    await store.upsertSystemAdmin({
      uid: "u-single",
      email: "single@example.com",
      isSystemAdmin: true
    });
    expect(client.authStore.get().user?.isAdmin).toBe(true);
    expect(getIdTokenResultSpy).toHaveBeenCalledWith(true);

    await store.deleteSystemAdmin("u-single");
    expect(client.authStore.get().user?.isAdmin).toBe(false);
    // Attributes and preferences remain intact after admin demotion!
    expect(client.attributesStore.get().pointsAllTime).toBe(170);

    // 5. Single-tenant presence tracking without scopeId: 'manager' role on users/{uid} has trackPresence: true
    const t0 = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(t0);
    client.recordActivity();
    await client.syncPresence();
    expect((await store.getUser("u-single"))?.lastSeen).toBe(new Date(t0).toISOString());

    client.destroy();
    vi.restoreAllMocks();
  });

  it("supports unified custom role, capability, preference, and attribute accessors and updates across both unscoped and scoped modes", async () => {
    interface CustomAttrs {
      points: number;
      tier: string;
    }

    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs, CustomAttrs>();

    // Global unscoped record: role = 'member' with ad-hoc ['edit_content'], preferences = { theme: 'dark' }, attributes = { points: 42, tier: 'silver' }
    await store.upsertUser({
      uid: "u-dual",
      email: "dual@example.com",
      role: "member",
      capabilities: ["edit_content"],
      preferences: { theme: "dark" },
      attributes: { points: 42, tier: "silver" }
    });

    // Scoped record in 'ws-alpha': role = 'manager', preferences = { use12h: false }, attributes = { points: 100, tier: 'gold' }
    await store.upsertScopeMember("ws-alpha", {
      uid: "u-dual",
      email: "dual@example.com",
      role: "manager",
      capabilities: [],
      preferences: { use12h: false },
      attributes: { points: 100, tier: "gold" }
    });

    // Scoped record in 'ws-beta': role = 'owner', attributes = { points: 999, tier: 'platinum' }
    await store.upsertScopeMember("ws-beta", {
      uid: "u-dual",
      email: "dual@example.com",
      role: "owner",
      capabilities: [],
      attributes: { points: 999, tier: "platinum" }
    });

    const client = createLanyardClient<TestRole, TestCap, TestPrefs, CustomAttrs>({
      store,
      policy: TEST_POLICY,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "dualapp"
    });

    // Before sign-in, all role/capability checks return false/null/empty
    expect(client.getRole()).toBeNull();
    expect(client.getRole("ws-alpha")).toBeNull();
    expect(client.hasRole("member")).toBe(false);
    expect(client.hasCapability("edit_content")).toBe(false);
    expect(client.getCapabilities()).toEqual([]);

    client.setActiveUser({
      uid: "u-dual",
      email: "dual@example.com",
      emailVerified: true,
      displayName: "Dualy McDual",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });

    // 1. Unscoped (single-tenant) role, capability, preference, and attribute checks:
    expect(client.getRole()).toBe("member");
    expect(client.hasRole("member")).toBe(true);
    expect(client.hasMinimumRole("manager")).toBe(false);
    expect(client.hasCapability("edit_content")).toBe(true);
    expect(client.hasCapability("invite_members")).toBe(false);
    expect(client.hasAnyCapability(["invite_members", "edit_content"])).toBe(true);
    expect(client.hasAllCapabilities(["edit_content"])).toBe(true);
    expect(client.hasAllCapabilities(["edit_content", "invite_members"])).toBe(false);
    expect(client.getCapabilities()).toEqual(["edit_content"]);
    expect(client.getAttributes()).toEqual({ points: 42, tier: "silver" });
    expect(client.getPreferences()).toEqual({ theme: "dark", use12h: true });

    // 2. Scoped ('ws-alpha' and 'ws-beta') role, capability, preference, and attribute checks:
    expect(client.getRole("ws-alpha")).toBe("manager");
    expect(client.hasRole("manager", "ws-alpha")).toBe(true);
    expect(client.hasRole("owner", "ws-alpha")).toBe(false);
    expect(client.hasCapability("invite_members", "ws-alpha")).toBe(true);
    expect(client.hasCapability("edit_content", "ws-alpha")).toBe(true);
    expect(client.getCapabilities("ws-alpha").sort()).toEqual(["edit_content", "invite_members"]);
    expect(client.getAttributes("ws-alpha")).toEqual({ points: 100, tier: "gold" });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "system", use12h: false });

    expect(client.getRole("ws-beta")).toBe("owner");
    expect(client.hasRole("owner", "ws-beta")).toBe(true);
    expect(client.hasCapability("invite_members", "ws-beta")).toBe(true);
    expect(client.getAttributes("ws-beta")).toEqual({ points: 999, tier: "platinum" });

    // Unknown or invalid scopeId returns safe defaults
    expect(client.getRole("ws-unknown")).toBeNull();
    expect(client.getRole("../invalid")).toBeNull();
    expect(client.getAttributes("ws-unknown")).toEqual({});
    expect(client.getPreferences("ws-unknown")).toEqual(DEFAULT_PREFS);

    // 3. Updating scoped preferences via both `updateScopePreferences` and `updatePreferences(patch, { scopeId })`:
    await client.updateScopePreferences("ws-alpha", { theme: "dark" });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "dark", use12h: false });
    expect((await store.getScopeMember("ws-alpha", "u-dual"))?.preferences).toEqual({
      theme: "dark",
      use12h: false
    });

    await client.updatePreferences({ use12h: true }, { scopeId: "ws-alpha" });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "dark", use12h: true });

    // Global preferences remain independent of scoped preferences
    expect(client.getPreferences()).toEqual({ theme: "dark", use12h: true });
    await client.updatePreferences({ theme: "light" });
    expect(client.getPreferences()).toEqual({ theme: "light", use12h: true });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "dark", use12h: true });

    // Calling updateScopePreferences on a non-member scope throws and never creates a phantom member
    await expect(client.updateScopePreferences("ws-nonmember", { theme: "dark" })).rejects.toThrow(
      /does not exist in scope/
    );
    expect(await store.getScopeMember("ws-nonmember", "u-dual")).toBeNull();

    // 4. Client-side 4-tier property permission checks (canReadAttribute, canWriteAttribute, canReadHiddenAttribute, canWriteHiddenAttribute, canWriteSecret):
    const fourTierPolicy = createPermissionPolicy<TestRole, TestCap>({
      roles: {
        owner: { weight: 30, inherits: ["manager"], capabilities: "*" },
        manager: { weight: 20, inherits: ["member"], capabilities: ["edit_content", "invite_members"] },
        member: { weight: 10, capabilities: [] }
      },
      attributeCapabilities: {
        points: "edit_content",
        tier: { read: "invite_members", write: "invite_members" }
      },
      hiddenAttributeCapabilities: {
        moderatorNotes: { read: "invite_members", write: "edit_content" }
      },
      secretCapabilities: {
        personalGeminiKey: { allowSelfWrite: true },
        workspaceOpenaiKey: { write: "invite_members", allowSelfWrite: false }
      }
    });

    const clientFourTier = createLanyardClient<TestRole, TestCap, TestPrefs, CustomAttrs>({
      store,
      policy: fourTierPolicy,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "fourtierapp"
    });

    // Before sign-in, all permission checks return false
    expect(clientFourTier.canReadAttribute("points")).toBe(false);
    expect(clientFourTier.canWriteAttribute("points")).toBe(false);
    expect(clientFourTier.canReadHiddenAttribute("moderatorNotes")).toBe(false);
    expect(clientFourTier.canWriteHiddenAttribute("moderatorNotes")).toBe(false);
    expect(clientFourTier.canWriteSecret("personalGeminiKey")).toBe(false);

    clientFourTier.setActiveUser({
      uid: "u-dual",
      email: "dual@example.com",
      emailVerified: true,
      displayName: "Dualy McDual",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });

    // Unscoped ('u-dual' is 'member' with ad-hoc ['edit_content']):
    // - Attributes: self can read own 'tier' (isSelf defaults to true), cannot read another user's 'tier' ({ isSelf: false }), can write 'points' (has 'edit_content'), cannot write 'tier' (lacks 'invite_members')
    expect(clientFourTier.canReadAttribute("tier")).toBe(true);
    expect(clientFourTier.canReadAttribute("tier", { isSelf: false })).toBe(false);
    expect(clientFourTier.canWriteAttribute("points")).toBe(true);
    expect(clientFourTier.canWriteAttribute("tier")).toBe(false);
    // - HiddenAttributes: lacks 'invite_members' so cannot read 'moderatorNotes', but has 'edit_content' so CAN write 'moderatorNotes'
    expect(clientFourTier.canReadHiddenAttribute("moderatorNotes")).toBe(false);
    expect(clientFourTier.canWriteHiddenAttribute("moderatorNotes")).toBe(true);
    // - Secrets: can write own 'personalGeminiKey' (allowSelfWrite: true), cannot write 'workspaceOpenaiKey' (allowSelfWrite: false, lacks 'invite_members')
    expect(clientFourTier.canWriteSecret("personalGeminiKey")).toBe(true);
    expect(clientFourTier.canWriteSecret("workspaceOpenaiKey")).toBe(false);

    // Scoped in 'ws-alpha' ('u-dual' is 'manager' -> has 'edit_content' + 'invite_members'):
    expect(clientFourTier.canReadAttribute("tier", { scopeId: "ws-alpha", isSelf: false })).toBe(true);
    expect(clientFourTier.canWriteAttribute("tier", "ws-alpha")).toBe(true);
    expect(clientFourTier.canReadHiddenAttribute("moderatorNotes", "ws-alpha")).toBe(true);
    expect(clientFourTier.canWriteHiddenAttribute("moderatorNotes", "ws-alpha")).toBe(true);
    expect(clientFourTier.canWriteSecret("workspaceOpenaiKey", { scopeId: "ws-alpha", isSelf: false })).toBe(true);

    // Scoped in 'ws-beta' ('u-dual' is 'owner' -> capabilities: '*'):
    expect(clientFourTier.canWriteAttribute("tier", "ws-beta")).toBe(true);
    expect(clientFourTier.canWriteSecret("workspaceOpenaiKey", { scopeId: "ws-beta", isSelf: false })).toBe(true);

    // Non-member scope ('ws-unknown') or invalid scopeId ('../bad') returns false
    expect(clientFourTier.canReadAttribute("points", "ws-unknown")).toBe(false);
    expect(clientFourTier.canWriteSecret("personalGeminiKey", "ws-unknown")).toBe(false);
    expect(clientFourTier.canWriteSecret("personalGeminiKey", "../bad")).toBe(false);

    // Policy-less client fallback behavior (when policy is omitted from createLanyardClient):
    const clientNoPolicy = createLanyardClient<TestRole, TestCap, TestPrefs, CustomAttrs>({
      store,
      defaultPreferences: DEFAULT_PREFS
    });

    // While signed out, all permission checks return false
    expect(clientNoPolicy.canReadAttribute("points")).toBe(false);
    expect(clientNoPolicy.canWriteAttribute("points")).toBe(false);
    expect(clientNoPolicy.canReadHiddenAttribute("staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteHiddenAttribute("staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteSecret("personalGeminiKey")).toBe(false);

    // Non-admin user without a policy: can read own attributes and write own secrets (isSelf: true),
    // but cannot read others' attributes, write attributes/hiddenAttributes, or write non-self secrets
    clientNoPolicy.setActiveUser({
      uid: "u-dual",
      email: "dual@example.com",
      emailVerified: true,
      displayName: "Dual User",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: false,
      providerIds: ["google.com"]
    });
    expect(clientNoPolicy.canReadAttribute("points")).toBe(true);
    expect(clientNoPolicy.canReadAttribute("points", { isSelf: false })).toBe(false);
    expect(clientNoPolicy.canReadAttribute("points", "ws-alpha")).toBe(true);
    expect(clientNoPolicy.canReadAttribute("points", "ws-unknown")).toBe(false);
    expect(clientNoPolicy.canWriteAttribute("points")).toBe(false);
    expect(clientNoPolicy.canReadHiddenAttribute("staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteHiddenAttribute("staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteSecret("personalGeminiKey")).toBe(true);
    expect(clientNoPolicy.canWriteSecret("personalGeminiKey", { isSelf: false })).toBe(false);
    expect(clientNoPolicy.canWriteSecret("personalGeminiKey", "ws-alpha")).toBe(true);
    expect(clientNoPolicy.canWriteSecret("personalGeminiKey", "ws-unknown")).toBe(false);

    // System admin without a policy: allowed for all attribute/hiddenAttribute/secret operations
    clientNoPolicy.setActiveUser({
      uid: "u-admin",
      email: "admin@example.com",
      emailVerified: true,
      displayName: "Admin User",
      photoUrl: null,
      isAnonymous: false,
      isAdmin: true,
      providerIds: ["google.com"]
    });
    expect(clientNoPolicy.canReadAttribute("points", { isSelf: false })).toBe(true);
    expect(clientNoPolicy.canWriteAttribute("points")).toBe(true);
    expect(clientNoPolicy.canReadHiddenAttribute("staffNotes")).toBe(true);
    expect(clientNoPolicy.canWriteHiddenAttribute("staffNotes")).toBe(true);
    expect(clientNoPolicy.canWriteSecret("workspaceOpenaiKey", { scopeId: "ws-unknown", isSelf: false })).toBe(true);

    clientNoPolicy.destroy();
    clientFourTier.destroy();
    client.destroy();
  });
});

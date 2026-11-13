import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as firebaseAuth from "firebase/auth";
import * as firebaseFirestore from "firebase/firestore";
import {
  createPermissionPolicy,
  EmailLinkInvalidError,
  EmailLinkMismatchError,
  GLOBAL_SCOPE,
  InMemoryLanyardStore
} from "../core/index.js";
import {
  createLanyardClient,
  formatExistingAccountError,
  getSocialProvider,
  HEARTBEAT_INTERVAL_MS,
  normalizeFirebaseUser
} from "./index.js";
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
    signInWithCustomToken: vi.fn(),
    signOut: vi.fn(),
    onAuthStateChanged: vi.fn(),
    sendSignInLinkToEmail: vi.fn(),
    isSignInWithEmailLink: vi.fn(),
    signInWithEmailLink: vi.fn(),
    verifyBeforeUpdateEmail: vi.fn(),
    sendEmailVerification: vi.fn(),
    applyActionCode: vi.fn(),
    fetchSignInMethodsForEmail: vi.fn(),
    updateProfile: vi.fn()
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

const TEST_CAPS = ["edit_content", "invite_members", "delete_workspace"] as const;
type TestRole = "owner" | "manager" | "member";
type TestCap = (typeof TEST_CAPS)[number];

interface TestPrefs {
  theme: "light" | "dark" | "system";
  use12h: boolean;
}

const DEFAULT_PREFS: TestPrefs = {
  theme: "system",
  use12h: true
};

const TEST_POLICY = createPermissionPolicy<TestRole, TestCap>({
  capabilities: TEST_CAPS,
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
  get length(): number {
    return this.map.size;
  }
  key(i: number): string | null {
    return [...this.map.keys()][i] ?? null;
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
      roles: ["member"],
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
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(1);
    expect((await store.getScopeMember("ws-1", "u-1"))?.photoUrl).toBeNull();

    // Trigger membership emission again -> retries and succeeds!
    await store.grantScopeRoles("ws-1", "u-1", ["manager"]);
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(2);
    expect((await store.getScopeMember("ws-1", "u-1"))?.photoUrl).toBe("https://example.com/u1-oauth.png");

    // Admin-only user signing in syncs their avatar to their users/{uid} card (not ws-1), without creating an admin
    // directory entry: only setSystemAdminStatus writes those
    client.setActiveUser({
      uid: "u-admin",
      email: "admin@example.com",
      emailVerified: true,
      displayName: "Root Admin",
      photoUrl: "https://example.com/admin.png",
      isAdmin: true,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect((await store.getUser("u-admin"))?.photoUrl).toBe("https://example.com/admin.png");
    expect(await store.getSystemAdmin("u-admin")).toBeNull();
    expect(await store.getScopeMember("ws-1", "u-admin")).toBeNull();

    // Update preferences with syncToStore = false and syncToStore = true
    // (u-1's dark theme doesn't carry over to u-admin, who has no saved preferences)
    await client.updatePreferences(GLOBAL_SCOPE, { use12h: false }, false);
    expect(client.preferencesStore.get()).toEqual({ theme: "system", use12h: false });
    await client.updatePreferences(GLOBAL_SCOPE, { theme: "light" }, true);

    await client.signOut();
    unsubAuthUser();
    expect(authUsersObserved).toEqual([null, "u-1", "u-admin", null]);
  });

  it("canDeleteUser follows userCapabilities.delete in each scope, and is admin-only without it", async () => {
    const policy = createPermissionPolicy<TestRole, TestCap>({
      capabilities: TEST_CAPS,
      roles: {
        owner: { inherits: ["manager"], capabilities: "*" },
        manager: { inherits: ["member"], capabilities: ["invite_members"] },
        member: { capabilities: [] }
      },
      userCapabilities: { write: "edit_content", delete: "invite_members" }
    });
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>({ policy });
    await store.upsertUser({ uid: "u-del", email: "del@example.com", roles: ["member"] });
    await store.upsertScopeMember("ws-1", { uid: "u-del", email: "del@example.com", roles: ["manager"] });
    const user = {
      uid: "u-del",
      email: "del@example.com",
      emailVerified: true,
      displayName: "Del",
      photoUrl: null,
      isAdmin: false,
      providerIds: ["password"]
    };
    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      policy,
      defaultPreferences: DEFAULT_PREFS
    });
    client.setActiveUser(user);
    // A manager in ws-1 may remove members there, but holds no global role that deletes accounts
    expect(client.canDeleteUser("ws-1")).toBe(true);
    expect(client.canDeleteUser(GLOBAL_SCOPE)).toBe(false);
    expect(client.canDeleteUser("ws-other")).toBe(false);
    client.destroy();

    const noPolicy = createLanyardClient<TestRole, TestCap, TestPrefs>({ store, defaultPreferences: DEFAULT_PREFS });
    noPolicy.setActiveUser(user);
    expect(noPolicy.canDeleteUser("ws-1")).toBe(false);
    noPolicy.setActiveUser({ ...user, isAdmin: true });
    expect(noPolicy.canDeleteUser(GLOBAL_SCOPE)).toBe(true);
    noPolicy.destroy();
  });

  it("waits for Firebase to restore a saved session before completing a magic link, so it never replaces it", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    const restoredUser = {
      uid: "u-restored",
      email: "restored@example.com",
      emailVerified: true,
      providerData: [],
      getIdTokenResult: vi.fn().mockResolvedValue({ claims: {} })
    };
    // On page load, currentUser is null until Firebase has read the persisted session
    const fakeAuth: any = {
      currentUser: null,
      authStateReady: vi.fn(async () => {
        await new Promise((r) => setTimeout(r, 0));
        fakeAuth.currentUser = restoredUser;
      })
    };
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValue(true);
    localStorage.setItem("bootapp_emailForSignIn", "other@example.com");
    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "bootapp"
    });

    expect(await client.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123" })).toEqual({
      status: "signed-in-as-other",
      currentEmail: "restored@example.com"
    });
    expect(fakeAuth.authStateReady).toHaveBeenCalled();
    expect(firebaseAuth.signInWithEmailLink).not.toHaveBeenCalled();
  });

  it("handles OAuth login, magic email links, and account linking", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    const fakeAuth: any = {
      authStateReady: async () => {},
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

    // 2. Passwordless Magic Email Link
    await expect(client.sendPasswordlessEmailLink("   ")).rejects.toThrow(/valid email/);
    await client.sendPasswordlessEmailLink("  Magic@Example.com ", "https://app.example.com/callback");
    expect(firebaseAuth.sendSignInLinkToEmail).toHaveBeenCalledWith(
      fakeAuth,
      "magic@example.com",
      expect.objectContaining({ url: "https://app.example.com/callback", handleCodeInApp: true })
    );
    expect(localStorage.getItem("testapp_emailForSignIn")).toBe("magic@example.com");

    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValue(true);
    vi.mocked(firebaseAuth.signInWithEmailLink).mockResolvedValueOnce({
      user: {
        uid: "u-magic",
        email: "magic@example.com",
        emailVerified: true,
        providerData: [],
        getIdTokenResult: vi.fn().mockResolvedValue({ claims: {} })
      }
    } as any);
    // Someone is already signed in: the link isn't used, so the app can ask before switching accounts
    expect(await client.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123" })).toEqual({
      status: "signed-in-as-other",
      currentEmail: "social@example.com"
    });
    expect(firebaseAuth.signInWithEmailLink).not.toHaveBeenCalled();
    const signedInUser = fakeAuth.currentUser;
    fakeAuth.currentUser = null;
    const magicResult = await client.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123" });
    expect(magicResult).toMatchObject({ status: "signed-in", user: { uid: "u-magic" } });
    expect(firebaseAuth.signInWithEmailLink).toHaveBeenCalledWith(
      fakeAuth,
      "magic@example.com",
      "https://app.example.com/?oobCode=123"
    );
    expect(localStorage.getItem("testapp_emailForSignIn")).toBeNull();
    fakeAuth.currentUser = signedInUser;
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReset();

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
      roles: ["manager"]
    });
    await store.upsertScopeMember("ws-1", {
      uid: "u-mem",
      email: "mem@example.com",
      roles: ["member"]
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
      isAdmin: false,
      providerIds: []
    });

    client.recordActivity("ws-1");
    await client.syncPresence("ws-1");
    expect((await store.getScopeMember("ws-1", "u-mem"))?.lastSeen).toBeUndefined();

    // 2. Manager ('manager' has trackPresence: true)
    client.setActiveUser({
      uid: "u-mgr",
      email: "mgr@example.com",
      emailVerified: true,
      displayName: "Manager",
      photoUrl: "https://example.com/mgr.png",
      isAdmin: false,
      providerIds: []
    });

    const baseTime = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(baseTime);

    // If store.recordPresenceHeartbeat rejects once, lastSynced is rolled back so next sync retries
    const hbSpy = vi.spyOn(store, "recordPresenceHeartbeat");
    hbSpy.mockRejectedValueOnce(new Error("Write failed"));
    client.recordActivity("ws-1");
    await client.syncPresence("ws-1");
    expect(client.getPresenceStatus("ws-1").lastSynced).toBe(0);

    // Next attempt succeeds
    await client.syncPresence("ws-1");
    expect(client.getPresenceStatus("ws-1").lastSynced).toBe(baseTime);

    // Activity 1 minute later is throttled (not written to store yet)
    vi.spyOn(Date, "now").mockReturnValue(baseTime + 60_000);
    client.recordActivity("ws-1");
    await client.syncPresence("ws-1");
    expect((await store.getScopeMember("ws-1", "u-mgr"))?.lastSeen).toBe(new Date(baseTime).toISOString());

    // Unless isUnloading: true is passed
    await client.syncPresence("ws-1", { isUnloading: true });
    expect((await store.getScopeMember("ws-1", "u-mgr"))?.lastSeen).toBe(new Date(baseTime + 60_000).toISOString());

    // startPresenceHeartbeat starts interval and cleans up cleanly
    const stopHeartbeat = client.startPresenceHeartbeat("ws-1");
    stopHeartbeat();

    vi.restoreAllMocks();
  });

  it("tests FirestoreClientStore subscriptions, avatar sync, and presence heartbeats", async () => {
    const fakeDb: any = {};
    const store = new FirestoreClientStore<TestRole, TestCap, TestPrefs>({
      db: fakeDb
    });

    // 1. subscribeToPreferences + savePreferences on the self-only users/{uid}/private/preferences tier doc
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((ref: any, onNext: any) => {
      expect(ref.path).toBe("users/u-1/private/preferences");
      onNext({
        exists: () => true,
        data: () => ({
          theme: "dark",
          tier: "gold",
          _lanyard: { tier: "preferences", uid: "u-1", scopeId: null, updatedAt: "2026-01-01" }
        })
      });
      return () => {};
    });
    const prefObserved: Partial<TestPrefs>[] = [];
    const unsubPref1 = store.subscribeToPreferences("u-1", (p) => prefObserved.push(p));
    // Tier metadata (`_lanyard`) is stripped from the emitted preferences; ordinary keys like `tier` are kept
    expect(prefObserved).toEqual([{ theme: "dark", tier: "gold" }]);
    unsubPref1();

    // A missing preferences doc emits empty preferences
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      onNext({ exists: () => false, data: () => undefined });
      return () => {};
    });
    const emptyPrefObserved: Partial<TestPrefs>[] = [];
    store.subscribeToPreferences("u-1", (p) => emptyPrefObserved.push(p))();
    expect(emptyPrefObserved).toEqual([{}]);

    await store.savePreferences("u-1", { use12h: false });
    expect(firebaseFirestore.setDoc).toHaveBeenLastCalledWith(
      expect.objectContaining({ path: "users/u-1/private/preferences" }),
      {
        use12h: false,
        _lanyard: { tier: "preferences", uid: "u-1", scopeId: null, updatedAt: expect.any(String) }
      },
      { merge: true }
    );

    // Scoped preferences live in the member's own private/preferences tier doc
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((ref: any, onNext: any) => {
      expect(ref.path).toBe("workspaces/ws-1/members/u-1/private/preferences");
      onNext({
        exists: () => true,
        data: () => ({ use12h: true, _lanyard: { tier: "preferences", uid: "u-1", scopeId: "ws-1" } })
      });
      return () => {};
    });
    const scopePrefObserved: Partial<TestPrefs>[] = [];
    store.subscribeToScopePreferences("ws-1", "u-1", (p) => scopePrefObserved.push(p))();
    expect(scopePrefObserved).toEqual([{ use12h: true }]);

    await store.saveScopePreferences("ws-1", "u-1", { theme: "light" });
    expect(firebaseFirestore.setDoc).toHaveBeenLastCalledWith(
      expect.objectContaining({ path: "workspaces/ws-1/members/u-1/private/preferences" }),
      {
        theme: "light",
        _lanyard: { tier: "preferences", uid: "u-1", scopeId: "ws-1", updatedAt: expect.any(String) }
      },
      { merge: true }
    );

    // The reserved tier metadata key can't be written as a preference, globally or per scope
    vi.mocked(firebaseFirestore.setDoc).mockClear();
    await expect(store.savePreferences("u-1", { _lanyard: { tier: "attributes" } } as any)).rejects.toThrow(
      "Invalid preferences key '_lanyard'"
    );
    await expect(store.saveScopePreferences("ws-1", "u-1", { _lanyard: "x" } as any)).rejects.toThrow(
      "Invalid preferences key '_lanyard'"
    );
    expect(firebaseFirestore.setDoc).not.toHaveBeenCalled();

    // 2. subscribeToUserMemberships
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_q: any, onNext: any) => {
      onNext({
        forEach(cb: any) {
          cb({
            id: "u-1",
            ref: { parent: { parent: { id: "ws-1" } } },
            data: () => ({
              uid: "u-1",
              email: "u1@example.com",
              roles: ["owner"],
              scopeName: "Primary Workspace"
            })
          });
        }
      });
      return () => {};
    });
    const userMembers: any[] = [];
    store.subscribeToUserMemberships("u-1", (m) => userMembers.push(...m));
    expect(userMembers).toHaveLength(1);
    expect(userMembers[0].roles).toEqual(["owner"]);
    expect(userMembers[0].scopeId).toBe("ws-1");
    expect(userMembers[0].scopeName).toBe("Primary Workspace");

    // 3. subscribeToScopeMembers
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      onNext({
        forEach(cb: any) {
          cb({
            id: "u-2",
            data: () => ({
              uid: "u-2",
              email: "u2@example.com",
              roles: ["member", "manager"]
            })
          });
        }
      });
      return () => {};
    });
    const scopeMembers: any[] = [];
    store.subscribeToScopeMembers("ws-1", (m) => scopeMembers.push(...m));
    expect(scopeMembers).toHaveLength(1);
    expect(scopeMembers[0].roles).toEqual(["member", "manager"]);

    // 3b. include: ["attributes"] adds ONE collection-group listener on the scope's attributes tiers and waits for
    // both listeners before emitting merged members
    let emitCards!: (snap: any) => void;
    let emitTiers!: (snap: any) => void;
    vi.mocked(firebaseFirestore.onSnapshot)
      .mockImplementationOnce((_ref: any, onNext: any) => {
        emitCards = onNext;
        return () => {};
      })
      .mockImplementationOnce((_q: any, onNext: any) => {
        emitTiers = onNext;
        return () => {};
      });
    vi.mocked(firebaseFirestore.where).mockClear();
    const included: any[][] = [];
    store.subscribeToScopeMembers("ws-1", (m) => included.push(m), { include: ["attributes"] });
    expect(firebaseFirestore.collectionGroup).toHaveBeenLastCalledWith(fakeDb, "private");
    expect(firebaseFirestore.where).toHaveBeenCalledWith("_lanyard.tier", "==", "attributes");
    expect(firebaseFirestore.where).toHaveBeenCalledWith("_lanyard.scopeId", "==", "ws-1");
    emitCards({ forEach: (cb: any) => cb({ id: "u-2", data: () => ({ uid: "u-2", roles: ["member"] }) }) });
    expect(included).toHaveLength(0);
    emitTiers({
      forEach: (cb: any) =>
        cb({
          data: () => ({
            points: 3,
            email: "u2@example.com",
            _lanyard: { tier: "attributes", uid: "u-2", scopeId: "ws-1" }
          })
        })
    });
    expect(included.at(-1)).toEqual([
      expect.objectContaining({ uid: "u-2", email: "u2@example.com", attributes: { points: 3 } })
    ]);

    // 4. syncAvatar uses updateDoc for scoped members and setDoc for users/{uid}
    await store.syncAvatar({ uid: "u-1", scopeId: "ws-1", photoUrl: "https://example.com/u1.png" });
    expect(firebaseFirestore.updateDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "workspaces/ws-1/members/u-1" }),
      { photoUrl: "https://example.com/u1.png" }
    );

    await store.syncAvatar({
      uid: "u-admin",
      displayName: "Admin",
      photoUrl: "https://example.com/admin.png"
    });
    // Avatar sync writes the card only, never an email (email is server-owned)
    expect(firebaseFirestore.setDoc).toHaveBeenCalledWith(
      expect.objectContaining({ path: "users/u-admin" }),
      {
        uid: "u-admin",
        displayName: "Admin",
        photoUrl: "https://example.com/admin.png"
      },
      { merge: true }
    );
    expect(firebaseFirestore.setDoc).not.toHaveBeenCalledWith(
      expect.objectContaining({ path: "users/u-admin/private/attributes" }),
      expect.anything(),
      expect.anything()
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
      roles: ["manager"],
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
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(1);

    // 3. Subsequent membership emissions with the same photoUrl do not trigger duplicate syncAvatar calls
    await store.grantScopeRoles("ws-1", "u-1", ["owner"]);
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(1);
  });

  it("auto-applies mode=verifyEmail action codes on boot, but never completes a magic sign-in link on its own", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    const fakeAuth: any = { currentUser: null, authStateReady: async () => {} };

    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});

    // 1. Boot with mode=verifyEmail&oobCode=VERIFY_CODE_123 (with active currentUser reload & token refresh)
    const reloadSpy = vi.fn().mockResolvedValue(undefined);
    const getIdTokenResultSpy = vi.fn().mockResolvedValue({ claims: { admin: false } });
    fakeAuth.currentUser = {
      uid: "u-verified-email",
      email: "newemail@example.com",
      emailVerified: true,
      displayName: "Verified User",
      photoURL: null,
      providerData: [{ providerId: "google.com" }],
      reload: reloadSpy,
      getIdTokenResult: getIdTokenResultSpy
    };
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
    vi.mocked(firebaseAuth.applyActionCode).mockResolvedValueOnce(undefined);

    const clientVerify = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      defaultPreferences: DEFAULT_PREFS
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(firebaseAuth.applyActionCode).toHaveBeenCalledWith(fakeAuth, "VERIFY_CODE_123");
    expect(reloadSpy).toHaveBeenCalledTimes(1);
    expect(getIdTokenResultSpy).toHaveBeenCalledWith(true);
    expect(clientVerify.authStore.get().user?.email).toBe("newemail@example.com");
    clientVerify.destroy();
    fakeAuth.currentUser = null;

    // 2. Boot with someone else's magic sign-in link that carries their email (login CSRF): nothing signs in on
    //    construction, the link's email is never used, and completing from the address bar needs the user's email
    const magicHref = "https://app.example.com/?mode=signIn&oobCode=MAGIC_123&email=attacker%40evil.example#profile";
    const replaceState = vi.fn();
    vi.stubGlobal("window", {
      location: {
        href: magicHref,
        search: "?mode=signIn&oobCode=MAGIC_123&email=attacker%40evil.example",
        origin: "https://app.example.com",
        pathname: "/",
        hash: "#profile"
      },
      history: { state: null, replaceState },
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
    expect(firebaseAuth.signInWithEmailLink).not.toHaveBeenCalled();
    expect(clientMagic.authStore.get().user).toBeNull();

    expect(await clientMagic.completePasswordlessSignIn()).toEqual({ status: "needs-email" });
    expect(firebaseAuth.signInWithEmailLink).not.toHaveBeenCalled();
    expect(replaceState).not.toHaveBeenCalled();

    // The user types the address the link was sent to; afterwards the link's parameters leave the address bar
    const typed = await clientMagic.completePasswordlessSignIn({ email: " Boot@Example.com" });
    expect(typed).toMatchObject({ status: "signed-in", user: { uid: "u-boot-magic" } });
    expect(firebaseAuth.signInWithEmailLink).toHaveBeenCalledWith(fakeAuth, "boot@example.com", magicHref);
    expect(clientMagic.authStore.get().user?.uid).toBe("u-boot-magic");
    expect(replaceState).toHaveBeenCalledWith(null, "", "/#profile");
    clientMagic.destroy();
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReset();
    vi.unstubAllGlobals();
  });

  it("enforces presence edge cases: no-new-activity guard, multi-user/multi-scope isolation, real-time role changes, and window activity listeners", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.upsertScopeMember("ws-1", {
      uid: "u-alice",
      email: "alice@example.com",
      roles: ["manager"]
    });
    await store.upsertScopeMember("ws-2", {
      uid: "u-alice",
      email: "alice@example.com",
      roles: ["member"] // untracked role in ws-2
    });
    await store.upsertScopeMember("ws-1", {
      uid: "u-bob",
      email: "bob@example.com",
      roles: ["owner"]
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
      isAdmin: false,
      providerIds: []
    });

    client.recordActivity("ws-1");
    client.recordActivity("ws-2");
    await client.syncPresence("ws-1");
    await client.syncPresence("ws-2");

    expect(hbSpy).toHaveBeenCalledTimes(1);
    expect((await store.getScopeMember("ws-1", "u-alice"))?.lastSeen).toBe(new Date(t0).toISOString());
    expect((await store.getScopeMember("ws-2", "u-alice"))?.lastSeen).toBeUndefined();

    // 2. No-new-activity guard: 10 minutes pass, but Alice has NOT triggered recordActivity since t0
    vi.spyOn(Date, "now").mockReturnValue(t0 + 10 * 60_000);
    await client.syncPresence("ws-1");
    expect(hbSpy).toHaveBeenCalledTimes(1); // still 1!

    // 3. Real-time role demotion mid-session: Alice is demoted from 'manager' to 'member' in ws-1
    await store.upsertScopeMember("ws-1", {
      uid: "u-alice",
      email: "alice@example.com",
      roles: ["member"],
      lastSeen: new Date(t0).toISOString()
    });
    client.recordActivity("ws-1");
    await client.syncPresence("ws-1", { isUnloading: true });
    expect(hbSpy).toHaveBeenCalledTimes(1); // blocked immediately upon demotion!

    // Real-time role promotion: Alice is promoted in ws-2 from 'member' to 'manager'
    await store.upsertScopeMember("ws-2", {
      uid: "u-alice",
      email: "alice@example.com",
      roles: ["manager"]
    });
    client.recordActivity("ws-2");
    await client.syncPresence("ws-2");
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

    const stopBobHeartbeat = client.startPresenceHeartbeat("ws-1");
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
      roles: ["owner"]
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
      roles: ["manager"]
    });
    expect(client.preferencesStore.get()).toEqual({ theme: "light", use12h: true });
    expect(client.membershipsStore.get().memberships).toHaveLength(0);
  });

  it("enforces client security guards: localStorage prototype pollution, redirectUrl validation, dev-auth SSRF prevention, and Firestore path traversal", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    const fakeAuth: any = { currentUser: { uid: "u-sec", email: "sec@example.com" } };
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});

    // 1. Poison the guest preferences cache with __proto__ and non-object JSON before client boot
    localStorage.setItem(
      "secapp_guest_preferences",
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
    localStorage.setItem("secapp_guest_preferences", "[1, 2, 3]");
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
      db: {} as any
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
      roles: ["manager"],
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
      isAdmin: true,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(syncSpy).toHaveBeenCalledTimes(4);
    expect((await store.getUser("u-retry"))?.photoUrl).toBe("https://example.com/retry.png");
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
      isAdmin: false,
      providerIds: ["google.com"]
    });

    // Without a policy, non-admin in GLOBAL_SCOPE or in non-member scopeId does not track presence
    clientNoPolicy.recordActivity(GLOBAL_SCOPE);
    await clientNoPolicy.syncPresence(GLOBAL_SCOPE);
    clientNoPolicy.recordActivity("ws-not-member");
    await clientNoPolicy.syncPresence("ws-not-member");
    expect(clientNoPolicy.getPresenceStatus("ws-1").lastSynced).toBe(0);

    // Reject first heartbeat write -> lastSynced rolls back to 0 so immediate retry succeeds!
    const hbSpy = vi.spyOn(store, "recordPresenceHeartbeat").mockRejectedValueOnce(new Error("Offline"));
    clientNoPolicy.recordActivity("ws-1");
    await clientNoPolicy.syncPresence("ws-1");
    expect(hbSpy).toHaveBeenCalledTimes(1);
    expect(clientNoPolicy.getPresenceStatus("ws-1").lastSynced).toBe(0); // rolled back!

    await clientNoPolicy.syncPresence("ws-1");
    expect(hbSpy).toHaveBeenCalledTimes(2);
    expect(clientNoPolicy.getPresenceStatus("ws-1").lastSynced).toBe(t0);

    // 3. Uninitialized auth guards & fallbacks
    await expect(clientNoPolicy.loginWithSocialProvider("google")).rejects.toThrow(/not initialized/);
    await expect(clientNoPolicy.sendPasswordlessEmailLink("a@b.com")).rejects.toThrow(/not initialized/);
    await expect(clientNoPolicy.completePasswordlessSignIn({ email: "a@b.com" })).rejects.toThrow(/not initialized/);
    await expect(clientNoPolicy.linkSocialProvider("google")).rejects.toThrow(/No authenticated user/);
    await expect(clientNoPolicy.unlinkSocialProvider("google.com")).rejects.toThrow(/No authenticated user/);
    await expect(clientNoPolicy.sendEmailUpdateVerification("a@b.com")).rejects.toThrow(/No authenticated user/);
    expect(await clientNoPolicy.getSignInMethodsForEmail("a@b.com")).toEqual([]);

    // Auth with localStorage email fallback on completePasswordlessSignIn, failed fetchSignInMethodsForEmail, and failed dev login fetch
    const fakeAuth: any = { currentUser: null, authStateReady: async () => {} };
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});
    const clientWithAuth = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "retryapp"
    });

    // completePasswordlessSignIn when the URL is not a sign-in link, or when no email is stored or typed
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValueOnce(false);
    expect(await clientWithAuth.completePasswordlessSignIn({ href: "https://app.example.com/" })).toEqual({
      status: "not-a-link"
    });

    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValue(true);
    localStorage.removeItem("retryapp_emailForSignIn");
    expect(await clientWithAuth.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123" })).toEqual({
      status: "needs-email"
    });

    // The email this device stored when it requested the link is used
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
    const completedStored = await clientWithAuth.completePasswordlessSignIn({
      href: "https://app.example.com/?oobCode=123"
    });
    expect(completedStored).toMatchObject({ status: "signed-in", user: { email: "stored@example.com" } });
    expect(localStorage.getItem("retryapp_emailForSignIn")).toBeNull();

    // Firebase errors map to typed errors; a stored email for a different link is forgotten and the app asks instead
    const firebaseError = (code: string) => Object.assign(new Error(code), { code });
    vi.mocked(firebaseAuth.signInWithEmailLink).mockRejectedValueOnce(firebaseError("auth/invalid-email"));
    await expect(
      clientWithAuth.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123", email: "x@y.z" })
    ).rejects.toBeInstanceOf(EmailLinkMismatchError);
    localStorage.setItem("retryapp_emailForSignIn", "stale@example.com");
    vi.mocked(firebaseAuth.signInWithEmailLink).mockRejectedValueOnce(firebaseError("auth/invalid-email"));
    expect(await clientWithAuth.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123" })).toEqual({
      status: "needs-email"
    });
    expect(localStorage.getItem("retryapp_emailForSignIn")).toBeNull();
    for (const code of ["auth/invalid-action-code", "auth/expired-action-code"]) {
      vi.mocked(firebaseAuth.signInWithEmailLink).mockRejectedValueOnce(firebaseError(code));
      await expect(
        clientWithAuth.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123", email: "x@y.z" })
      ).rejects.toBeInstanceOf(EmailLinkInvalidError);
    }
    vi.mocked(firebaseAuth.signInWithEmailLink).mockRejectedValueOnce(firebaseError("auth/network-request-failed"));
    await expect(
      clientWithAuth.completePasswordlessSignIn({ href: "https://app.example.com/?oobCode=123", email: "x@y.z" })
    ).rejects.toMatchObject({ code: "auth/network-request-failed" });
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReset();

    // getSignInMethodsForEmail catches errors and returns []
    vi.mocked(firebaseAuth.fetchSignInMethodsForEmail).mockRejectedValueOnce(new Error("Network error"));
    expect(await clientWithAuth.getSignInMethodsForEmail("stored@example.com")).toEqual([]);

    // 4. FirestoreClientStore error callbacks, custom collection names, and unsafe photoUrl ignore
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementation((_ref: any, _onNext: any, onError?: any) => {
      if (onError) onError(new Error("permission-denied"));
      return () => {};
    });

    const fsStore = new FirestoreClientStore<TestRole, TestCap, TestPrefs>({
      db: { type: "custom-fs" } as any,
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

  it("multiplexes FirestoreClientStore users/{uid} listeners (1 onSnapshot per UID) and strips unauthorized fields on updateUserProfile", async () => {
    const fakeDb: any = {};
    const fsStore = new FirestoreClientStore<TestRole, TestCap, TestPrefs, { pointsAllTime: number }>({
      db: fakeDb
    });

    let emitSnapshot!: (snap: any) => void;
    const underlyingUnsub = vi.fn();
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      emitSnapshot = onNext;
      return underlyingUnsub;
    });

    const userEvents: any[] = [];
    const lateUserEvents: any[] = [];

    // 1. Multiple subscribeToUser calls on 'u-mux' open ONLY 1 Firestore listener on the card
    const unsubUser = fsStore.subscribeToUser("u-mux", (u) => userEvents.push(u));
    expect(firebaseFirestore.onSnapshot).toHaveBeenCalledTimes(1);

    emitSnapshot({
      exists: () => true,
      data: () => ({
        uid: "u-mux",
        email: "mux@example.com",
        firstName: "Testy",
        lastName: "McTest",
        isSystemAdmin: false,
        roles: ["manager"],
        // Legacy inline preferences on the card are ignored; preferences only come from private/preferences
        preferences: { theme: "dark", use12h: false },
        attributes: { pointsAllTime: 420 }
      })
    });

    expect(userEvents).toHaveLength(1);
    expect(userEvents[0]).toMatchObject({
      uid: "u-mux",
      roles: ["manager"],
      attributes: { pointsAllTime: 420 }
    });
    expect(userEvents[0].preferences).toBeUndefined();

    // 2. Late subscriber immediately receives the latest cached snapshot without triggering a 2nd Firestore read!
    const unsubLateUser = fsStore.subscribeToUser("u-mux", (u) => lateUserEvents.push(u));
    expect(firebaseFirestore.onSnapshot).toHaveBeenCalledTimes(1);
    expect(lateUserEvents).toHaveLength(1);
    expect(lateUserEvents[0]).toMatchObject({ uid: "u-mux", roles: ["manager"] });

    // Non-existent doc snapshot emits null to userCallbacks
    emitSnapshot({ exists: () => false, data: () => undefined });
    expect(userEvents[userEvents.length - 1]).toBeNull();

    // 3. Ref-counted cleanup: underlying Firestore listener stays active until ALL subscribers detach
    unsubUser();
    expect(underlyingUnsub).not.toHaveBeenCalled();
    unsubLateUser();
    expect(underlyingUnsub).toHaveBeenCalledTimes(1);

    // Preferences use their own listener on the private tier doc, never the card listener
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce(() => () => {});
    fsStore.subscribeToPreferences("u-mux", () => {})();
    expect(firebaseFirestore.onSnapshot).toHaveBeenCalledTimes(2);
    expect(vi.mocked(firebaseFirestore.onSnapshot).mock.calls[1][0]).toMatchObject({
      path: "users/u-mux/private/preferences"
    });

    // 4. updateUserProfile strictly whitelists Tier-1 fields and strips malicious privilege escalation fields
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

  it("opens one scoped preferences listener per membership, closes it when the membership ends, and never leaks across users", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.upsertScopeMember("ws-a", { uid: "u-1", email: "u1@example.com", roles: ["member"] });
    await store.upsertScopeMember("ws-b", { uid: "u-1", email: "u1@example.com", roles: ["member"] });
    await store.saveScopePreferences("ws-a", "u-1", { theme: "dark" });
    await store.upsertScopeMember("ws-a", { uid: "u-2", email: "u2@example.com", roles: ["member"] });

    const unsubs = new Map<string, ReturnType<typeof vi.fn>>();
    const originalSubscribe = store.subscribeToScopePreferences.bind(store);
    const subscribeSpy = vi.spyOn(store, "subscribeToScopePreferences").mockImplementation((scopeId, uid, onChange) => {
      const unsub = vi.fn(originalSubscribe(scopeId, uid, onChange));
      unsubs.set(`${scopeId}/${uid}`, unsub);
      return unsub;
    });

    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "scopeprefs"
    });
    const user1 = {
      uid: "u-1",
      email: "u1@example.com",
      emailVerified: true,
      displayName: null,
      photoUrl: null,
      isAdmin: false,
      providerIds: []
    };
    client.setActiveUser(user1);

    expect(subscribeSpy.mock.calls.map(([scopeId, uid]) => `${scopeId}/${uid}`).sort()).toEqual([
      "ws-a/u-1",
      "ws-b/u-1"
    ]);
    expect(client.getPreferences("ws-a")).toEqual({ ...DEFAULT_PREFS, theme: "dark" });
    expect(client.getPreferences("ws-b")).toEqual(DEFAULT_PREFS);
    expect(client.membershipsStore.get().memberships.find((m) => m.scopeId === "ws-a")?.preferences).toEqual({
      theme: "dark"
    });

    // Remote changes (e.g. from another device) flow in through the scoped listener
    await store.saveScopePreferences("ws-b", "u-1", { use12h: false });
    expect(client.getPreferences("ws-b")).toEqual({ ...DEFAULT_PREFS, use12h: false });

    // Membership card re-emissions (presence, avatar) don't reopen listeners
    await store.recordPresenceHeartbeat({ uid: "u-1", scopeId: "ws-a", lastSeenIso: "2026-01-01T00:00:00.000Z" });
    expect(subscribeSpy).toHaveBeenCalledTimes(2);

    // Leaving a scope closes its listener and drops its preferences
    await store.deleteScopeMember("ws-b", "u-1");
    expect(unsubs.get("ws-b/u-1")).toHaveBeenCalledTimes(1);
    expect(unsubs.get("ws-a/u-1")).not.toHaveBeenCalled();
    expect(client.getPreferences("ws-b")).toEqual(DEFAULT_PREFS);

    // Switching users closes the previous user's listeners and never shows their scoped preferences
    client.setActiveUser({ ...user1, uid: "u-2", email: "u2@example.com" });
    expect(unsubs.get("ws-a/u-1")).toHaveBeenCalledTimes(1);
    expect(client.getPreferences("ws-a")).toEqual(DEFAULT_PREFS);
    await store.saveScopePreferences("ws-a", "u-1", { theme: "light" });
    expect(client.getPreferences("ws-a")).toEqual(DEFAULT_PREFS);

    // Sign-out closes everything
    client.setActiveUser(null);
    expect(unsubs.get("ws-a/u-2")).toHaveBeenCalledTimes(1);
    expect(client.membershipsStore.get().memberships).toEqual([]);
    client.destroy();
  });

  it("merges card-placed and attributes-tier keys into attributesStore and memberships, and rejects a store/policy placement mismatch", async () => {
    type Attrs = { badges: string[]; points: number };
    const policy = createPermissionPolicy<TestRole, TestCap>({ cardFields: { attributes: ["badges"] } });

    expect(() =>
      createLanyardClient<TestRole, TestCap, TestPrefs, Attrs>({
        store: new InMemoryLanyardStore<TestRole, TestCap, TestPrefs, Attrs>(),
        policy,
        defaultPreferences: DEFAULT_PREFS
      })
    ).toThrow(/Store cardFields do not match the policy's cardFields/);

    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs, Attrs>({ policy });
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", attributes: { badges: ["early"], points: 1 } });
    await store.upsertScopeMember("ws-a", {
      uid: "u-1",
      email: "u1@example.com",
      roles: ["member"],
      attributes: { badges: ["scoped"], points: 10 }
    });

    const client = createLanyardClient<TestRole, TestCap, TestPrefs, Attrs>({
      store,
      policy,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "attrtiers"
    });
    client.setActiveUser({
      uid: "u-1",
      email: "u1@example.com",
      emailVerified: true,
      displayName: null,
      photoUrl: null,
      isAdmin: false,
      providerIds: []
    });

    // The card carries only the card-placed key; attributesStore merges in the tier
    expect(client.userRecordStore.get()?.attributes).toEqual({ badges: ["early"] });
    expect(client.getAttributes(GLOBAL_SCOPE)).toEqual({ badges: ["early"], points: 1 });
    expect(client.getAttributes("ws-a")).toEqual({ badges: ["scoped"], points: 10 });

    // Server-side updates to either location flow into the merged view
    await store.updateUserAttributes("u-1", { points: 2 });
    await store.updateUserAttributes("u-1", { badges: ["early", "vip"] });
    expect(client.getAttributes(GLOBAL_SCOPE)).toEqual({ badges: ["early", "vip"], points: 2 });
    await store.updateScopeMemberAttributes("ws-a", "u-1", { points: 11 });
    expect(client.getAttributes("ws-a")).toEqual({ badges: ["scoped"], points: 11 });

    // Leaving the scope drops its attributes; signing out clears everything
    await store.deleteScopeMember("ws-a", "u-1");
    expect(client.getAttributes("ws-a")).toEqual({});
    client.setActiveUser(null);
    expect(client.getAttributes(GLOBAL_SCOPE)).toEqual({});
    client.destroy();
  });

  it("merges a private email into userRecordStore and memberships, never writes it, and shows the server's sync", async () => {
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>();
    await store.upsertUser({ uid: "u-1", email: "old@example.com", firstName: "Uno" });
    await store.upsertScopeMember("ws-a", { uid: "u-1", email: "old@example.com", roles: ["member"] });
    const upsertUser = vi.spyOn(store, "upsertUser");
    const updateUserProfile = vi.spyOn(store, "updateUserProfile");
    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "privateemail"
    });

    client.setActiveUser({
      uid: "u-1",
      email: "new@example.com",
      emailVerified: true,
      displayName: null,
      photoUrl: null,
      isAdmin: false,
      providerIds: []
    });

    // The card holds no email, but userRecordStore merges the user's own tier email in; the client never writes it
    await new Promise((r) => setTimeout(r, 0));
    expect(client.userRecordStore.get()?.email).toBe("old@example.com");
    expect(upsertUser).not.toHaveBeenCalled();
    expect(updateUserProfile).not.toHaveBeenCalled();
    expect(client.userRecordStore.get()?.firstName).toBe("Uno");
    expect(client.membershipsStore.get().memberships[0].email).toBe("old@example.com");

    // When the server syncs the verified email, the client shows it
    await store.upsertUser({ ...(await store.getUser("u-1"))!, email: "new@example.com" });
    await vi.waitFor(() => expect(client.userRecordStore.get()?.email).toBe("new@example.com"));

    client.setActiveUser(null);
    expect(client.userRecordStore.get()).toBeNull();
    client.destroy();
  });

  it("lets staff and admins include members' attributes tier and private email in list subscriptions, and rejects everyone else", async () => {
    type Attrs = { points: number };
    const policy = createPermissionPolicy<TestRole, TestCap>({
      roles: { owner: { capabilities: ["invite_members"] }, manager: { capabilities: ["invite_members"] }, member: {} },
      staffCapability: "invite_members"
    });
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs, Attrs>({ policy });
    await store.upsertScopeMember("ws-a", { uid: "u-staff", email: "staff@example.com", roles: ["manager"] });
    await store.upsertScopeMember("ws-a", {
      uid: "u-peer",
      email: "peer@example.com",
      roles: ["member"],
      attributes: { points: 7 }
    });
    await store.upsertUser({ uid: "u-peer", email: "peer@example.com", attributes: { points: 70 } });

    // Each client signs in with its stored email, so the verified-email sync leaves stored emails alone
    const makeClient = (uid: string, email: string, isAdmin = false) => {
      const client = createLanyardClient<TestRole, TestCap, TestPrefs, Attrs>({
        store,
        policy,
        defaultPreferences: DEFAULT_PREFS,
        storageKeyPrefix: `include-${uid}`
      });
      client.setActiveUser({
        uid,
        email,
        emailVerified: true,
        displayName: null,
        photoUrl: null,
        isAdmin,
        providerIds: []
      });
      return client;
    };

    // Scope staff get every member's tier merged in, and live tier updates
    const staff = makeClient("u-staff", "staff@example.com");
    const roster: any[][] = [];
    const unsubRoster = staff.subscribeToUsers("ws-a", (m) => roster.push(m), { include: ["attributes"] });
    expect(roster.at(-1)?.find((m) => m.uid === "u-peer")).toMatchObject({
      email: "peer@example.com",
      attributes: { points: 7 }
    });
    await store.updateScopeMemberAttributes("ws-a", "u-peer", { points: 8 });
    expect(roster.at(-1)?.find((m) => m.uid === "u-peer")?.attributes).toEqual({ points: 8 });
    unsubRoster();
    // ...but without include, other members' private fields stay out
    const plainRoster: any[][] = [];
    staff.subscribeToUsers("ws-a", (m) => plainRoster.push(m))();
    expect(plainRoster.at(-1)?.find((m) => m.uid === "u-peer")).toMatchObject({ email: "" });
    expect(plainRoster.at(-1)?.find((m) => m.uid === "u-peer")?.attributes).toBeUndefined();

    // Non-staff members, staff of another scope, and non-staff global users are rejected up front
    const peer = makeClient("u-peer", "peer@example.com");
    expect(() => peer.subscribeToUsers("ws-a", () => {}, { include: ["attributes"] })).toThrow(
      /Forbidden: include: \["attributes"\] requires staff access in scope 'ws-a'/
    );
    expect(() => staff.subscribeToUsers("ws-b", () => {}, { include: ["attributes"] })).toThrow(/scope 'ws-b'/);
    expect(() => staff.subscribeToUsers(GLOBAL_SCOPE, () => {}, { include: ["attributes"] })).toThrow(
      /the global scope/
    );

    // queryMembers follows the same rules: staff (and admins) for attributes-tier keys
    expect(await staff.queryMembers("ws-a", { attributes: { points: 8 } })).toEqual(["u-peer"]);
    await expect(peer.queryMembers("ws-a", { attributes: { points: 8 } })).rejects.toThrow(
      /Forbidden: queryMembers on attributes-tier keys requires staff access in scope 'ws-a'/
    );
    await expect(staff.queryMembers("ws-b", { attributes: { points: 8 } })).rejects.toThrow(/scope 'ws-b'/);
    await expect(staff.queryMembers("ws-a", { attributes: {} })).rejects.toThrow(/at least one attribute/);

    // System admins may include anywhere
    const admin = makeClient("u-admin", "admin@example.com", true);
    const directory: any[][] = [];
    admin.subscribeToUsers(GLOBAL_SCOPE, (u) => directory.push(u), { include: ["attributes"] })();
    expect(directory.at(-1)?.find((u) => u.uid === "u-peer")).toMatchObject({
      email: "peer@example.com",
      attributes: { points: 70 }
    });
    expect(await admin.queryMembers(GLOBAL_SCOPE, { attributes: { points: 70 } })).toEqual(["u-peer"]);

    [staff, peer, admin].forEach((c) => c.destroy());
  });

  it("reads and writes policy custom documents only for the audiences in customDocs", async () => {
    const policy = createPermissionPolicy<TestRole, TestCap>({
      roles: { owner: { capabilities: ["invite_members"] }, manager: { capabilities: ["invite_members"] }, member: {} },
      staffCapability: "invite_members",
      customDocs: { shiftNotes: { read: { self: true, staff: true }, write: { staff: true } } }
    });
    const store = new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>({ policy });
    await store.upsertScopeMember("ws-a", { uid: "u-staff", email: "staff@example.com", roles: ["manager"] });
    await store.upsertScopeMember("ws-a", { uid: "u-peer", email: "peer@example.com", roles: ["member"] });
    await store.upsertScopeMember("ws-a", { uid: "u-other", email: "other@example.com", roles: ["member"] });
    const makeClient = (uid: string, email: string) => {
      const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
        store,
        policy,
        defaultPreferences: DEFAULT_PREFS,
        storageKeyPrefix: `customdocs-${uid}`
      });
      client.setActiveUser({
        uid,
        email,
        emailVerified: true,
        displayName: null,
        photoUrl: null,
        isAdmin: false,
        providerIds: []
      });
      return client;
    };
    const staff = makeClient("u-staff", "staff@example.com");
    const peer = makeClient("u-peer", "peer@example.com");

    // Staff write, the owner reads (default target is the signed-in user) and subscribes
    await staff.updateCustomDoc("ws-a", "shiftNotes", "u-peer", { note: "great shift" });
    expect(await peer.readCustomDoc("ws-a", "shiftNotes")).toEqual({ note: "great shift" });
    const events: Record<string, any>[] = [];
    const unsub = peer.subscribeToCustomDoc("ws-a", "shiftNotes", "u-peer", (v) => events.push(v));
    await staff.updateCustomDoc("ws-a", "shiftNotes", "u-peer", { rating: 5 });
    expect(events.at(-1)).toEqual({ note: "great shift", rating: 5 });
    unsub();

    // The owner can't write their own notes, nor read another member's; outsiders and unknown docs are rejected
    await expect(peer.updateCustomDoc("ws-a", "shiftNotes", "u-peer", { note: "self-praise" })).rejects.toThrow(
      /Forbidden: cannot write custom doc 'shiftNotes'/
    );
    await expect(peer.readCustomDoc("ws-a", "shiftNotes", "u-other")).rejects.toThrow(
      /Forbidden: cannot read custom doc 'shiftNotes'/
    );
    await expect(staff.readCustomDoc("ws-b", "shiftNotes", "u-peer")).rejects.toThrow(/not a member of scope 'ws-b'/);
    await expect(staff.readCustomDoc("ws-a", "unknownDoc", "u-peer")).rejects.toThrow(
      /Unknown custom doc 'unknownDoc'/
    );
    expect(await store.getCustomDoc("shiftNotes", "u-peer", "ws-a")).toEqual({ note: "great shift", rating: 5 });

    [staff, peer].forEach((c) => c.destroy());
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
      roles: ["manager"], // 'manager' has trackPresence: true in TEST_POLICY
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
    await expect(client.updateProfile(GLOBAL_SCOPE, { firstName: "Anon" })).rejects.toThrow(/No authenticated user/);

    client.setActiveUser({
      uid: "u-single",
      email: "single@example.com",
      emailVerified: true,
      displayName: "Testy McTest",
      photoUrl: "https://example.com/oauth-single.png",
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));

    // 1. Single subscription populates preferencesStore, attributesStore, and userRecordStore, and syncs OAuth avatar to users/{uid}
    expect(client.preferencesStore.get()).toEqual({ theme: "dark", use12h: false });
    expect(client.attributesStore.get()).toEqual({ pointsAllTime: 120, awardedBadges: ["first-checkin"] });
    expect(client.userRecordStore.get()?.photoUrl).toBe("https://example.com/oauth-single.png");

    // 2. Self-service updateProfile updates firstName/lastName on users/{uid}, auto-computes displayName, and syncs to authStore & Firebase Auth
    await client.updateProfile(GLOBAL_SCOPE, { firstName: "Formy", lastName: "McFormerson" });
    expect(client.userRecordStore.get()?.firstName).toBe("Formy");
    expect(client.userRecordStore.get()?.lastName).toBe("McFormerson");
    expect(client.userRecordStore.get()?.displayName).toBe("Formy McFormerson");
    expect(client.authStore.get().user?.displayName).toBe("Formy McFormerson");
    expect(firebaseAuth.updateProfile).toHaveBeenCalledWith(fakeAuth.currentUser, {
      displayName: "Formy McFormerson"
    });

    // A verified email change in Firebase Auth leaves the stored email for the server's checkAuth sync
    client.setActiveUser({
      uid: "u-single",
      email: "updated-single@example.com",
      emailVerified: true,
      displayName: "Formy McFormerson",
      photoUrl: "https://example.com/oauth-single.png",
      isAdmin: false,
      providerIds: ["google.com"]
    });
    await new Promise((r) => setTimeout(r, 0));
    expect((await store.getUser("u-single"))?.email).toBe("single@example.com");
    expect(formatExistingAccountError("test@example.com", ["google.com"])).toContain("Google");

    // 3. Server updates attributes -> client attributesStore updates reactively
    await store.updateUserAttributes("u-single", { pointsAllTime: 170 });
    expect(client.attributesStore.get().pointsAllTime).toBe(170);

    // 4. A change to the admin directory entry refreshes the ID token, and authStore.user.isAdmin follows the claim
    await store.upsertSystemAdmin({
      uid: "u-single",
      email: "single@example.com",
      isSystemAdmin: true
    });
    expect(getIdTokenResultSpy).toHaveBeenCalledWith(true);
    await vi.waitFor(() => expect(client.authStore.get().user?.isAdmin).toBe(true));

    // Demotion: the claim is revoked first, and the directory change prompts the refresh that picks it up
    getIdTokenResultSpy.mockResolvedValue({ claims: { admin: false } });
    await store.deleteSystemAdmin("u-single");
    await vi.waitFor(() => expect(client.authStore.get().user?.isAdmin).toBe(false));
    // Attributes and preferences remain intact after admin demotion!
    expect(client.attributesStore.get().pointsAllTime).toBe(170);

    // 5. Single-tenant presence tracking with GLOBAL_SCOPE: 'manager' role on users/{uid} has trackPresence: true
    const t0 = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(t0);
    client.recordActivity(GLOBAL_SCOPE);
    await client.syncPresence(GLOBAL_SCOPE);
    expect((await store.getUser("u-single"))?.lastSeen).toBe(new Date(t0).toISOString());

    // 6. Unscoped subscribeToUsers(GLOBAL_SCOPE, cb) directory subscription on client & store
    const observedDirectory: string[][] = [];
    const unsubDir = client.subscribeToUsers(GLOBAL_SCOPE, (users) => {
      observedDirectory.push(users.map((u) => u.uid));
    });
    expect(observedDirectory.at(-1)).toEqual(["u-single"]);
    await store.upsertUser({
      uid: "u-second",
      email: "second@example.com",
      roles: ["member"]
    });
    expect(observedDirectory.at(-1)?.sort()).toEqual(["u-second", "u-single"]);
    unsubDir();

    client.destroy();
    vi.restoreAllMocks();
  });

  it("supports unified custom role, capability, preference, and attribute accessors and updates across both unscoped and scoped modes", async () => {
    interface CustomAttrs {
      points: number;
      tier: string;
    }

    type DualRole = "owner" | "manager" | "editor" | "member";
    const dualPolicy = createPermissionPolicy<DualRole, TestCap>({
      capabilities: TEST_CAPS,
      roles: {
        owner: { inherits: ["manager"], capabilities: "*" },
        manager: { inherits: ["editor"], capabilities: ["invite_members"] },
        editor: { inherits: ["member"], capabilities: ["edit_content"] },
        member: { capabilities: [] }
      },
      userCapabilities: {
        read: "edit_content",
        write: "invite_members",
        assignRoles: "invite_members"
      },
      staffCapability: "invite_members",
      attributeCapabilities: {
        points: "edit_content",
        tier: { write: "invite_members" }
      },
      hiddenAttributeCapabilities: {
        moderatorNotes: { write: "edit_content" }
      },
      secretCapabilities: {
        personalGeminiKey: { self: true },
        workspaceOpenaiKey: { capability: "invite_members" }
      }
    });

    const store = new InMemoryLanyardStore<DualRole, TestCap, TestPrefs, CustomAttrs>();

    // Global unscoped record: roles = ['editor'], preferences = { theme: 'dark' }, attributes = { points: 42, tier: 'silver' }
    await store.upsertUser({
      uid: "u-dual",
      email: "dual@example.com",
      roles: ["editor"],
      preferences: { theme: "dark" },
      attributes: { points: 42, tier: "silver" }
    });

    // Scoped record in 'ws-alpha': roles = ['manager'], preferences = { use12h: false }, attributes = { points: 100, tier: 'gold' }
    await store.upsertScopeMember("ws-alpha", {
      uid: "u-dual",
      email: "dual@example.com",
      roles: ["manager"],
      preferences: { use12h: false },
      attributes: { points: 100, tier: "gold" }
    });

    // Scoped record in 'ws-beta': roles = ['owner'], attributes = { points: 999, tier: 'platinum' }
    await store.upsertScopeMember("ws-beta", {
      uid: "u-dual",
      email: "dual@example.com",
      roles: ["owner"],
      attributes: { points: 999, tier: "platinum" }
    });

    const client = createLanyardClient<DualRole, TestCap, TestPrefs, CustomAttrs>({
      store,
      policy: dualPolicy,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "dualapp"
    });

    // Before sign-in, all role/capability checks return false/empty
    expect(client.getRoles(GLOBAL_SCOPE)).toEqual([]);
    expect(client.getRoles("ws-alpha")).toEqual([]);
    expect(client.hasRole("member", GLOBAL_SCOPE)).toBe(false);
    expect(client.hasAnyRole(["member", "editor"], GLOBAL_SCOPE)).toBe(false);
    expect(client.hasAllRoles(["member"], GLOBAL_SCOPE)).toBe(false);
    expect(client.hasCapability("edit_content", GLOBAL_SCOPE)).toBe(false);
    expect(client.getCapabilities(GLOBAL_SCOPE)).toEqual([]);
    expect(client.canAssignRoles(GLOBAL_SCOPE)).toBe(false);

    client.setActiveUser({
      uid: "u-dual",
      email: "dual@example.com",
      emailVerified: true,
      displayName: "Dualy McDual",
      photoUrl: null,
      isAdmin: false,
      providerIds: ["google.com"]
    });

    // 1. Unscoped (GLOBAL_SCOPE) role, capability, preference, and attribute checks:
    // Assignable roles follow the server's ceiling: the assign-roles capability, then the user's rank in that scope
    expect(client.getAssignableRoles(GLOBAL_SCOPE)).toEqual([]); // editor can't assign roles
    expect(client.getAssignableRoles("ws-alpha")).toEqual(["manager", "editor", "member"]);
    expect(client.getAssignableRoles("ws-beta")).toEqual(["owner", "manager", "editor", "member"]);
    expect(client.getRoles(GLOBAL_SCOPE)).toEqual(["editor"]);
    expect(client.hasRole("editor", GLOBAL_SCOPE)).toBe(true);
    expect(client.hasRole("member", GLOBAL_SCOPE)).toBe(true); // inherited via editor -> member!
    expect(client.hasRole("manager", GLOBAL_SCOPE)).toBe(false);
    expect(client.hasAnyRole(["manager", "editor"], GLOBAL_SCOPE)).toBe(true);
    expect(client.hasAllRoles(["editor", "member"], GLOBAL_SCOPE)).toBe(true);
    expect(client.hasAllRoles(["editor", "manager"], GLOBAL_SCOPE)).toBe(false);
    expect(client.hasCapability("edit_content", GLOBAL_SCOPE)).toBe(true);
    expect(client.hasCapability("invite_members", GLOBAL_SCOPE)).toBe(false);
    expect(client.hasAnyCapability(["invite_members", "edit_content"], GLOBAL_SCOPE)).toBe(true);
    expect(client.hasAllCapabilities(["edit_content"], GLOBAL_SCOPE)).toBe(true);
    expect(client.hasAllCapabilities(["edit_content", "invite_members"], GLOBAL_SCOPE)).toBe(false);
    expect(client.getCapabilities(GLOBAL_SCOPE)).toEqual(["edit_content"]);
    expect(client.getAttributes(GLOBAL_SCOPE)).toEqual({ points: 42, tier: "silver" });
    expect(client.getPreferences(GLOBAL_SCOPE)).toEqual({ theme: "dark", use12h: true });

    // 2. Scoped ('ws-alpha' and 'ws-beta') role, capability, preference, and attribute checks:
    expect(client.getRoles("ws-alpha")).toEqual(["manager"]);
    expect(client.hasRole("manager", "ws-alpha")).toBe(true);
    expect(client.hasRole("editor", "ws-alpha")).toBe(true);
    expect(client.hasRole("member", "ws-alpha")).toBe(true);
    expect(client.hasRole("owner", "ws-alpha")).toBe(false);
    expect(client.hasCapability("invite_members", "ws-alpha")).toBe(true);
    expect(client.hasCapability("edit_content", "ws-alpha")).toBe(true);
    expect(client.getCapabilities("ws-alpha").sort()).toEqual(["edit_content", "invite_members"]);
    expect(client.getAttributes("ws-alpha")).toEqual({ points: 100, tier: "gold" });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "system", use12h: false });

    expect(client.getRoles("ws-beta")).toEqual(["owner"]);
    expect(client.hasRole("owner", "ws-beta")).toBe(true);
    expect(client.hasCapability("invite_members", "ws-beta")).toBe(true);
    expect(client.hasCapability("delete_workspace", "ws-beta")).toBe(true);
    expect(client.getCapabilities("ws-beta").sort()).toEqual(["delete_workspace", "edit_content", "invite_members"]);
    expect(client.getAttributes("ws-beta")).toEqual({ points: 999, tier: "platinum" });

    // Unknown or invalid scopeId returns safe defaults
    expect(client.getRoles("ws-unknown")).toEqual([]);
    expect(client.getRoles("../invalid")).toEqual([]);
    expect(client.getAttributes("ws-unknown")).toEqual({});
    expect(client.getPreferences("ws-unknown")).toEqual(DEFAULT_PREFS);

    // 3. Updating scoped preferences and profile via `updatePreferences("ws-alpha", patch)` and `updateProfile("ws-alpha", patch)`:
    await client.updatePreferences("ws-alpha", { theme: "dark" });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "dark", use12h: false });
    expect((await store.getScopeMember("ws-alpha", "u-dual"))?.preferences).toEqual({
      theme: "dark",
      use12h: false
    });

    await client.updatePreferences("ws-alpha", { use12h: true });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "dark", use12h: true });

    await client.updateProfile("ws-alpha", { firstName: "Alpha", lastName: "Member" });
    expect((await store.getScopeMember("ws-alpha", "u-dual"))?.displayName).toBe("Alpha Member");

    // Global preferences remain independent of scoped preferences
    expect(client.getPreferences(GLOBAL_SCOPE)).toEqual({ theme: "dark", use12h: true });
    await client.updatePreferences(GLOBAL_SCOPE, { theme: "light" });
    expect(client.getPreferences(GLOBAL_SCOPE)).toEqual({ theme: "light", use12h: true });
    expect(client.getPreferences("ws-alpha")).toEqual({ theme: "dark", use12h: true });

    // Calling updatePreferences on a non-member scope throws and never creates a phantom member
    await expect(client.updatePreferences("ws-nonmember", { theme: "dark" })).rejects.toThrow(
      /does not exist in scope/
    );
    expect(await store.getScopeMember("ws-nonmember", "u-dual")).toBeNull();

    // 4. Client-side 4-tier property & user permission checks (canReadUser, canWriteUser, canAssignRoles, canReadAttribute, canWriteAttribute, canReadHiddenAttribute, canWriteHiddenAttribute, canWriteSecret):
    const clientFourTier = createLanyardClient<DualRole, TestCap, TestPrefs, CustomAttrs>({
      store,
      policy: dualPolicy,
      defaultPreferences: DEFAULT_PREFS,
      storageKeyPrefix: "fourtierapp"
    });

    // Before sign-in, all permission checks return false
    expect(clientFourTier.canReadUser(GLOBAL_SCOPE)).toBe(false);
    expect(clientFourTier.canWriteUser(GLOBAL_SCOPE)).toBe(false);
    expect(clientFourTier.canAssignRoles(GLOBAL_SCOPE)).toBe(false);
    expect(clientFourTier.canReadAttribute(GLOBAL_SCOPE, "points")).toBe(false);
    expect(clientFourTier.canWriteAttribute(GLOBAL_SCOPE, "points")).toBe(false);
    expect(clientFourTier.canReadHiddenAttribute(GLOBAL_SCOPE, "moderatorNotes")).toBe(false);
    expect(clientFourTier.canWriteHiddenAttribute(GLOBAL_SCOPE, "moderatorNotes")).toBe(false);
    expect(clientFourTier.canWriteSecret(GLOBAL_SCOPE, "personalGeminiKey")).toBe(false);

    clientFourTier.setActiveUser({
      uid: "u-dual",
      email: "dual@example.com",
      emailVerified: true,
      displayName: "Dualy McDual",
      photoUrl: null,
      isAdmin: false,
      providerIds: ["google.com"]
    });

    // Unscoped ('u-dual' has roles: ['editor'] -> has 'edit_content', lacks 'invite_members'):
    expect(clientFourTier.canReadUser(GLOBAL_SCOPE)).toBe(true);
    expect(clientFourTier.canReadUser(GLOBAL_SCOPE, { isSelf: false })).toBe(true);
    expect(clientFourTier.canWriteUser(GLOBAL_SCOPE)).toBe(false);
    expect(clientFourTier.canAssignRoles(GLOBAL_SCOPE)).toBe(false);
    expect(clientFourTier.canAssignRoles("ws-alpha")).toBe(true);
    // - Attributes: self can read own 'tier' (isSelf defaults to true), cannot read another user's 'tier' ({ isSelf: false }; not staff), can write 'points' (has 'edit_content'), cannot write 'tier' (lacks 'invite_members')
    expect(clientFourTier.canReadAttribute(GLOBAL_SCOPE, "tier")).toBe(true);
    expect(clientFourTier.canReadAttribute(GLOBAL_SCOPE, "tier", { isSelf: false })).toBe(false);
    expect(clientFourTier.canWriteAttribute(GLOBAL_SCOPE, "points")).toBe(true);
    expect(clientFourTier.canWriteAttribute(GLOBAL_SCOPE, "tier")).toBe(false);
    // - HiddenAttributes: not staff (lacks 'invite_members') so cannot read 'moderatorNotes', but has 'edit_content' so CAN write 'moderatorNotes'
    expect(clientFourTier.canReadHiddenAttribute(GLOBAL_SCOPE, "moderatorNotes")).toBe(false);
    expect(clientFourTier.canWriteHiddenAttribute(GLOBAL_SCOPE, "moderatorNotes")).toBe(true);
    // - Secrets: can write own 'personalGeminiKey' (self: true), cannot write 'workspaceOpenaiKey' (no self, lacks 'invite_members')
    expect(clientFourTier.canWriteSecret(GLOBAL_SCOPE, "personalGeminiKey")).toBe(true);
    expect(clientFourTier.canWriteSecret(GLOBAL_SCOPE, "workspaceOpenaiKey")).toBe(false);

    // Scoped in 'ws-alpha' ('u-dual' is 'manager' -> has 'edit_content' + 'invite_members', so is scope staff):
    expect(clientFourTier.canReadAttribute("ws-alpha", "tier", { isSelf: false })).toBe(true);
    expect(clientFourTier.canWriteAttribute("ws-alpha", "tier")).toBe(true);
    expect(clientFourTier.canReadHiddenAttribute("ws-alpha", "moderatorNotes")).toBe(true);
    expect(clientFourTier.canWriteHiddenAttribute("ws-alpha", "moderatorNotes")).toBe(true);
    expect(clientFourTier.canWriteSecret("ws-alpha", "workspaceOpenaiKey", { isSelf: false })).toBe(true);

    // Scoped in 'ws-beta' ('u-dual' is 'owner' -> capabilities: '*'):
    expect(clientFourTier.canWriteAttribute("ws-beta", "tier")).toBe(true);
    expect(clientFourTier.canWriteSecret("ws-beta", "workspaceOpenaiKey", { isSelf: false })).toBe(true);

    // Non-member scope ('ws-unknown') or invalid scopeId ('../bad') returns false
    expect(clientFourTier.canReadAttribute("ws-unknown", "points")).toBe(false);
    expect(clientFourTier.canWriteSecret("ws-unknown", "personalGeminiKey")).toBe(false);
    expect(clientFourTier.canWriteSecret("../bad", "personalGeminiKey")).toBe(false);

    // Policy-less client fallback behavior (when policy is omitted from createLanyardClient):
    const clientNoPolicy = createLanyardClient<DualRole, TestCap, TestPrefs, CustomAttrs>({
      store,
      defaultPreferences: DEFAULT_PREFS
    });

    // While signed out, all permission checks return false
    expect(clientNoPolicy.canReadUser(GLOBAL_SCOPE)).toBe(false);
    expect(clientNoPolicy.canWriteUser(GLOBAL_SCOPE)).toBe(false);
    expect(clientNoPolicy.canAssignRoles(GLOBAL_SCOPE)).toBe(false);
    expect(clientNoPolicy.canReadAttribute(GLOBAL_SCOPE, "points")).toBe(false);
    expect(clientNoPolicy.canWriteAttribute(GLOBAL_SCOPE, "points")).toBe(false);
    expect(clientNoPolicy.canReadHiddenAttribute(GLOBAL_SCOPE, "staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteHiddenAttribute(GLOBAL_SCOPE, "staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteSecret(GLOBAL_SCOPE, "personalGeminiKey")).toBe(false);

    // Non-admin user without a policy: can read own user/attributes and write own secrets (isSelf: true),
    // but cannot read others' user/attributes, write users/attributes/hiddenAttributes, or write non-self secrets
    clientNoPolicy.setActiveUser({
      uid: "u-dual",
      email: "dual@example.com",
      emailVerified: true,
      displayName: "Dual User",
      photoUrl: null,
      isAdmin: false,
      providerIds: ["google.com"]
    });
    expect(clientNoPolicy.canReadUser(GLOBAL_SCOPE, { isSelf: true })).toBe(true);
    expect(clientNoPolicy.canReadUser(GLOBAL_SCOPE)).toBe(false);
    expect(clientNoPolicy.canReadUser(GLOBAL_SCOPE, { isSelf: false })).toBe(false);
    expect(clientNoPolicy.canWriteUser(GLOBAL_SCOPE)).toBe(false);
    expect(clientNoPolicy.canAssignRoles(GLOBAL_SCOPE)).toBe(false);
    expect(clientNoPolicy.canReadAttribute(GLOBAL_SCOPE, "points")).toBe(true);
    expect(clientNoPolicy.canReadAttribute(GLOBAL_SCOPE, "points", { isSelf: false })).toBe(false);
    expect(clientNoPolicy.canReadAttribute("ws-alpha", "points")).toBe(true);
    expect(clientNoPolicy.canReadAttribute("ws-unknown", "points")).toBe(false);
    expect(clientNoPolicy.canWriteAttribute(GLOBAL_SCOPE, "points")).toBe(false);
    expect(clientNoPolicy.canReadHiddenAttribute(GLOBAL_SCOPE, "staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteHiddenAttribute(GLOBAL_SCOPE, "staffNotes")).toBe(false);
    expect(clientNoPolicy.canWriteSecret(GLOBAL_SCOPE, "personalGeminiKey")).toBe(true);
    expect(clientNoPolicy.canWriteSecret(GLOBAL_SCOPE, "personalGeminiKey", { isSelf: false })).toBe(false);
    expect(clientNoPolicy.canWriteSecret("ws-alpha", "personalGeminiKey")).toBe(true);
    expect(clientNoPolicy.canWriteSecret("ws-unknown", "personalGeminiKey")).toBe(false);

    // System admin without a policy: allowed for all attribute/hiddenAttribute/secret operations
    clientNoPolicy.setActiveUser({
      uid: "u-admin",
      email: "admin@example.com",
      emailVerified: true,
      displayName: "Admin User",
      photoUrl: null,
      isAdmin: true,
      providerIds: ["google.com"]
    });
    expect(clientNoPolicy.canReadUser(GLOBAL_SCOPE, { isSelf: false })).toBe(true);
    expect(clientNoPolicy.canWriteUser(GLOBAL_SCOPE)).toBe(true);
    expect(clientNoPolicy.canAssignRoles(GLOBAL_SCOPE)).toBe(true);
    expect(clientNoPolicy.canReadAttribute(GLOBAL_SCOPE, "points", { isSelf: false })).toBe(true);
    expect(clientNoPolicy.canWriteAttribute(GLOBAL_SCOPE, "points")).toBe(true);
    expect(clientNoPolicy.canReadHiddenAttribute(GLOBAL_SCOPE, "staffNotes")).toBe(true);
    expect(clientNoPolicy.canWriteHiddenAttribute(GLOBAL_SCOPE, "staffNotes")).toBe(true);
    expect(clientNoPolicy.canWriteSecret("ws-unknown", "workspaceOpenaiKey", { isSelf: false })).toBe(true);

    clientNoPolicy.destroy();
    clientFourTier.destroy();
    client.destroy();
  });

  it("supports optional defaultRole (empty roles array) and indexed subscribeToSystemAdmins / subscribeToUsers({ isSystemAdmin }) on FirestoreClientStore", async () => {
    const fakeDb: any = { type: "fs" };
    // Instantiate FirestoreClientStore without defaultRole
    const fsStore = new FirestoreClientStore({
      db: fakeDb
    });

    // 1. User document without `roles` field resolves to `roles: []` when defaultRole is omitted
    let emitUserSnap!: (snap: any) => void;
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      emitUserSnap = onNext;
      return () => {};
    });

    const userEvents: any[] = [];
    const unsubUser = fsStore.subscribeToUser("u-no-role", (u) => userEvents.push(u));
    emitUserSnap({
      exists: () => true,
      data: () => ({
        uid: "u-no-role",
        email: "norole@example.com"
      })
    });
    expect(userEvents[0]?.roles).toEqual([]);
    unsubUser();

    // 2. subscribeToSystemAdmins / subscribeToUsers(GLOBAL_SCOPE, cb, { isSystemAdmin: true }) uses where("isSystemAdmin", "==", true)
    vi.mocked(firebaseFirestore.where).mockClear();
    vi.mocked(firebaseFirestore.query).mockClear();
    let emitAdminsSnap!: (snap: any) => void;
    vi.mocked(firebaseFirestore.onSnapshot).mockImplementationOnce((_ref: any, onNext: any) => {
      emitAdminsSnap = onNext;
      return () => {};
    });

    const client = createLanyardClient({
      store: fsStore,
      defaultPreferences: DEFAULT_PREFS
    });

    const adminsList: any[][] = [];
    const unsubAdmins = client.subscribeToSystemAdmins((admins) => adminsList.push(admins));

    expect(firebaseFirestore.where).toHaveBeenCalledWith("isSystemAdmin", "==", true);
    expect(firebaseFirestore.query).toHaveBeenCalledTimes(1);

    emitAdminsSnap({
      forEach: (cb: (doc: any) => void) => {
        cb({
          id: "u-admin-1",
          data: () => ({
            uid: "u-admin-1",
            email: "admin1@example.com",
            displayName: "Admin One",
            isSystemAdmin: true
          })
        });
      }
    });

    expect(adminsList).toHaveLength(1);
    // Email is private by default, so a legacy email left on the card isn't exposed through card subscriptions
    expect(adminsList[0]).toEqual([
      expect.objectContaining({
        uid: "u-admin-1",
        email: "",
        displayName: "Admin One",
        isSystemAdmin: true,
        roles: []
      })
    ]);

    unsubAdmins();
    client.destroy();
  });
});

describe("lanyard/client email verification", () => {
  function createSignedInClient(currentUser: Record<string, any> | null) {
    const fakeAuth: any = { currentUser };
    vi.mocked(firebaseAuth.onAuthStateChanged).mockImplementation(() => () => {});
    const client = createLanyardClient<TestRole, TestCap, TestPrefs>({
      auth: fakeAuth,
      store: new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>(),
      defaultPreferences: DEFAULT_PREFS
    });
    return { client, fakeAuth };
  }

  function unverifiedUser(overrides: Record<string, any> = {}) {
    return {
      uid: "u-github",
      email: "Octo@Example.com",
      emailVerified: false,
      displayName: "Octo",
      photoURL: null,
      providerData: [{ providerId: "github.com" }],
      reload: vi.fn().mockResolvedValue(undefined),
      getIdTokenResult: vi.fn().mockResolvedValue({ claims: {} }),
      ...overrides
    };
  }

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("localStorage", new MemoryLocalStorage());
    vi.stubGlobal("window", {
      location: {
        href: "https://app.example.com/campaigns#/c/abc",
        search: "",
        origin: "https://app.example.com",
        pathname: "/campaigns",
        hash: "#/c/abc"
      },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn()
    });
    vi.mocked(firebaseAuth.isSignInWithEmailLink).mockReturnValue(false);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends a verification email to the signed-in user's own address, returning to the current page by default", async () => {
    const user = unverifiedUser();
    const { client } = createSignedInClient(user);

    await expect(client.sendEmailVerificationLink()).resolves.toBe(true);
    expect(firebaseAuth.sendEmailVerification).toHaveBeenCalledTimes(1);
    expect(firebaseAuth.sendEmailVerification).toHaveBeenCalledWith(user, {
      url: "https://app.example.com/campaigns#/c/abc"
    });
    client.destroy();
  });

  it("uses a validated redirectUrl and rejects unsafe ones without sending", async () => {
    const user = unverifiedUser();
    const { client } = createSignedInClient(user);

    await client.sendEmailVerificationLink("https://app.example.com/verified");
    expect(firebaseAuth.sendEmailVerification).toHaveBeenCalledWith(user, { url: "https://app.example.com/verified" });

    vi.mocked(firebaseAuth.sendEmailVerification).mockClear();
    await expect(client.sendEmailVerificationLink("javascript:alert(1)")).rejects.toThrow(
      /protocol must be http: or https:/
    );
    await expect(client.sendEmailVerificationLink("not-a-url")).rejects.toThrow(/valid absolute http\(s\) URL/);
    expect(firebaseAuth.sendEmailVerification).not.toHaveBeenCalled();
    client.destroy();
  });

  it("does not send another email when the address is already verified", async () => {
    const { client } = createSignedInClient(unverifiedUser({ emailVerified: true }));

    await expect(client.sendEmailVerificationLink()).resolves.toBe(false);
    expect(firebaseAuth.sendEmailVerification).not.toHaveBeenCalled();
    client.destroy();
  });

  it("refuses to send when nobody is signed in, the user has no email, or Auth is not initialized", async () => {
    const signedOut = createSignedInClient(null);
    await expect(signedOut.client.sendEmailVerificationLink()).rejects.toThrow(/No authenticated user/);
    signedOut.client.destroy();

    const noEmail = createSignedInClient(unverifiedUser({ email: null }));
    await expect(noEmail.client.sendEmailVerificationLink()).rejects.toThrow(/no email address/);
    noEmail.client.destroy();

    const noAuth = createLanyardClient<TestRole, TestCap, TestPrefs>({
      store: new InMemoryLanyardStore<TestRole, TestCap, TestPrefs>(),
      defaultPreferences: DEFAULT_PREFS
    });
    await expect(noAuth.sendEmailVerificationLink()).rejects.toThrow(/No authenticated user/);
    noAuth.destroy();

    expect(firebaseAuth.sendEmailVerification).not.toHaveBeenCalled();
  });

  it("refreshEmailVerification reloads the user, forces a fresh token, and publishes the verified user", async () => {
    const user = unverifiedUser();
    user.reload.mockImplementation(async () => {
      user.emailVerified = true;
    });
    user.getIdTokenResult.mockResolvedValue({ claims: { admin: false } });
    const { client } = createSignedInClient(user);

    await expect(client.refreshEmailVerification()).resolves.toBe(true);
    expect(user.reload).toHaveBeenCalledTimes(1);
    expect(user.getIdTokenResult).toHaveBeenCalledWith(true);
    expect(user.reload.mock.invocationCallOrder[0]).toBeLessThan(user.getIdTokenResult.mock.invocationCallOrder[0]);
    expect(client.authStore.get().user).toMatchObject({
      uid: "u-github",
      email: "octo@example.com",
      emailVerified: true
    });
    client.destroy();
  });

  it("refreshEmailVerification reports false while the email is still unverified", async () => {
    const user = unverifiedUser();
    const { client } = createSignedInClient(user);

    await expect(client.refreshEmailVerification()).resolves.toBe(false);
    expect(user.getIdTokenResult).toHaveBeenCalledWith(true);
    expect(client.authStore.get().user?.emailVerified).toBe(false);
    client.destroy();
  });

  it("refreshEmailVerification refuses when nobody is signed in", async () => {
    const { client } = createSignedInClient(null);
    await expect(client.refreshEmailVerification()).rejects.toThrow(/No authenticated user/);
    client.destroy();
  });
});

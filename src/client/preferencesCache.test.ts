import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GLOBAL_SCOPE, InMemoryLanyardStore, type LanyardUser } from "../core/index.js";
import { createLanyardClient } from "./index.js";

/**
 * On a shared browser, the preferences cache must never carry one person's preferences to the next. Each signed-in
 * user's cached preferences live under their own key and are removed when their session ends (as is a pending
 * magic-link email); signed-out visitors get their own guest cache; and nobody's preferences are shown before auth
 * says whose they are.
 */

interface Prefs {
  theme: "light" | "dark" | "system";
  use12h: boolean;
  savedSearch?: string;
}
const DEFAULT_PREFS: Prefs = { theme: "system", use12h: true };

class MemoryLocalStorage {
  map = new Map<string, string>();
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

function user(uid: string): LanyardUser {
  return {
    uid,
    email: `${uid}@example.com`,
    emailVerified: true,
    displayName: uid,
    photoUrl: null,
    isAdmin: false,
    providerIds: ["password"]
  };
}

let storage: MemoryLocalStorage;
beforeEach(() => {
  storage = new MemoryLocalStorage();
  vi.stubGlobal("localStorage", storage);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function newClient(store: InMemoryLanyardStore<string, string, Prefs>) {
  return createLanyardClient<string, string, Prefs>({
    store,
    defaultPreferences: DEFAULT_PREFS,
    storageKeyPrefix: "app"
  });
}

describe("preferences cache on a shared browser", () => {
  it("signing out leaves none of the user's preferences (or pending sign-in email) behind for the next visitor", async () => {
    const store = new InMemoryLanyardStore<string, string, Prefs>();
    await store.savePreferences("alice", { theme: "dark", savedSearch: "alice's private search" });
    const client = newClient(store);
    client.setActiveUser(user("alice"));
    expect(client.preferencesStore.get()).toMatchObject({ theme: "dark", savedSearch: "alice's private search" });
    storage.setItem("app_emailForSignIn", "alice@example.com");
    expect(storage.getItem("app_user_preferences_alice")).toContain("alice's private search");

    await client.signOut();
    expect(client.preferencesStore.get()).toEqual(DEFAULT_PREFS);
    expect([...storage.map.values()].join("\n")).not.toContain("alice");

    // The next visitor loads the page on the same browser and sees defaults
    expect(newClient(store).preferencesStore.get()).toEqual(DEFAULT_PREFS);
  });

  it("a session that ends without signOut (revoked, or signed out in another tab) clears the cache too", async () => {
    const store = new InMemoryLanyardStore<string, string, Prefs>();
    await store.savePreferences("alice", { savedSearch: "alice's private search" });
    const client = newClient(store);
    client.setActiveUser(user("alice"));
    client.setActiveUser(null); // what onAuthStateChanged reports
    expect([...storage.map.values()].join("\n")).not.toContain("alice");
  });

  it("the next user never sees the previous user's preferences, even if the previous session never signed out", async () => {
    const store = new InMemoryLanyardStore<string, string, Prefs>();
    await store.savePreferences("alice", { theme: "dark", savedSearch: "alice's private search" });
    await store.savePreferences("bob", { use12h: false });
    const first = newClient(store);
    first.setActiveUser(user("alice"));

    // Same tab switches account
    first.setActiveUser(user("bob"));
    expect(first.preferencesStore.get()).toEqual({ theme: "system", use12h: false });

    // Page reload: before auth resolves, nothing of Alice's shows; then Bob signs in
    const second = newClient(store);
    expect(second.preferencesStore.get()).toEqual(DEFAULT_PREFS);
    second.setActiveUser(user("bob"));
    expect(second.preferencesStore.get()).toEqual({ theme: "system", use12h: false });
  });

  it("a signed-in user's reload paints from their own cache until the server's copy arrives", async () => {
    const store = new InMemoryLanyardStore<string, string, Prefs>();
    const first = newClient(store);
    first.setActiveUser(user("alice"));
    await first.updatePreferences(GLOBAL_SCOPE, { theme: "dark" });

    // Reload with a slow preferences listener
    let emit: ((prefs: Partial<Prefs>) => void) | undefined;
    store.subscribeToPreferences = (_uid, onChange) => {
      emit = onChange;
      return () => {};
    };
    const second = newClient(store);
    second.setActiveUser(user("alice"));
    expect(second.preferencesStore.get()).toEqual({ theme: "dark", use12h: true });
    emit!({ theme: "light" });
    expect(second.preferencesStore.get()).toEqual({ theme: "light", use12h: true });
  });

  it("signed-out visitors keep their own guest preferences, separate from any account", async () => {
    const store = new InMemoryLanyardStore<string, string, Prefs>();
    await store.savePreferences("alice", { use12h: false });
    const client = newClient(store);
    await client.updatePreferences(GLOBAL_SCOPE, { theme: "dark" });
    expect(newClient(store).preferencesStore.get()).toEqual({ theme: "dark", use12h: true });

    // Signing in shows the account's preferences, not the guest's; signing out restores the guest's
    client.setActiveUser(user("alice"));
    expect(client.preferencesStore.get()).toEqual({ theme: "system", use12h: false });
    await client.signOut();
    expect(client.preferencesStore.get()).toEqual({ theme: "dark", use12h: true });
  });

  it("removes caches left by sessions that ended while no page was open, as soon as auth says who (if anyone) is here", async () => {
    // Left behind when alice's session ended without this page running (e.g. a revocation seen on the next load)
    storage.setItem("app_user_preferences_alice", JSON.stringify({ savedSearch: "alice's private search" }));
    storage.setItem("app_user_preferences_carol", JSON.stringify({ savedSearch: "carol's private search" }));
    const store = new InMemoryLanyardStore<string, string, Prefs>();

    newClient(store).setActiveUser(null);
    expect(storage.getItem("app_user_preferences_alice")).toBeNull();

    newClient(store).setActiveUser(user("bob"));
    expect(storage.getItem("app_user_preferences_carol")).toBeNull();
    // Other apps' keys on the same origin are left alone
    storage.setItem("otherapp_user_preferences_dave", "{}");
    newClient(store).setActiveUser(null);
    expect(storage.getItem("otherapp_user_preferences_dave")).toBe("{}");
  });

  it("drops the shared cache older versions wrote, which may hold a previous user's preferences", () => {
    storage.setItem("app_user_preferences", JSON.stringify({ savedSearch: "someone's private search" }));
    const client = newClient(new InMemoryLanyardStore<string, string, Prefs>());
    expect(client.preferencesStore.get()).toEqual(DEFAULT_PREFS);
    expect(storage.getItem("app_user_preferences")).toBeNull();
  });
});

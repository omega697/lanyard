import { describe, expect, it, vi } from "vitest";
import * as firebaseAuth from "firebase/auth";
import { InMemoryLanyardStore } from "../core/index.js";
import { createLanyardClient } from "./index.js";

vi.mock("firebase/auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("firebase/auth")>()),
  onAuthStateChanged: vi.fn(() => () => {}),
  signOut: vi.fn(async () => {})
}));

/** A Firebase user double whose ID token carries `claims.admin`; forced refreshes return the current `claims`. */
function fakeUser(claims: { admin: boolean }) {
  return {
    uid: "u-1",
    email: "u1@example.com",
    emailVerified: true,
    displayName: "U One",
    photoURL: null,
    providerData: [],
    claims,
    forcedRefreshes: 0,
    async getIdToken(force?: boolean) {
      return (await this.getIdTokenResult(force)).token;
    },
    async getIdTokenResult(force?: boolean) {
      if (force) this.forcedRefreshes++;
      return { token: `token-${this.forcedRefreshes}`, claims: { iat: Math.floor(Date.now() / 1000), ...this.claims } };
    }
  };
}

async function signedInClient(store: InMemoryLanyardStore, user: ReturnType<typeof fakeUser>) {
  const lanyard = createLanyardClient({ auth: { currentUser: user } as any, store, defaultPreferences: {} });
  const listener = vi.mocked(firebaseAuth.onAuthStateChanged).mock.calls.at(-1)![1] as (u: any) => Promise<void>;
  await listener(user);
  return lanyard;
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

describe("the client's isAdmin is the Firebase claim, never the stored record", () => {
  it("a stale isSystemAdmin record doesn't make a non-admin look like an admin", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [], isSystemAdmin: true });
    const user = fakeUser({ admin: false });
    const lanyard = await signedInClient(store, user);
    await settle();

    expect(lanyard.authStore.get().user?.isAdmin).toBe(false);
    lanyard.destroy();
  });

  it("a demoted admin stops looking like an admin once their claim says so, even if their record still says admin", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [], isSystemAdmin: true });
    const user = fakeUser({ admin: true });
    const lanyard = await signedInClient(store, user);
    await settle();
    expect(lanyard.authStore.get().user?.isAdmin).toBe(true);

    // The claim is revoked; a change to the record is only a hint to refresh, and the refreshed claim decides
    user.claims = { admin: false };
    await store.upsertUser({ ...(await store.getUser("u-1"))!, firstName: "Changed" });
    await store.upsertSystemAdmin({ uid: "u-1", email: "u1@example.com", isSystemAdmin: false });
    await settle();
    expect(user.forcedRefreshes).toBeGreaterThan(0);
    expect(lanyard.authStore.get().user?.isAdmin).toBe(false);

    // Re-flipping the stale record to admin doesn't promote them in the UI
    await store.upsertSystemAdmin({ uid: "u-1", email: "u1@example.com", isSystemAdmin: true });
    await settle();
    expect(lanyard.authStore.get().user?.isAdmin).toBe(false);
    lanyard.destroy();
  });

  it("a promotion shows once the refreshed claim says admin", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [] });
    const user = fakeUser({ admin: false });
    const lanyard = await signedInClient(store, user);
    await settle();

    user.claims = { admin: true };
    await store.upsertSystemAdmin({ uid: "u-1", email: "u1@example.com", isSystemAdmin: true });
    await settle();
    expect(lanyard.authStore.get().user?.isAdmin).toBe(true);
    lanyard.destroy();
  });

  it("refreshes only when the record's admin flag changes, not on every update while it disagrees with the claim", async () => {
    const store = new InMemoryLanyardStore();
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [], isSystemAdmin: true });
    const user = fakeUser({ admin: false });
    const lanyard = await signedInClient(store, user);
    await settle();
    const afterSignIn = user.forcedRefreshes;
    expect(afterSignIn).toBeLessThanOrEqual(1);

    // Ordinary record updates (presence heartbeats, profile edits) while the record still says admin
    for (const firstName of ["A", "B", "C"]) {
      await store.patchUser("u-1", { firstName });
      await settle();
    }
    expect(user.forcedRefreshes).toBe(afterSignIn);

    // The flag itself changing is still a hint worth a refresh
    await store.deleteSystemAdmin("u-1");
    await settle();
    await store.upsertSystemAdmin({ uid: "u-1", email: "u1@example.com", isSystemAdmin: true });
    await settle();
    expect(user.forcedRefreshes).toBeGreaterThan(afterSignIn);
    lanyard.destroy();
  });
});

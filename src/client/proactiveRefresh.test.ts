import { describe, expect, it, vi } from "vitest";
import * as firebaseAuth from "firebase/auth";
import { InMemoryLanyardStore, REVOCATION_CLOCK_SKEW_MS } from "../core/index.js";
import { createLanyardClient } from "./index.js";

vi.mock("firebase/auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("firebase/auth")>()),
  onAuthStateChanged: vi.fn(() => () => {}),
  signOut: vi.fn(async () => {}),
  isSignInWithEmailLink: vi.fn(() => false)
}));

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** A Firebase user double: each forced refresh issues a new token (iat = now) with the claims from `claimsAfterRefresh`. */
function fakeUser(initial: { iat: number; admin: boolean }, claimsAfterRefresh: { admin: boolean }) {
  let claims: Record<string, any> = { iat: initial.iat, admin: initial.admin };
  return {
    uid: "u-1",
    email: "u1@example.com",
    emailVerified: true,
    displayName: "U One",
    photoURL: null,
    providerData: [],
    forcedRefreshes: 0,
    async getIdToken(force?: boolean) {
      return (await this.getIdTokenResult(force)).token;
    },
    async getIdTokenResult(force?: boolean) {
      if (force) {
        this.forcedRefreshes++;
        claims = { iat: nowSeconds(), admin: claimsAfterRefresh.admin };
      }
      return { token: `token-${claims.iat}-${this.forcedRefreshes}`, claims };
    }
  };
}

async function signedInClient(store: InMemoryLanyardStore, user: ReturnType<typeof fakeUser>) {
  const lanyard = createLanyardClient({ auth: { currentUser: user } as any, store, defaultPreferences: {} });
  const listener = vi.mocked(firebaseAuth.onAuthStateChanged).mock.calls.at(-1)![1] as (u: any) => Promise<void>;
  await listener(user);
  return { lanyard, signOut: () => listener(null) };
}

const waitFor = async (predicate: () => boolean, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs;
  while (!predicate() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  return predicate();
};

describe("proactive token refresh on revocation", () => {
  it("refreshes a token that predates a new revocation epoch, without any request, and publishes the new claims", async () => {
    const store = new InMemoryLanyardStore();
    const user = fakeUser({ iat: nowSeconds() - 600, admin: true }, { admin: false });
    const { lanyard } = await signedInClient(store, user);
    expect(lanyard.authStore.get().user?.isAdmin).toBe(true);

    // A revocation far enough in the past that no waiting is needed for the new token to be past it
    await store.bumpRevocationEpoch(Date.now() - REVOCATION_CLOCK_SKEW_MS - 1500);

    expect(await waitFor(() => user.forcedRefreshes === 1)).toBe(true);
    expect(await waitFor(() => lanyard.authStore.get().user?.isAdmin === false)).toBe(true);
    lanyard.destroy();
  });

  it("waits until a refreshed token would be past the revocation before refreshing", async () => {
    const store = new InMemoryLanyardStore();
    const user = fakeUser({ iat: nowSeconds() - 600, admin: false }, { admin: false });
    const { lanyard } = await signedInClient(store, user);
    const epoch = Date.now();
    await store.bumpRevocationEpoch(epoch);

    await new Promise((resolve) => setTimeout(resolve, REVOCATION_CLOCK_SKEW_MS / 2));
    expect(user.forcedRefreshes).toBe(0);
    expect(await waitFor(() => user.forcedRefreshes === 1, REVOCATION_CLOCK_SKEW_MS + 3000)).toBe(true);
    const iat = (await user.getIdTokenResult()).claims.iat;
    expect(iat * 1000).toBeGreaterThan(epoch + REVOCATION_CLOCK_SKEW_MS);
    lanyard.destroy();
  }, 10_000);

  it("leaves a token issued after the revocation alone, and stops watching after sign-out", async () => {
    const store = new InMemoryLanyardStore();
    await store.bumpRevocationEpoch(Date.now() - 60_000);
    const user = fakeUser({ iat: nowSeconds(), admin: false }, { admin: false });
    const { lanyard, signOut } = await signedInClient(store, user);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(user.forcedRefreshes).toBe(0);

    await signOut();
    await store.bumpRevocationEpoch(Date.now() + 60_000);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(user.forcedRefreshes).toBe(0);
    lanyard.destroy();
  });

  it("refuses to start with a store that doesn't implement subscribeToRevocationEpoch", () => {
    const partial = Object.assign(Object.create(new InMemoryLanyardStore()), { subscribeToRevocationEpoch: undefined });
    expect(() => createLanyardClient({ store: partial, defaultPreferences: {} })).toThrow(/subscribeToRevocationEpoch/);
  });
});

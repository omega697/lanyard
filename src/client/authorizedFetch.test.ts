import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as firebaseAuth from "firebase/auth";
import {
  EmailNotVerifiedError,
  EMAIL_NOT_VERIFIED_ERROR_CODE,
  InMemoryLanyardStore,
  SESSION_REVOKED_ERROR_CODE,
  SessionRevokedError,
  TOKEN_STALE_ERROR_CODE,
  TokenStaleError
} from "../core/index.js";
import { createLanyardClient } from "./index.js";

vi.mock("firebase/auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("firebase/auth")>()),
  onAuthStateChanged: vi.fn(() => () => {}),
  signOut: vi.fn(async () => {}),
  isSignInWithEmailLink: vi.fn(() => false)
}));

/** A Firebase user double whose forced refreshes walk through `tokens` in order. */
function fakeUser(tokens: Array<{ token: string; admin?: boolean }>) {
  let index = 0;
  const result = () => ({ token: tokens[index].token, claims: { admin: tokens[index].admin ?? false } });
  const advance = (force?: boolean) => {
    if (force && index < tokens.length - 1) index++;
  };
  return {
    uid: "u-1",
    email: "u1@example.com",
    emailVerified: true,
    displayName: "U One",
    photoURL: null,
    providerData: [],
    forcedRefreshes: 0,
    async getIdToken(force?: boolean) {
      if (force) this.forcedRefreshes++;
      advance(force);
      return tokens[index].token;
    },
    async getIdTokenResult(force?: boolean) {
      if (force) this.forcedRefreshes++;
      advance(force);
      return result();
    }
  };
}

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function setup(user: ReturnType<typeof fakeUser> | null, options: { staleTokenRetryDelayMs?: number } = {}) {
  const auth: any = { currentUser: user };
  const lanyard = createLanyardClient({
    auth,
    store: new InMemoryLanyardStore(),
    defaultPreferences: {},
    staleTokenRetryDelayMs: options.staleTokenRetryDelayMs ?? 10
  });
  if (user) {
    // Deliver the signed-in user the way Firebase's auth listener would
    const listener = vi.mocked(firebaseAuth.onAuthStateChanged).mock.calls.at(-1)![1] as (u: any) => Promise<void>;
    await listener(user);
  }
  return { auth, lanyard };
}

describe("authorizedFetch", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    vi.mocked(firebaseAuth.signOut).mockClear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("attaches the current ID token and passes the request through", async () => {
    const { lanyard } = await setup(fakeUser([{ token: "t1" }]));
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { ok: true }));

    const res = await lanyard.authorizedFetch("/api/thing", {
      method: "POST",
      body: JSON.stringify({ a: 1 }),
      headers: { "Content-Type": "application/json" }
    });

    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/thing");
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ a: 1 }));
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer t1");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("on auth/token-stale, forces a refresh, retries once, and publishes the refreshed claims", async () => {
    const user = fakeUser([
      { token: "admin-token", admin: true },
      { token: "demoted-token", admin: false }
    ]);
    const { lanyard } = await setup(user);
    expect(lanyard.authStore.get().user?.isAdmin).toBe(true);
    fetchMock
      .mockResolvedValueOnce(jsonResponse(401, { error: "stale", code: TOKEN_STALE_ERROR_CODE }))
      .mockResolvedValueOnce(jsonResponse(403, { error: "Forbidden" }));

    const res = await lanyard.authorizedFetch("/api/admin");

    expect(res.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(new Headers(fetchMock.mock.calls[1][1].headers).get("Authorization")).toBe("Bearer demoted-token");
    expect(lanyard.authStore.get().user?.isAdmin).toBe(false);
    expect(firebaseAuth.signOut).not.toHaveBeenCalled();
  });

  it("waits and refreshes again if the first refreshed token is still stale (same-second issue), then gives up", async () => {
    const { lanyard } = await setup(fakeUser([{ token: "t1" }, { token: "t2" }, { token: "t3" }]));
    const stale = () => jsonResponse(401, { error: "stale", code: TOKEN_STALE_ERROR_CODE });
    fetchMock
      .mockResolvedValueOnce(stale())
      .mockResolvedValueOnce(stale())
      .mockResolvedValueOnce(jsonResponse(200, {}));
    expect((await lanyard.authorizedFetch("/api/x")).status).toBe(200);
    expect(new Headers(fetchMock.mock.calls[2][1].headers).get("Authorization")).toBe("Bearer t3");

    fetchMock.mockReset();
    fetchMock.mockImplementation(async () => stale());
    await expect(lanyard.authorizedFetch("/api/x")).rejects.toBeInstanceOf(TokenStaleError);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("on auth/session-revoked, signs out locally and throws SessionRevokedError", async () => {
    const { auth, lanyard } = await setup(fakeUser([{ token: "t1" }]));
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { error: "revoked", code: SESSION_REVOKED_ERROR_CODE }));

    const error = await lanyard.authorizedFetch("/api/x").catch((e) => e);

    expect(error).toBeInstanceOf(SessionRevokedError);
    expect(error.code).toBe(SESSION_REVOKED_ERROR_CODE);
    expect(firebaseAuth.signOut).toHaveBeenCalledWith(auth);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("on auth/email-not-verified, throws EmailNotVerifiedError without retrying", async () => {
    const user = fakeUser([{ token: "t1" }]);
    const { lanyard } = await setup(user);
    const refreshesBefore = user.forcedRefreshes;
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { error: "verify", code: EMAIL_NOT_VERIFIED_ERROR_CODE }));

    const error = await lanyard.authorizedFetch("/api/x").catch((e) => e);

    expect(error).toBeInstanceOf(EmailNotVerifiedError);
    expect(error.code).toBe(EMAIL_NOT_VERIFIED_ERROR_CODE);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(user.forcedRefreshes).toBe(refreshesBefore);
  });

  it("returns other responses untouched (401 without a code, 403, 500, non-JSON bodies)", async () => {
    const { lanyard } = await setup(fakeUser([{ token: "t1" }]));
    for (const res of [
      jsonResponse(401, { error: "Unauthorized" }),
      jsonResponse(403, { error: "Forbidden" }),
      jsonResponse(500, { error: "boom" }),
      new Response("not json", { status: 401 })
    ]) {
      fetchMock.mockResolvedValueOnce(res);
      expect((await lanyard.authorizedFetch("/api/x")).status).toBe(res.status);
    }
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(firebaseAuth.signOut).not.toHaveBeenCalled();
  });

  it("retries a Request object with its body intact", async () => {
    const { lanyard } = await setup(fakeUser([{ token: "t1" }, { token: "t2" }]));
    fetchMock
      .mockResolvedValueOnce(jsonResponse(401, { error: "stale", code: TOKEN_STALE_ERROR_CODE }))
      .mockResolvedValueOnce(jsonResponse(200, {}));

    await lanyard.authorizedFetch(new Request("http://localhost/api/x", { method: "POST", body: "payload" }));

    const retried = fetchMock.mock.calls[1][0] as Request;
    expect(await retried.text()).toBe("payload");
    expect(retried.headers.get("Authorization")).toBe("Bearer t2");
  });

  it("refuses to send a request without a signed-in user", async () => {
    const { lanyard } = await setup(null);
    await expect(lanyard.authorizedFetch("/api/x")).rejects.toThrow(/No authenticated user/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

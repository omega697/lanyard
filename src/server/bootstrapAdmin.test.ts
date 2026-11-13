import { describe, expect, it, vi } from "vitest";
import { InMemoryLanyardStore, createPermissionPolicy } from "../core/index.js";
import { createLanyardServer, type AdminAuthAdapter } from "./index.js";

/**
 * bootstrapFirstAdmin is the trusted way to create the very first admin (e.g. from a setup script). It refuses once any
 * admin exists, whether recorded in the store's directory or known only by a Firebase claim, and only promotes an
 * existing account whose email is verified, so it can't be used to mint an admin later or to claim someone's address.
 */

interface FakeAccount {
  uid: string;
  email: string;
  emailVerified: boolean;
  disabled?: boolean;
  customClaims?: Record<string, any>;
}

function fakeAdminAuth(accounts: FakeAccount[]) {
  return {
    verifyIdToken: async () => {
      throw new Error("not used");
    },
    getUserByEmail: async (email: string) => {
      const account = accounts.find((a) => a.email === email);
      if (!account) throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
      return { ...account };
    },
    createUser: vi.fn(async () => ({ uid: "should-not-be-created" })),
    setCustomUserClaims: vi.fn(async (uid: string, claims: Record<string, any> | null) => {
      const account = accounts.find((a) => a.uid === uid)!;
      account.customClaims = { ...(claims || {}) };
    }),
    getUser: async (uid: string) => {
      const account = accounts.find((a) => a.uid === uid);
      if (!account) throw Object.assign(new Error("User not found"), { code: "auth/user-not-found" });
      return { uid, customClaims: account.customClaims ?? {} };
    },
    // Pages of two, to exercise paging
    listUsers: async (maxResults?: number, pageToken?: string) => {
      const start = pageToken ? Number(pageToken) : 0;
      const size = Math.min(maxResults ?? 1000, 2);
      const users = accounts.slice(start, start + size).map((a) => ({ uid: a.uid, customClaims: a.customClaims }));
      return { users, ...(start + size < accounts.length ? { pageToken: String(start + size) } : {}) };
    }
  } satisfies AdminAuthAdapter;
}

const policy = createPermissionPolicy({ roles: { member: { capabilities: [] } } });

function setup(accounts: FakeAccount[]) {
  const store = new InMemoryLanyardStore({ policy });
  const adminAuth = fakeAdminAuth(accounts);
  const server = createLanyardServer({ adminAuth, store, policy });
  return { store, adminAuth, server };
}

describe("bootstrapFirstAdmin", () => {
  it("promotes an existing, verified account when there are no admins, keeping its other claims", async () => {
    const accounts: FakeAccount[] = [
      { uid: "u-1", email: "a@example.com", emailVerified: true },
      { uid: "u-2", email: "b@example.com", emailVerified: true },
      { uid: "u-3", email: "founder@example.com", emailVerified: true, customClaims: { plan: "pro" } }
    ];
    const { store, server } = setup(accounts);
    try {
      const profile = await server.bootstrapFirstAdmin({ email: " Founder@Example.com " });
      expect(profile).toMatchObject({
        uid: "u-3",
        email: "founder@example.com",
        isSystemAdmin: true,
        addedBy: "bootstrap"
      });
      expect(accounts[2].customClaims).toEqual({ plan: "pro", admin: true });
      expect(await store.getSystemAdmin("u-3")).toMatchObject({ isSystemAdmin: true });
    } finally {
      server.close();
    }
  });

  it("refuses once an admin exists, including one known only by their Firebase claim", async () => {
    const accounts: FakeAccount[] = [
      { uid: "u-1", email: "a@example.com", emailVerified: true },
      { uid: "u-2", email: "b@example.com", emailVerified: true },
      // On the second page, with no directory entry (e.g. promoted in the Firebase console)
      { uid: "u-admin", email: "admin@example.com", emailVerified: true, customClaims: { admin: true } },
      { uid: "u-4", email: "late@example.com", emailVerified: true }
    ];
    const { adminAuth, server } = setup(accounts);
    try {
      await expect(server.bootstrapFirstAdmin({ email: "late@example.com" })).rejects.toThrow(
        /an admin already exists/
      );
      expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
    } finally {
      server.close();
    }
  });

  it("goes by Firebase claims, not the directory: a stale directory entry with no claim behind it doesn't lock it out", async () => {
    const accounts: FakeAccount[] = [
      { uid: "u-old", email: "old@example.com", emailVerified: true },
      { uid: "u-1", email: "a@example.com", emailVerified: true }
    ];
    const { store, server } = setup(accounts);
    // u-old's claim was removed elsewhere, but their directory entry was left behind
    await store.upsertSystemAdmin({ uid: "u-old", email: "old@example.com", isSystemAdmin: true });
    try {
      await server.bootstrapFirstAdmin({ email: "a@example.com" });
      expect(accounts[1].customClaims?.admin).toBe(true);
    } finally {
      server.close();
    }
  });

  it("names the account whose admin claim blocks it", async () => {
    const accounts: FakeAccount[] = [
      { uid: "u-admin", email: "admin@example.com", emailVerified: true, customClaims: { admin: true } },
      { uid: "u-1", email: "a@example.com", emailVerified: true }
    ];
    const { server } = setup(accounts);
    try {
      await expect(server.bootstrapFirstAdmin({ email: "a@example.com" })).rejects.toThrow(/'u-admin'/);
    } finally {
      server.close();
    }
  });

  it("refuses a disabled account, which couldn't sign in to use admin powers", async () => {
    const accounts: FakeAccount[] = [{ uid: "u-1", email: "a@example.com", emailVerified: true, disabled: true }];
    const { adminAuth, server } = setup(accounts);
    try {
      await expect(server.bootstrapFirstAdmin({ email: "a@example.com" })).rejects.toThrow(/disabled/);
      expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
    } finally {
      server.close();
    }
  });

  it("if the directory write fails after the claim is set, the new admin can finish it with setSystemAdminStatus", async () => {
    const accounts: FakeAccount[] = [{ uid: "u-1", email: "a@example.com", emailVerified: true }];
    const { store, server } = setup(accounts);
    const realUpsert = store.upsertSystemAdmin.bind(store);
    store.upsertSystemAdmin = async () => {
      throw new Error("store unavailable");
    };
    try {
      await expect(server.bootstrapFirstAdmin({ email: "a@example.com" })).rejects.toThrow(/store unavailable/);
      // The claim is set (the authority), so bootstrap won't run again...
      expect(accounts[0].customClaims?.admin).toBe(true);
      await expect(server.bootstrapFirstAdmin({ email: "a@example.com" })).rejects.toThrow(/an admin already exists/);
      // ...and the new admin completes their own directory entry
      store.upsertSystemAdmin = realUpsert;
      await server.setSystemAdminStatus({ email: "a@example.com", isAdmin: true, actor: { uid: "u-1" } });
      expect(await store.getSystemAdmin("u-1")).toMatchObject({ isSystemAdmin: true });
    } finally {
      server.close();
    }
  });

  it("refuses without changing anything if listing accounts fails partway, or a custom adapter repeats a page", async () => {
    const accounts: FakeAccount[] = [
      { uid: "u-1", email: "a@example.com", emailVerified: true },
      { uid: "u-2", email: "b@example.com", emailVerified: true },
      { uid: "u-3", email: "c@example.com", emailVerified: true }
    ];
    const failing = fakeAdminAuth(accounts);
    const realList = failing.listUsers;
    failing.listUsers = async (max?: number, token?: string) => {
      if (token) throw new Error("listing failed");
      return realList(max, token);
    };
    const repeating = fakeAdminAuth(accounts);
    repeating.listUsers = async () => ({ users: [], pageToken: "same" });
    // A longer cycle: a -> b -> a
    const cycling = fakeAdminAuth(accounts);
    cycling.listUsers = async (_max?: number, token?: string) => ({ users: [], pageToken: token === "a" ? "b" : "a" });
    for (const [adminAuth, reason] of [
      [failing, /listing failed/],
      [repeating, /page token it had already returned/],
      [cycling, /page token it had already returned/]
    ] as const) {
      const server = createLanyardServer({ adminAuth, store: new InMemoryLanyardStore({ policy }), policy });
      try {
        await expect(server.bootstrapFirstAdmin({ email: "a@example.com" })).rejects.toThrow(reason);
        expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
      } finally {
        server.close();
      }
    }
  });

  it("can't be used twice", async () => {
    const accounts: FakeAccount[] = [
      { uid: "u-1", email: "a@example.com", emailVerified: true },
      { uid: "u-2", email: "b@example.com", emailVerified: true }
    ];
    const { server } = setup(accounts);
    try {
      await server.bootstrapFirstAdmin({ email: "a@example.com" });
      await expect(server.bootstrapFirstAdmin({ email: "b@example.com" })).rejects.toThrow(/an admin already exists/);
      expect(accounts[1].customClaims?.admin).toBeUndefined();
    } finally {
      server.close();
    }
  });

  it("never creates an account, and refuses one whose email isn't verified", async () => {
    const accounts: FakeAccount[] = [{ uid: "u-1", email: "squatter@example.com", emailVerified: false }];
    const { adminAuth, server } = setup(accounts);
    try {
      await expect(server.bootstrapFirstAdmin({ email: "nobody@example.com" })).rejects.toThrow(
        /no account for 'nobody@example\.com'/
      );
      expect(adminAuth.createUser).not.toHaveBeenCalled();
      await expect(server.bootstrapFirstAdmin({ email: "squatter@example.com" })).rejects.toThrow(/not verified/);
      expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
    } finally {
      server.close();
    }
  });

  it("needs adminAuth.listUsers to rule out claim-only admins", async () => {
    const accounts: FakeAccount[] = [{ uid: "u-1", email: "a@example.com", emailVerified: true }];
    const { listUsers: _omitted, ...withoutListUsers } = fakeAdminAuth(accounts);
    const server = createLanyardServer({
      adminAuth: withoutListUsers,
      store: new InMemoryLanyardStore({ policy }),
      policy
    });
    try {
      await expect(server.bootstrapFirstAdmin({ email: "a@example.com" })).rejects.toThrow(/adminAuth\.listUsers/);
    } finally {
      server.close();
    }
  });
});

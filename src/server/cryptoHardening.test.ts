import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemoryLanyardStore, createPermissionPolicy } from "../core/index.js";
import { FirestoreServerStore } from "./firestore.js";
import { createSecretCipher, decryptSecret, encryptSecret } from "./encryption.js";

/**
 * The built-in AES-256-GCM cipher must authenticate every secret with a full 16-byte tag and refuse malformed
 * envelopes, and one unreadable secret mustn't make a user's other secrets unreadable.
 */

const KEY = "crypto-hardening-test-key";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("built-in secret cipher", () => {
  const cipher = createSecretCipher(KEY);

  it("refuses a truncated auth tag, which would make forging a secret far easier", () => {
    const encrypted = cipher.encrypt("sk-live-123");
    // A 4-byte prefix of the real tag, which Node's GCM accepts by default. The envelope check refuses it before
    // decryption; pinning authTagLength to 16 is a second guard that this test can't observe separately.
    expect(() => cipher.decrypt({ ...encrypted, tag: encrypted.tag.slice(0, 8) })).toThrow();
    expect(() => decryptSecret({ ...encrypted, tag: encrypted.tag.slice(0, 24) }, KEY)).toThrow();
    expect(cipher.decrypt(encrypted)).toBe("sk-live-123");
  });

  it("refuses envelopes whose IV, tag or ciphertext isn't well-formed hex of the right length", () => {
    const encrypted = cipher.encrypt("sk-live-123");
    const malformed = [
      { ...encrypted, iv: encrypted.iv.slice(0, 22) }, // 11-byte IV
      { ...encrypted, iv: `${encrypted.iv}00` }, // 13-byte IV
      { ...encrypted, iv: `zz${encrypted.iv.slice(2)}` }, // not hex (Buffer.from would silently drop it)
      { ...encrypted, tag: `${encrypted.tag}00` }, // 17-byte tag
      { ...encrypted, tag: `${encrypted.tag.slice(0, 30)}zz` },
      { ...encrypted, ciphertext: `${encrypted.ciphertext}0` }, // odd length
      { ...encrypted, ciphertext: `zz${encrypted.ciphertext}` }
    ];
    for (const envelope of malformed) {
      expect(() => cipher.decrypt(envelope)).toThrow(/Invalid encrypted secret payload/);
    }
  });

  it("still round-trips, including an empty string", () => {
    expect(cipher.decrypt(cipher.encrypt(""))).toBe("");
    expect(decryptSecret(encryptSecret("héllo", KEY), KEY)).toBe("héllo");
  });
});

describe("decrypting a user's secrets", () => {
  const policy = createPermissionPolicy({
    roles: { member: { capabilities: [] } },
    secretCapabilities: { geminiKey: { self: true }, openaiKey: { self: true }, anthropicKey: { self: true } }
  });

  function fakeDb() {
    const docs = new Map<string, Record<string, any>>();
    const db: any = {
      doc(path: string) {
        return {
          path,
          async get() {
            const data = docs.get(path);
            return { id: path.split("/").pop()!, exists: Boolean(data), data: () => (data ? { ...data } : undefined) };
          },
          async set(payload: Record<string, any>, options?: { merge?: boolean }) {
            docs.set(path, { ...(options?.merge ? docs.get(path) || {} : {}), ...payload });
          }
        };
      }
    };
    return { db, docs };
  }

  it("FirestoreServerStore skips a corrupt secret with a warning and still returns the others", async () => {
    const { db, docs } = fakeDb();
    const store = new FirestoreServerStore({ db, policy, encryptionKey: KEY });
    await store.updateUserSecrets("u-1", { geminiKey: "AIza-1", openaiKey: "sk-1", anthropicKey: "sk-ant-1" });
    const raw = docs.get("users/u-1/private/secrets")!;
    docs.set("users/u-1/private/secrets", { ...raw, openaiKey: { ...raw.openaiKey, tag: "00".repeat(16) } });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(await store.getUserSecrets("u-1")).toEqual({ geminiKey: "AIza-1", anthropicKey: "sk-ant-1" });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("Couldn't decrypt secret 'openaiKey'"));
    expect(warn.mock.calls.join("\n")).not.toContain("sk-");
  });

  it("InMemoryLanyardStore does the same", async () => {
    const cipher = createSecretCipher(KEY);
    let corruptNext = false;
    const flakyCipher = {
      encrypt: (plaintext: string) => {
        const encrypted = cipher.encrypt(plaintext);
        if (!corruptNext) return encrypted;
        corruptNext = false;
        return { ...encrypted, tag: "00".repeat(16) };
      },
      decrypt: cipher.decrypt
    };
    const store = new InMemoryLanyardStore({ policy, cipher: flakyCipher });
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [] });
    await store.updateUserSecrets("u-1", { geminiKey: "AIza-1" });
    corruptNext = true;
    await store.updateUserSecrets("u-1", { openaiKey: "sk-1" });
    vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(await store.getUserSecrets("u-1")).toEqual({ geminiKey: "AIza-1" });
  });

  it("InMemoryLanyardStore counts a malformed stored value as a failure too, rather than dropping it silently", async () => {
    const cipher = createSecretCipher(KEY);
    let malformedNext = false;
    const store = new InMemoryLanyardStore({
      policy,
      cipher: {
        encrypt: (plaintext: string) =>
          malformedNext ? ({ iv: "not-an-envelope" } as any) : cipher.encrypt(plaintext),
        decrypt: cipher.decrypt
      }
    });
    await store.upsertUser({ uid: "u-1", email: "u1@example.com", roles: [] });
    await store.updateUserSecrets("u-1", { geminiKey: "AIza-1" });
    malformedNext = true;
    await store.updateUserSecrets("u-1", { openaiKey: "sk-1" });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(await store.getUserSecrets("u-1")).toEqual({ geminiKey: "AIza-1" });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("Couldn't decrypt secret 'openaiKey'"));
    await store.updateUserSecrets("u-1", { geminiKey: "" });
    await expect(store.getUserSecrets("u-1")).rejects.toThrow(/Couldn't decrypt any secret/);
  });

  it("still fails loudly when nothing can be decrypted, which usually means the wrong master key", async () => {
    const { db } = fakeDb();
    await new FirestoreServerStore({ db, policy, encryptionKey: KEY }).updateUserSecrets("u-1", {
      geminiKey: "AIza-1",
      openaiKey: "sk-1"
    });
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const wrongKey = new FirestoreServerStore({ db, policy, encryptionKey: "some-other-key" });
    await expect(wrongKey.getUserSecrets("u-1")).rejects.toThrow(/Couldn't decrypt any secret.*master encryption key/);
  });
});

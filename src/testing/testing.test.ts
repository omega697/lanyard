import { describe, expect, it } from "vitest";
import { InMemoryLanyardStore, SESSION_REVOCATION_RETENTION_MS } from "../core/index.js";
import { assertRevocationEpochConformance, assertSessionRevocationConformance } from "./index.js";

describe("revocation epoch store contract", () => {
  it("InMemoryLanyardStore conforms to the revocation epoch contract (server and client sides)", async () => {
    const store = new InMemoryLanyardStore();
    await assertRevocationEpochConformance({ serverStore: store, clientStore: store });
  });

  it("rejects a store whose epoch moves backwards", async () => {
    let epoch: number | null = null;
    const listeners = new Set<(epochMs: number | null) => void>();
    const regressingStore = {
      getRevocationEpoch: async () => epoch,
      bumpRevocationEpoch: async (atMs: number) => {
        if (!Number.isInteger(atMs) || atMs < 0) throw new Error("invalid");
        epoch = atMs; // Bug under test: overwrites instead of keeping the max
        listeners.forEach((l) => l(epoch));
        return epoch;
      },
      subscribeToRevocationEpoch: (onChange: (epochMs: number | null) => void) => {
        listeners.add(onChange);
        onChange(epoch);
        return () => listeners.delete(onChange);
      }
    };

    await expect(assertRevocationEpochConformance({ serverStore: regressingStore, timeoutMs: 500 })).rejects.toThrow(
      /older timestamp must keep/
    );
  });
});

describe("session revocation store contract", () => {
  it("InMemoryLanyardStore conforms to the session revocation contract", async () => {
    await assertSessionRevocationConformance({ serverStore: new InMemoryLanyardStore() });
  });

  it("rejects a store that never prunes expired session revocations", async () => {
    let revocations: Record<string, number> = {};
    const listeners = new Set<(r: Record<string, number>) => void>();
    const neverPrunes = {
      getSessionRevocations: async () => ({ ...revocations }),
      recordSessionRevocation: async (uid: string, atMs: number) => {
        if (!uid || /[/]|^\.\.?$/.test(uid) || !Number.isInteger(atMs) || atMs < 0) throw new Error("invalid");
        // Bug under test: keeps every entry forever
        revocations = { ...revocations, [uid]: Math.max(revocations[uid] ?? 0, atMs) };
        listeners.forEach((l) => l({ ...revocations }));
        return { ...revocations };
      },
      subscribeToSessionRevocations: (onChange: (r: Record<string, number>) => void) => {
        listeners.add(onChange);
        onChange({ ...revocations });
        return () => listeners.delete(onChange);
      }
    };

    await expect(assertSessionRevocationConformance({ serverStore: neverPrunes, timeoutMs: 500 })).rejects.toThrow(
      /pruned map|must be pruned/
    );
  });

  it("keeps the retention window at 24 hours", () => {
    expect(SESSION_REVOCATION_RETENTION_MS).toBe(24 * 60 * 60 * 1000);
  });
});

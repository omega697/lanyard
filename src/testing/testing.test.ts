import { describe, expect, it } from "vitest";
import { InMemoryLanyardStore } from "../core/index.js";
import { assertRevocationEpochConformance } from "./index.js";

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

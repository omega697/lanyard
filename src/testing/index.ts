import type { LanyardClientStore, LanyardServerStore } from "../core/index.js";

/** Options for {@link assertRevocationEpochConformance}. */
export interface RevocationEpochConformanceOptions {
  /** A server store with no revocation recorded yet (a fresh store, or a fresh namespace in a shared backend). */
  serverStore: Pick<LanyardServerStore, "getRevocationEpoch" | "bumpRevocationEpoch" | "subscribeToRevocationEpoch">;
  /** Optional client store backed by the same data as `serverStore`, checked for live updates too. */
  clientStore?: Pick<LanyardClientStore, "subscribeToRevocationEpoch">;
  /** How long to wait for a subscription to deliver an expected value, in milliseconds (default 5000). */
  timeoutMs?: number;
}

type EpochSubscribe = (onChange: (epochMs: number | null) => void, onError: (error: unknown) => void) => () => void;

function fail(message: string): never {
  throw new Error(`Revocation epoch conformance: ${message}`);
}

/** Subscribes until a delivered value satisfies `predicate`, failing on a subscription error or timeout. */
function waitForEpoch(
  subscribe: EpochSubscribe,
  predicate: (epochMs: number | null) => boolean,
  timeoutMs: number,
  description: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let unsubscribe: (() => void) | undefined;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // The initial emission may arrive synchronously, before subscribe() has returned its unsubscribe function
      queueMicrotask(() => unsubscribe?.());
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(
      () => finish(new Error(`Revocation epoch conformance: timed out waiting for ${description}`)),
      timeoutMs
    );
    unsubscribe = subscribe(
      (epochMs) => {
        if (predicate(epochMs)) finish();
      },
      (error) =>
        finish(
          new Error(`Revocation epoch conformance: subscription errored while waiting for ${description}: ${error}`)
        )
    );
    if (settled) unsubscribe();
  });
}

/**
 * Verifies that a store implements the revocation epoch contract Lanyard relies on for immediate revocation:
 * a monotonic "most recent revocation" timestamp (epoch milliseconds, `null` when nothing has been revoked) that
 * never moves backwards, rejects invalid values, and is delivered live to server and client subscribers.
 *
 * Framework-agnostic: call it from any test runner and it rejects with a descriptive error on the first violation.
 * Pass a store with no revocation recorded yet.
 */
export async function assertRevocationEpochConformance(options: RevocationEpochConformanceOptions): Promise<void> {
  const { serverStore, clientStore, timeoutMs = 5000 } = options;
  const serverSubscribe: EpochSubscribe = (onChange, onError) =>
    serverStore.subscribeToRevocationEpoch(onChange, onError);

  if ((await serverStore.getRevocationEpoch()) !== null) {
    fail("getRevocationEpoch() must resolve null when no revocation has been recorded (pass a fresh store)");
  }
  await waitForEpoch(serverSubscribe, (v) => v === null, timeoutMs, "the initial null emission from the server store");

  const t1 = 1_700_000_000_000;
  if ((await serverStore.bumpRevocationEpoch(t1)) !== t1) {
    fail(`bumpRevocationEpoch(${t1}) must resolve the stored epoch ${t1}`);
  }
  if ((await serverStore.getRevocationEpoch()) !== t1) fail(`getRevocationEpoch() must resolve ${t1} after a bump`);

  if ((await serverStore.bumpRevocationEpoch(t1 - 1000)) !== t1) {
    fail("bumpRevocationEpoch() with an older timestamp must keep (and resolve) the newer stored epoch");
  }
  if ((await serverStore.getRevocationEpoch()) !== t1) fail("the epoch must never move backwards");

  await Promise.all([
    serverStore.bumpRevocationEpoch(t1 + 3000),
    serverStore.bumpRevocationEpoch(t1 + 1000),
    serverStore.bumpRevocationEpoch(t1 + 2000)
  ]);
  if ((await serverStore.getRevocationEpoch()) !== t1 + 3000) {
    fail("concurrent bumps must leave the largest timestamp stored");
  }

  for (const invalid of [Number.NaN, -1, Number.POSITIVE_INFINITY, 1.5]) {
    let rejected = false;
    try {
      await serverStore.bumpRevocationEpoch(invalid);
    } catch {
      rejected = true;
    }
    if (!rejected) fail(`bumpRevocationEpoch(${invalid}) must reject: epochs are non-negative integer milliseconds`);
  }
  if ((await serverStore.getRevocationEpoch()) !== t1 + 3000) fail("a rejected bump must not change the epoch");

  await waitForEpoch(
    serverSubscribe,
    (v) => v === t1 + 3000,
    timeoutMs,
    "a new server subscription to deliver the current epoch"
  );

  // A live subscription must see later bumps
  const sawLiveBump = waitForEpoch(
    serverSubscribe,
    (v) => v === t1 + 4000,
    timeoutMs,
    "a live server subscription to deliver a later bump"
  );
  await serverStore.bumpRevocationEpoch(t1 + 4000);
  await sawLiveBump;

  if (clientStore) {
    const clientSubscribe: EpochSubscribe = (onChange, onError) =>
      clientStore.subscribeToRevocationEpoch(onChange, onError);
    await waitForEpoch(
      clientSubscribe,
      (v) => v === t1 + 4000,
      timeoutMs,
      "a client subscription to deliver the current epoch"
    );
    const clientSawLiveBump = waitForEpoch(
      clientSubscribe,
      (v) => v === t1 + 5000,
      timeoutMs,
      "a live client subscription to deliver a server bump"
    );
    await serverStore.bumpRevocationEpoch(t1 + 5000);
    await clientSawLiveBump;
  }

  // Unsubscribing must stop delivery
  const latest = clientStore ? t1 + 5000 : t1 + 4000;
  const received: Array<number | null> = [];
  let initialDelivered: () => void = () => {};
  const initial = new Promise<void>((resolve) => (initialDelivered = resolve));
  const unsubscribe = serverStore.subscribeToRevocationEpoch(
    (epochMs) => {
      received.push(epochMs);
      if (epochMs === latest) initialDelivered();
    },
    () => {}
  );
  const deliveredInitial = await Promise.race([
    initial.then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), timeoutMs))
  ]);
  unsubscribe();
  if (!deliveredInitial) fail(`timed out waiting for a new server subscription to deliver the current epoch ${latest}`);
  const deliveredBeforeUnsubscribe = received.length;
  await serverStore.bumpRevocationEpoch(latest + 1000);
  await new Promise((resolve) => setTimeout(resolve, Math.min(250, timeoutMs)));
  if (received.length !== deliveredBeforeUnsubscribe)
    fail("a subscription must not deliver values after unsubscribing");
}

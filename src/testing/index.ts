import { SESSION_REVOCATION_RETENTION_MS, type LanyardClientStore, type LanyardServerStore } from "../core/index.js";

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

/** Options for {@link assertSessionRevocationConformance}. */
export interface SessionRevocationConformanceOptions {
  /** A server store with no session revocations recorded yet. */
  serverStore: Pick<
    LanyardServerStore,
    "getSessionRevocations" | "recordSessionRevocation" | "subscribeToSessionRevocations"
  >;
  /** How long to wait for a subscription to deliver an expected value, in milliseconds (default 5000). */
  timeoutMs?: number;
}

type SessionRevocations = Readonly<Record<string, number>>;

function sameRevocations(actual: SessionRevocations, expected: SessionRevocations): boolean {
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, i) => key === expectedKeys[i] && actual[key] === expected[key])
  );
}

function describeRevocations(revocations: SessionRevocations): string {
  return JSON.stringify(Object.fromEntries(Object.entries(revocations).sort(([a], [b]) => a.localeCompare(b))));
}

/**
 * Verifies that a store implements the session revocation contract Lanyard relies on to cut off signed-out and
 * disabled users: a map of uid to the time (epoch milliseconds) their sessions were revoked, where each user's entry
 * only moves forward, entries older than {@link SESSION_REVOCATION_RETENTION_MS} relative to a newly recorded
 * revocation are pruned in the same atomic write, invalid input is rejected, and changes are delivered live.
 *
 * Framework-agnostic: rejects with a descriptive error on the first violation. Pass a store with no session
 * revocations recorded yet.
 */
export async function assertSessionRevocationConformance(options: SessionRevocationConformanceOptions): Promise<void> {
  const { serverStore, timeoutMs = 5000 } = options;
  const failSession = (message: string): never => {
    throw new Error(`Session revocation conformance: ${message}`);
  };
  const expectRevocations = async (expected: SessionRevocations, context: string) => {
    const actual = await serverStore.getSessionRevocations();
    if (!sameRevocations(actual, expected)) {
      failSession(`${context}: expected ${describeRevocations(expected)}, got ${describeRevocations(actual)}`);
    }
  };
  const waitForRevocations = (expected: SessionRevocations, description: string) =>
    new Promise<void>((resolve, reject) => {
      let settled = false;
      let unsubscribe: (() => void) | undefined;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        queueMicrotask(() => unsubscribe?.());
        if (error) reject(error);
        else resolve();
      };
      const timer = setTimeout(
        () => finish(new Error(`Session revocation conformance: timed out waiting for ${description}`)),
        timeoutMs
      );
      unsubscribe = serverStore.subscribeToSessionRevocations(
        (revocations) => {
          if (sameRevocations(revocations, expected)) finish();
        },
        (error) =>
          finish(
            new Error(`Session revocation conformance: subscription errored while waiting for ${description}: ${error}`)
          )
      );
      if (settled) unsubscribe();
    });

  await expectRevocations({}, "a fresh store must have no session revocations (pass a fresh store)");
  await waitForRevocations({}, "the initial empty emission");

  const t = 1_700_000_000_000;
  const recorded = await serverStore.recordSessionRevocation("u-one", t);
  if (!sameRevocations(recorded, { "u-one": t })) {
    failSession(`recordSessionRevocation must resolve the stored map, got ${describeRevocations(recorded)}`);
  }
  await expectRevocations({ "u-one": t }, "after recording a revocation");

  await serverStore.recordSessionRevocation("u-one", t - 1000);
  await expectRevocations({ "u-one": t }, "an older revocation for the same user must not move it backwards");

  await Promise.all([
    serverStore.recordSessionRevocation("u-two", t + 1),
    serverStore.recordSessionRevocation("u-three", t + 2)
  ]);
  await expectRevocations(
    { "u-one": t, "u-two": t + 1, "u-three": t + 2 },
    "concurrent revocations for different users must all be kept"
  );

  for (const [uid, atMs] of [
    ["", t],
    ["a/b", t],
    ["..", t],
    ["u-ok", Number.NaN],
    ["u-ok", -1],
    ["u-ok", 1.5]
  ] as const) {
    let rejected = false;
    try {
      await serverStore.recordSessionRevocation(uid, atMs);
    } catch {
      rejected = true;
    }
    if (!rejected) failSession(`recordSessionRevocation(${JSON.stringify(uid)}, ${atMs}) must reject`);
  }
  await expectRevocations(
    { "u-one": t, "u-two": t + 1, "u-three": t + 2 },
    "rejected revocations must not change the map"
  );

  // Pruning happens relative to the newly recorded revocation: entries older than the retention window go, newer stay
  const recent = t + 6000;
  await serverStore.recordSessionRevocation("u-recent", recent);
  const later = t + SESSION_REVOCATION_RETENTION_MS + 5000;
  const live = waitForRevocations(
    { "u-recent": recent, "u-later": later },
    "a live subscription to see the pruned map"
  );
  await serverStore.recordSessionRevocation("u-later", later);
  await live;
  await expectRevocations(
    { "u-recent": recent, "u-later": later },
    `entries older than ${SESSION_REVOCATION_RETENTION_MS} ms before a new revocation must be pruned, newer ones kept`
  );

  // Unsubscribing must stop delivery
  let deliveries = 0;
  let initialDelivered: () => void = () => {};
  const initial = new Promise<void>((resolve) => (initialDelivered = resolve));
  const unsubscribe = serverStore.subscribeToSessionRevocations(
    () => {
      deliveries++;
      initialDelivered();
    },
    () => {}
  );
  const deliveredInitial = await Promise.race([
    initial.then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), timeoutMs))
  ]);
  unsubscribe();
  if (!deliveredInitial) failSession("timed out waiting for a new subscription to deliver the current map");
  const deliveredBeforeUnsubscribe = deliveries;
  await serverStore.recordSessionRevocation("u-after-unsubscribe", later + 1);
  await new Promise((resolve) => setTimeout(resolve, Math.min(250, timeoutMs)));
  if (deliveries !== deliveredBeforeUnsubscribe) failSession("a subscription must not deliver after unsubscribing");
}

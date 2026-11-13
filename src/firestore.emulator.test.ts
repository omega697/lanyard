import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { type Server as HttpServer } from "node:http";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import express from "express";
import {
  deleteApp as deleteAdminApp,
  initializeApp as initializeAdminApp,
  type App as AdminApp
} from "firebase-admin/app";
import { getAuth as getAdminAuth, type Auth as AdminAuth } from "firebase-admin/auth";
import { getFirestore as getAdminFirestore, type Firestore as AdminFirestore } from "firebase-admin/firestore";
import { deleteApp as deleteClientApp, initializeApp as initializeClientApp, type FirebaseApp } from "firebase/app";
import {
  applyActionCode,
  connectAuthEmulator,
  getAuth as getClientAuth,
  GoogleAuthProvider,
  isSignInWithEmailLink,
  sendSignInLinkToEmail,
  signInWithCredential,
  signInWithEmailAndPassword,
  signInWithEmailLink,
  signOut as clientSignOut,
  type Auth as ClientAuth
} from "firebase/auth";
import {
  collectionGroup as clientCollectionGroup,
  connectFirestoreEmulator,
  deleteDoc as clientDeleteDoc,
  doc as clientDoc,
  getDoc as clientGetDoc,
  getDocs as clientGetDocs,
  query as clientQuery,
  where as clientWhere,
  getFirestore as getClientFirestore,
  setDoc as clientSetDoc,
  terminate,
  updateDoc as clientUpdateDoc,
  type Firestore as ClientFirestore
} from "firebase/firestore";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { FirestoreClientStore } from "./client/firestore.js";
import { createLanyardClient } from "./client/index.js";
import {
  createPermissionPolicy,
  EMAIL_LINK_INVALID_ERROR_CODE,
  EMAIL_LINK_MISMATCH_ERROR_CODE,
  EmailLinkInvalidError,
  EmailLinkMismatchError,
  GLOBAL_SCOPE,
  InMemoryLanyardStore,
  REVOCATION_CLOCK_SKEW_MS,
  SESSION_REVOKED_ERROR_CODE,
  SessionRevokedError,
  TOKEN_STALE_ERROR_CODE,
  type LanyardReadable,
  type VerifiedEmailChangeEvent
} from "./core/index.js";
import { FirestoreServerStore } from "./server/firestore.js";
import { createLanyardServer, encryptSecret, isEncryptedSecretData } from "./server/index.js";
import { generateFirestoreRules } from "./rules/index.js";
import { assertRevocationEpochConformance, assertSessionRevocationConformance } from "./testing/index.js";

/**
 * Resolves the Cloud Firestore Emulator jar: `FIRESTORE_EMULATOR_JAR` if set, otherwise the newest
 * `cloud-firestore-emulator-v*.jar` downloaded by firebase-tools into `~/.cache/firebase/emulators`.
 */
function resolveFirestoreEmulatorJar(): string {
  if (process.env.FIRESTORE_EMULATOR_JAR) return process.env.FIRESTORE_EMULATOR_JAR;
  const emulatorsDir = join(homedir(), ".cache", "firebase", "emulators");
  if (!existsSync(emulatorsDir)) return "";
  const jars = readdirSync(emulatorsDir)
    .map((name) => ({ name, match: /^cloud-firestore-emulator-v(\d+)\.(\d+)\.(\d+)\.jar$/.exec(name) }))
    .filter((entry): entry is { name: string; match: RegExpExecArray } => entry.match !== null)
    .sort((a, b) => {
      for (let i = 1; i <= 3; i++) {
        const diff = Number(b.match[i]) - Number(a.match[i]);
        if (diff !== 0) return diff;
      }
      return 0;
    });
  return jars.length > 0 ? join(emulatorsDir, jars[0].name) : "";
}

const EMULATOR_JAR = resolveFirestoreEmulatorJar();
const AUTH_EMULATOR_SERVER_JS = join(
  dirname(process.execPath),
  "..",
  "lib",
  "node_modules",
  "firebase-tools",
  "lib",
  "emulator",
  "auth",
  "server.js"
);

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close(() => reject(new Error("Could not determine free port")));
      }
    });
    srv.on("error", reject);
  });
}

async function startFirestoreEmulator(port: number): Promise<ChildProcess> {
  // Newer emulator jars also start WebChannel/WebSocket servers on fixed default ports; pick free ones so the
  // tests don't collide with any other Firestore emulator already running on this machine.
  const webchannelPort = await getFreePort();
  const websocketPort = await getFreePort();
  return new Promise((resolve, reject) => {
    const proc = spawn(
      "java",
      [
        "-jar",
        EMULATOR_JAR,
        "--host",
        "127.0.0.1",
        "--port",
        String(port),
        "--webchannel_port",
        String(webchannelPort),
        "--websocket_port",
        String(websocketPort)
      ],
      {
        stdio: ["ignore", "pipe", "pipe"]
      }
    );

    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        proc.kill("SIGKILL");
        reject(new Error("Timed out waiting for Cloud Firestore Emulator to start"));
      }
    }, 20_000);

    const onData = (chunk: Buffer) => {
      const text = chunk.toString();
      if (!settled && (text.includes("API endpoint:") || text.includes("Dev App Server is now running"))) {
        settled = true;
        clearTimeout(timeout);
        resolve(proc);
      }
    };

    proc.stdout?.on("data", onData);
    proc.stderr?.on("data", onData);
    proc.on("error", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(err);
      }
    });
    proc.on("exit", (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`Firestore Emulator exited early with code ${code}`));
      }
    });
  });
}

function waitForStore<T>(store: LanyardReadable<T>, predicate: (value: T) => boolean, timeoutMs = 5_000): Promise<T> {
  return new Promise((resolve, reject) => {
    let unsub: (() => void) | null = null;
    const timer = setTimeout(() => {
      if (unsub) unsub();
      reject(new Error("Timed out waiting for store predicate"));
    }, timeoutMs);

    unsub = store.subscribe((val) => {
      if (predicate(val)) {
        clearTimeout(timer);
        if (unsub) unsub();
        resolve(val);
      }
    });
  });
}

async function startAuthEmulator(port: number, projectId: string): Promise<HttpServer> {
  const require = createRequire(import.meta.url);
  const { createApp } = require(AUTH_EMULATOR_SERVER_JS);
  const app = await createApp(projectId);
  return new Promise((resolve, reject) => {
    const server: HttpServer = app.listen(port, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

function createMockRes() {
  const res: any = {
    statusCode: 200,
    body: null,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: any) {
      res.body = payload;
      return res;
    }
  };
  return res;
}

const emulatorsAvailable = existsSync(EMULATOR_JAR) && existsSync(AUTH_EMULATOR_SERVER_JS);
if (!emulatorsAvailable) {
  const message =
    `Firestore/Auth emulator integration tests cannot run (Firestore jar: '${EMULATOR_JAR || "not found"}', ` +
    `Auth emulator: '${AUTH_EMULATOR_SERVER_JS}'). Install firebase-tools and run 'firebase setup:emulators:firestore'.`;
  // Set LANYARD_REQUIRE_EMULATORS=1 (e.g. in CI) to fail instead of silently skipping these security-critical tests
  if (process.env.LANYARD_REQUIRE_EMULATORS === "1") {
    throw new Error(message);
  }
  console.warn(`[lanyard] SKIPPING: ${message}`);
}

describe.skipIf(!emulatorsAvailable)(
  "Real Cloud Firestore & Firebase Auth Emulator integration tests (FirestoreServerStore + FirestoreClientStore)",
  () => {
    let emulatorProc: ChildProcess | null = null;
    let authEmulatorServer: HttpServer | null = null;
    let emulatorPort = 0;
    let authEmulatorPort = 0;
    let projectId = "";
    let origEmulatorHost: string | undefined;
    let origAuthEmulatorHost: string | undefined;
    let adminApp: AdminApp;
    let clientApp: FirebaseApp;
    let adminDb: AdminFirestore;
    let adminAuth: AdminAuth;
    let clientDb: ClientFirestore;
    let clientAuth: ClientAuth;

    beforeAll(async () => {
      projectId = `lanyard-emu-test-${Date.now()}`;
      origEmulatorHost = process.env.FIRESTORE_EMULATOR_HOST;
      origAuthEmulatorHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;

      // Start the in-process Auth emulator first so its port is bound before the Firestore emulator launches:
      // newer Firestore emulator jars bind additional ports during/after startup, which can otherwise steal a
      // pre-selected port.
      authEmulatorPort = await getFreePort();
      process.env.FIREBASE_AUTH_EMULATOR_HOST = `127.0.0.1:${authEmulatorPort}`;
      authEmulatorServer = await startAuthEmulator(authEmulatorPort, projectId);

      emulatorPort = await getFreePort();
      process.env.FIRESTORE_EMULATOR_HOST = `127.0.0.1:${emulatorPort}`;
      emulatorProc = await startFirestoreEmulator(emulatorPort);

      adminApp = initializeAdminApp({ projectId }, "lanyard-admin-emu");
      adminDb = getAdminFirestore(adminApp);
      adminAuth = getAdminAuth(adminApp);

      clientApp = initializeClientApp({ projectId, apiKey: "fake-api-key" }, "lanyard-client-emu");
      clientDb = getClientFirestore(clientApp);
      connectFirestoreEmulator(clientDb, "127.0.0.1", emulatorPort);
      clientAuth = getClientAuth(clientApp);
      connectAuthEmulator(clientAuth, `http://127.0.0.1:${authEmulatorPort}`, { disableWarnings: true });
    }, 30_000);

    afterAll(async () => {
      try {
        if (clientDb) await terminate(clientDb);
        if (clientApp) await deleteClientApp(clientApp);
        if (adminApp) await deleteAdminApp(adminApp);
      } catch {}

      if (authEmulatorServer) {
        await new Promise<void>((resolve) => authEmulatorServer!.close(() => resolve()));
        authEmulatorServer = null;
      }

      if (emulatorProc) {
        emulatorProc.kill("SIGTERM");
        emulatorProc = null;
      }

      if (origEmulatorHost !== undefined) {
        process.env.FIRESTORE_EMULATOR_HOST = origEmulatorHost;
      } else {
        delete process.env.FIRESTORE_EMULATOR_HOST;
      }

      if (origAuthEmulatorHost !== undefined) {
        process.env.FIREBASE_AUTH_EMULATOR_HOST = origAuthEmulatorHost;
      } else {
        delete process.env.FIREBASE_AUTH_EMULATOR_HOST;
      }
    });

    it("FirestoreServerStore and FirestoreClientStore conform to the revocation epoch contract on real Firestore", async () => {
      // Runs before any test loads security rules, so the client reads the epoch document under open emulator rules
      const metaCollection = `lanyard_meta_conformance_${Date.now()}`;
      await assertRevocationEpochConformance({
        serverStore: new FirestoreServerStore({ db: adminDb, metaCollection }),
        clientStore: new FirestoreClientStore({ db: clientDb, metaCollection })
      });

      // A malformed stored epoch fails closed: reads reject and subscriptions report an error instead of a value
      const corruptCollection = `${metaCollection}_corrupt`;
      await adminDb.doc(`${corruptCollection}/revocation`).set({ lastRevocationAtMs: "not-a-number" });
      const corruptStore = new FirestoreServerStore({ db: adminDb, metaCollection: corruptCollection });
      await expect(corruptStore.getRevocationEpoch()).rejects.toThrow(/Invalid revocation epoch/);
      const subscriptionError = await new Promise<unknown>((resolve) => {
        const unsubscribe = corruptStore.subscribeToRevocationEpoch(
          () => {},
          (error) => {
            unsubscribe();
            resolve(error);
          }
        );
      });
      expect(String(subscriptionError)).toMatch(/Invalid revocation epoch/);
    }, 30_000);

    it("FirestoreServerStore conforms to the session revocation contract on real Firestore", async () => {
      const metaCollection = `lanyard_meta_sessions_${Date.now()}`;
      await assertSessionRevocationConformance({
        serverStore: new FirestoreServerStore({ db: adminDb, metaCollection })
      });

      // A malformed stored map fails closed
      const corruptCollection = `${metaCollection}_corrupt`;
      await adminDb.doc(`${corruptCollection}/session_revocations`).set({ revokedAtMs: { "u-bad": "yesterday" } });
      const corruptStore = new FirestoreServerStore({ db: adminDb, metaCollection: corruptCollection });
      await expect(corruptStore.getSessionRevocations()).rejects.toThrow(/Invalid revocation epoch/);
    }, 30_000);

    it("enforces single-tenant multi-role hierarchy, sibling role isolation, field-level attributes/hiddenAttributes, AES-256-GCM encrypted secrets, and live client reactivity on real Firestore", async () => {
      type Role = "attendee" | "scanner" | "merch_seller" | "auditor" | "moderator";
      type Cap =
        | "view:schedule"
        | "write:points"
        | "read:merch"
        | "write:merch"
        | "write:badges"
        | "read:scanner_log"
        | "write:scanner_log"
        | "read:merch_pin"
        | "write:merch_pin"
        | "write:audit_hash"
        | "write:ai_keys";

      interface Prefs {
        leaderboardOptIn?: boolean;
        theme?: string;
      }
      interface Attrs {
        pointsAllTime: number;
        merchCreditBalance: number;
        awardedBadges: string[];
        readonlySystemBadge: string;
      }
      interface HiddenAttrs {
        scannerAuditLog: string;
        merchPosPin: string;
        blindAuditHash: string;
        superAdminSecret: string;
      }
      interface Secrets {
        geminiKey: string;
        openaiKey: string;
      }

      const policy = createPermissionPolicy<Role, Cap>({
        roles: {
          attendee: { capabilities: ["view:schedule"], trackPresence: false },
          scanner: {
            inherits: ["attendee"],
            capabilities: ["write:points", "read:scanner_log", "write:scanner_log"],
            trackPresence: true
          },
          merch_seller: {
            inherits: ["attendee"],
            capabilities: ["read:merch", "write:merch", "read:merch_pin", "write:merch_pin"],
            trackPresence: false
          },
          auditor: {
            inherits: ["attendee"],
            capabilities: ["read:merch", "read:scanner_log"],
            trackPresence: false
          },
          moderator: {
            inherits: ["scanner", "merch_seller", "auditor"],
            capabilities: ["write:badges", "write:audit_hash", "write:ai_keys"]
          }
        },
        userCapabilities: {
          read: "read:scanner_log",
          write: "write:badges"
        },
        // Holders of 'read:merch' (merch_seller, auditor, moderator) are staff: they read attributes/hiddenAttributes tiers
        staffCapability: "read:merch",
        attributeCapabilities: {
          pointsAllTime: "write:points",
          merchCreditBalance: { write: "write:merch" },
          awardedBadges: "write:badges",
          readonlySystemBadge: {}
        },
        hiddenAttributeCapabilities: {
          scannerAuditLog: { write: "write:scanner_log" },
          merchPosPin: { write: "write:merch_pin" },
          blindAuditHash: { write: "write:audit_hash" }
        },
        secretCapabilities: {
          geminiKey: { self: true },
          openaiKey: { capability: "write:ai_keys" }
        }
      });

      const serverStore = new FirestoreServerStore<Role, Cap, Prefs, Attrs, HiddenAttrs, Secrets>({
        db: adminDb,
        policy,
        usersCollection: "users_st",
        metaCollection: "lanyard_meta_st",
        encryptionKey: "emulator-test-master-encryption-key"
      });
      const clientStore = new FirestoreClientStore<Role, Cap, Prefs, Attrs>({
        db: clientDb,
        usersCollection: "users_st",
        metaCollection: "lanyard_meta_st"
      });

      const server = createLanyardServer<Role, Cap, Prefs, Attrs, HiddenAttrs, Secrets>({
        adminAuth,
        store: serverStore,
        policy
      });
      // The system admin acting below is a hand-built actor, so its admin status comes from its real Firebase claim
      await adminAuth.createUser({ uid: "root-admin", email: "root-admin@example.com", emailVerified: true });
      await adminAuth.setCustomUserClaims("root-admin", { admin: true });

      // 1. Provision single-tenant users in real Firebase Auth Emulator + real Firestore (including omitting optional firstName/lastName to verify no undefined field errors!)
      const attendee = await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "attendee@example.com",
        firstName: "Testy",
        lastName: "McTest",
        roles: ["attendee"],
        preferences: { leaderboardOptIn: false },
        attributes: {
          pointsAllTime: 10,
          merchCreditBalance: 100,
          awardedBadges: ["registered"],
          readonlySystemBadge: "pioneer"
        }
      });
      const scanner = await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "scanner@example.com",
        roles: ["scanner"] // firstName & lastName intentionally omitted!
      });
      const merchSeller = await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "merch@example.com",
        roles: ["merch_seller"]
      });
      const auditor = await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "auditor@example.com",
        roles: ["auditor"]
      });
      const moderator = await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "moderator@example.com",
        firstName: "Moddy",
        lastName: "McModerator",
        roles: ["moderator"]
      });

      // 2. Connect real Firebase Auth Emulator + FirestoreClientStore for `attendee` and verify live onAuthStateChanged & onSnapshot updates
      const client = createLanyardClient<Role, Cap, Prefs, Attrs>({
        auth: clientAuth,
        store: clientStore,
        policy,
        defaultPreferences: { leaderboardOptIn: false, theme: "light" }
      });
      await signInWithCredential(
        clientAuth,
        GoogleAuthProvider.credential(
          JSON.stringify({
            sub: attendee.uid,
            email: attendee.email,
            email_verified: true,
            name: "Testy McTest",
            picture: "https://example.com/testy.png"
          })
        )
      );

      // Verify real GoogleAuthService verifies the Auth Emulator ID token on `server.checkAuth`
      const realIdToken = await clientAuth.currentUser!.getIdToken();
      const checkAuthReq: any = { headers: { authorization: `Bearer ${realIdToken}` } };
      let checkAuthNextCalled = false;
      await server.checkAuth(checkAuthReq, createMockRes(), () => {
        checkAuthNextCalled = true;
      });
      expect(checkAuthNextCalled).toBe(true);
      expect(checkAuthReq.user?.uid).toBe(attendee.uid);
      expect(checkAuthReq.user?.email).toBe(attendee.email);
      expect(checkAuthReq.user?.isAdmin).toBe(false);

      // Wait for real Firestore onSnapshot to deliver initial attributes to client
      const initialAttrs = await waitForStore(client.attributesStore, (a) => a.pointsAllTime === 10);
      expect(initialAttrs).toEqual({
        pointsAllTime: 10,
        merchCreditBalance: 100,
        awardedBadges: ["registered"],
        readonlySystemBadge: "pioneer"
      });

      // 3. Sibling role isolation on real Firestore:
      // Scanner updates pointsAllTime (10 -> 35) and scannerAuditLog, but is blocked from merchCreditBalance & merchPosPin
      await server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 35 }
      });
      await server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: scanner,
        targetUid: attendee.uid,
        patch: { scannerAuditLog: "Checked in at Main Hall" }
      });

      // Client's real Firestore onSnapshot listener immediately receives pointsAllTime: 35 (while merchCreditBalance: 100 is preserved!)
      const updatedAttrs = await waitForStore(client.attributesStore, (a) => a.pointsAllTime === 35);
      expect(updatedAttrs.merchCreditBalance).toBe(100);
      expect(updatedAttrs.awardedBadges).toEqual(["registered"]);

      // Verify hiddenAttributes in `users_st/{uid}/private/hiddenAttributes` NEVER leak into `userRecordStore` or `attributesStore`
      expect((client.userRecordStore.get() as any)?.scannerAuditLog).toBeUndefined();
      expect((client.attributesStore.get() as any)?.scannerAuditLog).toBeUndefined();

      // Merch seller updates merchCreditBalance (100 -> 80) and merchPosPin, but is blocked from pointsAllTime
      await server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: merchSeller,
        targetUid: attendee.uid,
        patch: { merchCreditBalance: 80 }
      });
      await server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: merchSeller,
        targetUid: attendee.uid,
        patch: { merchPosPin: "7744" }
      });
      await expect(
        server.updateUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: merchSeller,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 999 }
        })
      ).rejects.toThrow(/Forbidden/);

      // Tier-based read redaction from real Firestore: scanner is NOT staff; merch_seller is staff
      expect(
        await server.readUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: scanner,
          targetUid: attendee.uid
        })
      ).toEqual({});
      await expect(
        server.readUserHiddenAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: scanner,
          targetUid: attendee.uid
        })
      ).rejects.toThrow(/Forbidden/);
      expect(
        await server.readUserHiddenAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: merchSeller,
          targetUid: attendee.uid
        })
      ).toEqual({
        scannerAuditLog: "Checked in at Main Hall",
        merchPosPin: "7744"
      });

      // Auditor (staff) reads the whole attributes tier, but cannot write anything
      expect(
        await server.readUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: auditor,
          targetUid: attendee.uid
        })
      ).toEqual({
        pointsAllTime: 35,
        merchCreditBalance: 80,
        awardedBadges: ["registered"],
        readonlySystemBadge: "pioneer"
      });
      await expect(
        server.updateUserHiddenAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: auditor,
          targetUid: attendee.uid,
          patch: { scannerAuditLog: "Auditor tamper" }
        })
      ).rejects.toThrow(/Forbidden/);

      // 4. Write-only hiddenAttribute (`blindAuditHash`), superAdmin hiddenAttribute, & AES-256-GCM encrypted `secrets` on real Firestore:
      await server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: moderator,
        targetUid: attendee.uid,
        patch: { blindAuditHash: "sha256:998877" }
      });
      await server.updateUserHiddenAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: { uid: "root-admin" },
        targetUid: attendee.uid,
        patch: { superAdminSecret: "root-eyes-only" }
      });

      // Moderator (staff via merch_seller/auditor) reads the whole hiddenAttributes tier
      expect(
        await server.readUserHiddenAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: moderator,
          targetUid: attendee.uid
        })
      ).toEqual({
        scannerAuditLog: "Checked in at Main Hall",
        merchPosPin: "7744",
        blindAuditHash: "sha256:998877",
        superAdminSecret: "root-eyes-only"
      });

      // System admin reads all 4 hiddenAttribute fields from real Firestore
      expect(
        await server.readUserHiddenAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: { uid: "root-admin" },
          targetUid: attendee.uid
        })
      ).toEqual({
        scannerAuditLog: "Checked in at Main Hall",
        merchPosPin: "7744",
        blindAuditHash: "sha256:998877",
        superAdminSecret: "root-eyes-only"
      });

      // Write-only AES-256-GCM encrypted user secrets on real Firestore (`users_st/{uid}/private/secrets`):
      const secretStatus1 = await server.updateUserSecrets({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        patch: { geminiKey: "AIzaSyRealFirestoreKey123" }
      });
      expect(secretStatus1).toEqual({ geminiKey: true });

      // Inspect raw Firestore document directly via Admin SDK to prove AES-256-GCM encryption at rest!
      const rawSecretSnap = await adminDb.doc(`users_st/${attendee.uid}/private/secrets`).get();
      const rawSecretData = rawSecretSnap.data();
      expect(isEncryptedSecretData(rawSecretData?.geminiKey)).toBe(true);
      expect(JSON.stringify(rawSecretData)).not.toContain("AIzaSyRealFirestoreKey123");

      // Server decrypts it cleanly via getDecryptedUserSecrets, and clearing with "" deletes the field via FieldValue.delete()
      expect(await server.getDecryptedUserSecrets(GLOBAL_SCOPE, attendee.uid)).toEqual({
        geminiKey: "AIzaSyRealFirestoreKey123"
      });
      expect(
        await server.updateUserSecrets({
          scopeId: GLOBAL_SCOPE,
          actor: attendee,
          targetUid: attendee.uid,
          patch: { geminiKey: "" }
        })
      ).toEqual({});
      expect(await server.getDecryptedUserSecrets(GLOBAL_SCOPE, attendee.uid)).toEqual({});

      // 5. Client self-service preferences & profile updates on real Firestore preserve roles and attributes
      await client.updatePreferences(GLOBAL_SCOPE, { leaderboardOptIn: true, theme: "dark" });
      await client.updateProfile(GLOBAL_SCOPE, { firstName: "UpdatedTesty" });

      const afterSelfUpdate = await waitForStore(client.userRecordStore, (u) => u?.firstName === "UpdatedTesty");
      await waitForStore(client.preferencesStore, (p) => p.leaderboardOptIn === true && p.theme === "dark");
      expect(afterSelfUpdate?.roles).toEqual(["attendee"]);
      // Attributes come from the private attributes tier (merged into attributesStore), not the card
      expect(afterSelfUpdate?.attributes).toEqual({});
      expect(client.attributesStore.get().pointsAllTime).toBe(35);
      expect(client.attributesStore.get().merchCreditBalance).toBe(80);
      const rawAttrs = (await adminDb.doc(`users_st/${attendee.uid}/private/attributes`).get()).data();
      expect(rawAttrs).toMatchObject({
        pointsAllTime: 35,
        merchCreditBalance: 80,
        _lanyard: { tier: "attributes", uid: attendee.uid, scopeId: null, updatedAt: expect.any(String) }
      });
      // Preferences never land on the card; they live only in the self-only private/preferences tier doc
      expect(afterSelfUpdate?.preferences).toBeUndefined();
      const rawCard = (await adminDb.doc(`users_st/${attendee.uid}`).get()).data();
      expect(rawCard).not.toHaveProperty("preferences");
      expect(rawCard).not.toHaveProperty("attributes");
      const rawPrefs = (await adminDb.doc(`users_st/${attendee.uid}/private/preferences`).get()).data();
      expect(rawPrefs).toEqual({
        leaderboardOptIn: true,
        theme: "dark",
        _lanyard: { tier: "preferences", uid: attendee.uid, scopeId: null, updatedAt: expect.any(String) }
      });

      // 6. Per-user multi-role grant & revocation on real Firestore:
      await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "attendee@example.com",
        roles: ["attendee", "scanner"]
      });
      await server.updateUserAttributes({
        scopeId: GLOBAL_SCOPE,
        actor: attendee,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 60 }
      });
      await waitForStore(client.attributesStore, (a) => a.pointsAllTime === 60);

      // Revoke scanner role on real Firestore
      await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "attendee@example.com",
        roles: ["attendee"]
      });
      await expect(
        server.updateUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: attendee,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 99 }
        })
      ).rejects.toThrow(/Forbidden/);

      // 7. Real-time system admin promotion & demotion on real Firebase Auth Emulator + real Firestore + stale JWT rejection:
      await server.setSystemAdminStatus({
        email: "attendee@example.com",
        isAdmin: true,
        actor: { uid: "root-admin" }
      });
      await waitForStore(client.authStore, (s) => s.user?.isAdmin === true);

      // Force token refresh on clientAuth and verify the real Auth Emulator minted the custom `admin: true` claim
      const promotedTokenResult = await clientAuth.currentUser!.getIdTokenResult(true);
      expect(promotedTokenResult.claims.admin).toBe(true);
      const staleAdminJwt = promotedTokenResult.token;

      await server.setSystemAdminStatus({
        email: "attendee@example.com",
        isAdmin: false,
        actor: { uid: "root-admin" }
      });
      await waitForStore(client.authStore, (s) => s.user?.isAdmin === false);

      // Even if a request arrives with a real signed Auth Emulator JWT that still has `admin: true`, `checkAuth`
      // refuses it as stale: the demotion bumped the revocation epoch, so the user must refresh to admin:false
      const staleReq: any = { headers: { authorization: `Bearer ${staleAdminJwt}` } };
      const resStaleCheck = createMockRes();
      let staleNext = false;
      await server.checkAuth(staleReq, resStaleCheck, () => {
        staleNext = true;
      });
      expect(staleNext).toBe(false);
      expect(resStaleCheck.statusCode).toBe(401);
      expect(resStaleCheck.body).toMatchObject({ code: TOKEN_STALE_ERROR_CODE });

      // And attendee's attributes & preferences are still intact in real Firestore after admin demotion!
      const preservedInFirestore = await serverStore.getUser(attendee.uid);
      expect(preservedInFirestore?.isSystemAdmin).toBe(false);
      expect(preservedInFirestore?.attributes?.pointsAllTime).toBe(60);
      expect(preservedInFirestore?.preferences?.leaderboardOptIn).toBe(true);

      // 8. Concurrent updates from sibling roles (`scanner` + `merch_seller`) via Promise.all on real Firestore
      // verify Firestore native `{ merge: true }` map merging without lost updates:
      await Promise.all([
        server.updateUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: scanner,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 75 }
        }),
        server.updateUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: merchSeller,
          targetUid: attendee.uid,
          patch: { merchCreditBalance: 65 }
        })
      ]);
      const afterConcurrent = await waitForStore(
        client.attributesStore,
        (a) => a.pointsAllTime === 75 && a.merchCreditBalance === 65
      );
      expect(afterConcurrent).toEqual({
        pointsAllTime: 75,
        merchCreditBalance: 65,
        awardedBadges: ["registered"],
        readonlySystemBadge: "pioneer"
      });

      // 9. Atomic multi-key patch rejection on real Firestore:
      // Scanner attempts to update allowed `pointsAllTime` + forbidden `awardedBadges` -> 403 and no partial write!
      await expect(
        server.updateUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: scanner,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 9999, awardedBadges: ["forged"] }
        })
      ).rejects.toThrow(/Forbidden/);
      expect((await serverStore.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(75);

      // 10. Role demotion (`moderator` -> `scanner`) persisted in real Firestore:
      await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "moderator@example.com",
        roles: ["scanner"]
      });
      await expect(
        server.updateUserAttributes({
          scopeId: GLOBAL_SCOPE,
          actor: moderator,
          targetUid: attendee.uid,
          patch: { awardedBadges: ["after-demotion"] }
        })
      ).rejects.toThrow(/Forbidden/);

      // 11. Saving preferences alone never creates a card (they live only in the private/preferences tier doc)...
      await clientStore.savePreferences("prefs-only-uid", { theme: "dark" });
      expect(await serverStore.getUser("prefs-only-uid")).toBeNull();
      expect((await adminDb.doc("users_st/prefs-only-uid").get()).exists).toBe(false);

      // ...while a profile-only stub card a user creates for themselves holds no roles: stores never substitute
      // default roles, so it can't do anything a role grants until the server provisions it
      await clientStore.updateUserProfile("prefs-only-uid", { firstName: "Stubby" });
      const stubUser = await serverStore.getUser("prefs-only-uid");
      expect(stubUser?.roles).toBeUndefined();
      expect(stubUser?.preferences).toEqual({ theme: "dark" });

      let stubAllowedAsAttendee = false;
      await server.requireCapability("view:schedule", GLOBAL_SCOPE)(
        { user: { uid: "prefs-only-uid", email: "stub@example.com", isAdmin: false } } as any,
        createMockRes(),
        () => {
          stubAllowedAsAttendee = true;
        }
      );
      expect(stubAllowedAsAttendee).toBe(false);

      // 12. Unscoped directory subscription (`client.subscribeToUsers(GLOBAL_SCOPE, cb)`) on real Firestore
      const directoryUsers = await new Promise<any[]>((resolve) => {
        const unsub = client.subscribeToUsers(GLOBAL_SCOPE, (users) => {
          if (users.length >= 6) {
            unsub();
            resolve(users);
          }
        });
      });
      expect(directoryUsers.map((u) => u.uid)).toEqual(
        expect.arrayContaining([
          attendee.uid,
          scanner.uid,
          merchSeller.uid,
          auditor.uid,
          moderator.uid,
          "prefs-only-uid"
        ])
      );

      // 13. Non-admin user management & safe user deletion on real Firestore + Auth Emulator (including recursive cleanup of subcollections like `history`):
      const modPromoted = await server.upsertUserByEmail({
        scopeId: GLOBAL_SCOPE,
        email: "moderator@example.com",
        roles: ["moderator"]
      });
      await adminDb.doc(`users_st/${merchSeller.uid}/history/tx-1`).set({ amount: -20, item: "T-Shirt" });

      // Swapped UID safeguard on real Firestore:
      await expect(
        server.deleteUser({
          scopeId: GLOBAL_SCOPE,
          actor: modPromoted,
          targetUid: scanner.uid, // Swapped UID!
          confirmTargetEmail: "merch@example.com"
        })
      ).rejects.toThrow(/confirmTargetEmail 'merch@example\.com' does not match target user's email/);
      expect(await serverStore.getUser(scanner.uid)).not.toBeNull();

      // Moderator deletes `merchSeller` with matching `confirmTargetEmail` -> deletes `users_st/{uid}`, `history/tx-1` subcollection, and Auth user!
      await server.deleteUser({
        scopeId: GLOBAL_SCOPE,
        actor: modPromoted,
        targetUid: merchSeller.uid,
        confirmTargetEmail: "merch@example.com"
      });
      expect(await serverStore.getUser(merchSeller.uid)).toBeNull();
      expect((await adminDb.doc(`users_st/${merchSeller.uid}/history/tx-1`).get()).exists).toBe(false);
      await expect(adminAuth.getUser(merchSeller.uid)).rejects.toThrow();

      client.destroy();
    });

    it("enforces multi-tenant capabilities, FieldValue.arrayUnion/arrayRemove, collectionGroup memberships, and hiddenAttribute/secret cleanup on real Firestore", async () => {
      type Role = "member" | "manager" | "owner";
      type Cap = "edit:content" | "manage:billing" | "read:notes" | "write:notes" | "manage:secrets";

      const policy = createPermissionPolicy<Role, Cap>({
        capabilities: ["edit:content", "manage:billing", "read:notes", "write:notes", "manage:secrets"],
        roles: {
          member: { capabilities: [] },
          manager: { inherits: ["member"], capabilities: ["edit:content", "read:notes"] },
          owner: { inherits: ["manager"], capabilities: "*" }
        },
        staffCapability: "read:notes",
        attributeCapabilities: {
          quotaTier: "manage:billing"
        },
        hiddenAttributeCapabilities: {
          internalNotes: { write: "write:notes" }
        },
        secretCapabilities: {
          geminiKey: { capability: "manage:secrets" }
        }
      });

      const serverStore = new FirestoreServerStore<
        Role,
        Cap,
        Record<string, any>,
        { quotaTier: string },
        { internalNotes: string },
        { geminiKey: string }
      >({
        db: adminDb,
        policy,
        usersCollection: "users_mt",
        scopeCollection: "orgs_mt",
        membersSubcollection: "members_mt",
        encryptionKey: "emulator-mt-master-key"
      });
      const clientStore = new FirestoreClientStore<Role, Cap, Record<string, any>, { quotaTier: string }>({
        db: clientDb,
        usersCollection: "users_mt",
        scopeCollection: "orgs_mt",
        membersSubcollection: "members_mt"
      });

      const server = createLanyardServer<
        Role,
        Cap,
        Record<string, any>,
        { quotaTier: string },
        { internalNotes: string },
        { geminiKey: string }
      >({
        adminAuth,
        store: serverStore,
        policy
      });

      // 1. Grant additive roles via FieldValue.arrayUnion and revoke via FieldValue.arrayRemove on real Firestore
      const m1 = await server.grantRolesByEmail({
        scopeId: "org-1",
        email: "worker@example.com",
        roles: ["member"]
      });
      await server.grantRolesByEmail({
        scopeId: "org-1",
        email: "worker@example.com",
        roles: ["manager"]
      });
      expect((await serverStore.getScopeMember("org-1", m1.uid))?.roles).toEqual(["member", "manager"]);

      await server.revokeRoles("org-1", m1.uid, ["manager"]);
      expect((await serverStore.getScopeMember("org-1", m1.uid))?.roles).toEqual(["member"]);

      // 2. Add worker to org-2 as owner and verify real Firestore collectionGroup query in subscribeToUserMemberships
      await server.upsertUserByEmail({
        scopeId: "org-2",
        email: "worker@example.com",
        roles: ["owner"]
      });

      const client = createLanyardClient<Role, Cap, Record<string, any>, { quotaTier: string }>({
        auth: clientAuth,
        store: clientStore,
        policy,
        defaultPreferences: {}
      });
      await signInWithCredential(
        clientAuth,
        GoogleAuthProvider.credential(
          JSON.stringify({
            sub: m1.uid,
            email: "worker@example.com",
            email_verified: true,
            name: "Worky McWorker"
          })
        )
      );

      const membershipsState = await waitForStore(
        client.membershipsStore,
        (s) => !s.isLoading && s.memberships.length === 2
      );
      expect(membershipsState.memberships.map((m) => m.scopeId).sort()).toEqual(["org-1", "org-2"]);

      // 3. Cross-tenant isolation on real Firestore:
      // Worker is `owner` in `org-2` (can write hiddenAttributes and user secrets in `org-2`),
      // but only `member` in `org-1`
      await server.updateUserHiddenAttributes({
        scopeId: "org-2",
        actor: m1,
        targetUid: m1.uid,
        patch: { internalNotes: "Org 2 note" }
      });
      await server.updateUserSecrets({
        scopeId: "org-2",
        actor: m1,
        targetUid: m1.uid,
        patch: { geminiKey: "AIzaSyMemberKeyOrg2" }
      });
      expect(
        await server.getUserSecretsStatus({
          scopeId: "org-2",
          actor: m1,
          targetUid: m1.uid
        })
      ).toEqual({ geminiKey: true });
      expect(await server.getDecryptedUserSecrets("org-2", m1.uid)).toEqual({
        geminiKey: "AIzaSyMemberKeyOrg2"
      });
      const rawScopedMemberSecretSnap = await adminDb.doc(`orgs_mt/org-2/members_mt/${m1.uid}/private/secrets`).get();
      expect(isEncryptedSecretData(rawScopedMemberSecretSnap.data()?.geminiKey)).toBe(true);
      expect(JSON.stringify(rawScopedMemberSecretSnap.data())).not.toContain("AIzaSyMemberKeyOrg2");

      await expect(
        server.updateUserHiddenAttributes({
          scopeId: "org-1",
          actor: m1,
          targetUid: m1.uid,
          patch: { internalNotes: "Unauthorized Org 1 note" }
        })
      ).rejects.toThrow(/Forbidden/);
      await expect(
        server.updateUserSecrets({
          scopeId: "org-1",
          actor: m1,
          targetUid: m1.uid,
          patch: { geminiKey: "AIzaSyUnauthorizedOrg1" }
        })
      ).rejects.toThrow(/Forbidden/);

      // 4. Deleting scope member in `org-2` also deletes both `private/hiddenAttributes` and `private/secrets` in real Firestore
      await serverStore.deleteScopeMember("org-2", m1.uid);
      expect(await serverStore.getScopeMember("org-2", m1.uid)).toBeNull();
      expect(await serverStore.getScopeMemberHiddenAttributes("org-2", m1.uid)).toEqual({});
      expect(await serverStore.getScopeMemberSecrets("org-2", m1.uid)).toEqual({});

      client.destroy();
    });

    it("enforces real Firestore Security Rules and thoroughly validates all direct FirestoreClientStore operations", async () => {
      // The rules under test are generated from a policy matching this scenario: managers and owners are staff (and
      // can read global user profiles), and shiftNotes are readable by the member and staff and writable by staff.
      const rulesPolicy = createPermissionPolicy<"member" | "manager" | "owner", "invite_members" | "edit:content">({
        roles: {
          member: { capabilities: [] },
          manager: { inherits: ["member"], capabilities: ["invite_members"] },
          owner: { inherits: ["manager"], capabilities: ["edit:content"] }
        },
        staffCapability: "invite_members",
        userCapabilities: { read: "invite_members" },
        customDocs: { shiftNotes: { read: { self: true, staff: true }, write: { staff: true } } }
      });
      const wrapRules = (block: string) => `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
${block}
  }
}
`;
      const referenceRules = wrapRules(generateFirestoreRules(rulesPolicy));

      const rulesRes = await fetch(`http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rules: {
            files: [{ name: "firestore.rules", content: referenceRules }]
          }
        })
      });
      expect(rulesRes.status).toBe(200);

      async function createAuthedClient(uid: string, email: string, isAdmin = false, emailVerified = true) {
        // Unverified users sign in with a password: Google sign-in won't attach to an unverified-email account
        const password = emailVerified ? undefined : "emulator-test-password";
        await adminAuth.createUser({ uid, email, emailVerified, ...(password ? { password } : {}) });
        if (isAdmin) {
          await adminAuth.setCustomUserClaims(uid, { admin: true });
        }
        const app = initializeClientApp(
          { projectId, apiKey: "fake-api-key" },
          `client-${uid}-${Math.random().toString(36).slice(2, 7)}`
        );
        const auth = getClientAuth(app);
        connectAuthEmulator(auth, `http://127.0.0.1:${authEmulatorPort}`, { disableWarnings: true });
        if (password) {
          await signInWithEmailAndPassword(auth, email, password);
        } else {
          await signInWithCredential(
            auth,
            GoogleAuthProvider.credential(
              JSON.stringify({
                sub: uid,
                email,
                email_verified: true
              })
            )
          );
        }
        const db = getClientFirestore(app);
        connectFirestoreEmulator(db, "127.0.0.1", emulatorPort);
        return { app, auth, db };
      }

      const memberClient = await createAuthedClient("u-member", "member@example.com", false);
      const mgrClient = await createAuthedClient("u-mgr", "mgr@example.com", false);
      const sysAdminClient = await createAuthedClient("u-sysadmin", "sysadmin@example.com", true);

      try {
        type Role = "member" | "manager" | "owner";
        type Cap = "invite_members" | "edit:content";
        interface Prefs {
          theme: "light" | "dark";
          compactMode: boolean;
        }

        const serverStore = new FirestoreServerStore<
          Role,
          Cap,
          Prefs,
          { badge: string },
          { secretNote: string },
          { geminiKey: string }
        >({
          db: adminDb,
          // This test drives the store directly; it declares the one secret key it writes
          policy: createPermissionPolicy<Role, Cap>({ secretCapabilities: { geminiKey: { self: true } } }),
          usersCollection: "users",
          scopeCollection: "workspaces",
          membersSubcollection: "members",
          encryptionKey: "emulator-rules-test-key"
        });

        const memberStore = new FirestoreClientStore<Role, Cap, Prefs, { badge: string }>({
          db: memberClient.db,
          usersCollection: "users",
          scopeCollection: "workspaces",
          membersSubcollection: "members"
        });

        // 1. `subscribeToUser` reads the card; `subscribeToPreferences` reads the self-only private/preferences doc.
        // Legacy inline `preferences` on the card are ignored.
        await adminDb.doc("users/u-member").set({ uid: "u-member", preferences: { theme: "light" } });
        await adminDb.doc("users/u-member/private/preferences").set({
          compactMode: true,
          _lanyard: { tier: "preferences", uid: "u-member", scopeId: null, updatedAt: "2026-01-01" }
        });

        const userEvents: any[] = [];
        const prefEvents: any[] = [];
        const unsubUser = memberStore.subscribeToUser("u-member", (u) => userEvents.push(u));
        const unsubPrefs = memberStore.subscribeToPreferences("u-member", (p) => prefEvents.push(p));

        await clientGetDoc(clientDoc(memberClient.db, "users", "u-member"));
        await new Promise((r) => setTimeout(r, 150));
        expect(userEvents.at(-1)?.uid).toBe("u-member");
        // The card has no roles field: it holds no roles (stores never substitute defaults)
        expect(userEvents.at(-1)?.roles).toEqual([]);
        expect(userEvents.at(-1)?.preferences).toBeUndefined();
        expect(prefEvents.at(-1)).toEqual({ compactMode: true });

        // Direct client `savePreferences`, `syncAvatar`, `updateUserProfile`, and `recordPresenceHeartbeat` (global)
        await memberStore.savePreferences("u-member", { theme: "dark", compactMode: false });
        await memberStore.syncAvatar({
          uid: "u-member",
          photoUrl: "https://example.com/avatar.png",
          displayName: "Memby McMember"
        });
        await memberStore.updateUserProfile("u-member", {
          firstName: "Memby",
          lastName: "McMember",
          displayName: "Memby McMember",
          photoUrl: "https://example.com/avatar2.png"
        });
        await memberStore.recordPresenceHeartbeat({
          uid: "u-member",
          lastSeenIso: "2026-10-21T12:00:00.000Z"
        });

        await new Promise((r) => setTimeout(r, 150));
        const latestUser = userEvents.at(-1);
        expect(latestUser?.firstName).toBe("Memby");
        expect(latestUser?.lastName).toBe("McMember");
        expect(latestUser?.photoUrl).toBe("https://example.com/avatar2.png");
        expect(latestUser?.lastSeen).toBe("2026-10-21T12:00:00.000Z");
        expect(prefEvents.at(-1)).toEqual({ compactMode: false, theme: "dark" });

        // Unsubscribing preferences leaves the card subscription untouched, and vice versa
        unsubPrefs();
        await memberStore.savePreferences("u-member", { theme: "light", compactMode: false });
        await new Promise((r) => setTimeout(r, 150));
        expect(prefEvents.at(-1)).toEqual({ compactMode: false, theme: "dark" });
        expect(userEvents.at(-1)?.preferences).toBeUndefined();
        unsubUser();
        expect((await serverStore.getUser("u-member"))?.preferences).toEqual({ theme: "light", compactMode: false });

        // Preferences tier security: only the owner (and admins) can read or write it; the card can't hold preferences
        expect(
          (await clientGetDoc(clientDoc(memberClient.db, "users", "u-member", "private", "preferences"))).data()
        ).toMatchObject({ theme: "light", compactMode: false, _lanyard: { tier: "preferences" } });
        expect(
          (await clientGetDoc(clientDoc(sysAdminClient.db, "users", "u-member", "private", "preferences"))).data()
        ).toMatchObject({ theme: "light" });
        await expect(
          clientGetDoc(clientDoc(mgrClient.db, "users", "u-member", "private", "preferences"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientSetDoc(
            clientDoc(mgrClient.db, "users", "u-member", "private", "preferences"),
            { theme: "dark", _lanyard: { tier: "preferences", uid: "u-member", scopeId: null } },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Owner writes must carry correct tier metadata
        await expect(
          clientSetDoc(
            clientDoc(memberClient.db, "users", "u-member", "private", "preferences"),
            { theme: "dark", _lanyard: { tier: "attributes", uid: "u-member", scopeId: null } },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { preferences: { theme: "dark" } })
        ).rejects.toMatchObject({ code: "permission-denied" });

        // 2. Provision scoped memberships via serverStore (`org-A` has `u-mgr` as manager and `u-member` as member; `org-B` has another user)
        await serverStore.upsertScopeMember("org-A", {
          uid: "u-mgr",
          email: "mgr@example.com",
          roles: ["manager"]
        });
        await serverStore.upsertScopeMember("org-A", {
          uid: "u-member",
          email: "member@example.com",
          roles: ["member"],
          attributes: { badge: "starter" }
        });
        await serverStore.upsertScopeMember("org-B", {
          uid: "u-other",
          email: "other@example.com",
          roles: ["owner"]
        });
        await serverStore.updateUserHiddenAttributes("u-member", { secretNote: "Top secret global note" });
        await serverStore.updateScopeMemberHiddenAttributes("org-A", "u-member", {
          secretNote: "Top secret org-A note"
        });
        await serverStore.updateUserSecrets("u-member", { geminiKey: "AIzaSyGlobalSecret" });
        await serverStore.updateScopeMemberSecrets("org-A", "u-member", { geminiKey: "AIzaSyOrgASecret" });

        // 3. Direct client `subscribeToUserMemberships` (`collectionGroup` query) & `subscribeToScopeMembers` under Security Rules
        const membershipsList: any[] = [];
        const unsubMemberships = memberStore.subscribeToUserMemberships("u-member", (m) => membershipsList.push(m));
        const rosterList: any[] = [];
        const unsubRoster = memberStore.subscribeToScopeMembers("org-A", (r) => rosterList.push(r));

        await new Promise((r) => setTimeout(r, 200));
        expect(membershipsList.at(-1)?.map((m: any) => m.scopeId)).toEqual(["org-A"]);
        expect(
          rosterList
            .at(-1)
            ?.map((m: any) => m.uid)
            .sort()
        ).toEqual(["u-member", "u-mgr"]);

        // 4. Scoped `syncAvatar`, `updateScopeMemberProfile`, `recordPresenceHeartbeat`, and `saveScopePreferences` update existing scoped member doc without creating phantom docs
        await memberStore.syncAvatar({
          uid: "u-member",
          scopeId: "org-A",
          photoUrl: "https://example.com/scoped-avatar.png"
        });
        await memberStore.updateScopeMemberProfile("org-A", "u-member", {
          firstName: "Scoped",
          lastName: "Member",
          displayName: "Scoped Member"
        });
        await memberStore.recordPresenceHeartbeat({
          uid: "u-member",
          scopeId: "org-A",
          lastSeenIso: "2026-10-21T12:05:00.000Z"
        });
        await memberStore.saveScopePreferences("org-A", "u-member", { theme: "dark", compactMode: false });
        await memberStore.saveScopePreferences("org-A", "u-member", { compactMode: true });
        const scopePrefEvents: any[] = [];
        const unsubScopePrefs = memberStore.subscribeToScopePreferences("org-A", "u-member", (p) =>
          scopePrefEvents.push(p)
        );
        await new Promise((r) => setTimeout(r, 150));

        const updatedOrgAMember = rosterList.at(-1)?.find((m: any) => m.uid === "u-member");
        expect(updatedOrgAMember?.photoUrl).toBe("https://example.com/scoped-avatar.png");
        expect(updatedOrgAMember?.displayName).toBe("Scoped Member");
        expect(updatedOrgAMember?.lastSeen).toBe("2026-10-21T12:05:00.000Z");
        // Scoped preferences never appear on the roster card; they come from the member's private/preferences doc
        expect(updatedOrgAMember?.preferences).toBeUndefined();
        expect(scopePrefEvents.at(-1)).toEqual({ theme: "dark", compactMode: true });
        unsubScopePrefs();
        expect((await serverStore.getScopeMember("org-A", "u-member"))?.preferences).toEqual({
          theme: "dark",
          compactMode: true
        });
        expect((await adminDb.doc("workspaces/org-A/members/u-member").get()).data()).not.toHaveProperty("preferences");
        expect((await adminDb.doc("workspaces/org-A/members/u-member/private/preferences").get()).data()).toEqual({
          theme: "dark",
          compactMode: true,
          _lanyard: { tier: "preferences", uid: "u-member", scopeId: "org-A", updatedAt: expect.any(String) }
        });

        // Scope staff (`u-mgr` is an org-A manager) can't read or write a member's scoped preferences
        await expect(
          clientGetDoc(clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member", "private", "preferences"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientSetDoc(
            clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member", "private", "preferences"),
            { theme: "light", _lanyard: { tier: "preferences", uid: "u-member", scopeId: "org-A" } },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        // A scoped preferences doc can't claim a different scope in its metadata
        await expect(
          clientSetDoc(
            clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member", "private", "preferences"),
            { theme: "light", _lanyard: { tier: "preferences", uid: "u-member", scopeId: "org-B" } },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });

        // Calling scoped `syncAvatar`, `recordPresenceHeartbeat`, or `saveScopePreferences` on a scope where user is NOT a member (`org-B`) must fail and NEVER create a phantom member doc
        await expect(
          memberStore.syncAvatar({
            uid: "u-member",
            scopeId: "org-B",
            photoUrl: "https://example.com/phantom.png"
          })
        ).rejects.toThrow();
        await expect(
          memberStore.recordPresenceHeartbeat({
            uid: "u-member",
            scopeId: "org-B",
            lastSeenIso: "2026-10-21T12:05:00.000Z"
          })
        ).rejects.toThrow();
        await expect(
          memberStore.saveScopePreferences("org-B", "u-member", { theme: "dark", compactMode: true })
        ).rejects.toThrow();
        expect(await serverStore.getScopeMember("org-B", "u-member")).toBeNull();
        expect((await adminDb.doc("workspaces/org-B/members/u-member/private/preferences").get()).exists).toBe(false);

        // Also verify `grantUserRoles` and `revokeUserRoles` on global `users/u-member` in real Firestore
        await serverStore.grantUserRoles("u-member", ["manager"]);
        expect((await serverStore.getUser("u-member"))?.roles).toEqual([" manager".trim()]);
        await serverStore.revokeUserRoles("u-member", ["manager"]);
        // Revoking their only role leaves them with none (no default roles substituted on read)
        expect((await serverStore.getUser("u-member"))?.roles).toEqual([]);

        unsubMemberships();
        unsubRoster();

        // 5. Security Rules Attack Surface Verification (Direct Client SDK Attacks):
        // Attack A: Non-admin user tries to self-escalate `isSystemAdmin`, `roles`, or `attributes` on `users/u-member`
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { isSystemAdmin: true })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { roles: ["owner"] })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { attributes: { badge: "hacked" } })
        ).rejects.toMatchObject({ code: "permission-denied" });

        // Attack B: Non-admin user tries to spoof another user's `uid` or read another user's global profile
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { uid: "u-other" })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(clientGetDoc(clientDoc(memberClient.db, "users", "u-mgr"))).rejects.toMatchObject({
          code: "permission-denied"
        });

        // Attack C: Non-admin user tries to read or write their own `private/hiddenAttributes` or `private/secrets`
        await expect(
          clientGetDoc(clientDoc(memberClient.db, "users", "u-member", "private", "hiddenAttributes"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientSetDoc(clientDoc(memberClient.db, "users", "u-member", "private", "hiddenAttributes"), {
            secretNote: "hacked"
          })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientGetDoc(clientDoc(memberClient.db, "users", "u-member", "private", "secrets"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientGetDoc(
            clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member", "private", "hiddenAttributes")
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Even manager cannot read raw `private/secrets` directly from the client SDK!
        await expect(
          clientGetDoc(clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member", "private", "secrets"))
        ).rejects.toMatchObject({ code: "permission-denied" });

        // Attack D: Scoped member tries to self-escalate `roles` or `attributes` on `workspaces/org-A/members/u-member`
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member"), {
            roles: ["owner"]
          })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member"), {
            attributes: { badge: "hacked" }
          })
        ).rejects.toMatchObject({ code: "permission-denied" });

        // Attack E: Manager of `org-A` (`u-mgr`) tries to read or write `org-B` members or hiddenAttributes (cross-tenant isolation)
        await expect(
          clientGetDoc(clientDoc(mgrClient.db, "workspaces", "org-B", "members", "u-other"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientSetDoc(clientDoc(mgrClient.db, "workspaces", "org-B", "members", "u-mgr"), {
            uid: "u-mgr",
            roles: ["owner"]
          })
        ).rejects.toMatchObject({ code: "permission-denied" });

        // Attack F: The attributes tier is readable only by its owner and staff, and never writable from clients
        await serverStore.updateUserAttributes("u-member", { badge: "global-badge" });
        await serverStore.upsertScopeMember("org-A", {
          uid: "u-mgr",
          email: "mgr@example.com",
          roles: ["manager"],
          attributes: { badge: "mgr-badge" }
        });
        expect((await adminDb.doc("workspaces/org-A/members/u-member").get()).data()).not.toHaveProperty("attributes");
        expect((await adminDb.doc("users/u-member").get()).data()).not.toHaveProperty("attributes");
        expect(
          (await clientGetDoc(clientDoc(memberClient.db, "users", "u-member", "private", "attributes"))).data()
        ).toMatchObject({ badge: "global-badge", _lanyard: { tier: "attributes", scopeId: null } });
        expect(
          (
            await clientGetDoc(
              clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member", "private", "attributes")
            )
          ).data()
        ).toMatchObject({ badge: "starter", _lanyard: { tier: "attributes", scopeId: "org-A" } });
        const ownScopeAttrEvents: any[] = [];
        const unsubOwnScopeAttrs = memberStore.subscribeToScopeAttributes("org-A", "u-member", (a) =>
          ownScopeAttrEvents.push(a)
        );
        await new Promise((r) => setTimeout(r, 150));
        expect(ownScopeAttrEvents.at(-1)).toEqual({ badge: "starter" });
        unsubOwnScopeAttrs();
        // A non-staff member can't read a fellow member's (or another user's) attributes
        await expect(
          clientGetDoc(clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-mgr", "private", "attributes"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientGetDoc(clientDoc(mgrClient.db, "users", "u-member", "private", "attributes"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Owners and staff can't write the attributes tier directly
        await expect(
          clientSetDoc(
            clientDoc(memberClient.db, "users", "u-member", "private", "attributes"),
            { badge: "self-awarded" },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientSetDoc(
            clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member", "private", "attributes"),
            { badge: "staff-awarded" },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Scope staff (org-A manager) can read org-A members' attributes, but not another scope's
        expect(
          (
            await clientGetDoc(
              clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member", "private", "attributes")
            )
          ).data()
        ).toMatchObject({ badge: "starter" });
        await expect(
          clientGetDoc(clientDoc(mgrClient.db, "workspaces", "org-B", "members", "u-other", "private", "attributes"))
        ).rejects.toMatchObject({ code: "permission-denied" });

        // Attack G: Email is private (stored in the attributes tier, never on cards) and server-owned: clients can't
        // write it at all, not even their own verified address
        expect((await adminDb.doc("workspaces/org-A/members/u-mgr").get()).data()).not.toHaveProperty("email");
        expect((await adminDb.doc("workspaces/org-A/members/u-mgr/private/attributes").get()).data()).toMatchObject({
          email: "mgr@example.com"
        });
        expect((await serverStore.getScopeMember("org-A", "u-mgr"))?.email).toBe("mgr@example.com");
        const rosterEmails: any[][] = [];
        const unsubRosterEmails = memberStore.subscribeToScopeMembers("org-A", (m) => rosterEmails.push(m));
        await new Promise((r) => setTimeout(r, 150));
        unsubRosterEmails();
        expect(rosterEmails.at(-1)?.map((m: any) => m.email)).toEqual(["", ""]);

        // The client store refuses email in profile patches before writing anything
        await expect(memberStore.updateUserProfile("u-member", { email: "member@example.com" } as any)).rejects.toThrow(
          /email/i
        );
        await expect(
          memberStore.updateScopeMemberProfile("org-A", "u-member", { email: "member@example.com" } as any)
        ).rejects.toThrow(/email/i);
        // The server writes it (here as provisioning would)
        await serverStore.upsertUser({ ...(await serverStore.getUser("u-member"))!, email: "member@example.com" });
        expect((await adminDb.doc("users/u-member/private/attributes").get()).data()).toMatchObject({
          email: "member@example.com",
          badge: "global-badge",
          _lanyard: { tier: "attributes", uid: "u-member", scopeId: null }
        });
        expect((await serverStore.getScopeMember("org-A", "u-member"))?.email).toBe("member@example.com");
        const ownEmailEvents: any[] = [];
        const unsubOwnEmail = memberStore.subscribeToAttributes("u-member", (attrs, email) =>
          ownEmailEvents.push({ attrs, email })
        );
        await new Promise((r) => setTimeout(r, 150));
        expect(ownEmailEvents.at(-1)).toEqual({ attrs: { badge: "global-badge" }, email: "member@example.com" });
        unsubOwnEmail();

        const ownAttrsRef = clientDoc(memberClient.db, "users", "u-member", "private", "attributes");
        const lanyardMeta = { tier: "attributes", uid: "u-member", scopeId: null };
        // Not even the owner's own verified address (a client write would race the server's onVerifiedEmailChange)
        await expect(
          clientSetDoc(ownAttrsRef, { email: "member@example.com", _lanyard: lanyardMeta }, { merge: true })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientSetDoc(
            clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member", "private", "attributes"),
            { email: "member@example.com", _lanyard: { ...lanyardMeta, scopeId: "org-A" } },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Claiming someone else's address
        await expect(
          clientSetDoc(ownAttrsRef, { email: "ceo@example.com", _lanyard: lanyardMeta }, { merge: true })
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Sneaking another key in alongside the verified email
        await expect(
          clientSetDoc(
            ownAttrsRef,
            { email: "member@example.com", badge: "forged", _lanyard: lanyardMeta },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Writing another user's email, even their real one
        await expect(
          clientSetDoc(
            clientDoc(mgrClient.db, "users", "u-member", "private", "attributes"),
            { email: "member@example.com", _lanyard: lanyardMeta },
            { merge: true }
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        expect((await adminDb.doc("workspaces/org-B/members/u-member/private/attributes").get()).exists).toBe(false);
        // Avatar sync still works, and carries no email
        await memberStore.syncAvatar({ uid: "u-member", photoUrl: "https://example.com/member-synced.png" });
        expect((await adminDb.doc("users/u-member").get()).data()).toMatchObject({
          photoUrl: "https://example.com/member-synced.png"
        });
        expect((await adminDb.doc("users/u-member").get()).data()).not.toHaveProperty("email");

        // A user whose sign-in email isn't verified can't write it, even to their own attributes tier
        const unverifiedClient = await createAuthedClient("u-unverified", "unverified@example.com", false, false);
        try {
          expect((await unverifiedClient.auth.currentUser!.getIdTokenResult()).claims.email_verified).toBe(false);
          await expect(
            clientSetDoc(
              clientDoc(unverifiedClient.db, "users", "u-unverified", "private", "attributes"),
              { email: "unverified@example.com", _lanyard: { tier: "attributes", uid: "u-unverified", scopeId: null } },
              { merge: true }
            )
          ).rejects.toMatchObject({ code: "permission-denied" });
        } finally {
          await deleteClientApp(unverifiedClient.app);
        }

        // Attack H: Only scope staff can list a scope's attributes tiers (include: ["attributes"])
        const mgrStore = new FirestoreClientStore<Role, Cap, Prefs, { badge: string }>({
          db: mgrClient.db,
          usersCollection: "users",
          scopeCollection: "workspaces",
          membersSubcollection: "members"
        });
        const attributesTiersQuery = (db: any, scopeId: string | null) =>
          clientQuery(
            clientCollectionGroup(db, "private"),
            clientWhere("_lanyard.tier", "==", "attributes"),
            clientWhere("_lanyard.scopeId", "==", scopeId)
          );
        const staffRoster: any[][] = [];
        const unsubStaffRoster = mgrStore.subscribeToScopeMembers("org-A", (m) => staffRoster.push(m), {
          include: ["attributes"]
        });
        await new Promise((r) => setTimeout(r, 250));
        unsubStaffRoster();
        const memberWithTier = staffRoster.at(-1)?.find((m: any) => m.uid === "u-member");
        expect(memberWithTier).toMatchObject({ email: "member@example.com", attributes: { badge: "starter" } });
        expect(staffRoster.at(-1)?.find((m: any) => m.uid === "u-mgr")).toMatchObject({
          email: "mgr@example.com",
          attributes: { badge: "mgr-badge" }
        });
        // queryMemberUids: staff (and the server) can look members up by attributes-tier values; members can't
        expect(await mgrStore.queryMemberUids("org-A", { badge: "starter" })).toEqual(["u-member"]);
        expect(await mgrStore.queryMemberUids("org-A", { badge: "nobody-has-this" })).toEqual([]);
        expect(await serverStore.queryMemberUids("org-A", { badge: "mgr-badge" })).toEqual(["u-mgr"]);
        expect(await serverStore.queryMemberUids(null, { badge: "global-badge" })).toEqual(["u-member"]);
        await expect(memberStore.queryMemberUids("org-A", { badge: "starter" })).rejects.toMatchObject({
          code: "permission-denied"
        });
        // Card-placed keys are queried on the member cards, which every scope member can read
        const teamPolicy = createPermissionPolicy<Role, Cap>({ cardFields: { attributes: ["team"] } });
        const teamServerStore = new FirestoreServerStore<Role, Cap, Prefs, { team: string }>({
          db: adminDb,
          policy: teamPolicy,
          scopeCollection: "workspaces",
          membersSubcollection: "members"
        });
        await teamServerStore.updateScopeMemberAttributes("org-A", "u-mgr", { team: "blue" });
        expect((await adminDb.doc("workspaces/org-A/members/u-mgr").get()).data()?.attributes).toEqual({
          team: "blue"
        });
        const memberTeamStore = new FirestoreClientStore<Role, Cap, Prefs, { team: string }>({
          db: memberClient.db,
          policy: teamPolicy,
          scopeCollection: "workspaces",
          membersSubcollection: "members"
        });
        expect(await memberTeamStore.queryMemberUids("org-A", { team: "blue" })).toEqual(["u-mgr"]);
        await expect(memberTeamStore.queryMemberUids("org-B", { team: "blue" })).rejects.toMatchObject({
          code: "permission-denied"
        });

        // Custom documents: org-A staff write a member's shiftNotes, the member reads them, and nobody else gets in
        await mgrStore.updateCustomDoc("shiftNotes", "u-member", "org-A", { note: "great shift" });
        expect((await adminDb.doc("workspaces/org-A/members/u-member/private/shiftNotes").get()).data()).toEqual({
          note: "great shift",
          _lanyard: { tier: "shiftNotes", uid: "u-member", scopeId: "org-A", updatedAt: expect.any(String) }
        });
        expect(await memberStore.getCustomDoc("shiftNotes", "u-member", "org-A")).toEqual({ note: "great shift" });
        await expect(
          memberStore.updateCustomDoc("shiftNotes", "u-member", "org-A", { note: "self-praise" })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(memberStore.getCustomDoc("shiftNotes", "u-mgr", "org-A")).rejects.toMatchObject({
          code: "permission-denied"
        });
        await expect(
          mgrStore.updateCustomDoc("shiftNotes", "u-other", "org-B", { note: "cross-tenant" })
        ).rejects.toMatchObject({ code: "permission-denied" });

        // A non-staff member's include fails (the store reports an empty list), and raw queries are denied
        const memberRoster: any[][] = [];
        const unsubMemberRoster = memberStore.subscribeToScopeMembers("org-A", (m) => memberRoster.push(m), {
          include: ["attributes"]
        });
        await new Promise((r) => setTimeout(r, 250));
        unsubMemberRoster();
        expect(memberRoster.at(-1)).toEqual([]);
        await expect(clientGetDocs(attributesTiersQuery(memberClient.db, "org-A"))).rejects.toMatchObject({
          code: "permission-denied"
        });
        // Staff of org-A can't list org-B's tiers, and nobody can list across scopes without the scope filter
        await expect(clientGetDocs(attributesTiersQuery(mgrClient.db, "org-B"))).rejects.toMatchObject({
          code: "permission-denied"
        });
        await expect(
          clientGetDocs(
            clientQuery(
              clientCollectionGroup(mgrClient.db, "private"),
              clientWhere("_lanyard.tier", "==", "attributes")
            )
          )
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Not global staff (yet): the global users' tiers can't be listed either
        await expect(clientGetDocs(attributesTiersQuery(mgrClient.db, null))).rejects.toMatchObject({
          code: "permission-denied"
        });

        // Positive Verification:
        // - Non-admin user with global `manager` role on `users/u-mgr` CAN read another user's profile (`users/u-member`) via `hasUserCapability(['manager', 'owner'])`!
        await adminDb
          .doc("users/u-mgr")
          .set({ uid: "u-mgr", email: "mgr@example.com", roles: ["manager"] }, { merge: true });
        const mgrReadOtherUser = await clientGetDoc(clientDoc(mgrClient.db, "users", "u-member"));
        expect(mgrReadOtherUser.exists()).toBe(true);
        expect(mgrReadOtherUser.data()?.firstName).toBe("Memby");
        // ...and, as global staff, that user's attributes tier, including through include: ["attributes"]
        expect(
          (await clientGetDoc(clientDoc(mgrClient.db, "users", "u-member", "private", "attributes"))).data()
        ).toMatchObject({ badge: "global-badge" });
        const staffDirectory: any[][] = [];
        const unsubStaffDirectory = mgrStore.subscribeToUsers((users) => staffDirectory.push(users), {
          include: ["attributes"]
        });
        await new Promise((r) => setTimeout(r, 250));
        unsubStaffDirectory();
        expect(staffDirectory.at(-1)?.find((u: any) => u.uid === "u-member")).toMatchObject({
          email: "member@example.com",
          attributes: { badge: "global-badge" }
        });

        // - Manager of `org-A` CAN read/write `org-A` member `private/hiddenAttributes`, and System Admin CAN read/write global `private/hiddenAttributes`
        const orgAHiddenSnap = await clientGetDoc(
          clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member", "private", "hiddenAttributes")
        );
        expect(orgAHiddenSnap.data()).toMatchObject({
          secretNote: "Top secret org-A note",
          _lanyard: { tier: "hiddenAttributes", uid: "u-member", scopeId: "org-A" }
        });

        const globalHiddenSnap = await clientGetDoc(
          clientDoc(sysAdminClient.db, "users", "u-member", "private", "hiddenAttributes")
        );
        expect(globalHiddenSnap.data()).toMatchObject({ secretNote: "Top secret global note" });

        // Generated rules for cardVisibility: "staff", plus app-level rules calling hasScopeCapability,
        // hasScopeRole (including abstract/inherited roles), hasUserCapability, hasUserRole, and fail-closed typo checks
        const appCapabilities = ["invite_members", "delete_workspace"] as const;
        type AppRuleRole = "staff_base" | "member" | "manager" | "owner";
        type AppRuleCap = (typeof appCapabilities)[number];
        const appPolicy = createPermissionPolicy<AppRuleRole, AppRuleCap>({
          capabilities: appCapabilities,
          roles: {
            staff_base: { abstract: true, capabilities: ["invite_members"] },
            member: { capabilities: [] },
            manager: { inherits: ["member", "staff_base"], capabilities: [] },
            owner: { inherits: ["manager"], capabilities: "*" }
          },
          staffCapability: "invite_members",
          cardVisibility: "staff"
        });
        const appRulesBlock = `${generateFirestoreRules(appPolicy)}
    match /workspaces/{scopeId} {
      allow get: if isScopeMember(scopeId);
      allow update: if hasScopeRole(scopeId, 'staff_base');
      allow delete: if hasScopeCapability(scopeId, 'delete_workspace');

      match /typoCap/{docId} {
        allow read: if hasScopeCapability(scopeId, 'delete_workspcae');
      }
      match /typoRole/{docId} {
        allow read: if hasScopeRole(scopeId, 'managre');
      }
    }
    match /globalReports/{docId} {
      allow read: if hasUserCapability('invite_members');
      allow write: if hasUserRole('owner');
    }`;
        const staffCardsRes = await fetch(
          `http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              rules: {
                files: [
                  {
                    name: "firestore.rules",
                    content: wrapRules(appRulesBlock)
                  }
                ]
              }
            })
          }
        );
        expect(staffCardsRes.status).toBe(200);
        await expect(
          clientGetDoc(clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-mgr"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        expect(
          (await clientGetDoc(clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member"))).exists()
        ).toBe(true);
        expect(
          (await clientGetDoc(clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member"))).exists()
        ).toBe(true);

        // App-level rules evaluate inherited abstract roles (`hasScopeRole(scopeId, 'staff_base')`) and
        // closed-world "*" capabilities (`hasScopeCapability(scopeId, 'delete_workspace')`)
        await adminDb.doc("workspaces/org-A").set({ name: "Org A" });
        await adminDb.doc("globalReports/r1").set({ title: "Q4" });
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "workspaces", "org-A"), { name: "Member Edit" })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await clientUpdateDoc(clientDoc(mgrClient.db, "workspaces", "org-A"), { name: "Mgr Edit via staff_base" });
        // Manager lacks 'delete_workspace'; promoting to 'owner' grants it via closed-world "*"
        await expect(clientDeleteDoc(clientDoc(mgrClient.db, "workspaces", "org-A"))).rejects.toMatchObject({
          code: "permission-denied"
        });
        await adminDb.doc("workspaces/org-A/members/u-mgr").set({ roles: ["owner"] }, { merge: true });
        await clientDeleteDoc(clientDoc(mgrClient.db, "workspaces", "org-A"));
        await adminDb.doc("workspaces/org-A/members/u-mgr").set({ roles: ["manager"] }, { merge: true });
        await expect(
          clientGetDoc(clientDoc(mgrClient.db, "workspaces", "org-A", "typoCap", "d1"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Misspelled capability or role in firestore.rules fails closed EVEN for a system admin!
        await expect(
          clientGetDoc(clientDoc(sysAdminClient.db, "workspaces", "org-A", "typoCap", "d1"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientGetDoc(clientDoc(sysAdminClient.db, "workspaces", "org-A", "typoRole", "d1"))
        ).rejects.toMatchObject({ code: "permission-denied" });
        // Global `u-mgr` holds `manager` -> inherits `staff_base` -> has `invite_members` (`hasUserCapability`),
        // but does NOT hold `owner` (`hasUserRole('owner')`)
        expect((await clientGetDoc(clientDoc(mgrClient.db, "globalReports", "r1"))).exists()).toBe(true);
        await expect(clientGetDoc(clientDoc(memberClient.db, "globalReports", "r1"))).rejects.toMatchObject({
          code: "permission-denied"
        });
        await expect(
          clientUpdateDoc(clientDoc(mgrClient.db, "globalReports", "r1"), { title: "Denied" })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await clientUpdateDoc(clientDoc(sysAdminClient.db, "globalReports", "r1"), { title: "Admin Updated" });
      } finally {
        await terminate(memberClient.db);
        await deleteClientApp(memberClient.app);
        await terminate(mgrClient.db);
        await deleteClientApp(mgrClient.app);
        await terminate(sysAdminClient.db);
        await deleteClientApp(sysAdminClient.app);
      }
    }, 30_000);

    // Grounds the revocation design in real Firebase Auth behavior instead of assumptions. Runs last because it
    // replaces the emulator's security rules.
    it("behaves as Lanyard's revocation design assumes: stale claims persist until a forced refresh, rules can read the token's iat, and session revocation is keyed on auth_time", async () => {
      const uid = "u-revocation-grounding";
      const email = "revocation-grounding@example.com";
      await adminAuth.createUser({ uid, email, emailVerified: true });
      await adminAuth.setCustomUserClaims(uid, { admin: true });

      const app = initializeClientApp({ projectId, apiKey: "fake-api-key" }, `client-${uid}`);
      const auth = getClientAuth(app);
      connectAuthEmulator(auth, `http://127.0.0.1:${authEmulatorPort}`, { disableWarnings: true });
      const db = getClientFirestore(app);
      connectFirestoreEmulator(db, "127.0.0.1", emulatorPort);
      try {
        const { user } = await signInWithCredential(
          auth,
          GoogleAuthProvider.credential(JSON.stringify({ sub: uid, email, email_verified: true }))
        );
        const adminToken = await user.getIdTokenResult();
        expect(adminToken.claims.admin).toBe(true);
        const adminTokenIat = Number(adminToken.claims.iat);

        // 1. The problem: after demotion the already-issued token still says admin:true, and the Admin SDK's default
        //    verification (no revocation check) still accepts it with the stale claim.
        await adminAuth.setCustomUserClaims(uid, { admin: false });
        expect((await user.getIdTokenResult()).claims.admin).toBe(true);
        expect((await adminAuth.verifyIdToken(adminToken.token)).admin).toBe(true);

        // 2. A forced refresh picks up the new claim without signing the user out, and the new token is issued no
        //    earlier than the old one. iat has one-second granularity, so a token minted in the same second as a
        //    revocation can't be told apart from one minted just before it.
        await new Promise((resolve) => setTimeout(resolve, 1100));
        const demotedToken = await user.getIdTokenResult(true);
        expect(demotedToken.claims.admin).toBe(false);
        const demotedTokenIat = Number(demotedToken.claims.iat);
        expect(Number.isInteger(demotedTokenIat)).toBe(true);
        expect(demotedTokenIat).toBeGreaterThan(adminTokenIat);

        // 3. Firestore rules can read request.auth.token.iat (seconds) and compare it to a stored value
        const rulesRes = await fetch(
          `http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              rules: {
                files: [
                  {
                    name: "firestore.rules",
                    content: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /iat_probe/{issuedAfterSeconds} {
      allow get: if request.auth != null && request.auth.token.iat > int(issuedAfterSeconds);
    }
  }
}
`
                  }
                ]
              }
            })
          }
        );
        expect(rulesRes.status).toBe(200);
        await clientGetDoc(clientDoc(db, "iat_probe", String(demotedTokenIat - 1)));
        await expect(clientGetDoc(clientDoc(db, "iat_probe", String(demotedTokenIat + 3600)))).rejects.toMatchObject({
          code: "permission-denied"
        });

        // 4. Session revocation is keyed on auth_time (the sign-in time), not iat. After revokeRefreshTokens the old
        //    token fails verification with the revocation check. Production Firebase documents that the refresh itself
        //    then fails, but the Auth emulator still mints a token, so neither the emulator nor a design may rely on
        //    refresh failing. Any token minted after the revocation keeps the original auth_time (with a newer iat),
        //    and the Admin SDK's revocation check rejects it. So iat alone can't detect a revoked session: a refreshed
        //    token's iat is newer than the revocation.
        await adminAuth.revokeRefreshTokens(uid);
        await expect(adminAuth.verifyIdToken(demotedToken.token, true)).rejects.toMatchObject({
          code: "auth/id-token-revoked"
        });
        // Emulator-only: firebase-admin checks revocation even without checkRevoked when talking to the Auth emulator
        // (production skips it unless asked). Tests of Lanyard's own revocation handling must not rely on this.
        await expect(adminAuth.verifyIdToken(demotedToken.token)).rejects.toMatchObject({
          code: "auth/id-token-revoked"
        });
        // Cross a second boundary first: iat has one-second granularity
        await new Promise((resolve) => setTimeout(resolve, 1100));
        const afterRevoke = await user.getIdTokenResult(true).catch(() => null);
        if (afterRevoke) {
          expect(Number(afterRevoke.claims.auth_time)).toBe(Number(demotedToken.claims.auth_time));
          expect(Number(afterRevoke.claims.iat)).toBeGreaterThan(demotedTokenIat);
          await expect(adminAuth.verifyIdToken(afterRevoke.token, true)).rejects.toMatchObject({
            code: "auth/id-token-revoked"
          });
        }
      } finally {
        await terminate(db);
        await deleteClientApp(app);
      }
    }, 30_000);

    /** A client Auth instance connected to the Auth emulator, with no one signed in. */
    function emulatorClientAuth(name: string) {
      const app = initializeClientApp({ projectId, apiKey: "fake-api-key" }, `${name}-${Date.now()}`);
      const auth = getClientAuth(app);
      connectAuthEmulator(auth, `http://127.0.0.1:${authEmulatorPort}`, { disableWarnings: true });
      return { app, auth };
    }

    /**
     * The most recent email action link the Auth emulator "sent" to `email`: the raw link, its continue URL, and the URL
     * the app's page actually opens with (`handleCodeInApp`), which is the continue URL with the action parameters added.
     */
    async function latestEmailLink(email: string, requestType = "EMAIL_SIGNIN") {
      const res = await fetch(`http://127.0.0.1:${authEmulatorPort}/emulator/v1/projects/${projectId}/oobCodes`);
      const { oobCodes } = (await res.json()) as {
        oobCodes: { email: string; requestType: string; oobLink: string; oobCode: string }[];
      };
      const code = oobCodes.filter((c) => c.email === email && c.requestType === requestType).at(-1);
      if (!code) {
        const seen = oobCodes.map((c) => `${c.requestType} to ${c.email}`).join(", ");
        throw new Error(`No ${requestType} link was sent to ${email} (sent: ${seen})`);
      }
      const linkParams = new URL(code.oobLink).searchParams;
      const continueUrl = linkParams.get("continueUrl");
      const landing = new URL(continueUrl ?? "http://localhost:5173/");
      for (const key of ["apiKey", "oobCode", "mode", "lang"]) {
        const value = linkParams.get(key);
        if (value) landing.searchParams.set(key, value);
      }
      return { link: code.oobLink, oobCode: code.oobCode, continueUrl, landingUrl: landing.toString() };
    }

    // Grounds the magic-link design: what Firebase does when a link is completed with the wrong email or reused
    it("behaves as Lanyard's magic-link design assumes: completing with the wrong email fails without using up the link, and a used link can't be reused", async () => {
      const { app, auth } = emulatorClientAuth("client-email-link-grounding");
      try {
        await sendSignInLinkToEmail(auth, "link-owner@example.com", {
          url: "http://localhost:5173/finish",
          handleCodeInApp: true
        });
        const { link } = await latestEmailLink("link-owner@example.com");
        expect(isSignInWithEmailLink(auth, link)).toBe(true);

        // The wrong email is rejected, and nobody is signed in
        const mismatch = await signInWithEmailLink(auth, "someone-else@example.com", link).catch((e) => e);
        expect(mismatch?.code).toBe("auth/invalid-email");
        expect(auth.currentUser).toBeNull();

        // The rejected attempt didn't consume the link: the right email still completes it
        const { user } = await signInWithEmailLink(auth, "link-owner@example.com", link);
        expect(user.email).toBe("link-owner@example.com");
        await clientSignOut(auth);

        // A link that was used can't be used again, and that's a different error from a mismatch
        const reused = await signInWithEmailLink(auth, "link-owner@example.com", link).catch((e) => e);
        expect(reused?.code).toBe("auth/invalid-action-code");
        expect(auth.currentUser).toBeNull();
      } finally {
        await deleteClientApp(app);
      }
    }, 30_000);

    it("FIXED: a magic link signs the visitor in only with an email from this device or the user, never one from the link (login CSRF)", async () => {
      class MemoryLocalStorage {
        private map = new Map<string, string>();
        getItem = (k: string) => this.map.get(k) ?? null;
        setItem = (k: string, v: string) => void this.map.set(k, String(v));
        removeItem = (k: string) => void this.map.delete(k);
        key = (i: number) => [...this.map.keys()][i] ?? null;
        get length() {
          return this.map.size;
        }
      }
      vi.stubGlobal("localStorage", new MemoryLocalStorage());
      const attacker = emulatorClientAuth("client-csrf-attacker");
      const victim = emulatorClientAuth("client-csrf-victim");
      const newLanyard = (auth: ClientAuth, storageKeyPrefix: string) =>
        createLanyardClient({ auth, store: new InMemoryLanyardStore(), defaultPreferences: {}, storageKeyPrefix });
      const attackerLanyard = newLanyard(attacker.auth, "attacker");
      const victimLanyard = newLanyard(victim.auth, "victim");
      try {
        // The attacker requests a sign-in link for their own address. Lanyard no longer puts the address in it...
        await attackerLanyard.sendPasswordlessEmailLink("csrf-attacker@example.com");
        const { continueUrl, landingUrl } = await latestEmailLink("csrf-attacker@example.com");
        expect(new URL(continueUrl!).searchParams.has("email")).toBe(false);
        // ...but they can add it themselves to the page URL before sending the link to the victim
        const attackLink = `${landingUrl}&email=${encodeURIComponent("csrf-attacker@example.com")}`;

        // 1. A victim with no stored email isn't signed in; the app must ask them for the address
        expect(await victimLanyard.completePasswordlessSignIn({ href: attackLink })).toEqual({ status: "needs-email" });
        expect(victim.auth.currentUser).toBeNull();

        // 2. A victim who requested their own link on this device: the stored email doesn't match the attacker's link,
        //    so it's dropped and the app asks again, rather than failing in a way that looks like the victim's fault
        localStorage.setItem("victim_emailForSignIn", "csrf-victim@example.com");
        expect(await victimLanyard.completePasswordlessSignIn({ href: attackLink })).toEqual({ status: "needs-email" });
        expect(localStorage.getItem("victim_emailForSignIn")).toBeNull();
        expect(victim.auth.currentUser).toBeNull();

        // 3. A typed address that doesn't match is a typed error, and the link stays usable
        const mismatch = await victimLanyard
          .completePasswordlessSignIn({ href: attackLink, email: "csrf-victim@example.com" })
          .catch((e) => e);
        expect(mismatch).toBeInstanceOf(EmailLinkMismatchError);
        expect(mismatch.code).toBe(EMAIL_LINK_MISMATCH_ERROR_CODE);
        expect(victim.auth.currentUser).toBeNull();

        // 4. A victim who is already signed in keeps their session: the app must ask before switching accounts
        await signInWithCredential(
          victim.auth,
          GoogleAuthProvider.credential(
            JSON.stringify({ sub: "u-csrf-victim", email: "csrf-victim@example.com", email_verified: true })
          )
        );
        expect(await victimLanyard.completePasswordlessSignIn({ href: attackLink })).toEqual({
          status: "signed-in-as-other",
          currentEmail: "csrf-victim@example.com"
        });
        expect(victim.auth.currentUser?.email).toBe("csrf-victim@example.com");
        await victimLanyard.signOut();

        // The link's real owner, typing their own address, signs in; a used link can't be replayed
        const owner = await victimLanyard.completePasswordlessSignIn({
          href: attackLink,
          email: "CSRF-Attacker@Example.com "
        });
        expect(owner).toMatchObject({ status: "signed-in", user: { email: "csrf-attacker@example.com" } });
        await victimLanyard.signOut();
        const replay = await victimLanyard
          .completePasswordlessSignIn({ href: attackLink, email: "csrf-attacker@example.com" })
          .catch((e) => e);
        expect(replay).toBeInstanceOf(EmailLinkInvalidError);
        expect(replay.code).toBe(EMAIL_LINK_INVALID_ERROR_CODE);

        // Not a sign-in link at all
        expect(
          await victimLanyard.completePasswordlessSignIn({ href: "http://localhost:5173/?email=x%40y.z" })
        ).toEqual({ status: "not-a-link" });
      } finally {
        attackerLanyard.destroy();
        victimLanyard.destroy();
        vi.unstubAllGlobals();
        await deleteClientApp(attacker.app);
        await deleteClientApp(victim.app);
      }
    }, 30_000);

    it("a magic-link-only user can change their email, and the server syncs it and calls onVerifiedEmailChange once", async () => {
      class MemoryLocalStorage {
        private map = new Map<string, string>();
        getItem = (k: string) => this.map.get(k) ?? null;
        setItem = (k: string, v: string) => void this.map.set(k, String(v));
        removeItem = (k: string) => void this.map.delete(k);
        key = (i: number) => [...this.map.keys()][i] ?? null;
        get length() {
          return this.map.size;
        }
      }
      vi.stubGlobal("localStorage", new MemoryLocalStorage());
      const suffix = Date.now();
      const oldEmail = `link-user-${suffix}@example.com`;
      const newEmail = `link-user-new-${suffix}@example.com`;
      const usersCollection = `users_email_change_${suffix}`;
      const metaCollection = `meta_email_change_${suffix}`;
      const rules = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
${generateFirestoreRules(createPermissionPolicy({}), { usersCollection, metaCollection })}
  }
}
`;
      const rulesRes = await fetch(`http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: rules }] } })
      });
      expect(rulesRes.status).toBe(200);
      const store = new FirestoreServerStore({ db: adminDb, usersCollection, metaCollection });
      const events: VerifiedEmailChangeEvent[] = [];
      const server = createLanyardServer({
        adminAuth: adminAuth as any,
        store,
        onVerifiedEmailChange: (event) => void events.push(event)
      });
      const { app, auth } = emulatorClientAuth("client-email-change");
      const db = getClientFirestore(app);
      connectFirestoreEmulator(db, "127.0.0.1", emulatorPort);
      // The browser's Lanyard client reads (and, before email became server-owned, wrote) the same documents
      const lanyard = createLanyardClient({
        auth,
        store: new FirestoreClientStore({ db, usersCollection, metaCollection }),
        defaultPreferences: {}
      });
      try {
        // 1. Sign in with a magic link only (no other provider), as a first-time user
        await lanyard.sendPasswordlessEmailLink(oldEmail);
        const signIn = await lanyard.completePasswordlessSignIn({ href: (await latestEmailLink(oldEmail)).landingUrl });
        expect(signIn.status).toBe("signed-in");
        const uid = auth.currentUser!.uid;
        expect(auth.currentUser!.providerData.map((p) => p.providerId)).toEqual(["password"]);
        await store.upsertUser({ uid, email: oldEmail, roles: [] });
        expect((await runMiddleware(server.checkAuth, await auth.currentUser!.getIdToken())).nextCalled).toBe(true);
        expect(events).toEqual([]);

        // 2. Request the change; Firebase emails a confirmation link to the NEW address (filed under the current one)
        await lanyard.sendEmailUpdateVerification(newEmail);
        const { oobCode } = await latestEmailLink(oldEmail, "VERIFY_AND_CHANGE_EMAIL");
        // Until it's confirmed, nothing changes
        expect((await adminAuth.getUser(uid)).email).toBe(oldEmail);

        // 3. Confirming it changes the Firebase account's email, verified
        await applyActionCode(auth, oobCode);
        const changed = await adminAuth.getUser(uid);
        expect(changed.email).toBe(newEmail);
        expect(changed.emailVerified).toBe(true);

        // 4. The app picks up the change in the browser first (refreshEmailVerification reloads the user), and only
        //    then makes a request. The client must not write the email itself: if it did, checkAuth would see no
        //    difference and the hook would never fire. (The Auth emulator keeps the session across the change;
        //    production Firebase may instead end it, and then the user signs in again, which step 5 covers.)
        expect(await lanyard.refreshEmailVerification()).toBe(true);
        expect(lanyard.authStore.get().user?.email).toBe(newEmail);
        await new Promise((resolve) => setTimeout(resolve, 500));
        expect((await store.getUser(uid))?.email).toBe(oldEmail);
        const refreshedToken = await auth.currentUser!.getIdToken(true);
        expect((await runMiddleware(server.checkAuth, refreshedToken)).nextCalled).toBe(true);
        expect(events).toEqual([{ uid, email: newEmail, previousEmail: oldEmail }]);
        expect((await store.getUser(uid))?.email).toBe(newEmail);
        expect((await runMiddleware(server.checkAuth, refreshedToken)).nextCalled).toBe(true);
        expect(events).toHaveLength(1);

        // 5. Signing in again with a magic link goes to the new address and reaches the same account; nothing re-fires
        await lanyard.signOut();
        await lanyard.sendPasswordlessEmailLink(newEmail);
        const again = await lanyard.completePasswordlessSignIn({ href: (await latestEmailLink(newEmail)).landingUrl });
        expect(again).toMatchObject({ status: "signed-in", user: { uid, email: newEmail } });
        expect((await runMiddleware(server.checkAuth, await auth.currentUser!.getIdToken())).nextCalled).toBe(true);
        expect(events).toHaveLength(1);

        // 6. The old address no longer leads into this account: a link sent to it signs in a different (new) user
        await lanyard.signOut();
        await lanyard.sendPasswordlessEmailLink(oldEmail);
        const oldAddress = await lanyard.completePasswordlessSignIn({
          href: (await latestEmailLink(oldEmail)).landingUrl
        });
        expect(oldAddress.status).toBe("signed-in");
        expect(auth.currentUser!.uid).not.toBe(uid);
      } finally {
        lanyard.destroy();
        server.close();
        vi.unstubAllGlobals();
        await terminate(db);
        await deleteClientApp(app);
      }
    }, 30_000);

    it("FIXED: change-email links don't carry the new address", async () => {
      const user = await signInEmulatorUser("u-change-email", "change-email@example.com");
      const lanyard = createLanyardClient({
        auth: user.auth,
        store: new InMemoryLanyardStore(),
        defaultPreferences: {}
      });
      try {
        await lanyard.sendEmailUpdateVerification("changed-email@example.com");
        // The emulator files the link under the account's current address
        const { continueUrl } = await latestEmailLink("change-email@example.com", "VERIFY_AND_CHANGE_EMAIL");
        expect(new URL(continueUrl!).searchParams.has("email")).toBe(false);
      } finally {
        lanyard.destroy();
        await user.close();
      }
    }, 30_000);

    // --- Attack reproductions, verified against real Auth emulator tokens ---
    async function signInEmulatorUser(uid: string, email: string, claims?: Record<string, unknown>) {
      await adminAuth.createUser({ uid, email, emailVerified: true });
      if (claims) await adminAuth.setCustomUserClaims(uid, claims);
      const app = initializeClientApp({ projectId, apiKey: "fake-api-key" }, `client-${uid}`);
      const auth = getClientAuth(app);
      connectAuthEmulator(auth, `http://127.0.0.1:${authEmulatorPort}`, { disableWarnings: true });
      const db = getClientFirestore(app);
      connectFirestoreEmulator(db, "127.0.0.1", emulatorPort);
      const { user } = await signInWithCredential(
        auth,
        GoogleAuthProvider.credential(JSON.stringify({ sub: uid, email, email_verified: true }))
      );
      return {
        user,
        auth,
        db,
        async close() {
          await terminate(db);
          await deleteClientApp(app);
        }
      };
    }

    /** Runs Express-style middleware against a bearer token and reports whether it called next() and what it sent. */
    async function runMiddleware(
      middleware: (req: any, res: any, next: () => void) => unknown,
      token: string,
      req: any = {}
    ) {
      const outcome = { nextCalled: false, status: 200, body: undefined as any, req };
      req.headers = { ...(req.headers || {}), authorization: `Bearer ${token}` };
      const res: any = {
        status(code: number) {
          outcome.status = code;
          return res;
        },
        json(body: any) {
          outcome.body = body;
          return res;
        }
      };
      await middleware(req, res, () => {
        outcome.nextCalled = true;
      });
      return outcome;
    }

    const crossSecondBoundary = () => new Promise((resolve) => setTimeout(resolve, 1100));

    /**
     * An AdminAuthAdapter that verifies tokens like production's default `verifyIdToken`: no revocation check. In
     * emulator mode firebase-admin always checks revocation (production only does when asked, at the cost of a network
     * call), which would mask Lanyard's own revocation handling. Emulator tokens are unsigned, so this decodes the
     * payload directly; everything else delegates to the real emulator-backed Admin SDK.
     */
    function productionLikeAdminAuth() {
      return {
        verifyIdToken: async (idToken: string) => {
          const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
          return { ...payload, uid: payload.user_id ?? payload.sub };
        },
        getUserByEmail: (email: string) => adminAuth.getUserByEmail(email),
        createUser: (properties: any) => adminAuth.createUser(properties),
        setCustomUserClaims: (uid: string, claims: Record<string, any> | null) =>
          adminAuth.setCustomUserClaims(uid, claims),
        revokeRefreshTokens: (uid: string) => adminAuth.revokeRefreshTokens(uid),
        getUser: (uid: string) => adminAuth.getUser(uid)
      };
    }

    it("FIXED (H1): a demoted claim-only admin's still-valid token is refused at once, and can't re-promote them", async () => {
      const suffix = Date.now();
      const store = new FirestoreServerStore({
        db: adminDb,
        usersCollection: `users_h1_${suffix}`,
        metaCollection: `meta_h1_${suffix}`
      });
      const server = createLanyardServer({ adminAuth: adminAuth as any, store });
      await adminAuth.createUser({ uid: "u-h1-other-admin", email: "h1-other-admin@example.com", emailVerified: true });
      await adminAuth.setCustomUserClaims("u-h1-other-admin", { admin: true });
      // An admin known only by their claim (e.g. bootstrapped with a script), with no users/{uid} document
      const victim = await signInEmulatorUser("u-h1-admin", "h1-admin@example.com", { admin: true });
      try {
        const staleAdminToken = await victim.user.getIdToken();
        await crossSecondBoundary();
        await server.setSystemAdminStatus({
          email: "h1-admin@example.com",
          isAdmin: false,
          actor: { uid: "u-h1-other-admin" }
        });

        // The token they already hold is refused as stale, so it can't act as admin (or re-create an admin record)
        const stale = await runMiddleware(server.checkAuth, staleAdminToken);
        expect(stale.nextCalled).toBe(false);
        expect(stale.body).toMatchObject({ code: TOKEN_STALE_ERROR_CODE });
        expect(await store.getSystemAdmin("u-h1-admin")).toBeNull();

        // After refreshing past the revocation, their token says admin:false and requireAdmin refuses it
        await new Promise((resolve) => setTimeout(resolve, REVOCATION_CLOCK_SKEW_MS + 1100));
        const refreshedToken = await victim.user.getIdToken(true);
        const authed = await runMiddleware(server.checkAuth, refreshedToken);
        expect(authed.nextCalled).toBe(true);
        const admin = await runMiddleware(server.requireAdmin, refreshedToken, authed.req);
        expect(admin.nextCalled).toBe(false);
        expect(admin.status).toBe(403);
      } finally {
        server.close();
        await victim.close();
      }
    }, 30_000);

    it("FIXED (H2): setSystemAdminStatus refuses a non-admin actor, even one claiming isAdmin, before changing anything", async () => {
      const suffix = Date.now();
      const store = new FirestoreServerStore({
        db: adminDb,
        usersCollection: `users_h2_${suffix}`,
        metaCollection: `meta_h2_${suffix}`
      });
      const server = createLanyardServer({ adminAuth: adminAuth as any, store });
      await adminAuth.createUser({ uid: "u-h2-attacker", email: "h2-attacker@example.com", emailVerified: true });

      try {
        // An app route that forwards the caller (or a body-supplied actor) without its own admin check
        for (const actor of [
          { uid: "u-h2-attacker", isAdmin: false },
          { uid: "u-h2-attacker", isAdmin: true }
        ]) {
          await expect(
            server.setSystemAdminStatus({ email: "h2-attacker@example.com", isAdmin: true, actor })
          ).rejects.toThrow(/Forbidden/);
        }
        await expect(
          server.setSystemAdminStatus({
            email: "h2-new-account@example.com",
            isAdmin: true,
            actor: { uid: "u-h2-attacker", isAdmin: true } as any
          })
        ).rejects.toThrow(/Forbidden/);

        // Nothing changed: no admin claim, no admin record, no account provisioned
        expect((await adminAuth.getUser("u-h2-attacker")).customClaims?.admin).not.toBe(true);
        expect(await store.getSystemAdmin("u-h2-attacker")).toBeNull();
        await expect(adminAuth.getUserByEmail("h2-new-account@example.com")).rejects.toMatchObject({
          code: "auth/user-not-found"
        });
      } finally {
        server.close();
      }
    }, 30_000);

    it("FIXED: a session revoked through revokeUserSessions is refused at once, on every server instance, even after a refresh", async () => {
      const suffix = Date.now();
      const storeConfig = {
        db: adminDb,
        usersCollection: `users_sr_${suffix}`,
        metaCollection: `meta_sr_${suffix}`
      };
      const server = createLanyardServer({
        adminAuth: productionLikeAdminAuth(),
        store: new FirestoreServerStore(storeConfig)
      });
      // A second instance (e.g. another Cloud Run container) that only learns of the revocation through Firestore
      const otherInstance = createLanyardServer({
        adminAuth: productionLikeAdminAuth(),
        store: new FirestoreServerStore(storeConfig)
      });
      const signedOut = await signInEmulatorUser("u-signed-out", "signed-out@example.com");
      try {
        const tokenBeforeRevocation = await signedOut.user.getIdToken();
        expect((await runMiddleware(server.checkAuth, tokenBeforeRevocation)).nextCalled).toBe(true);
        expect((await runMiddleware(otherInstance.checkAuth, tokenBeforeRevocation)).nextCalled).toBe(true);
        // Cross a second boundary so the revocation is unambiguously after sign-in (auth_time has one-second granularity)
        await crossSecondBoundary();

        await server.revokeUserSessions({ uid: "u-signed-out", actor: { uid: "u-signed-out" } });

        const outcome = await runMiddleware(server.checkAuth, tokenBeforeRevocation);
        expect(outcome.nextCalled).toBe(false);
        expect(outcome.status).toBe(401);
        expect(outcome.body).toMatchObject({ code: SESSION_REVOKED_ERROR_CODE });

        let otherOutcome = await runMiddleware(otherInstance.checkAuth, tokenBeforeRevocation);
        for (let i = 0; i < 50 && otherOutcome.nextCalled; i++) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          otherOutcome = await runMiddleware(otherInstance.checkAuth, tokenBeforeRevocation);
        }
        expect(otherOutcome.nextCalled).toBe(false);
        expect(otherOutcome.body).toMatchObject({ code: SESSION_REVOKED_ERROR_CODE });

        // The Auth emulator still lets the revoked session refresh; the refreshed token keeps the old auth_time
        await crossSecondBoundary();
        const refreshed = await signedOut.user.getIdToken(true).catch(() => null);
        if (refreshed) {
          const refreshedOutcome = await runMiddleware(server.checkAuth, refreshed);
          expect(refreshedOutcome.nextCalled).toBe(false);
          expect(refreshedOutcome.body).toMatchObject({ code: SESSION_REVOKED_ERROR_CODE });
        }
      } finally {
        server.close();
        otherInstance.close();
        await signedOut.close();
      }
    }, 30_000);

    it("authorizedFetch end to end: a call with a token that predates a revocation is transparently refreshed and retried without signing out, and a revoked session signs the user out", async () => {
      const suffix = Date.now();
      const store = new FirestoreServerStore({
        db: adminDb,
        usersCollection: `users_fetch_${suffix}`,
        metaCollection: `meta_fetch_${suffix}`
      });
      const server = createLanyardServer({ adminAuth: productionLikeAdminAuth(), store });
      const app = express();
      // Echoes when the token the server accepted was issued
      app.get("/me", server.checkAuth as any, (req: any, res) => {
        const token = String(req.headers.authorization).replace(/^Bearer /, "");
        const { iat } = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
        res.json({ uid: req.user.uid, tokenIssuedAtSeconds: iat });
      });
      const httpServer = await new Promise<HttpServer>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const url = `http://127.0.0.1:${(httpServer.address() as { port: number }).port}/me`;

      const user = await signInEmulatorUser("u-fetch", "fetch@example.com", { admin: true });
      const lanyard = createLanyardClient({
        auth: user.auth,
        store: new FirestoreClientStore({ db: user.db, usersCollection: `users_fetch_${suffix}` }),
        defaultPreferences: {}
      });
      try {
        expect((await lanyard.authorizedFetch(url)).status).toBe(200);

        // A revocation (here: a claim change plus an epoch bump, as a demotion will do) supersedes the current token
        await crossSecondBoundary();
        await adminAuth.setCustomUserClaims("u-fetch", { admin: false });
        const epoch = await store.bumpRevocationEpoch(Date.now());
        const staleToken = await user.user.getIdToken();
        let check = await runMiddleware(server.checkAuth, staleToken);
        for (let i = 0; i < 50 && check.nextCalled; i++) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          check = await runMiddleware(server.checkAuth, staleToken);
        }
        expect(check.body).toMatchObject({ code: TOKEN_STALE_ERROR_CODE });

        // The app's call succeeds anyway: refused as stale, refreshed past the revocation, retried
        const res = await lanyard.authorizedFetch(url);
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.tokenIssuedAtSeconds * 1000).toBeGreaterThan(epoch + REVOCATION_CLOCK_SKEW_MS);
        expect((await user.user.getIdTokenResult()).claims.admin).toBe(false);
        expect(user.auth.currentUser?.uid).toBe("u-fetch");

        // Signing them out everywhere: the next call signs them out locally and throws a typed error
        await crossSecondBoundary();
        await server.revokeUserSessions({ uid: "u-fetch", actor: { uid: "u-fetch" } });
        const error = await lanyard.authorizedFetch(url).catch((e) => e);
        expect(error).toBeInstanceOf(SessionRevokedError);
        expect(user.auth.currentUser).toBeNull();
      } finally {
        lanyard.destroy();
        server.close();
        await new Promise<void>((resolve) => httpServer.close(() => resolve()));
        await user.close();
      }
    }, 60_000);

    it("under the generated rules, signed-in clients can read only the revocation epoch, and refresh to new claims on their own when it moves", async () => {
      const suffix = Date.now();
      const usersCollection = `users_proactive_${suffix}`;
      const metaCollection = `meta_proactive_${suffix}`;
      const rules = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
${generateFirestoreRules(createPermissionPolicy({}), { usersCollection, metaCollection })}
  }
}
`;
      const rulesRes = await fetch(`http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: rules }] } })
      });
      expect(rulesRes.status).toBe(200);

      const serverStore = new FirestoreServerStore({ db: adminDb, usersCollection, metaCollection });
      await serverStore.bumpRevocationEpoch(Date.now() - 60_000);
      await serverStore.recordSessionRevocation("u-someone-else", Date.now() - 60_000);

      const user = await signInEmulatorUser("u-proactive", "proactive@example.com", { admin: true });
      const signedOutApp = initializeClientApp({ projectId, apiKey: "fake-api-key" }, `client-signed-out-${suffix}`);
      const signedOutDb = getClientFirestore(signedOutApp);
      connectFirestoreEmulator(signedOutDb, "127.0.0.1", emulatorPort);
      const lanyard = createLanyardClient({
        auth: user.auth,
        store: new FirestoreClientStore({ db: user.db, usersCollection, metaCollection }),
        defaultPreferences: {}
      });
      try {
        // Rules: the epoch is readable when signed in; session revocations never; clients can't write either
        await clientGetDoc(clientDoc(user.db, `${metaCollection}/revocation`));
        await expect(clientGetDoc(clientDoc(signedOutDb, `${metaCollection}/revocation`))).rejects.toMatchObject({
          code: "permission-denied"
        });
        await expect(clientGetDoc(clientDoc(user.db, `${metaCollection}/session_revocations`))).rejects.toMatchObject({
          code: "permission-denied"
        });
        await expect(
          clientSetDoc(clientDoc(user.db, `${metaCollection}/revocation`), { lastRevocationAtMs: 0 })
        ).rejects.toMatchObject({ code: "permission-denied" });

        // A demotion: the claim changes in Firebase, then the epoch moves. No request is made.
        await crossSecondBoundary();
        await adminAuth.setCustomUserClaims("u-proactive", { admin: false });
        const epoch = await serverStore.bumpRevocationEpoch(Date.now());

        let claims = (await user.user.getIdTokenResult()).claims;
        const deadline = Date.now() + 15_000;
        while (claims.admin !== false && Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, 200));
          claims = (await user.user.getIdTokenResult()).claims;
        }
        expect(claims.admin).toBe(false);
        expect(Number(claims.iat) * 1000).toBeGreaterThan(epoch + REVOCATION_CLOCK_SKEW_MS);
        expect(user.auth.currentUser?.uid).toBe("u-proactive");
      } finally {
        lanyard.destroy();
        await terminate(signedOutDb);
        await deleteClientApp(signedOutApp);
        await user.close();
      }
    }, 60_000);

    it("FIXED: generated rules reject a demoted admin's stale claim, a revoked admin session, and an unverified user", async () => {
      const suffix = Date.now();
      const usersCollection = `users_rules_${suffix}`;
      const metaCollection = `meta_rules_${suffix}`;
      const rules = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
${generateFirestoreRules(createPermissionPolicy({}), { usersCollection, metaCollection })}
  }
}
`;
      const rulesRes = await fetch(`http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: rules }] } })
      });
      expect(rulesRes.status).toBe(200);
      await adminDb.doc(`${usersCollection}/u-rules-victim/private/preferences`).set({ theme: "dark" });

      const store = new FirestoreServerStore({
        db: adminDb,
        usersCollection,
        metaCollection
      });
      const server = createLanyardServer({ adminAuth: adminAuth as any, store });
      await adminAuth.createUser({
        uid: "u-rules-other-admin",
        email: "rules-other-admin@example.com",
        emailVerified: true
      });
      await adminAuth.setCustomUserClaims("u-rules-other-admin", { admin: true });
      const demoted = await signInEmulatorUser("u-rules-admin", "rules-admin@example.com", { admin: true });
      const revokedAdmin = await signInEmulatorUser("u-rules-revoked-admin", "rules-revoked-admin@example.com", {
        admin: true
      });
      await adminAuth.createUser({
        uid: "u-rules-unverified",
        email: "rules-unverified@example.com",
        emailVerified: false,
        password: "emulator-test-password"
      });
      const unverifiedApp = initializeClientApp({ projectId, apiKey: "fake-api-key" }, `client-u-rules-unverified`);
      const unverifiedAuth = getClientAuth(unverifiedApp);
      connectAuthEmulator(unverifiedAuth, `http://127.0.0.1:${authEmulatorPort}`, { disableWarnings: true });
      await signInWithEmailAndPassword(unverifiedAuth, "rules-unverified@example.com", "emulator-test-password");
      const unverifiedDb = getClientFirestore(unverifiedApp);
      connectFirestoreEmulator(unverifiedDb, "127.0.0.1", emulatorPort);
      await adminDb.doc(`${usersCollection}/u-rules-unverified`).set({ uid: "u-rules-unverified" });

      try {
        // 1. Demotion: as an admin they can read another user's private preferences until setSystemAdminStatus demotes them
        await clientGetDoc(clientDoc(demoted.db, `${usersCollection}/u-rules-victim/private/preferences`));
        await crossSecondBoundary();
        await server.setSystemAdminStatus({
          email: "rules-admin@example.com",
          isAdmin: false,
          actor: { uid: "u-rules-other-admin" }
        });

        // Denied right after demotion, even though the client still holds the un-refreshed admin:true token
        await expect(
          clientGetDoc(clientDoc(demoted.db, `${usersCollection}/u-rules-victim/private/preferences`))
        ).rejects.toMatchObject({ code: "permission-denied" });

        // 2. Session revocation: wait past the demotion's epoch skew, refresh the second admin so their iat is fresh,
        //    then revoke their sessions. Even if they refresh again (new iat, same auth_time), rules deny them.
        await new Promise((resolve) => setTimeout(resolve, REVOCATION_CLOCK_SKEW_MS + 1100));
        await revokedAdmin.user.getIdToken(true);
        await clientGetDoc(clientDoc(revokedAdmin.db, `${usersCollection}/u-rules-victim/private/preferences`));
        await crossSecondBoundary();
        await server.revokeUserSessions({ uid: "u-rules-revoked-admin", actor: { uid: "u-rules-other-admin" } });
        await expect(
          clientGetDoc(clientDoc(revokedAdmin.db, `${usersCollection}/u-rules-victim/private/preferences`))
        ).rejects.toMatchObject({ code: "permission-denied" });
        await crossSecondBoundary();
        await revokedAdmin.user.getIdToken(true).catch(() => null);
        await expect(
          clientGetDoc(clientDoc(revokedAdmin.db, `${usersCollection}/u-rules-victim/private/preferences`))
        ).rejects.toMatchObject({ code: "permission-denied" });

        // 3. Unverified email: by default (requireVerifiedEmail: true), even isOwner(uid) reads/writes are denied
        await expect(
          clientGetDoc(clientDoc(unverifiedDb, `${usersCollection}/u-rules-unverified`))
        ).rejects.toMatchObject({ code: "permission-denied" });

        // 4. H3: an unverified account pre-registered under someone's address cannot receive roles or admin status
        await expect(
          server.upsertUserByEmail({ scopeId: GLOBAL_SCOPE, email: "rules-unverified@example.com", roles: [] })
        ).rejects.toMatchObject({ code: "auth/email-not-verified" });
        await expect(
          server.setSystemAdminStatus({
            email: "rules-unverified@example.com",
            isAdmin: true,
            actor: { uid: "u-rules-other-admin" }
          })
        ).rejects.toMatchObject({ code: "auth/email-not-verified" });
        expect((await adminAuth.getUser("u-rules-unverified")).customClaims?.admin).not.toBe(true);
      } finally {
        server.close();
        await terminate(unverifiedDb);
        await deleteClientApp(unverifiedApp);
        await revokedAdmin.close();
        await demoted.close();
      }
    }, 30_000);

    it("FIXED: an avatar or email sync that read a user before a role revocation or demotion doesn't undo it on real Firestore", async () => {
      const suffix = Date.now();
      type Role = "member" | "manager";
      const policy = createPermissionPolicy<Role, "edit">({
        roles: { member: { capabilities: [] }, manager: { inherits: ["member"], capabilities: ["edit"] } }
      });
      const store = new FirestoreServerStore<Role, "edit">({
        db: adminDb,
        usersCollection: `users_lost_update_${suffix}`,
        scopeCollection: `orgs_lost_update_${suffix}`,
        metaCollection: `meta_lost_update_${suffix}`
      });
      await store.upsertUser({ uid: "u-lu", email: "lu-old@example.com", roles: ["manager"], isSystemAdmin: true });
      await store.upsertScopeMember("org-1", { uid: "u-lu", email: "lu-old@example.com", roles: ["manager"] });
      const server = createLanyardServer({
        adminAuth: adminAuth as any,
        store,
        policy,
        authService: {
          async verifyToken() {
            const t = Math.floor(Date.now() / 1000);
            return {
              uid: "u-lu",
              email: "lu-new@example.com",
              emailVerified: true,
              photoUrl: "https://example.com/lu.png",
              adminClaim: false,
              issuedAtSeconds: t,
              authTimeSeconds: t - 60
            };
          }
        }
      });
      /** The next read of `method` returns what it read before `interleave` ran (a concurrent admin change). */
      const interleaveAfterNextRead = (method: "getUser" | "getScopeMember", interleave: () => Promise<void>) => {
        const original = (store as any)[method].bind(store);
        vi.spyOn(store, method).mockImplementationOnce(async (...args: any[]) => {
          const snapshot = await original(...args);
          await interleave();
          return snapshot;
        });
      };
      try {
        // checkAuth's verified-email sync read the record, then the user was demoted and lost their role
        interleaveAfterNextRead("getUser", async () => {
          await store.revokeUserRoles("u-lu", ["manager"]);
          await store.deleteSystemAdmin("u-lu");
        });
        const authed = await runMiddleware(server.checkAuth, "unused");
        expect(authed.nextCalled).toBe(true);
        let stored = await store.getUser("u-lu");
        expect(stored?.email).toBe("lu-new@example.com");
        expect(stored?.roles).toEqual([]);
        expect(stored?.isSystemAdmin).toBe(false);

        // requireRole's scoped avatar sync read the member, then their scope role was revoked
        await store.grantScopeRoles("org-1", "u-lu", ["manager"]);
        interleaveAfterNextRead("getScopeMember", () => store.revokeScopeRoles("org-1", "u-lu", ["manager"]));
        authed.req.params = { scopeId: "org-1" };
        await runMiddleware(server.requireRole("member"), "unused", authed.req);
        const member = await store.getScopeMember("org-1", "u-lu");
        expect(member?.photoUrl).toBe("https://example.com/lu.png");
        expect(member?.roles).toEqual([]);

        // patchUser/patchScopeMember never create records
        await expect(store.patchUser("u-nobody", { firstName: "X" })).rejects.toThrow();
        await expect(store.patchScopeMember("org-1", "u-nobody", { firstName: "X" })).rejects.toThrow();
        expect((await adminDb.doc(`users_lost_update_${suffix}/u-nobody`).get()).exists).toBe(false);
      } finally {
        server.close();
      }
    }, 30_000);

    it("FIXED: staff with user-management rights can't delete an admin known only by their Firebase claim", async () => {
      const suffix = Date.now();
      type Role = "member" | "staff";
      const policy = createPermissionPolicy<Role, "manage">({
        roles: { member: { capabilities: [] }, staff: { inherits: ["member"], capabilities: ["manage"] } },
        userCapabilities: { write: "manage" }
      });
      const store = new FirestoreServerStore<Role, "manage">({
        db: adminDb,
        usersCollection: `users_target_admin_${suffix}`,
        metaCollection: `meta_target_admin_${suffix}`
      });
      const server = createLanyardServer({ adminAuth: adminAuth as any, store, policy });
      const adminUid = `u-claim-admin-${suffix}`;
      await adminAuth.createUser({ uid: adminUid, email: `claim-admin-${suffix}@example.com`, emailVerified: true });
      await adminAuth.setCustomUserClaims(adminUid, { admin: true });
      await store.upsertUser({ uid: "u-ta-staff", email: "ta-staff@example.com", roles: ["staff"] });
      // The admin's record carries no isSystemAdmin flag (promoted through the console or a script)
      await store.upsertUser({ uid: adminUid, email: `claim-admin-${suffix}@example.com`, roles: ["member"] });
      // A user record with no Firebase account (real firebase-admin reports auth/user-not-found for it)
      await store.upsertUser({ uid: `u-no-account-${suffix}`, email: `no-account-${suffix}@example.com`, roles: [] });
      try {
        await expect(
          server.deleteUser({
            scopeId: GLOBAL_SCOPE,
            actor: { uid: "u-ta-staff" },
            targetUid: adminUid,
            confirmTargetEmail: `claim-admin-${suffix}@example.com`
          })
        ).rejects.toThrow(/Forbidden/);
        expect((await adminAuth.getUser(adminUid)).customClaims?.admin).toBe(true);
        expect(await store.getUser(adminUid)).not.toBeNull();

        // A record with no Firebase account can't hold the claim: real firebase-admin reports auth/user-not-found,
        // which the guard recognizes, so staff can still manage it
        await server.updateUserProfile({
          scopeId: GLOBAL_SCOPE,
          actor: { uid: "u-ta-staff" },
          targetUid: `u-no-account-${suffix}`,
          patch: { firstName: "Nobody" }
        });
        expect((await store.getUser(`u-no-account-${suffix}`))?.firstName).toBe("Nobody");

        // An ordinary account (no claim) can be deleted
        const plainUid = `u-ta-plain-${suffix}`;
        await adminAuth.createUser({ uid: plainUid, email: `ta-plain-${suffix}@example.com`, emailVerified: true });
        await store.upsertUser({ uid: plainUid, email: `ta-plain-${suffix}@example.com`, roles: [] });
        await server.deleteUser({
          scopeId: GLOBAL_SCOPE,
          actor: { uid: "u-ta-staff" },
          targetUid: plainUid,
          confirmTargetEmail: `ta-plain-${suffix}@example.com`
        });
        expect(await store.getUser(plainUid)).toBeNull();
      } finally {
        server.close();
      }
    }, 30_000);

    it("FIXED: on real Firestore, a user whose roles were all revoked has no roles, rather than getting defaults back", async () => {
      const suffix = Date.now();
      type Role = "member" | "staff";
      const policy = createPermissionPolicy<Role, "edit">({
        roles: { member: { capabilities: [] }, staff: { inherits: ["member"], capabilities: ["edit"] } },
        defaultRoles: ["staff"]
      });
      const config = {
        usersCollection: `users_defaults_${suffix}`,
        scopeCollection: `orgs_defaults_${suffix}`,
        metaCollection: `meta_defaults_${suffix}`,
        // Stores used to take a defaultRoles option that they substituted for empty or missing roles on read
        defaultRoles: ["staff"]
      };
      const store = new FirestoreServerStore<Role, "edit">({ db: adminDb, ...config } as any);
      const clientStore = new FirestoreClientStore<Role, "edit">({ db: clientDb, ...config } as any);
      const server = createLanyardServer({ adminAuth: adminAuth as any, store, policy });
      // Earlier tests leave security rules loaded; this one reads with the client SDK, so open its collections
      const rulesRes = await fetch(`http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rules: {
            files: [
              {
                name: "firestore.rules",
                content: `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} { allow read, write: if true; }\n  }\n}\n`
              }
            ]
          }
        })
      });
      expect(rulesRes.status).toBe(200);
      try {
        await store.upsertUser({ uid: "u-def", email: "def@example.com", roles: ["staff"] });
        await store.upsertScopeMember("org-1", { uid: "u-def", email: "def@example.com", roles: ["staff"] });
        await store.revokeUserRoles("u-def", ["staff"]);
        await store.revokeScopeRoles("org-1", "u-def", ["staff"]);

        // Server reads, client reads, and authorization all agree with the stored (empty) roles, as the rules do
        expect((await store.getUser("u-def"))?.roles).toEqual([]);
        expect((await store.getScopeMember("org-1", "u-def"))?.roles).toEqual([]);
        const clientCard = await new Promise<any>((resolve) => {
          const unsubscribe = clientStore.subscribeToUser("u-def", (u) => {
            unsubscribe();
            resolve(u);
          });
        });
        expect(clientCard?.roles).toEqual([]);
        let allowed = false;
        await server.requireCapability("edit", GLOBAL_SCOPE)(
          { user: { uid: "u-def", email: "def@example.com", emailVerified: true, isAdmin: false } } as any,
          { status: () => ({ json: () => undefined }) } as any,
          () => {
            allowed = true;
          }
        );
        expect(allowed).toBe(false);

        // A grant of no roles to a new member gives them none, even though the policy lists defaults
        await store.grantScopeRoles("org-1", "u-volunteer", [], { uid: "u-volunteer", email: "v@example.com" } as any);
        expect((await store.getScopeMember("org-1", "u-volunteer"))?.roles).toEqual([]);
      } finally {
        server.close();
      }
    }, 30_000);

    it("FIXED: with cardFields.email, an owner can't put a different address on their card", async () => {
      const usersCollection = `users_card_email_${Date.now()}`;
      const policy = createPermissionPolicy({ cardFields: { email: true } });
      const rules = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
${generateFirestoreRules(policy, { usersCollection })}
  }
}
`;
      const rulesRes = await fetch(`http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: rules }] } })
      });
      expect(rulesRes.status).toBe(200);
      await adminDb.doc(`${usersCollection}/u-card-owner`).set({ uid: "u-card-owner", email: "owner@example.com" });
      const owner = await signInEmulatorUser("u-card-owner", "owner@example.com");
      try {
        const card = clientDoc(owner.db, `${usersCollection}/u-card-owner`);
        await expect(clientUpdateDoc(card, { email: "ceo@example.com" })).rejects.toMatchObject({
          code: "permission-denied"
        });
        await expect(clientUpdateDoc(card, { email: "ceo@example.com", firstName: "O" })).rejects.toMatchObject({
          code: "permission-denied"
        });
        // Ordinary profile fields are still self-editable
        await clientUpdateDoc(card, { firstName: "Owner" });
        expect((await adminDb.doc(`${usersCollection}/u-card-owner`).get()).data()).toMatchObject({
          email: "owner@example.com",
          firstName: "Owner"
        });
      } finally {
        await owner.close();
      }
    }, 30_000);

    it("FIXED: on real Firestore, secrets are closed-world: only declared keys can be written or read back", async () => {
      const suffix = Date.now();
      const usersCollection = `users_secrets_${suffix}`;
      // Mirrors canvus: AI keys are user-owned, OAuth tokens are written only by trusted backend code
      const policy = createPermissionPolicy({
        roles: { member: { capabilities: [] } },
        secretCapabilities: {
          geminiKey: { self: true },
          openaiKey: { self: true },
          anthropicKey: { self: true },
          gmailAccessToken: {},
          gmailRefreshToken: {},
          calendarAccessToken: {},
          calendarRefreshToken: {}
        }
      });
      const encryptionKey = "emulator-closed-world-secrets-key";
      const store = new FirestoreServerStore({ db: adminDb, policy, usersCollection, encryptionKey });
      const server = createLanyardServer({ adminAuth, store, policy });
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        const user = await server.upsertUserByEmail({ scopeId: GLOBAL_SCOPE, email: `secrets-${suffix}@example.com` });
        await adminAuth.createUser({ uid: `secrets-admin-${suffix}`, email: `sa-${suffix}@example.com` });
        await adminAuth.setCustomUserClaims(`secrets-admin-${suffix}`, { admin: true });
        const selfWrite = (patch: Record<string, string>) =>
          server.updateUserSecrets({ scopeId: GLOBAL_SCOPE, actor: user, targetUid: user.uid, patch } as any);

        // The user writes their own AI key, but can't touch the backend-owned OAuth tokens
        expect(await selfWrite({ geminiKey: "AIza-self" })).toEqual({ geminiKey: true });
        await expect(selfWrite({ gmailRefreshToken: "forged" })).rejects.toThrow(/Forbidden/);

        // Nobody can plant a key the policy doesn't declare: not the user, not an admin, not the store directly
        await expect(selfWrite({ webhookUrl: "https://attacker.example" })).rejects.toThrow(/Forbidden/);
        await expect(
          server.updateUserSecrets({
            scopeId: GLOBAL_SCOPE,
            actor: { uid: `secrets-admin-${suffix}` },
            targetUid: user.uid,
            patch: { webhookUrl: "https://attacker.example" }
          } as any)
        ).rejects.toThrow(/Forbidden/);
        await expect(store.updateUserSecrets(user.uid, { webhookUrl: "x" } as any)).rejects.toThrow(/not declared/);

        // Trusted backend code (e.g. an OAuth callback) writes the OAuth tokens through the store
        await store.updateUserSecrets(user.uid, { gmailRefreshToken: "refresh-1" } as any);
        expect(await server.getDecryptedUserSecrets(GLOBAL_SCOPE, user.uid)).toEqual({
          geminiKey: "AIza-self",
          gmailRefreshToken: "refresh-1"
        });

        // A key written behind Lanyard's back (or left over from an older policy) is ignored, with a warning
        await adminDb
          .doc(`${usersCollection}/${user.uid}/private/secrets`)
          .set({ webhookUrl: encryptSecret("https://attacker.example", encryptionKey) }, { merge: true });
        expect(await store.getUserSecretsStatus(user.uid)).toEqual({ geminiKey: true, gmailRefreshToken: true });
        expect(await server.getDecryptedUserSecrets(GLOBAL_SCOPE, user.uid)).toEqual({
          geminiKey: "AIza-self",
          gmailRefreshToken: "refresh-1"
        });
        expect(warn).toHaveBeenCalledWith(expect.stringContaining("Ignoring undeclared secret key 'webhookUrl'"));
      } finally {
        warn.mockRestore();
        server.close();
      }
    }, 30_000);

    it("FIXED: on real Firestore, a coordinator who can assign roles can't promote anyone above their rank or touch the volunteer roster", async () => {
      const suffix = Date.now();
      const scopeCollection = `campaigns_ceiling_${suffix}`;
      const usersCollection = `users_ceiling_${suffix}`;
      type Role = "volunteer" | "scanner" | "coordinator" | "owner";
      type Cap = "scan" | "assign_roles";
      // canvus's roles, once it turns on assign-roles
      const policy = createPermissionPolicy<Role, Cap>({
        capabilities: ["scan", "assign_roles"],
        roles: {
          volunteer: { systemManaged: true },
          scanner: { capabilities: ["scan"] },
          coordinator: { inherits: ["scanner"], capabilities: ["assign_roles"] },
          owner: { inherits: ["coordinator"], capabilities: "*" }
        },
        userCapabilities: { assignRoles: "assign_roles" }
      });
      const store = new FirestoreServerStore<Role, Cap>({ db: adminDb, policy, usersCollection, scopeCollection });
      const server = createLanyardServer({ adminAuth, store, policy });
      const rules = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
${generateFirestoreRules(policy, { usersCollection, scopeCollection })}
  }
}
`;
      const rulesRes = await fetch(`http://127.0.0.1:${emulatorPort}/emulator/v1/projects/${projectId}:securityRules`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: rules }] } })
      });
      expect(rulesRes.status).toBe(200);
      const campaign = "campaign-1";
      const coordUid = `coord-${suffix}`;
      const add = (uid: string, roles: Role[]) =>
        store.upsertScopeMember(campaign, { uid, email: `${uid}@example.com`, roles });
      await add(coordUid, ["coordinator"]);
      await add(`boss-${suffix}`, ["owner"]);
      await add(`vol-${suffix}`, ["volunteer"]);
      const coordinator = await signInEmulatorUser(coordUid, `${coordUid}@example.com`);
      const update = (targetUid: string, roles: Role[]) =>
        server.updateUserRoles({ scopeId: campaign, actor: { uid: coordUid }, targetUid, roles });
      const rolesOf = async (uid: string) => (await store.getScopeMember(campaign, uid))?.roles;
      try {
        // Through the server: no promotion above their rank, no edits to someone who outranks them, no self-promotion
        await expect(update(`vol-${suffix}`, ["owner"])).rejects.toThrow(/Forbidden: Role 'owner'/);
        await expect(update(`boss-${suffix}`, ["scanner"])).rejects.toThrow(/Forbidden: Target holds 'owner'/);
        await expect(update(coordUid, ["owner"])).rejects.toThrow(/Forbidden: Users can't change their own roles/);
        expect(await rolesOf(`boss-${suffix}`)).toEqual(["owner"]);

        // Promoting a volunteer keeps them on the roster, and the roster role can't be handed out by hand
        await update(`vol-${suffix}`, ["coordinator"]);
        expect(await rolesOf(`vol-${suffix}`)).toEqual(["volunteer", "coordinator"]);
        await expect(update(`boss-${suffix}`, ["owner", "volunteer"])).rejects.toThrow(/system-managed/);

        // Around the server: the generated rules don't let a non-admin client write roles at all
        await expect(
          clientUpdateDoc(clientDoc(coordinator.db, `${scopeCollection}/${campaign}/members/${coordUid}`), {
            roles: ["owner"]
          })
        ).rejects.toMatchObject({ code: "permission-denied" });
        expect(await rolesOf(coordUid)).toEqual(["coordinator"]);
      } finally {
        await coordinator.close();
        server.close();
      }
    }, 30_000);
  }
);

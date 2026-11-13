import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { type Server as HttpServer } from "node:http";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  deleteApp as deleteAdminApp,
  initializeApp as initializeAdminApp,
  type App as AdminApp
} from "firebase-admin/app";
import { getAuth as getAdminAuth, type Auth as AdminAuth } from "firebase-admin/auth";
import { getFirestore as getAdminFirestore, type Firestore as AdminFirestore } from "firebase-admin/firestore";
import { deleteApp as deleteClientApp, initializeApp as initializeClientApp, type FirebaseApp } from "firebase/app";
import {
  connectAuthEmulator,
  getAuth as getClientAuth,
  GoogleAuthProvider,
  signInWithCredential,
  signInWithEmailAndPassword,
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
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FirestoreClientStore } from "./client/firestore.js";
import { createLanyardClient } from "./client/index.js";
import { createPermissionPolicy, GLOBAL_SCOPE, type LanyardReadable } from "./core/index.js";
import { FirestoreServerStore } from "./server/firestore.js";
import { createLanyardServer, isEncryptedSecretData } from "./server/index.js";
import { generateFirestoreRules } from "./rules/index.js";
import { assertRevocationEpochConformance } from "./testing/index.js";

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
          geminiKey: { allowSelfWrite: true },
          openaiKey: { write: "write:ai_keys", allowSelfWrite: false }
        }
      });

      const serverStore = new FirestoreServerStore<Role, Cap, Prefs, Attrs, HiddenAttrs, Secrets>({
        db: adminDb,
        defaultRoles: ["attendee"],
        usersCollection: "users_st",
        encryptionKey: "emulator-test-master-encryption-key"
      });
      const clientStore = new FirestoreClientStore<Role, Cap, Prefs, Attrs>({
        db: clientDb,
        defaultRoles: ["attendee"],
        usersCollection: "users_st"
      });

      const server = createLanyardServer<Role, Cap, Prefs, Attrs, HiddenAttrs, Secrets>({
        adminAuth,
        store: serverStore,
        policy
      });

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
        actor: { uid: "root-admin", isAdmin: true },
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
          actor: { uid: "root-admin", isAdmin: true },
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

      // Even if a request arrives with a real signed Auth Emulator JWT that still has `admin: true`,
      // `checkAuth` + `requireAdmin` re-checks live Firestore `isSystemAdmin` and rejects with 403!
      const staleReq: any = { headers: { authorization: `Bearer ${staleAdminJwt}` } };
      await server.checkAuth(staleReq, createMockRes(), () => {});
      expect(staleReq.user?.isAdmin).toBe(false);
      const resStaleAdmin = createMockRes();
      await server.requireAdmin(staleReq, resStaleAdmin, () => {});
      expect(resStaleAdmin.statusCode).toBe(403);

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

      // ...while a profile-only stub card created via FirestoreClientStore resolves to `defaultRole` ("attendee") on server
      await clientStore.updateUserProfile("prefs-only-uid", { firstName: "Stubby" });
      const stubUser = await serverStore.getUser("prefs-only-uid");
      expect(stubUser?.roles).toEqual(["attendee"]);
      expect(stubUser?.preferences).toEqual({ theme: "dark" });

      let stubAllowedAsAttendee = false;
      await server.requireCapability("view:schedule", GLOBAL_SCOPE)(
        { user: { uid: "prefs-only-uid", email: "stub@example.com", isAdmin: false } } as any,
        createMockRes(),
        () => {
          stubAllowedAsAttendee = true;
        }
      );
      expect(stubAllowedAsAttendee).toBe(true);

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
          geminiKey: { write: "manage:secrets", allowSelfWrite: false }
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
        defaultRoles: ["member"],
        usersCollection: "users_mt",
        scopeCollection: "orgs_mt",
        membersSubcollection: "members_mt",
        encryptionKey: "emulator-mt-master-key"
      });
      const clientStore = new FirestoreClientStore<Role, Cap, Record<string, any>, { quotaTier: string }>({
        db: clientDb,
        defaultRoles: ["member"],
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
          defaultRoles: ["member"],
          usersCollection: "users",
          scopeCollection: "workspaces",
          membersSubcollection: "members",
          encryptionKey: "emulator-rules-test-key"
        });

        const memberStore = new FirestoreClientStore<Role, Cap, Prefs, { badge: string }>({
          db: memberClient.db,
          defaultRoles: ["member"],
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

        await new Promise((r) => setTimeout(r, 150));
        expect(userEvents.at(-1)?.uid).toBe("u-member");
        expect(userEvents.at(-1)?.roles).toEqual(["member"]);
        expect(userEvents.at(-1)?.preferences).toBeUndefined();
        expect(prefEvents.at(-1)).toEqual({ compactMode: true });

        // Direct client `savePreferences`, `syncAvatar`, `updateUserProfile`, and `recordPresenceHeartbeat` (global)
        await memberStore.savePreferences("u-member", { theme: "dark", compactMode: false });
        await memberStore.syncAvatar({
          uid: "u-member",
          photoUrl: "https://example.com/avatar.png",
          email: "member@example.com",
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
        expect((await serverStore.getUser("u-member"))?.roles).toEqual(["member"]);

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

        // Attack G: Email is private (stored in the attributes tier, never on cards), and owners can only write
        // their own verified Firebase Auth email there
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

        await memberStore.updateUserProfile("u-member", { email: "Member@Example.com" });
        await memberStore.updateScopeMemberProfile("org-A", "u-member", { email: "member@example.com" });
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
        // Wrong tier metadata
        await expect(
          clientSetDoc(
            ownAttrsRef,
            { email: "member@example.com", _lanyard: { ...lanyardMeta, scopeId: "org-A" } },
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
        // Writing a scoped email in a scope the user isn't a member of (no phantom docs)
        await expect(
          memberStore.updateScopeMemberProfile("org-B", "u-member", { email: "member@example.com" })
        ).rejects.toMatchObject({ code: "permission-denied" });
        expect((await adminDb.doc("workspaces/org-B/members/u-member/private/attributes").get()).exists).toBe(false);

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
          defaultRoles: ["member"],
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
    });

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
  }
);

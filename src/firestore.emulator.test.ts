import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
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
  type Auth as ClientAuth
} from "firebase/auth";
import {
  connectFirestoreEmulator,
  doc as clientDoc,
  getDoc as clientGetDoc,
  getFirestore as getClientFirestore,
  setDoc as clientSetDoc,
  terminate,
  updateDoc as clientUpdateDoc,
  type Firestore as ClientFirestore
} from "firebase/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FirestoreClientStore } from "./client/firestore.js";
import { createLanyardClient } from "./client/index.js";
import { createPermissionPolicy, type LanyardReadable } from "./core/index.js";
import { FirestoreServerStore } from "./server/firestore.js";
import { createLanyardServer, isEncryptedSecretData } from "./server/index.js";

const EMULATOR_JAR = join(homedir(), ".cache", "firebase", "emulators", "cloud-firestore-emulator-v1.21.0.jar");
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
  return new Promise((resolve, reject) => {
    const proc = spawn("java", ["-jar", EMULATOR_JAR, "--host", "127.0.0.1", "--port", String(port)], {
      stdio: ["ignore", "pipe", "pipe"]
    });

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

describe.skipIf(!existsSync(EMULATOR_JAR) || !existsSync(AUTH_EMULATOR_SERVER_JS))(
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
      emulatorPort = await getFreePort();
      authEmulatorPort = await getFreePort();
      projectId = `lanyard-emu-test-${Date.now()}`;

      origEmulatorHost = process.env.FIRESTORE_EMULATOR_HOST;
      origAuthEmulatorHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
      process.env.FIRESTORE_EMULATOR_HOST = `127.0.0.1:${emulatorPort}`;
      process.env.FIREBASE_AUTH_EMULATOR_HOST = `127.0.0.1:${authEmulatorPort}`;

      const [fsProc, authSrv] = await Promise.all([
        startFirestoreEmulator(emulatorPort),
        startAuthEmulator(authEmulatorPort, projectId)
      ]);
      emulatorProc = fsProc;
      authEmulatorServer = authSrv;

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
          attendee: { weight: 10, capabilities: ["view:schedule"], trackPresence: false },
          scanner: {
            weight: 20,
            inherits: ["attendee"],
            capabilities: ["write:points", "read:scanner_log", "write:scanner_log"],
            trackPresence: true
          },
          merch_seller: {
            weight: 20,
            inherits: ["attendee"],
            capabilities: ["read:merch", "write:merch", "read:merch_pin", "write:merch_pin"],
            trackPresence: false
          },
          auditor: {
            weight: 20,
            inherits: ["attendee"],
            capabilities: ["read:merch", "read:scanner_log"],
            trackPresence: false
          },
          moderator: {
            weight: 30,
            inherits: ["scanner", "merch_seller", "auditor"],
            capabilities: ["write:badges", "write:audit_hash", "write:ai_keys"]
          }
        },
        attributeCapabilities: {
          pointsAllTime: "write:points",
          merchCreditBalance: { read: "read:merch", write: "write:merch" },
          awardedBadges: "write:badges",
          readonlySystemBadge: { read: "read:merch" }
        },
        hiddenAttributeCapabilities: {
          scannerAuditLog: { read: "read:scanner_log", write: "write:scanner_log" },
          merchPosPin: { read: "read:merch_pin", write: "write:merch_pin" },
          blindAuditHash: { write: "write:audit_hash" }
        },
        secretCapabilities: {
          geminiKey: { allowSelfWrite: true },
          openaiKey: { write: "write:ai_keys", allowSelfWrite: false }
        }
      });

      const serverStore = new FirestoreServerStore<Role, Cap, Prefs, Attrs, HiddenAttrs, Secrets>({
        db: adminDb,
        defaultRole: "attendee",
        usersCollection: "users_st",
        encryptionKey: "emulator-test-master-encryption-key"
      });
      const clientStore = new FirestoreClientStore<Role, Cap, Prefs, Attrs>({
        db: clientDb,
        defaultRole: "attendee",
        usersCollection: "users_st"
      });

      const server = createLanyardServer<Role, Cap, Prefs, Attrs, HiddenAttrs, Secrets>({
        adminAuth,
        store: serverStore,
        policy
      });

      // 1. Provision single-tenant users in real Firebase Auth Emulator + real Firestore (including omitting optional firstName/lastName to verify no undefined field errors!)
      const attendee = await server.upsertUserByEmail({
        email: "attendee@example.com",
        firstName: "Testy",
        lastName: "McTest",
        role: "attendee",
        preferences: { leaderboardOptIn: false },
        attributes: {
          pointsAllTime: 10,
          merchCreditBalance: 100,
          awardedBadges: ["registered"],
          readonlySystemBadge: "pioneer"
        }
      });
      const scanner = await server.upsertUserByEmail({
        email: "scanner@example.com",
        role: "scanner" // firstName & lastName intentionally omitted!
      });
      const merchSeller = await server.upsertUserByEmail({
        email: "merch@example.com",
        role: "merch_seller"
      });
      const auditor = await server.upsertUserByEmail({
        email: "auditor@example.com",
        role: "auditor"
      });
      const moderator = await server.upsertUserByEmail({
        email: "moderator@example.com",
        firstName: "Moddy",
        lastName: "McModerator",
        role: "moderator"
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
      await server.updateUserAttributesAs({
        actorUid: scanner.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 35 }
      });
      await server.updateUserHiddenAttributesAs({
        actorUid: scanner.uid,
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
      await server.updateUserAttributesAs({
        actorUid: merchSeller.uid,
        targetUid: attendee.uid,
        patch: { merchCreditBalance: 80 }
      });
      await server.updateUserHiddenAttributesAs({
        actorUid: merchSeller.uid,
        targetUid: attendee.uid,
        patch: { merchPosPin: "7744" }
      });
      await expect(
        server.updateUserAttributesAs({
          actorUid: merchSeller.uid,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 999 }
        })
      ).rejects.toThrow(/Forbidden/);

      // Sibling attribute & hiddenAttribute read redaction from real Firestore:
      expect(
        await server.readUserAttributesAs({
          actorUid: scanner.uid,
          targetUid: attendee.uid
        })
      ).toEqual({
        pointsAllTime: 35,
        awardedBadges: ["registered"]
      });
      expect(
        await server.readUserHiddenAttributesAs({
          actorUid: scanner.uid,
          targetUid: attendee.uid
        })
      ).toEqual({
        scannerAuditLog: "Checked in at Main Hall"
      });
      expect(
        await server.readUserHiddenAttributesAs({
          actorUid: merchSeller.uid,
          targetUid: attendee.uid
        })
      ).toEqual({
        merchPosPin: "7744"
      });

      // Auditor can read merchCreditBalance, readonlySystemBadge, and scannerAuditLog, but cannot write anything
      expect(
        await server.readUserAttributesAs({
          actorUid: auditor.uid,
          targetUid: attendee.uid
        })
      ).toEqual({
        pointsAllTime: 35,
        merchCreditBalance: 80,
        awardedBadges: ["registered"],
        readonlySystemBadge: "pioneer"
      });
      await expect(
        server.updateUserHiddenAttributesAs({
          actorUid: auditor.uid,
          targetUid: attendee.uid,
          patch: { scannerAuditLog: "Auditor tamper" }
        })
      ).rejects.toThrow(/Forbidden/);

      // 4. Write-only hiddenAttribute (`blindAuditHash`), superAdmin hiddenAttribute, & AES-256-GCM encrypted `secrets` on real Firestore:
      await server.updateUserHiddenAttributesAs({
        actorUid: moderator.uid,
        targetUid: attendee.uid,
        patch: { blindAuditHash: "sha256:998877" }
      });
      await server.updateUserHiddenAttributesAs({
        actorUid: "root-admin",
        isSystemAdmin: true,
        targetUid: attendee.uid,
        patch: { superAdminSecret: "root-eyes-only" }
      });

      // Moderator reads both sibling hiddenAttributes via diamond inheritance, while `blindAuditHash` and `superAdminSecret` are redacted
      expect(
        await server.readUserHiddenAttributesAs({
          actorUid: moderator.uid,
          targetUid: attendee.uid
        })
      ).toEqual({
        scannerAuditLog: "Checked in at Main Hall",
        merchPosPin: "7744"
      });

      // System admin reads all 4 hiddenAttribute fields from real Firestore
      expect(
        await server.readUserHiddenAttributesAs({
          actorUid: "root-admin",
          isSystemAdmin: true,
          targetUid: attendee.uid
        })
      ).toEqual({
        scannerAuditLog: "Checked in at Main Hall",
        merchPosPin: "7744",
        blindAuditHash: "sha256:998877",
        superAdminSecret: "root-eyes-only"
      });

      // Write-only AES-256-GCM encrypted user secrets on real Firestore (`users_st/{uid}/private/secrets`):
      const secretStatus1 = await server.updateUserSecretsAs({
        actorUid: attendee.uid,
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
      expect(await server.getDecryptedUserSecrets(attendee.uid)).toEqual({
        geminiKey: "AIzaSyRealFirestoreKey123"
      });
      expect(
        await server.updateUserSecretsAs({
          actorUid: attendee.uid,
          targetUid: attendee.uid,
          patch: { geminiKey: "" }
        })
      ).toEqual({});
      expect(await server.getDecryptedUserSecrets(attendee.uid)).toEqual({});

      // 5. Client self-service preferences & profile updates on real Firestore preserve role, capabilities, and attributes
      await client.updatePreferences({ leaderboardOptIn: true, theme: "dark" });
      await client.updateProfile({ firstName: "UpdatedTesty" });

      const afterSelfUpdate = await waitForStore(
        client.userRecordStore,
        (u) => u?.firstName === "UpdatedTesty" && u?.preferences?.leaderboardOptIn === true
      );
      expect(afterSelfUpdate?.role).toBe("attendee");
      expect(afterSelfUpdate?.attributes?.pointsAllTime).toBe(35);
      expect(afterSelfUpdate?.attributes?.merchCreditBalance).toBe(80);

      // 6. Per-user ad-hoc capability grant & revocation on real Firestore:
      await server.upsertUserByEmail({
        email: "attendee@example.com",
        role: "attendee",
        capabilities: ["write:points"]
      });
      await server.updateUserAttributesAs({
        actorUid: attendee.uid,
        targetUid: attendee.uid,
        patch: { pointsAllTime: 60 }
      });
      await waitForStore(client.attributesStore, (a) => a.pointsAllTime === 60);

      // Revoke ad-hoc capability on real Firestore (empty array overwrites capabilities on merge: true)
      await server.upsertUserByEmail({
        email: "attendee@example.com",
        role: "attendee",
        capabilities: []
      });
      await expect(
        server.updateUserAttributesAs({
          actorUid: attendee.uid,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 99 }
        })
      ).rejects.toThrow(/Forbidden/);

      // 7. Real-time system admin promotion & demotion on real Firebase Auth Emulator + real Firestore + stale JWT rejection:
      await server.setSystemAdminStatus({
        email: "attendee@example.com",
        isAdmin: true,
        actorUid: "root-admin"
      });
      await waitForStore(client.authStore, (s) => s.user?.isAdmin === true);

      // Force token refresh on clientAuth and verify the real Auth Emulator minted the custom `admin: true` claim
      const promotedTokenResult = await clientAuth.currentUser!.getIdTokenResult(true);
      expect(promotedTokenResult.claims.admin).toBe(true);
      const staleAdminJwt = promotedTokenResult.token;

      await server.setSystemAdminStatus({
        email: "attendee@example.com",
        isAdmin: false,
        actorUid: "root-admin"
      });
      await waitForStore(client.authStore, (s) => s.user?.isAdmin === false);

      // Even if a request arrives with a real signed Auth Emulator JWT that still has `admin: true`,
      // `checkAuth` + `requireAdmin` re-checks live Firestore `isSystemAdmin` and rejects with 403!
      const staleReq: any = { headers: { authorization: `Bearer ${staleAdminJwt}` } };
      await server.checkAuth(staleReq, createMockRes(), () => {});
      expect(staleReq.user?.isAdmin).toBe(true);
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
        server.updateUserAttributesAs({
          actorUid: scanner.uid,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 75 }
        }),
        server.updateUserAttributesAs({
          actorUid: merchSeller.uid,
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
        server.updateUserAttributesAs({
          actorUid: scanner.uid,
          targetUid: attendee.uid,
          patch: { pointsAllTime: 9999, awardedBadges: ["forged"] }
        })
      ).rejects.toThrow(/Forbidden/);
      expect((await serverStore.getUser(attendee.uid))?.attributes?.pointsAllTime).toBe(75);

      // 10. Role demotion (`moderator` -> `scanner`) persisted in real Firestore:
      await server.upsertUserByEmail({
        email: "moderator@example.com",
        role: "scanner"
      });
      await expect(
        server.updateUserAttributesAs({
          actorUid: moderator.uid,
          targetUid: attendee.uid,
          patch: { awardedBadges: ["after-demotion"] }
        })
      ).rejects.toThrow(/Forbidden/);

      // 11. Preferences-only stub created via FirestoreClientStore resolves to `defaultRole` ("attendee") on server
      await clientStore.savePreferences("prefs-only-uid", { theme: "dark" });
      const stubUser = await serverStore.getUser("prefs-only-uid");
      expect(stubUser?.role).toBe("attendee");

      let stubAllowedAsAttendee = false;
      await server.requireUserCapability("view:schedule")(
        { user: { uid: "prefs-only-uid", email: "stub@example.com", isAdmin: false } } as any,
        createMockRes(),
        () => {
          stubAllowedAsAttendee = true;
        }
      );
      expect(stubAllowedAsAttendee).toBe(true);

      client.destroy();
    });

    it("enforces multi-tenant capabilities, FieldValue.arrayUnion/arrayRemove, collectionGroup memberships, and hiddenAttribute/secret cleanup on real Firestore", async () => {
      type Role = "member" | "manager" | "owner";
      type Cap = "edit:content" | "manage:billing" | "read:notes" | "write:notes" | "manage:secrets";

      const policy = createPermissionPolicy<Role, Cap>({
        roles: {
          member: { weight: 10, capabilities: [] },
          manager: { weight: 50, inherits: ["member"], capabilities: ["edit:content", "read:notes"] },
          owner: { weight: 100, inherits: ["manager"], capabilities: "*" }
        },
        attributeCapabilities: {
          quotaTier: "manage:billing"
        },
        hiddenAttributeCapabilities: {
          internalNotes: { read: "read:notes", write: "write:notes" }
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
        defaultRole: "member",
        usersCollection: "users_mt",
        scopeCollection: "orgs_mt",
        membersSubcollection: "members_mt",
        encryptionKey: "emulator-mt-master-key"
      });
      const clientStore = new FirestoreClientStore<Role, Cap, Record<string, any>, { quotaTier: string }>({
        db: clientDb,
        defaultRole: "member",
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

      // 1. Grant additive capabilities via FieldValue.arrayUnion and revoke via FieldValue.arrayRemove on real Firestore
      const m1 = await server.grantScopeCapabilitiesByEmail({
        scopeId: "org-1",
        email: "worker@example.com",
        capabilities: ["edit:content"]
      });
      await server.grantScopeCapabilitiesByEmail({
        scopeId: "org-1",
        email: "worker@example.com",
        capabilities: ["manage:billing"]
      });
      expect((await serverStore.getScopeMember("org-1", m1.uid))?.capabilities).toEqual([
        "edit:content",
        "manage:billing"
      ]);

      await server.revokeScopeCapabilities("org-1", m1.uid, ["edit:content"]);
      expect((await serverStore.getScopeMember("org-1", m1.uid))?.capabilities).toEqual(["manage:billing"]);

      // 2. Add worker to org-2 as owner and verify real Firestore collectionGroup query in subscribeToUserMemberships
      await server.upsertScopeMemberByEmail({
        scopeId: "org-2",
        email: "worker@example.com",
        role: "owner"
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
      // Worker is `owner` in `org-2` (can write hiddenAttributes and scope secrets in `org-2`),
      // but only `member` with `["manage:billing"]` in `org-1`
      await server.updateScopeMemberHiddenAttributesAs({
        scopeId: "org-2",
        actorUid: m1.uid,
        targetUid: m1.uid,
        patch: { internalNotes: "Org 2 note" }
      });
      await server.updateScopeMemberSecretsAs({
        scopeId: "org-2",
        actorUid: m1.uid,
        targetUid: m1.uid,
        patch: { geminiKey: "AIzaSyMemberKeyOrg2" }
      });
      expect(
        await server.getScopeMemberSecretsStatusAs({
          scopeId: "org-2",
          actorUid: m1.uid,
          targetUid: m1.uid
        })
      ).toEqual({ geminiKey: true });
      expect(await server.getDecryptedScopeMemberSecrets("org-2", m1.uid)).toEqual({
        geminiKey: "AIzaSyMemberKeyOrg2"
      });
      const rawScopedMemberSecretSnap = await adminDb.doc(`orgs_mt/org-2/members_mt/${m1.uid}/private/secrets`).get();
      expect(isEncryptedSecretData(rawScopedMemberSecretSnap.data()?.geminiKey)).toBe(true);
      expect(JSON.stringify(rawScopedMemberSecretSnap.data())).not.toContain("AIzaSyMemberKeyOrg2");

      await server.updateScopeSecretsAs({
        scopeId: "org-2",
        actorUid: m1.uid,
        patch: { geminiKey: "AIzaSySharedOrg2" }
      });
      expect(
        await server.getScopeSecretsStatusAs({
          scopeId: "org-2",
          actorUid: m1.uid
        })
      ).toEqual({ geminiKey: true });
      expect(await server.getDecryptedScopeSecrets("org-2")).toEqual({ geminiKey: "AIzaSySharedOrg2" });

      await expect(
        server.updateScopeMemberHiddenAttributesAs({
          scopeId: "org-1",
          actorUid: m1.uid,
          targetUid: m1.uid,
          patch: { internalNotes: "Unauthorized Org 1 note" }
        })
      ).rejects.toThrow(/Forbidden/);
      await expect(
        server.updateScopeSecretsAs({
          scopeId: "org-1",
          actorUid: m1.uid,
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
      const referenceRules = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function isSignedIn() {
      return request.auth != null;
    }

    function isOwner(uid) {
      return isSignedIn() && request.auth.uid == uid;
    }

    function isAdmin() {
      return isSignedIn() &&
        request.auth.token != null &&
        ("admin" in request.auth.token) &&
        request.auth.token.admin == true;
    }

    function memberPath(scopeId) {
      return /databases/$(database)/documents/workspaces/$(scopeId)/members/$(request.auth.uid);
    }

    function isScopeMember(scopeId) {
      return isAdmin() || (isSignedIn() && exists(memberPath(scopeId)));
    }

    function hasScopeCapability(scopeId, capability, rolesImplyingCapability) {
      return isAdmin() || (
        isSignedIn() &&
        get(memberPath(scopeId)).data != null && (
          get(memberPath(scopeId)).data.role in rolesImplyingCapability ||
          (capability in get(memberPath(scopeId)).data.get('capabilities', []))
        )
      );
    }

    match /users/{uid} {
      allow read: if isOwner(uid) || isAdmin();
      allow create: if isAdmin() || (
        isOwner(uid) &&
        request.resource.data.keys().hasOnly([
          'uid', 'email', 'firstName', 'lastName', 'displayName', 'photoUrl', 'lastSeen', 'preferences', 'createdAt', 'updatedAt'
        ]) &&
        (!('uid' in request.resource.data) || request.resource.data.uid == uid)
      );
      allow update: if isAdmin() || (
        isOwner(uid) &&
        request.resource.data.diff(resource.data).affectedKeys().hasOnly([
          'uid', 'email', 'firstName', 'lastName', 'displayName', 'photoUrl', 'lastSeen', 'preferences', 'updatedAt'
        ]) &&
        (!('uid' in request.resource.data) || request.resource.data.uid == uid)
      );

      match /private/{docId} {
        allow read, write: if isAdmin();
      }
    }

    match /{path=**}/members/{memberUid} {
      allow read: if isSignedIn() && (resource.data.uid == request.auth.uid || isAdmin());
    }

    match /workspaces/{scopeId}/members/{memberUid} {
      allow read: if isScopeMember(scopeId);
      allow create, delete: if hasScopeCapability(scopeId, 'invite_members', ['owner', 'manager']);
      allow update: if hasScopeCapability(scopeId, 'invite_members', ['owner', 'manager']) || (
        isOwner(memberUid) &&
        request.resource.data.diff(resource.data).affectedKeys().hasOnly(['lastSeen', 'photoUrl', 'preferences'])
      );

      match /private/hiddenAttributes {
        allow read, write: if hasScopeCapability(scopeId, 'invite_members', ['owner', 'manager']);
      }

      match /private/secrets {
        allow read, write: if false;
      }
    }
  }
}
`;

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

      async function createAuthedClient(uid: string, email: string, isAdmin = false) {
        await adminAuth.createUser({ uid, email, emailVerified: true });
        if (isAdmin) {
          await adminAuth.setCustomUserClaims(uid, { admin: true });
        }
        const app = initializeClientApp(
          { projectId, apiKey: "fake-api-key" },
          `client-${uid}-${Math.random().toString(36).slice(2, 7)}`
        );
        const auth = getClientAuth(app);
        connectAuthEmulator(auth, `http://127.0.0.1:${authEmulatorPort}`, { disableWarnings: true });
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
          defaultRole: "member",
          usersCollection: "users",
          scopeCollection: "workspaces",
          membersSubcollection: "members",
          encryptionKey: "emulator-rules-test-key"
        });

        const memberStore = new FirestoreClientStore<Role, Cap, Prefs, { badge: string }>({
          db: memberClient.db,
          defaultRole: "member",
          usersCollection: "users",
          scopeCollection: "workspaces",
          membersSubcollection: "members"
        });

        // 1. Legacy top-level preference fallback on `users/u-member` before `preferences` map exists,
        //    plus multiplexed `subscribeToUser` + `subscribeToPreferences` sharing 1 underlying listener
        await adminDb.doc("users/u-member").set({ uid: "u-member", compactMode: true });

        const userEvents: any[] = [];
        const prefEvents: any[] = [];
        const unsubUser = memberStore.subscribeToUser("u-member", (u) => userEvents.push(u));
        const unsubPrefs = memberStore.subscribeToPreferences("u-member", (p) => prefEvents.push(p));

        await new Promise((r) => setTimeout(r, 150));
        expect(userEvents.at(-1)?.uid).toBe("u-member");
        expect(userEvents.at(-1)?.role).toBe("member");
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

        // Unsubscribing one listener keeps the multiplexed subscription alive for the other
        unsubPrefs();
        await memberStore.savePreferences("u-member", { theme: "light", compactMode: false });
        await new Promise((r) => setTimeout(r, 150));
        expect(userEvents.at(-1)?.preferences).toEqual({ theme: "light", compactMode: false });
        unsubUser();

        // 2. Provision scoped memberships via serverStore (`org-A` has `u-mgr` as manager and `u-member` as member; `org-B` has another user)
        await serverStore.upsertScopeMember("org-A", {
          uid: "u-mgr",
          email: "mgr@example.com",
          role: "manager",
          capabilities: ["invite_members"]
        });
        await serverStore.upsertScopeMember("org-A", {
          uid: "u-member",
          email: "member@example.com",
          role: "member",
          capabilities: [],
          attributes: { badge: "starter" }
        });
        await serverStore.upsertScopeMember("org-B", {
          uid: "u-other",
          email: "other@example.com",
          role: "owner",
          capabilities: []
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

        // 4. Scoped `syncAvatar`, `recordPresenceHeartbeat`, and `saveScopePreferences` update existing scoped member doc without creating phantom docs
        await memberStore.syncAvatar({
          uid: "u-member",
          scopeId: "org-A",
          photoUrl: "https://example.com/scoped-avatar.png"
        });
        await memberStore.recordPresenceHeartbeat({
          uid: "u-member",
          scopeId: "org-A",
          lastSeenIso: "2026-10-21T12:05:00.000Z"
        });
        await memberStore.saveScopePreferences("org-A", "u-member", { theme: "dark", compactMode: false });
        await memberStore.saveScopePreferences("org-A", "u-member", { compactMode: true });
        await new Promise((r) => setTimeout(r, 150));

        const updatedOrgAMember = rosterList.at(-1)?.find((m: any) => m.uid === "u-member");
        expect(updatedOrgAMember?.photoUrl).toBe("https://example.com/scoped-avatar.png");
        expect(updatedOrgAMember?.lastSeen).toBe("2026-10-21T12:05:00.000Z");
        expect(updatedOrgAMember?.preferences).toEqual({ theme: "dark", compactMode: true });

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

        // Also verify `grantUserCapabilities` and `revokeUserCapabilities` on global `users/u-member` in real Firestore
        await serverStore.grantUserCapabilities("u-member", ["edit:content"]);
        expect((await serverStore.getUser("u-member"))?.capabilities).toEqual(["edit:content"]);
        await serverStore.revokeUserCapabilities("u-member", ["edit:content"]);
        expect((await serverStore.getUser("u-member"))?.capabilities).toEqual([]);

        unsubMemberships();
        unsubRoster();

        // 5. Security Rules Attack Surface Verification (Direct Client SDK Attacks):
        // Attack A: Non-admin user tries to self-escalate `isSystemAdmin`, `role`, `capabilities`, or `attributes` on `users/u-member`
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { isSystemAdmin: true })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { role: "owner" })
        ).rejects.toMatchObject({ code: "permission-denied" });
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "users", "u-member"), { capabilities: ["edit:content"] })
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

        // Attack D: Scoped member tries to self-escalate `role`, `capabilities`, or `attributes` on `workspaces/org-A/members/u-member`
        await expect(
          clientUpdateDoc(clientDoc(memberClient.db, "workspaces", "org-A", "members", "u-member"), {
            role: "owner"
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
            role: "owner"
          })
        ).rejects.toMatchObject({ code: "permission-denied" });

        // Positive Verification: Manager of `org-A` CAN read/write `org-A` member `private/hiddenAttributes`, and System Admin CAN read/write global `private/hiddenAttributes`
        const orgAHiddenSnap = await clientGetDoc(
          clientDoc(mgrClient.db, "workspaces", "org-A", "members", "u-member", "private", "hiddenAttributes")
        );
        expect(orgAHiddenSnap.data()).toEqual({ secretNote: "Top secret org-A note" });

        const globalHiddenSnap = await clientGetDoc(
          clientDoc(sysAdminClient.db, "users", "u-member", "private", "hiddenAttributes")
        );
        expect(globalHiddenSnap.data()).toEqual({ secretNote: "Top secret global note" });
      } finally {
        await terminate(memberClient.db);
        await deleteClientApp(memberClient.app);
        await terminate(mgrClient.db);
        await deleteClientApp(mgrClient.app);
        await terminate(sysAdminClient.db);
        await deleteClientApp(sysAdminClient.app);
      }
    });
  }
);

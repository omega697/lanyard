import {
  collection,
  collectionGroup,
  doc,
  onSnapshot,
  query,
  setDoc,
  updateDoc,
  where,
  type Firestore
} from "firebase/firestore";
import { assertValidResourceId, sanitizeAvatarUrl, type LanyardClientStore, type ScopedMember } from "../core/index.js";

const FORBIDDEN_PREF_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function sanitizePrefPatch<T extends Record<string, any>>(input: unknown): Partial<T> {
  const clean: Record<string, any> = {};
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return clean as Partial<T>;
  }
  for (const [k, v] of Object.entries(input as Record<string, any>)) {
    if (!FORBIDDEN_PREF_KEYS.has(k)) {
      clean[k] = v;
    }
  }
  return clean as Partial<T>;
}

function assertValidFirestoreDocId(id: string | null | undefined, label: string): string {
  const valid = assertValidResourceId(id, label);
  if (/^__.*__$/.test(valid)) {
    throw new Error(`Invalid ${label}: reserved Firestore document ID format`);
  }
  return valid;
}

export interface FirestoreClientStoreConfig<TRole extends string = string> {
  db: Firestore;
  /** Default role assigned if a stored document does not have a `role` field. */
  defaultRole: TRole;
  /** Optional custom role resolver for migrating legacy documents (e.g., `isCreator` flags). */
  resolveRole?: (data: Record<string, any>) => TRole;
  preferencesCollection?: string;
  systemAdminsCollection?: string;
  scopeCollection?: string;
  membersSubcollection?: string;
}

/**
 * Firestore implementation of `LanyardClientStore`.
 * Lives in `lanyard/client/firestore` so projects using custom storage adapters
 * do not need to bundle `firebase/firestore`.
 */
export class FirestoreClientStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>
> implements LanyardClientStore<TRole, TCapability, TPreferences> {
  private readonly db: Firestore;
  private readonly defaultRole: TRole;
  private readonly resolveRole?: (data: Record<string, any>) => TRole;
  private readonly preferencesCollection: string;
  private readonly systemAdminsCollection: string;
  private readonly scopeCollection: string;
  private readonly membersSubcollection: string;

  constructor(config: FirestoreClientStoreConfig<TRole>) {
    this.db = config.db;
    this.defaultRole = config.defaultRole;
    this.resolveRole = config.resolveRole;
    this.preferencesCollection = assertValidFirestoreDocId(
      config.preferencesCollection || "user_preferences",
      "preferencesCollection"
    );
    this.systemAdminsCollection = assertValidFirestoreDocId(
      config.systemAdminsCollection || "system_admins",
      "systemAdminsCollection"
    );
    this.scopeCollection = assertValidFirestoreDocId(config.scopeCollection || "workspaces", "scopeCollection");
    this.membersSubcollection = assertValidFirestoreDocId(
      config.membersSubcollection || "members",
      "membersSubcollection"
    );
  }

  private extractRole(data: Record<string, any>): TRole {
    if (this.resolveRole) {
      return this.resolveRole(data);
    }
    return (data.role as TRole) || this.defaultRole;
  }

  subscribeToPreferences(uid: string, onChange: (prefs: Partial<TPreferences>) => void): () => void {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const prefRef = doc(this.db, this.preferencesCollection, cleanUid);
    return onSnapshot(
      prefRef,
      (snap) => {
        if (snap.exists()) {
          onChange(sanitizePrefPatch<TPreferences>(snap.data() || {}));
        }
      },
      () => {
        // Ignore permission or offline errors cleanly
      }
    );
  }

  async savePreferences(uid: string, patch: Partial<TPreferences>): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const prefRef = doc(this.db, this.preferencesCollection, cleanUid);
    await setDoc(prefRef, sanitizePrefPatch<TPreferences>(patch), { merge: true });
  }

  subscribeToUserMemberships(uid: string, onChange: (members: ScopedMember<TRole, TCapability>[]) => void): () => void {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const membersQuery = query(collectionGroup(this.db, this.membersSubcollection), where("uid", "==", cleanUid));
    return onSnapshot(
      membersQuery,
      (snapshot) => {
        const list: ScopedMember<TRole, TCapability>[] = [];
        snapshot.forEach((docSnap) => {
          const data = docSnap.data();
          const scopeId = data.scopeId || docSnap.ref.parent?.parent?.id;
          list.push({
            uid: data.uid || docSnap.id,
            email: data.email || "",
            firstName: data.firstName,
            lastName: data.lastName,
            photoUrl: sanitizeAvatarUrl(data.photoUrl),
            role: this.extractRole(data),
            capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
            scopeId,
            scopeName: data.scopeName,
            lastSeen: data.lastSeen
          });
        });
        onChange(list);
      },
      () => {
        onChange([]);
      }
    );
  }

  subscribeToScopeMembers(
    scopeId: string,
    onChange: (members: ScopedMember<TRole, TCapability>[]) => void
  ): () => void {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const colRef = collection(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection);
    return onSnapshot(
      colRef,
      (snapshot) => {
        const list: ScopedMember<TRole, TCapability>[] = [];
        snapshot.forEach((docSnap) => {
          const data = docSnap.data();
          list.push({
            uid: data.uid || docSnap.id,
            email: data.email || "",
            firstName: data.firstName,
            lastName: data.lastName,
            photoUrl: sanitizeAvatarUrl(data.photoUrl),
            role: this.extractRole(data),
            capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
            scopeId: cleanScopeId,
            scopeName: data.scopeName,
            lastSeen: data.lastSeen
          });
        });
        onChange(list);
      },
      () => {
        onChange([]);
      }
    );
  }

  async syncAvatar(params: {
    uid: string;
    photoUrl: string;
    scopeId?: string;
    email?: string | null;
    displayName?: string | null;
  }): Promise<void> {
    const { uid, photoUrl, scopeId, email, displayName } = params;
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanPhotoUrl = sanitizeAvatarUrl(photoUrl);
    if (!cleanPhotoUrl) return;
    if (scopeId) {
      const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
      // Use updateDoc for existing scoped member docs so we never create a phantom member doc
      const memberRef = doc(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection, cleanUid);
      await updateDoc(memberRef, { photoUrl: cleanPhotoUrl });
    } else {
      const adminRef = doc(this.db, this.systemAdminsCollection, cleanUid);
      const payload: Record<string, any> = { uid: cleanUid, photoUrl: cleanPhotoUrl };
      if (email) payload.email = email;
      if (displayName) payload.displayName = displayName;
      await setDoc(adminRef, payload, { merge: true });
    }
  }

  async recordPresenceHeartbeat(params: {
    uid: string;
    scopeId?: string;
    lastSeenIso: string;
    photoUrl?: string | null;
  }): Promise<void> {
    const { uid, scopeId, lastSeenIso, photoUrl } = params;
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const cleanPhotoUrl = sanitizeAvatarUrl(photoUrl);
    const payload: Record<string, any> = { lastSeen: lastSeenIso };
    if (cleanPhotoUrl) {
      payload.photoUrl = cleanPhotoUrl;
    }

    if (scopeId) {
      const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
      const memberRef = doc(this.db, this.scopeCollection, cleanScopeId, this.membersSubcollection, cleanUid);
      await updateDoc(memberRef, payload);
    } else {
      const adminRef = doc(this.db, this.systemAdminsCollection, cleanUid);
      await setDoc(adminRef, payload, { merge: true });
    }
  }
}

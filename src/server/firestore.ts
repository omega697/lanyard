import { FieldValue, type Firestore } from "firebase-admin/firestore";
import {
  assertValidResourceId,
  sanitizeAvatarUrl,
  type LanyardServerStore,
  type ScopedMember,
  type SystemAdminProfile
} from "../core/index.js";

function assertValidFirestoreDocId(id: string | null | undefined, label: string): string {
  const valid = assertValidResourceId(id, label);
  if (/^__.*__$/.test(valid)) {
    throw new Error(`Invalid ${label}: reserved Firestore document ID format`);
  }
  return valid;
}

export interface FirestoreServerStoreConfig<TRole extends string = string> {
  db: Firestore;
  /** Default role assigned if a stored document does not have a `role` field. */
  defaultRole: TRole;
  /** Optional custom role resolver for migrating legacy documents (e.g., `isCreator` flags). */
  resolveRole?: (data: Record<string, any>) => TRole;
  systemAdminsCollection?: string;
  scopeCollection?: string;
  membersSubcollection?: string;
}

/**
 * Firebase Admin Firestore implementation of `LanyardServerStore`.
 * Isolated in `lanyard/server/firestore` so applications using custom storage
 * adapters do not need `firebase-admin/firestore`.
 */
export class FirestoreServerStore<
  TRole extends string = string,
  TCapability extends string = string
> implements LanyardServerStore<TRole, TCapability> {
  private readonly db: Firestore;
  private readonly defaultRole: TRole;
  private readonly resolveRole?: (data: Record<string, any>) => TRole;
  private readonly systemAdminsCollection: string;
  private readonly scopeCollection: string;
  private readonly membersSubcollection: string;

  constructor(config: FirestoreServerStoreConfig<TRole>) {
    this.db = config.db;
    this.defaultRole = config.defaultRole;
    this.resolveRole = config.resolveRole;
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

  private memberDocRef(scopeId: string, uid: string) {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    return this.db.doc(`${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}/${cleanUid}`);
  }

  async getSystemAdmin(uid: string): Promise<SystemAdminProfile | null> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    const snap = await this.db.doc(`${this.systemAdminsCollection}/${cleanUid}`).get();
    if (!snap.exists) return null;
    const data = snap.data() || {};
    return {
      uid: snap.id,
      email: data.email || "",
      displayName: data.displayName,
      firstName: data.firstName,
      lastName: data.lastName,
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      lastSeen: data.lastSeen,
      addedBy: data.addedBy,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt
    };
  }

  async listSystemAdmins(): Promise<SystemAdminProfile[]> {
    const snap = await this.db.collection(this.systemAdminsCollection).get();
    return snap.docs.map((d) => {
      const data = d.data();
      return {
        uid: d.id,
        email: data.email || "",
        displayName: data.displayName,
        firstName: data.firstName,
        lastName: data.lastName,
        photoUrl: sanitizeAvatarUrl(data.photoUrl),
        lastSeen: data.lastSeen,
        addedBy: data.addedBy,
        createdAt: data.createdAt,
        updatedAt: data.updatedAt
      };
    });
  }

  async upsertSystemAdmin(profile: SystemAdminProfile): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(profile.uid, "uid");
    const payload: SystemAdminProfile = {
      ...profile,
      uid: cleanUid,
      ...(profile.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(profile.photoUrl) } : {})
    };
    await this.db.doc(`${this.systemAdminsCollection}/${cleanUid}`).set(payload, { merge: true });
  }

  async deleteSystemAdmin(uid: string): Promise<void> {
    const cleanUid = assertValidFirestoreDocId(uid, "uid");
    await this.db.doc(`${this.systemAdminsCollection}/${cleanUid}`).delete();
  }

  async getScopeMember(scopeId: string, uid: string): Promise<ScopedMember<TRole, TCapability> | null> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const snap = await this.memberDocRef(cleanScopeId, uid).get();
    if (!snap.exists) return null;
    const data = snap.data() || {};
    return {
      uid: data.uid || snap.id,
      email: data.email || "",
      firstName: data.firstName,
      lastName: data.lastName,
      photoUrl: sanitizeAvatarUrl(data.photoUrl),
      role: this.extractRole(data),
      capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
      scopeId: cleanScopeId,
      scopeName: data.scopeName,
      lastSeen: data.lastSeen
    };
  }

  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability>[]> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const snap = await this.db.collection(`${this.scopeCollection}/${cleanScopeId}/${this.membersSubcollection}`).get();
    return snap.docs.map((d) => {
      const data = d.data();
      return {
        uid: data.uid || d.id,
        email: data.email || "",
        firstName: data.firstName,
        lastName: data.lastName,
        photoUrl: sanitizeAvatarUrl(data.photoUrl),
        role: this.extractRole(data),
        capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
        scopeId: cleanScopeId,
        scopeName: data.scopeName,
        lastSeen: data.lastSeen
      };
    });
  }

  async upsertScopeMember(scopeId: string, member: ScopedMember<TRole, TCapability>): Promise<void> {
    const cleanScopeId = assertValidFirestoreDocId(scopeId, "scopeId");
    const cleanUid = assertValidFirestoreDocId(member.uid, "uid");
    const payload: ScopedMember<TRole, TCapability> = {
      ...member,
      ...(member.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(member.photoUrl) } : {}),
      uid: cleanUid,
      scopeId: cleanScopeId,
      capabilities: Array.from(new Set(member.capabilities || []))
    };
    await this.memberDocRef(cleanScopeId, cleanUid).set(payload, { merge: true });
  }

  async grantScopeCapabilities(
    scopeId: string,
    uid: string,
    capabilities: readonly TCapability[],
    fallbackMember?: Omit<ScopedMember<TRole, TCapability>, "capabilities">
  ): Promise<ScopedMember<TRole, TCapability>> {
    const ref = this.memberDocRef(scopeId, uid);
    const snap = await ref.get();
    if (!snap.exists) {
      if (!fallbackMember) {
        throw new Error(`Member '${uid}' does not exist in scope '${scopeId}'`);
      }
      const created: ScopedMember<TRole, TCapability> = {
        ...fallbackMember,
        ...(fallbackMember.photoUrl !== undefined ? { photoUrl: sanitizeAvatarUrl(fallbackMember.photoUrl) } : {}),
        uid,
        scopeId,
        capabilities: Array.from(new Set(capabilities))
      };
      await ref.set(created, { merge: true });
      return created;
    }

    if (capabilities.length > 0) {
      await ref.update({
        capabilities: FieldValue.arrayUnion(...capabilities)
      });
    }
    return (await this.getScopeMember(scopeId, uid))!;
  }

  async revokeScopeCapabilities(scopeId: string, uid: string, capabilities: readonly TCapability[]): Promise<void> {
    if (capabilities.length === 0) return;
    const ref = this.memberDocRef(scopeId, uid);
    const snap = await ref.get();
    if (!snap.exists) return;
    await ref.update({
      capabilities: FieldValue.arrayRemove(...capabilities)
    });
  }

  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    await this.memberDocRef(scopeId, uid).delete();
  }
}

import {
  GoogleAuthProvider,
  GithubAuthProvider,
  OAuthProvider,
  signInWithPopup,
  linkWithPopup,
  unlink,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  sendSignInLinkToEmail,
  isSignInWithEmailLink,
  signInWithEmailLink,
  verifyBeforeUpdateEmail,
  applyActionCode,
  fetchSignInMethodsForEmail,
  updateProfile as firebaseUpdateProfile,
  type Auth,
  type User,
  type AuthProvider
} from "firebase/auth";
import {
  GLOBAL_SCOPE,
  createWritableStore,
  formatExistingAccountError,
  isValidEmail,
  isValidResourceId,
  sanitizeAvatarUrl,
  type GlobalScope,
  type LanyardClientStore,
  type LanyardReadable,
  type LanyardUser,
  type PermissionPolicy,
  type ScopeId,
  type ScopedMember,
  type SocialProviderType,
  type SubscribeToUsersOptions,
  type SystemAdminProfile,
  type UserProfilePatch,
  type UserRecord,
  type VerifiedEmailChangeEvent
} from "../core/index.js";

export {
  GLOBAL_SCOPE,
  formatExistingAccountError,
  type GlobalScope,
  type ScopeId,
  type SubscribeToUsersOptions,
  type VerifiedEmailChangeEvent
};

export const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

const FORBIDDEN_PREF_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function sanitizePreferencesObject<T extends Record<string, any>>(input: unknown): Partial<T> {
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

function validateRedirectUrl(redirectUrl: string): string {
  const trimmed = redirectUrl.trim();
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("Invalid redirectUrl: must be a valid absolute http(s) URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Invalid redirectUrl: protocol must be http: or https:");
  }
  return trimmed;
}

/**
 * Instantiates the Firebase `AuthProvider` corresponding to the given social provider type.
 */
export function getSocialProvider(type: SocialProviderType): AuthProvider {
  switch (type) {
    case "google":
      return new GoogleAuthProvider();
    case "microsoft":
      return new OAuthProvider("microsoft.com");
    case "github":
      return new GithubAuthProvider();
  }
}

/**
 * Converts a Firebase Auth `User` and decoded custom claims into a normalized `LanyardUser`.
 * Automatically falls back to linked OAuth `providerData[].photoURL` when top-level `user.photoURL`
 * is empty (e.g., when a user first signed in via magic email link and later linked Google/GitHub).
 */
export function normalizeFirebaseUser(user: User, claims: Record<string, any> = {}): LanyardUser {
  const providerData = Array.isArray(user.providerData) ? user.providerData : [];
  const providerIds = providerData.map((p) => p?.providerId).filter((id): id is string => Boolean(id));

  const directPhoto = sanitizeAvatarUrl(user.photoURL);
  const providerPhoto =
    directPhoto ||
    providerData.map((p) => sanitizeAvatarUrl(p?.photoURL)).find((url): url is string => Boolean(url)) ||
    null;

  return {
    uid: user.uid,
    email: user.email ? user.email.toLowerCase().trim() : null,
    emailVerified: Boolean(user.emailVerified),
    displayName: user.displayName || null,
    photoUrl: providerPhoto,
    isAdmin: Boolean(claims.admin),
    providerIds
  };
}

export interface AuthState {
  user: LanyardUser | null;
  isReady: boolean;
}

export interface MembershipsState<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> {
  memberships: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[];
  isLoading: boolean;
}

export interface LanyardClientConfig<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
> {
  /** Optional Firebase Auth instance. May be omitted in tests or custom auth environments. */
  auth?: Auth | null;
  /** Backing storage adapter implementing `LanyardClientStore` (e.g. `FirestoreClientStore` or `InMemoryLanyardStore`). */
  store: LanyardClientStore<TRole, TCapability, TPreferences, TAttributes>;
  /** Default preferences applied before remote preferences load or after sign-out. */
  defaultPreferences: TPreferences;
  /** Optional permission policy defining role hierarchy, capabilities, and per-role `trackPresence`. */
  policy?: PermissionPolicy<TRole, TCapability>;
  /** Prefix used for `localStorage` cache keys (preferences, emailForSignIn, and presence timestamps). */
  storageKeyPrefix?: string;
  /**
   * Optional callback invoked once per email change when the signed-in user's verified email address
   * in Firebase Auth differs from `record.email` on `users/{uid}` and is synced to the backing store.
   * If the callback returns a rejected Promise, Lanyard leaves `record.email` unchanged and clears its
   * deduplication key so the callback will be retried on the next snapshot/session.
   */
  onVerifiedEmailChange?: (event: VerifiedEmailChangeEvent) => void | Promise<void>;
}

/**
 * Creates a storage-agnostic Lanyard client instance managing authentication flows,
 * reactive Svelte-compatible stores (`authStore`, `userRecordStore`, `attributesStore`,
 * `membershipsStore`, `preferencesStore`), smart deduplicated avatar syncing, and
 * 5-minute `localStorage`-throttled presence heartbeats unified around explicit `scopeId: ScopeId` (`GLOBAL_SCOPE` or tenant `string`).
 */
export function createLanyardClient<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>
>(config: LanyardClientConfig<TRole, TCapability, TPreferences, TAttributes>) {
  const {
    auth = null,
    store,
    defaultPreferences,
    policy,
    storageKeyPrefix = "lanyard",
    onVerifiedEmailChange
  } = config;

  const prefStorageKey = `${storageKeyPrefix}_user_preferences`;
  const emailForSignInKey = `${storageKeyPrefix}_emailForSignIn`;

  // Tracks (targetKey -> syncedPhotoUrl) to prevent redundant avatar writes within a session
  const syncedAvatars = new Map<string, string>();

  function loadCachedPreferences(): TPreferences {
    if (typeof localStorage === "undefined") {
      return { ...defaultPreferences };
    }
    try {
      const raw = localStorage.getItem(prefStorageKey);
      if (raw) {
        const parsed = JSON.parse(raw);
        return { ...defaultPreferences, ...sanitizePreferencesObject<TPreferences>(parsed) };
      }
    } catch {
      // Ignore malformed localStorage cache
    }
    return { ...defaultPreferences };
  }

  const authStoreInternal = createWritableStore<AuthState>({
    user: null,
    isReady: false
  });

  const userRecordStoreInternal = createWritableStore<UserRecord<TRole, TCapability, TPreferences, TAttributes> | null>(
    null
  );

  const attributesStoreInternal = createWritableStore<Partial<TAttributes>>({});

  const membershipsStoreInternal = createWritableStore<MembershipsState<TRole, TCapability, TPreferences, TAttributes>>(
    {
      memberships: [],
      isLoading: false
    }
  );

  const preferencesStoreInternal = createWritableStore<TPreferences>(loadCachedPreferences());

  let unsubUserOrPrefs: (() => void) | null = null;
  let unsubMemberships: (() => void) | null = null;
  let unsubAuth: (() => void) | null = null;
  let authGeneration = 0;

  function cleanupUserSubscriptions(): void {
    if (unsubUserOrPrefs) {
      unsubUserOrPrefs();
      unsubUserOrPrefs = null;
    }
    if (unsubMemberships) {
      unsubMemberships();
      unsubMemberships = null;
    }
  }

  function applyRemotePreferences(remotePrefs: Partial<TPreferences> | undefined): void {
    if (!remotePrefs) return;
    preferencesStoreInternal.update((current) => {
      const merged = { ...current, ...sanitizePreferencesObject<TPreferences>(remotePrefs) };
      if (typeof localStorage !== "undefined") {
        try {
          localStorage.setItem(prefStorageKey, JSON.stringify(merged));
        } catch {}
      }
      return merged;
    });
  }

  /**
   * Programmatically sets the authenticated user (useful in tests or custom auth flows)
   * and wires up reactive store subscriptions for `users/{uid}`, preferences, memberships, and avatar syncing.
   */
  function setActiveUser(user: LanyardUser | null): void {
    authGeneration += 1;
    cleanupUserSubscriptions();

    if (!user) {
      syncedAvatars.clear();
      authStoreInternal.set({ user: null, isReady: true });
      userRecordStoreInternal.set(null);
      attributesStoreInternal.set({});
      membershipsStoreInternal.set({ memberships: [], isLoading: false });
      preferencesStoreInternal.set({ ...defaultPreferences });
      return;
    }

    authStoreInternal.set({ user, isReady: true });
    membershipsStoreInternal.set({ memberships: [], isLoading: true });

    const globalUserSyncKey = `user:${user.uid}`;

    // If user is a system admin with an avatar, sync their avatar to users/{uid} once per session/photo change
    if (user.isAdmin && user.photoUrl && typeof store.syncAvatar === "function") {
      if (syncedAvatars.get(globalUserSyncKey) !== user.photoUrl) {
        syncedAvatars.set(globalUserSyncKey, user.photoUrl);
        store
          .syncAvatar({
            uid: user.uid,
            photoUrl: user.photoUrl,
            email: user.email,
            displayName: user.displayName
          })
          .catch(() => {
            syncedAvatars.delete(globalUserSyncKey);
          });
      }
    }

    if (typeof store.subscribeToUser === "function") {
      unsubUserOrPrefs = store.subscribeToUser(user.uid, (record) => {
        userRecordStoreInternal.set(record);
        if (record) {
          applyRemotePreferences(record.preferences);
          attributesStoreInternal.set(sanitizePreferencesObject<TAttributes>(record.attributes || {}));

          // If a provisioned global user record exists with a stale/missing photoUrl, sync it once
          const isProvisionedProfile = Boolean(
            record.email || record.isSystemAdmin || record.firstName || record.lastName
          );
          if (
            isProvisionedProfile &&
            user.photoUrl &&
            record.photoUrl !== user.photoUrl &&
            typeof store.syncAvatar === "function"
          ) {
            if (syncedAvatars.get(globalUserSyncKey) !== user.photoUrl) {
              syncedAvatars.set(globalUserSyncKey, user.photoUrl);
              store
                .syncAvatar({
                  uid: user.uid,
                  photoUrl: user.photoUrl,
                  email: user.email,
                  displayName: user.displayName
                })
                .catch(() => {
                  syncedAvatars.delete(globalUserSyncKey);
                });
            }
          }

          // If a verified email change occurred on Firebase Auth, invoke onVerifiedEmailChange and sync the new email to users/{uid}
          const emailSyncKey = `email:${user.uid}`;
          if (
            user.email &&
            user.emailVerified &&
            record.email &&
            record.email.toLowerCase() !== user.email.toLowerCase() &&
            (typeof store.updateUserProfile === "function" || typeof onVerifiedEmailChange === "function")
          ) {
            if (syncedAvatars.get(emailSyncKey) !== user.email) {
              const previousEmail = record.email;
              const nextEmail = user.email;
              syncedAvatars.set(emailSyncKey, nextEmail);
              Promise.resolve()
                .then(async () => {
                  if (typeof onVerifiedEmailChange === "function") {
                    await onVerifiedEmailChange({
                      uid: user.uid,
                      email: nextEmail,
                      previousEmail
                    });
                  }
                  if (typeof store.updateUserProfile === "function") {
                    await store.updateUserProfile(user.uid, { email: nextEmail });
                  }
                })
                .catch(() => {
                  syncedAvatars.delete(emailSyncKey);
                });
            }
          }

          // Real-time system admin promotion/demotion sync from users/{uid}
          if (typeof record.isSystemAdmin === "boolean") {
            const currentAuth = authStoreInternal.get();
            if (
              currentAuth.user &&
              currentAuth.user.uid === user.uid &&
              currentAuth.user.isAdmin !== record.isSystemAdmin
            ) {
              authStoreInternal.set({
                ...currentAuth,
                user: { ...currentAuth.user, isAdmin: record.isSystemAdmin }
              });
              // Force-refresh the Firebase Auth ID token in the background so custom claims update immediately
              if (
                auth?.currentUser &&
                auth.currentUser.uid === user.uid &&
                typeof auth.currentUser.getIdTokenResult === "function"
              ) {
                auth.currentUser.getIdTokenResult(true).catch(() => {});
              }
            }
          }
        } else {
          attributesStoreInternal.set({});
        }
      });
    } else {
      unsubUserOrPrefs = store.subscribeToPreferences(user.uid, (remotePrefs) => {
        applyRemotePreferences(remotePrefs);
      });
    }

    unsubMemberships = store.subscribeToUserMemberships(user.uid, (members) => {
      // Smart Avatar Sync: when a pre-provisioned member doc loads with a stale/missing photoUrl,
      // optimistically reflect user.photoUrl in membershipsStore and sync to the store once per (scopeId, photoUrl).
      const normalizedMembers = members.map((m) => {
        if (user.photoUrl && m.scopeId && m.photoUrl !== user.photoUrl) {
          if (typeof store.syncAvatar === "function") {
            const scopeKey = `scope:${m.scopeId}:${user.uid}`;
            if (syncedAvatars.get(scopeKey) !== user.photoUrl) {
              syncedAvatars.set(scopeKey, user.photoUrl);
              store
                .syncAvatar({
                  uid: user.uid,
                  scopeId: m.scopeId,
                  photoUrl: user.photoUrl
                })
                .catch(() => {
                  syncedAvatars.delete(scopeKey);
                });
            }
          }
          return { ...m, photoUrl: user.photoUrl };
        }
        return m;
      });

      membershipsStoreInternal.set({
        memberships: normalizedMembers,
        isLoading: false
      });
    });
  }

  // Wire up Firebase Auth listener if an Auth instance is provided
  if (auth && typeof onAuthStateChanged === "function") {
    try {
      // Auto-handle magic email link or verifyEmail action code on boot
      if (typeof window !== "undefined") {
        if (isSignInWithEmailLink(auth, window.location.href)) {
          completePasswordlessSignIn().catch(() => {});
        } else if (window.location.search.includes("mode=verifyEmail")) {
          const params = new URLSearchParams(window.location.search);
          const oobCode = params.get("oobCode");
          if (oobCode) {
            applyActionCode(auth, oobCode)
              .then(async () => {
                const fbUser = auth.currentUser;
                if (!fbUser) return;
                if (typeof fbUser.reload === "function") {
                  await fbUser.reload();
                }
                let claims: Record<string, any> = {};
                if (typeof fbUser.getIdTokenResult === "function") {
                  const tokenResult = await fbUser.getIdTokenResult(true);
                  claims = tokenResult?.claims || {};
                }
                setActiveUser(normalizeFirebaseUser(auth.currentUser || fbUser, claims));
              })
              .catch(() => {});
          }
        }
      }

      unsubAuth = onAuthStateChanged(auth, async (fbUser) => {
        const gen = ++authGeneration;
        if (!fbUser) {
          setActiveUser(null);
          return;
        }
        let claims: Record<string, any> = {};
        try {
          if (typeof fbUser.getIdTokenResult === "function") {
            const tokenResult = await fbUser.getIdTokenResult();
            claims = tokenResult?.claims || {};
          }
        } catch {}
        if (gen !== authGeneration) return;
        setActiveUser(normalizeFirebaseUser(fbUser, claims));
      });
    } catch {
      authStoreInternal.set({ user: null, isReady: true });
    }
  } else {
    authStoreInternal.set({ user: null, isReady: true });
  }

  // --- Auth Flows ---

  async function loginWithSocialProvider(type: SocialProviderType): Promise<LanyardUser | null> {
    if (!auth) throw new Error("Firebase Auth is not initialized");
    const provider = getSocialProvider(type);
    const result = await signInWithPopup(auth, provider);
    if (result?.user) {
      let claims: Record<string, any> = {};
      try {
        const tokenResult = await result.user.getIdTokenResult(true);
        claims = tokenResult?.claims || {};
      } catch {}
      const normalized = normalizeFirebaseUser(result.user, claims);
      setActiveUser(normalized);
      return normalized;
    }
    return null;
  }

  async function sendPasswordlessEmailLink(email: string, redirectUrl?: string): Promise<void> {
    if (!auth) throw new Error("Firebase Auth is not initialized");
    const targetEmail = email.toLowerCase().trim();
    if (!isValidEmail(targetEmail)) {
      throw new Error("Please enter a valid email address.");
    }

    const defaultUrl =
      typeof window !== "undefined"
        ? `${window.location.origin}${window.location.pathname}?email=${encodeURIComponent(targetEmail)}${window.location.hash}`
        : `http://localhost:5173/?email=${encodeURIComponent(targetEmail)}`;

    const actionCodeSettings = {
      url: redirectUrl ? validateRedirectUrl(redirectUrl) : defaultUrl,
      handleCodeInApp: true
    };

    await sendSignInLinkToEmail(auth, targetEmail, actionCodeSettings);

    if (typeof localStorage !== "undefined") {
      localStorage.setItem(emailForSignInKey, targetEmail);
    }
  }

  async function completePasswordlessSignIn(providedEmail?: string, href?: string): Promise<LanyardUser | null> {
    if (!auth) throw new Error("Firebase Auth is not initialized");
    const targetHref = href || (typeof window !== "undefined" ? window.location.href : "");
    if (!targetHref || !isSignInWithEmailLink(auth, targetHref)) return null;

    let urlEmail: string | null = null;
    try {
      const parsedUrl = new URL(targetHref);
      urlEmail = parsedUrl.searchParams.get("email");
    } catch {}

    const email =
      providedEmail ||
      urlEmail ||
      (typeof localStorage !== "undefined" ? localStorage.getItem(emailForSignInKey) : null) ||
      auth.currentUser?.email;

    if (!email) return null;

    const result = await signInWithEmailLink(auth, email.toLowerCase().trim(), targetHref);
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(emailForSignInKey);
    }
    if (result?.user) {
      let claims: Record<string, any> = {};
      try {
        const tokenResult = await result.user.getIdTokenResult();
        claims = tokenResult?.claims || {};
      } catch {}
      const normalized = normalizeFirebaseUser(result.user, claims);
      setActiveUser(normalized);
      return normalized;
    }
    return null;
  }

  async function signOut(): Promise<void> {
    authGeneration += 1;
    cleanupUserSubscriptions();
    if (auth) {
      await firebaseSignOut(auth);
    }
    setActiveUser(null);
  }

  async function linkSocialProvider(type: SocialProviderType): Promise<LanyardUser | null> {
    if (!auth || !auth.currentUser) throw new Error("No authenticated user to link account to");
    const provider = getSocialProvider(type);
    const result = await linkWithPopup(auth.currentUser, provider);
    if (result?.user) {
      const tokenResult = await result.user.getIdTokenResult();
      const normalized = normalizeFirebaseUser(result.user, tokenResult.claims || {});
      setActiveUser(normalized);
      return normalized;
    }
    return null;
  }

  async function unlinkSocialProvider(providerId: string): Promise<LanyardUser | null> {
    if (!auth || !auth.currentUser) throw new Error("No authenticated user to unlink account from");
    const result = await unlink(auth.currentUser, providerId);
    if (result) {
      const tokenResult = await result.getIdTokenResult();
      const normalized = normalizeFirebaseUser(result, tokenResult.claims || {});
      setActiveUser(normalized);
      return normalized;
    }
    return null;
  }

  async function getSignInMethodsForEmail(email: string): Promise<string[]> {
    if (!email || !auth) return [];
    try {
      const methods = await fetchSignInMethodsForEmail(auth, email.toLowerCase().trim());
      return methods || [];
    } catch {
      return [];
    }
  }

  async function sendEmailUpdateVerification(newEmail: string, redirectUrl?: string): Promise<void> {
    if (!auth || !auth.currentUser) throw new Error("No authenticated user.");
    const targetEmail = newEmail.toLowerCase().trim();
    if (!isValidEmail(targetEmail)) {
      throw new Error("Please enter a valid email address.");
    }

    const defaultUrl =
      typeof window !== "undefined"
        ? `${window.location.origin}${window.location.pathname}?email=${encodeURIComponent(targetEmail)}`
        : `http://localhost:5173/?email=${encodeURIComponent(targetEmail)}`;

    await verifyBeforeUpdateEmail(auth.currentUser, targetEmail, {
      url: redirectUrl ? validateRedirectUrl(redirectUrl) : defaultUrl,
      handleCodeInApp: true
    });
  }

  // --- Self-Service Profile & Preferences (Unified with Explicit ScopeId) ---

  async function updatePreferences(
    scopeId: ScopeId,
    patch: Partial<TPreferences>,
    options: boolean | { syncToStore?: boolean } = true
  ): Promise<void> {
    const syncToStore = typeof options === "boolean" ? options : (options?.syncToStore ?? true);
    const cleanPatch = sanitizePreferencesObject<TPreferences>(patch);

    if (scopeId === GLOBAL_SCOPE) {
      preferencesStoreInternal.update((current) => {
        const updated = { ...current, ...cleanPatch };
        if (typeof localStorage !== "undefined") {
          try {
            localStorage.setItem(prefStorageKey, JSON.stringify(updated));
          } catch {}
        }
        return updated;
      });

      const currentUser = authStoreInternal.get().user;
      if (syncToStore && currentUser?.uid) {
        await store.savePreferences(currentUser.uid, cleanPatch);
      }
      return;
    }

    if (!isValidResourceId(scopeId)) {
      throw new Error("Invalid scopeId");
    }

    membershipsStoreInternal.update((state) => ({
      ...state,
      memberships: state.memberships.map((m) =>
        m.scopeId === scopeId
          ? {
              ...m,
              preferences: {
                ...(m.preferences || {}),
                ...cleanPatch
              }
            }
          : m
      )
    }));

    const currentUser = authStoreInternal.get().user;
    if (syncToStore && currentUser?.uid) {
      if (typeof store.saveScopePreferences !== "function") {
        throw new Error("Backing store does not implement saveScopePreferences");
      }
      await store.saveScopePreferences(scopeId, currentUser.uid, cleanPatch);
    }
  }

  async function updateProfile(scopeId: ScopeId, patch: UserProfilePatch): Promise<void> {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser?.uid) {
      throw new Error("No authenticated user.");
    }

    if (scopeId === GLOBAL_SCOPE) {
      if (typeof store.updateUserProfile !== "function") {
        throw new Error("Backing store does not implement updateUserProfile");
      }
      const resolvedPatch: UserProfilePatch = { ...patch };
      if (
        resolvedPatch.displayName === undefined &&
        (typeof resolvedPatch.firstName === "string" || typeof resolvedPatch.lastName === "string")
      ) {
        const existingRecord = userRecordStoreInternal.get();
        const first = (resolvedPatch.firstName ?? existingRecord?.firstName ?? "").trim();
        const last = (resolvedPatch.lastName ?? existingRecord?.lastName ?? "").trim();
        const computedDisplayName = [first, last].filter(Boolean).join(" ").trim();
        if (computedDisplayName) {
          resolvedPatch.displayName = computedDisplayName;
        }
      }
      await store.updateUserProfile(currentUser.uid, resolvedPatch);
      if (typeof resolvedPatch.displayName === "string") {
        const trimmedDisplay = resolvedPatch.displayName.trim();
        authStoreInternal.update((state) =>
          state.user && state.user.uid === currentUser.uid
            ? { ...state, user: { ...state.user, displayName: trimmedDisplay } }
            : state
        );
        if (
          auth?.currentUser &&
          auth.currentUser.uid === currentUser.uid &&
          typeof firebaseUpdateProfile === "function"
        ) {
          try {
            await firebaseUpdateProfile(auth.currentUser, { displayName: trimmedDisplay });
          } catch {}
        }
      }
      return;
    }

    if (!isValidResourceId(scopeId)) {
      throw new Error("Invalid scopeId");
    }
    if (typeof store.updateScopeMemberProfile !== "function") {
      throw new Error("Backing store does not implement updateScopeMemberProfile");
    }

    const existingMember = membershipsStoreInternal.get().memberships.find((m) => m.scopeId === scopeId);
    const resolvedPatch: UserProfilePatch = { ...patch };
    if (
      resolvedPatch.displayName === undefined &&
      (typeof resolvedPatch.firstName === "string" || typeof resolvedPatch.lastName === "string")
    ) {
      const first = (resolvedPatch.firstName ?? existingMember?.firstName ?? "").trim();
      const last = (resolvedPatch.lastName ?? existingMember?.lastName ?? "").trim();
      const computedDisplayName = [first, last].filter(Boolean).join(" ").trim();
      if (computedDisplayName) {
        resolvedPatch.displayName = computedDisplayName;
      }
    }

    await store.updateScopeMemberProfile(scopeId, currentUser.uid, resolvedPatch);
  }

  // --- Unified Role, Capability, and Custom Property Accessors (Explicit ScopeId) ---

  function resolveTargetSubject(
    scopeId: ScopeId
  ):
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
    | null {
    if (scopeId === GLOBAL_SCOPE) {
      return userRecordStoreInternal.get();
    }
    if (!isValidResourceId(scopeId)) return null;
    return membershipsStoreInternal.get().memberships.find((m) => m.scopeId === scopeId) || null;
  }

  function getRoles(scopeId: ScopeId): TRole[] {
    const subject = resolveTargetSubject(scopeId);
    return Array.isArray(subject?.roles) ? [...subject.roles] : [];
  }

  function getAssignableRoles(): readonly TRole[] {
    return policy ? policy.assignableRoles : [];
  }

  function hasRole(requiredRole: TRole, scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (policy) {
      return policy.hasRole(subject, requiredRole, isAdmin);
    }
    if (isAdmin) return true;
    return Array.isArray(subject?.roles) && subject.roles.includes(requiredRole);
  }

  function hasAnyRole(requiredRoles: readonly TRole[], scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (policy) {
      return policy.hasAnyRole(subject, requiredRoles, isAdmin);
    }
    if (isAdmin) return true;
    if (requiredRoles.length === 0) return false;
    return requiredRoles.some((r) => Array.isArray(subject?.roles) && subject.roles.includes(r));
  }

  function hasAllRoles(requiredRoles: readonly TRole[], scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (policy) {
      return policy.hasAllRoles(subject, requiredRoles, isAdmin);
    }
    if (isAdmin) return true;
    return requiredRoles.every((r) => Array.isArray(subject?.roles) && subject.roles.includes(r));
  }

  function getCapabilities(scopeId: ScopeId): TCapability[] {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return [];
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    const result = new Set<TCapability>();
    if (policy) {
      const addAllPolicyCaps = () => {
        for (const caps of Object.values(policy.roleCapabilities) as Array<readonly TCapability[] | "*" | undefined>) {
          if (Array.isArray(caps)) {
            for (const c of caps) result.add(c);
          }
        }
      };
      if (isAdmin) {
        addAllPolicyCaps();
      } else if (Array.isArray(subject?.roles)) {
        for (const role of subject.roles) {
          if (typeof role === "string" && Object.hasOwn(policy.roleCapabilities, role)) {
            const roleCaps = policy.roleCapabilities[role];
            if (roleCaps === "*") {
              addAllPolicyCaps();
            } else if (Array.isArray(roleCaps)) {
              for (const c of roleCaps) result.add(c);
            }
          }
        }
      }
    }
    return Array.from(result);
  }

  function hasCapability(capability: TCapability, scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (policy) {
      return policy.hasCapability(subject, capability, isAdmin);
    }
    return isAdmin;
  }

  function hasAnyCapability(capabilities: readonly TCapability[], scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (policy) {
      return policy.hasAnyCapability(subject, capabilities, isAdmin);
    }
    return isAdmin;
  }

  function hasAllCapabilities(capabilities: readonly TCapability[], scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (policy) {
      return policy.hasAllCapabilities(subject, capabilities, isAdmin);
    }
    if (isAdmin) return true;
    return capabilities.length === 0;
  }

  function getAttributes(scopeId: ScopeId): Partial<TAttributes> {
    if (scopeId === GLOBAL_SCOPE) {
      return { ...attributesStoreInternal.get() };
    }
    if (!isValidResourceId(scopeId)) return {};
    const membership = membershipsStoreInternal.get().memberships.find((m) => m.scopeId === scopeId);
    return sanitizePreferencesObject<TAttributes>(membership?.attributes || {});
  }

  function getPreferences(scopeId: ScopeId): TPreferences {
    if (scopeId === GLOBAL_SCOPE) {
      return { ...preferencesStoreInternal.get() };
    }
    if (!isValidResourceId(scopeId)) return { ...defaultPreferences };
    const membership = membershipsStoreInternal.get().memberships.find((m) => m.scopeId === scopeId);
    return {
      ...defaultPreferences,
      ...sanitizePreferencesObject<TPreferences>(membership?.preferences || {})
    };
  }

  /**
   * Checks whether the current user can read `key` on `attributes` within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   * Defaults `isSelf: true` when checking the current user's own attributes; pass `{ isSelf: false }`
   * when checking whether the current user can read another user's/member's `attributes` key.
   */
  function canReadAttribute(
    scopeId: ScopeId,
    key: (keyof TAttributes & string) | string,
    options?: { isSelf?: boolean }
  ): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isSelf = options?.isSelf ?? true;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (scopeId !== GLOBAL_SCOPE && !isAdmin && !subject) return false;
    if (policy) {
      return policy.canReadAttribute(subject, key, { isSystemAdmin: isAdmin, isSelf });
    }
    return isAdmin || isSelf;
  }

  /**
   * Checks whether the current user can write `key` on `attributes` within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   */
  function canWriteAttribute(scopeId: ScopeId, key: (keyof TAttributes & string) | string): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (!policy) return isAdmin;
    return policy.canWriteAttribute(subject, key, isAdmin);
  }

  /**
   * Checks whether the current user can read `key` on `hiddenAttributes` within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   * Self-ownership never grants read access to `hiddenAttributes`.
   */
  function canReadHiddenAttribute(scopeId: ScopeId, key: string): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (!policy) return isAdmin;
    return policy.canReadHiddenAttribute(subject, key, isAdmin);
  }

  /**
   * Checks whether the current user can write `key` on `hiddenAttributes` within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   * Self-ownership never grants write access to `hiddenAttributes`.
   */
  function canWriteHiddenAttribute(scopeId: ScopeId, key: string): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (!policy) return isAdmin;
    return policy.canWriteHiddenAttribute(subject, key, isAdmin);
  }

  /**
   * Checks whether the current user can write/clear `key` on write-only encrypted `secrets`
   * within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   * Defaults `isSelf: true` when checking the current user's own secrets; pass `{ isSelf: false }`
   * when checking whether the current user can write another user's/member's secrets.
   */
  function canWriteSecret(scopeId: ScopeId, key: string, options?: { isSelf?: boolean }): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isSelf = options?.isSelf ?? true;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (scopeId !== GLOBAL_SCOPE && !isAdmin && !subject) return false;
    if (policy) {
      return policy.canWriteSecret(subject, key, { isSystemAdmin: isAdmin, isSelf });
    }
    return isAdmin || isSelf;
  }

  /**
   * Checks whether the current user can read a user/member record within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   * Defaults `isSelf: false` since reading *another* user's profile is the primary check.
   */
  function canReadUser(scopeId: ScopeId, options?: { isSelf?: boolean }): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    const isSelf = options?.isSelf ?? false;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (scopeId !== GLOBAL_SCOPE && !isAdmin && !subject) return false;
    if (policy) {
      return policy.canReadUser(subject, { isSystemAdmin: isAdmin, isSelf });
    }
    return isAdmin || isSelf;
  }

  /**
   * Checks whether the current user can write (update/delete) another user/member record
   * within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   */
  function canWriteUser(scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (!policy) return isAdmin;
    return policy.canWriteUser(subject, isAdmin);
  }

  /**
   * Checks whether the current user can assign or modify roles on a user/member record
   * within `scopeId` (`GLOBAL_SCOPE` or tenant `string`).
   */
  function canAssignRoles(scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    const isAdmin = Boolean(currentUser.isAdmin);
    const subject = resolveTargetSubject(scopeId);
    if (!policy) return isAdmin;
    return policy.canAssignRoles(subject, isAdmin);
  }

  // --- Presence Tracking (5-minute localStorage-throttled) ---

  function getPresenceKeys(uid: string, scopeId: ScopeId) {
    const scopePart = scopeId === GLOBAL_SCOPE ? "" : `${scopeId}_`;
    return {
      lastActiveKey: `${storageKeyPrefix}_last_active_${scopePart}${uid}`,
      lastSyncedKey: `${storageKeyPrefix}_last_synced_${scopePart}${uid}`
    };
  }

  function shouldTrackPresence(scopeId: ScopeId): boolean {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser) return false;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return false;
    if (currentUser.isAdmin) return true;
    if (scopeId === GLOBAL_SCOPE) {
      const userRecord = userRecordStoreInternal.get();
      if (policy) {
        return policy.shouldTrackPresence(userRecord || {}, currentUser.isAdmin);
      }
      return false;
    }

    const membership = membershipsStoreInternal.get().memberships.find((m) => m.scopeId === scopeId);
    if (!membership) return false;

    if (policy) {
      return policy.shouldTrackPresence(membership, currentUser.isAdmin);
    }

    return true;
  }

  function recordActivity(scopeId: ScopeId): void {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser?.uid || typeof localStorage === "undefined") return;
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) return;
    const { lastActiveKey } = getPresenceKeys(currentUser.uid, scopeId);
    localStorage.setItem(lastActiveKey, Date.now().toString());
  }

  function getPresenceStatus(scopeId: ScopeId): { lastActive: number; lastSynced: number } {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser?.uid || typeof localStorage === "undefined") {
      return { lastActive: 0, lastSynced: 0 };
    }
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) {
      return { lastActive: 0, lastSynced: 0 };
    }
    const { lastActiveKey, lastSyncedKey } = getPresenceKeys(currentUser.uid, scopeId);
    return {
      lastActive: Number(localStorage.getItem(lastActiveKey) || 0),
      lastSynced: Number(localStorage.getItem(lastSyncedKey) || 0)
    };
  }

  async function syncPresence(scopeId: ScopeId, options: { isUnloading?: boolean } = {}): Promise<void> {
    const { isUnloading = false } = options;
    const currentUser = authStoreInternal.get().user;
    if (!currentUser?.uid || typeof localStorage === "undefined") return;
    if (!shouldTrackPresence(scopeId)) return;

    const { lastActiveKey, lastSyncedKey } = getPresenceKeys(currentUser.uid, scopeId);
    const lastActive = Number(localStorage.getItem(lastActiveKey) || 0);
    if (!lastActive) return;

    const lastSynced = Number(localStorage.getItem(lastSyncedKey) || 0);
    if (lastActive <= lastSynced) return;

    const elapsedSinceSync = Date.now() - lastSynced;
    if (isUnloading || elapsedSinceSync >= HEARTBEAT_INTERVAL_MS) {
      const lastSeenIso = new Date(lastActive).toISOString();
      localStorage.setItem(lastSyncedKey, lastActive.toString());

      try {
        await store.recordPresenceHeartbeat({
          uid: currentUser.uid,
          scopeId: scopeId === GLOBAL_SCOPE ? undefined : scopeId,
          lastSeenIso,
          photoUrl: currentUser.photoUrl
        });
      } catch {
        localStorage.setItem(lastSyncedKey, lastSynced.toString());
      }
    }
  }

  function startPresenceHeartbeat(scopeId: ScopeId): () => void {
    const tick = () => {
      recordActivity(scopeId);
      syncPresence(scopeId).catch(() => {});
    };

    tick();
    const interval = setInterval(tick, HEARTBEAT_INTERVAL_MS);

    const onActivity = () => {
      recordActivity(scopeId);
      const { lastSynced } = getPresenceStatus(scopeId);
      if (Date.now() - lastSynced >= HEARTBEAT_INTERVAL_MS) {
        syncPresence(scopeId).catch(() => {});
      }
    };

    if (typeof window !== "undefined") {
      window.addEventListener("pointerdown", onActivity, { passive: true });
      window.addEventListener("keydown", onActivity, { passive: true });
    }

    return () => {
      clearInterval(interval);
      if (typeof window !== "undefined") {
        window.removeEventListener("pointerdown", onActivity);
        window.removeEventListener("keydown", onActivity);
      }
    };
  }

  function subscribeToAuthUser(cb: (user: LanyardUser | null) => void): () => void {
    return authStoreInternal.subscribe((state) => cb(state.user));
  }

  function subscribeToUsers(
    scopeId: GlobalScope,
    cb: (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToUsersOptions
  ): () => void;
  function subscribeToUsers(
    scopeId: string,
    cb: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
  ): () => void;
  function subscribeToUsers(
    scopeId: ScopeId,
    cb: (
      users:
        | UserRecord<TRole, TCapability, TPreferences, TAttributes>[]
        | ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]
    ) => void,
    options?: SubscribeToUsersOptions
  ): () => void;
  function subscribeToUsers(
    scopeId: ScopeId,
    cb:
      | ((users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void)
      | ((members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void)
      | ((
          users:
            | UserRecord<TRole, TCapability, TPreferences, TAttributes>[]
            | ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]
        ) => void),
    options?: SubscribeToUsersOptions
  ): () => void {
    if (scopeId === GLOBAL_SCOPE) {
      if (typeof store.subscribeToUsers !== "function") {
        throw new Error("Backing store does not implement subscribeToUsers");
      }
      return store.subscribeToUsers(
        cb as (users: UserRecord<TRole, TCapability, TPreferences, TAttributes>[]) => void,
        options
      );
    }
    if (!isValidResourceId(scopeId)) {
      throw new Error("Invalid scopeId");
    }
    if (typeof store.subscribeToScopeMembers !== "function") {
      throw new Error("Backing store does not implement subscribeToScopeMembers");
    }
    return store.subscribeToScopeMembers(
      scopeId,
      cb as (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void
    );
  }

  /**
   * Subscribes to active system administrators (`isSystemAdmin === true`) in `usersCollection`.
   * Uses an indexed `where("isSystemAdmin", "==", true)` query in `FirestoreClientStore` so only
   * system admin documents are read from Firestore.
   */
  function subscribeToSystemAdmins(cb: (admins: SystemAdminProfile[]) => void): () => void {
    return subscribeToUsers(
      GLOBAL_SCOPE,
      (users) => {
        cb(users.filter((u) => u.isSystemAdmin === true) as SystemAdminProfile[]);
      },
      { isSystemAdmin: true }
    );
  }

  function destroy(): void {
    cleanupUserSubscriptions();
    if (unsubAuth) {
      unsubAuth();
      unsubAuth = null;
    }
  }

  return {
    authStore: authStoreInternal as LanyardReadable<AuthState>,
    userRecordStore: userRecordStoreInternal as LanyardReadable<UserRecord<
      TRole,
      TCapability,
      TPreferences,
      TAttributes
    > | null>,
    attributesStore: attributesStoreInternal as LanyardReadable<Partial<TAttributes>>,
    membershipsStore: membershipsStoreInternal as LanyardReadable<
      MembershipsState<TRole, TCapability, TPreferences, TAttributes>
    >,
    preferencesStore: preferencesStoreInternal as LanyardReadable<TPreferences>,
    setActiveUser,
    subscribeToAuthUser,
    subscribeToUsers,
    subscribeToSystemAdmins,
    loginWithSocialProvider,
    sendPasswordlessEmailLink,
    completePasswordlessSignIn,
    signOut,
    linkSocialProvider,
    unlinkSocialProvider,
    getSignInMethodsForEmail,
    sendEmailUpdateVerification,
    updatePreferences,
    updateProfile,
    getRoles,
    getAssignableRoles,
    hasRole,
    hasAnyRole,
    hasAllRoles,
    getCapabilities,
    hasCapability,
    hasAnyCapability,
    hasAllCapabilities,
    getAttributes,
    getPreferences,
    canReadUser,
    canWriteUser,
    canAssignRoles,
    canReadAttribute,
    canWriteAttribute,
    canReadHiddenAttribute,
    canWriteHiddenAttribute,
    canWriteSecret,
    recordActivity,
    getPresenceStatus,
    syncPresence,
    startPresenceHeartbeat,
    destroy
  };
}

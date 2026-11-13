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
  sendEmailVerification,
  applyActionCode,
  fetchSignInMethodsForEmail,
  updateProfile as firebaseUpdateProfile,
  type Auth,
  type User,
  type AuthProvider
} from "firebase/auth";
import {
  EMAIL_NOT_VERIFIED_ERROR_CODE,
  EmailLinkInvalidError,
  EmailLinkMismatchError,
  EmailNotVerifiedError,
  GLOBAL_SCOPE,
  REVOCATION_CLOCK_SKEW_MS,
  SESSION_REVOKED_ERROR_CODE,
  SessionRevokedError,
  TOKEN_STALE_ERROR_CODE,
  TokenStaleError,
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
  type SubscribeToMembersOptions,
  type SubscribeToUsersOptions,
  type SystemAdminProfile,
  type UserProfilePatch,
  type UserRecord,
  type VerifiedEmailChangeEvent
} from "../core/index.js";
import {
  assertStoreMatchesPolicyPlacement,
  resolveAttributeQueryLocation,
  resolveCardFields
} from "../core/tierDocs.js";

export {
  GLOBAL_SCOPE,
  formatExistingAccountError,
  type GlobalScope,
  type ScopeId,
  type SubscribeToMembersOptions,
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

/**
 * Outcome of `completePasswordlessSignIn`:
 * - `signed-in`: the link was completed;
 * - `needs-email`: a valid link, but no usable email on this device: ask the user for the address it was sent to;
 * - `signed-in-as-other`: someone (`currentEmail`) is already signed in, so the link wasn't used: ask before switching;
 * - `not-a-link`: the URL isn't a sign-in link (an ordinary page load).
 */
export type PasswordlessSignInResult =
  | { status: "signed-in"; user: LanyardUser }
  | { status: "needs-email" }
  | { status: "signed-in-as-other"; currentEmail: string }
  | { status: "not-a-link" };

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
  /**
   * Prefix used for `localStorage` cache keys: each signed-in user's preferences (`{prefix}_user_preferences_{uid}`,
   * removed when their session ends), signed-out visitors' preferences (`{prefix}_guest_preferences`), the pending
   * magic-link email (`{prefix}_emailForSignIn`), and presence timestamps. Whenever auth reports who is signed in, every
   * other user's preferences cache under this prefix is removed. With Firebase's default (local) persistence every tab
   * shares one user, but with session or in-memory persistence two tabs can be signed in as different users; then each
   * tab's sign-in removes the other user's cache, including preferences saved with `syncToStore: false`.
   */
  storageKeyPrefix?: string;
  /**
   * How long `authorizedFetch` waits before refreshing a second time when a freshly refreshed token is still reported
   * stale (it can share a second with the revocation), in milliseconds. Defaults to `REVOCATION_CLOCK_SKEW_MS + 1000`.
   */
  staleTokenRetryDelayMs?: number;
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
    staleTokenRetryDelayMs = REVOCATION_CLOCK_SKEW_MS + 1000
  } = config;
  assertStoreMatchesPolicyPlacement(store, resolveCardFields(policy));
  if (typeof (store as any).subscribeToRevocationEpoch !== "function") {
    throw new Error(
      "Lanyard client store must implement subscribeToRevocationEpoch() (required for immediate revocation); verify custom stores with lanyard/testing"
    );
  }

  // Each signed-in user's preferences are cached under their own key and removed when their session ends, so a shared
  // browser never shows one person's preferences to the next; signed-out visitors get a separate guest cache.
  const guestPrefStorageKey = `${storageKeyPrefix}_guest_preferences`;
  const userPrefStorageKey = (uid: string): string => `${storageKeyPrefix}_user_preferences_${uid}`;
  const emailForSignInKey = `${storageKeyPrefix}_emailForSignIn`;

  // Tracks (targetKey -> syncedPhotoUrl) to prevent redundant avatar writes within a session
  const syncedAvatars = new Map<string, string>();

  function removeCached(key: string): void {
    if (typeof localStorage === "undefined") return;
    try {
      localStorage.removeItem(key);
    } catch {}
  }

  function writeCachedPreferences(key: string, prefs: TPreferences): void {
    if (typeof localStorage === "undefined") return;
    try {
      localStorage.setItem(key, JSON.stringify(prefs));
    } catch {}
  }

  function loadCachedPreferences(key: string): TPreferences {
    if (typeof localStorage === "undefined") {
      return { ...defaultPreferences };
    }
    try {
      const raw = localStorage.getItem(key);
      if (raw) {
        const parsed = JSON.parse(raw);
        return { ...defaultPreferences, ...sanitizePreferencesObject<TPreferences>(parsed) };
      }
    } catch {
      // Ignore malformed localStorage cache
    }
    return { ...defaultPreferences };
  }

  /**
   * Removes every user's cached preferences except `keepUid`'s, including caches left by sessions that ended while no
   * page was open, so only the person auth says is here has anything cached.
   */
  function removeOtherUsersCachedPreferences(keepUid: string | null): void {
    if (typeof localStorage === "undefined") return;
    const prefix = `${storageKeyPrefix}_user_preferences_`;
    const keep = keepUid ? userPrefStorageKey(keepUid) : null;
    try {
      const stale: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(prefix) && key !== keep) stale.push(key);
      }
      stale.forEach((key) => localStorage.removeItem(key));
    } catch {}
  }

  /** Where the active user's (or a signed-out visitor's) global preferences are cached. */
  function activePrefStorageKey(): string {
    const uid = authStoreInternal.get().user?.uid;
    return uid ? userPrefStorageKey(uid) : guestPrefStorageKey;
  }

  // Older versions cached every user's preferences under one shared key, which may still hold a previous user's
  removeCached(`${storageKeyPrefix}_user_preferences`);

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

  // Until auth says who is signed in, show only the guest cache
  const preferencesStoreInternal = createWritableStore<TPreferences>(loadCachedPreferences(guestPrefStorageKey));

  let unsubUser: (() => void) | null = null;
  let unsubPrefs: (() => void) | null = null;
  let unsubAttributes: (() => void) | null = null;
  let unsubMemberships: (() => void) | null = null;
  let unsubAuth: (() => void) | null = null;
  let unsubRevocationEpoch: (() => void) | null = null;
  // Newest revocation epoch seen for the active user, and whether a proactive refresh loop is running
  let latestRevocationEpochMs: number | null = null;
  let proactiveRefreshRunning = false;
  let authGeneration = 0;

  // The user's own attributes are split between card-placed keys (on the card) and the `attributes` tier
  // document; `attributesStore` publishes their merge.
  let cardAttributes: Partial<TAttributes> = {};
  let tierAttributes: Partial<TAttributes> = {};

  function publishAttributes(): void {
    attributesStoreInternal.set(sanitizePreferencesObject<TAttributes>({ ...cardAttributes, ...tierAttributes }));
  }

  // Scoped preferences and attributes live in their own tier documents, so they're tracked per scope and
  // merged onto the membership objects published by `membershipsStore`.
  let latestMemberships: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[] = [];
  const scopePreferences = new Map<string, Partial<TPreferences>>();
  const scopeAttributes = new Map<string, Partial<TAttributes>>();
  const scopeEmails = new Map<string, string>();
  const scopeTierUnsubs = new Map<string, Array<() => void>>();

  function publishMemberships(isLoading: boolean): void {
    membershipsStoreInternal.set({
      memberships: latestMemberships.map((m) => {
        if (!m.scopeId) return m;
        const prefs = scopePreferences.get(m.scopeId);
        const attrs = scopeAttributes.get(m.scopeId);
        const email = scopeEmails.get(m.scopeId);
        return {
          ...m,
          ...(email ? { email } : {}),
          ...(prefs ? { preferences: { ...prefs } } : {}),
          ...(attrs ? { attributes: { ...(m.attributes || {}), ...attrs } } : {})
        };
      }),
      isLoading
    });
  }

  /** Opens tier listeners for each new membership scope and closes listeners for scopes the user left. */
  function syncScopeTierSubscriptions(uid: string): void {
    const activeScopeIds = new Set(latestMemberships.map((m) => m.scopeId).filter((id): id is string => Boolean(id)));
    for (const [scopeId, unsubs] of scopeTierUnsubs) {
      if (activeScopeIds.has(scopeId)) continue;
      unsubs.forEach((unsub) => unsub());
      scopeTierUnsubs.delete(scopeId);
      scopePreferences.delete(scopeId);
      scopeAttributes.delete(scopeId);
      scopeEmails.delete(scopeId);
    }
    for (const scopeId of activeScopeIds) {
      if (scopeTierUnsubs.has(scopeId)) continue;
      const unsubs: Array<() => void> = [];
      scopeTierUnsubs.set(scopeId, unsubs);
      if (typeof store.subscribeToScopePreferences === "function") {
        unsubs.push(
          store.subscribeToScopePreferences(scopeId, uid, (prefs) => {
            scopePreferences.set(scopeId, sanitizePreferencesObject<TPreferences>(prefs));
            publishMemberships(membershipsStoreInternal.get().isLoading);
          })
        );
      }
      if (typeof store.subscribeToScopeAttributes === "function") {
        unsubs.push(
          store.subscribeToScopeAttributes(scopeId, uid, (attrs, email) => {
            scopeAttributes.set(scopeId, sanitizePreferencesObject<TAttributes>(attrs));
            if (email) scopeEmails.set(scopeId, email);
            else scopeEmails.delete(scopeId);
            publishMemberships(membershipsStoreInternal.get().isLoading);
          })
        );
      }
    }
  }

  function cleanupUserSubscriptions(): void {
    if (unsubRevocationEpoch) {
      unsubRevocationEpoch();
      unsubRevocationEpoch = null;
    }
    latestRevocationEpochMs = null;
    if (unsubUser) {
      unsubUser();
      unsubUser = null;
    }
    if (unsubPrefs) {
      unsubPrefs();
      unsubPrefs = null;
    }
    if (unsubAttributes) {
      unsubAttributes();
      unsubAttributes = null;
    }
    if (unsubMemberships) {
      unsubMemberships();
      unsubMemberships = null;
    }
    scopeTierUnsubs.forEach((unsubs) => unsubs.forEach((unsub) => unsub()));
    scopeTierUnsubs.clear();
    scopePreferences.clear();
    scopeAttributes.clear();
    scopeEmails.clear();
    latestMemberships = [];
    cardAttributes = {};
    tierAttributes = {};
  }

  function applyRemotePreferences(uid: string, remotePrefs: Partial<TPreferences> | undefined): void {
    if (!remotePrefs) return;
    preferencesStoreInternal.update((current) => {
      const merged = { ...current, ...sanitizePreferencesObject<TPreferences>(remotePrefs) };
      writeCachedPreferences(userPrefStorageKey(uid), merged);
      return merged;
    });
  }

  /**
   * While a user is signed in, watches the revocation epoch and refreshes their token as soon as a revocation supersedes
   * it, so their next request (and Firestore access) already uses current claims. If the epoch can't be read (for
   * example, rules not yet regenerated), `authorizedFetch` still refreshes on demand.
   */
  function watchRevocationEpoch(uid: string): void {
    const generation = authGeneration;
    const unsubscribe = store.subscribeToRevocationEpoch(
      (epochMs) => {
        if (epochMs === null || generation !== authGeneration) return;
        latestRevocationEpochMs = Math.max(latestRevocationEpochMs ?? 0, epochMs);
        if (!proactiveRefreshRunning) void refreshPastRevocations(uid, generation);
      },
      () => {}
    );
    unsubRevocationEpoch = typeof unsubscribe === "function" ? unsubscribe : null;
  }

  async function refreshPastRevocations(uid: string, generation: number): Promise<void> {
    proactiveRefreshRunning = true;
    try {
      for (;;) {
        const user = auth?.currentUser;
        const target = latestRevocationEpochMs;
        if (!user || user.uid !== uid || generation !== authGeneration || target === null) return;
        const { claims } = await user.getIdTokenResult();
        if (Number(claims.iat) * 1000 <= target + REVOCATION_CLOCK_SKEW_MS) {
          // A token minted before then would still be stale, so wait until a new one will be past the revocation
          const waitMs = target + REVOCATION_CLOCK_SKEW_MS + 1000 - Date.now();
          if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
          if (generation !== authGeneration || auth?.currentUser?.uid !== uid) return;
          await refreshTokenAndClaims(user);
        }
        if (latestRevocationEpochMs === target) return;
      }
    } catch {
      // Best effort: authorizedFetch refreshes on demand if the server reports the token stale
    } finally {
      proactiveRefreshRunning = false;
    }
  }

  /**
   * Programmatically sets the authenticated user (useful in tests or custom auth flows)
   * and wires up reactive store subscriptions for `users/{uid}`, preferences, memberships, and avatar syncing.
   */
  function setActiveUser(user: LanyardUser | null): void {
    authGeneration += 1;
    cleanupUserSubscriptions();

    // When a user's session ends (sign-out, revocation, another tab, or switching accounts), remove what this browser
    // cached for them: their preferences and any pending magic-link email
    const previousUid = authStoreInternal.get().user?.uid;
    if (previousUid && previousUid !== user?.uid) removeCached(emailForSignInKey);
    removeOtherUsersCachedPreferences(user?.uid ?? null);

    if (!user) {
      syncedAvatars.clear();
      authStoreInternal.set({ user: null, isReady: true });
      userRecordStoreInternal.set(null);
      attributesStoreInternal.set({});
      membershipsStoreInternal.set({ memberships: [], isLoading: false });
      preferencesStoreInternal.set(loadCachedPreferences(guestPrefStorageKey));
      return;
    }

    authStoreInternal.set({ user, isReady: true });
    membershipsStoreInternal.set({ memberships: [], isLoading: true });
    // Paint from this user's own cache until the store delivers their preferences
    preferencesStoreInternal.set(loadCachedPreferences(userPrefStorageKey(user.uid)));
    watchRevocationEpoch(user.uid);

    const globalUserSyncKey = `user:${user.uid}`;

    // If user is a system admin with an avatar, sync their avatar to users/{uid} once per session/photo change
    if (user.isAdmin && user.photoUrl && typeof store.syncAvatar === "function") {
      if (syncedAvatars.get(globalUserSyncKey) !== user.photoUrl) {
        syncedAvatars.set(globalUserSyncKey, user.photoUrl);
        store
          .syncAvatar({
            uid: user.uid,
            photoUrl: user.photoUrl,
            displayName: user.displayName
          })
          .catch(() => {
            syncedAvatars.delete(globalUserSyncKey);
          });
      }
    }

    // userRecordStore combines the card with the user's own attributes tier, which holds a private email.
    type OwnRecord = UserRecord<TRole, TCapability, TPreferences, TAttributes>;
    let latestCard: OwnRecord | null = null;
    let tierEmail: string | undefined;
    // The record's admin flag as last seen, so only a change to it (not every record update) prompts a token refresh
    let lastRecordAdminFlag: boolean | undefined;
    const withTierEmail = (record: OwnRecord | null): OwnRecord | null =>
      record && tierEmail ? { ...record, email: tierEmail } : record;

    const handleUserRecord = (record: OwnRecord | null): void => {
      userRecordStoreInternal.set(record);
      if (record) {
        cardAttributes = record.attributes || {};
        publishAttributes();

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
                displayName: user.displayName
              })
              .catch(() => {
                syncedAvatars.delete(globalUserSyncKey);
              });
          }
        }

        // Email is never written from here: the server's checkAuth syncs it from the verified token, and fires its
        // onVerifiedEmailChange hook (a client write would race it and suppress the hook)

        // A change to the admin directory entry is only a hint that the user's claim may have changed: refresh the
        // token and publish what the claim says. The record itself never decides isAdmin (it can be stale).
        if (typeof record.isSystemAdmin === "boolean" && record.isSystemAdmin !== lastRecordAdminFlag) {
          lastRecordAdminFlag = record.isSystemAdmin;
          const currentAuth = authStoreInternal.get();
          if (
            currentAuth.user &&
            currentAuth.user.uid === user.uid &&
            currentAuth.user.isAdmin !== record.isSystemAdmin &&
            auth?.currentUser &&
            auth.currentUser.uid === user.uid &&
            typeof auth.currentUser.getIdTokenResult === "function"
          ) {
            refreshTokenAndClaims(auth.currentUser).catch(() => {});
          }
        }
      } else {
        cardAttributes = {};
        publishAttributes();
      }
    };

    if (typeof store.subscribeToUser === "function") {
      unsubUser = store.subscribeToUser(user.uid, (record) => {
        latestCard = record;
        handleUserRecord(withTierEmail(record));
      });
    }

    unsubPrefs = store.subscribeToPreferences(user.uid, (remotePrefs) => {
      applyRemotePreferences(user.uid, remotePrefs);
    });

    if (typeof store.subscribeToAttributes === "function") {
      unsubAttributes = store.subscribeToAttributes(user.uid, (attrs, email) => {
        tierAttributes = attrs;
        publishAttributes();
        if (email !== tierEmail) {
          tierEmail = email;
          if (latestCard) handleUserRecord(withTierEmail(latestCard));
        }
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

      latestMemberships = normalizedMembers;
      syncScopeTierSubscriptions(user.uid);
      publishMemberships(false);
    });
  }

  // Wire up Firebase Auth listener if an Auth instance is provided
  if (auth && typeof onAuthStateChanged === "function") {
    try {
      // Auto-handle a verifyEmail action code on boot. Magic sign-in links are never completed automatically: the app
      // calls completePasswordlessSignIn() and handles each outcome (such as asking for the email).
      if (typeof window !== "undefined") {
        if (window.location.search.includes("mode=verifyEmail")) {
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

    // The link never carries the email: completing it uses the email stored below, or asks the user (see
    // completePasswordlessSignIn)
    const defaultUrl =
      typeof window !== "undefined"
        ? `${window.location.origin}${window.location.pathname}${window.location.hash}`
        : "http://localhost:5173/";

    const actionCodeSettings = {
      url: redirectUrl ? validateRedirectUrl(redirectUrl) : defaultUrl,
      handleCodeInApp: true
    };

    await sendSignInLinkToEmail(auth, targetEmail, actionCodeSettings);

    if (typeof localStorage !== "undefined") {
      localStorage.setItem(emailForSignInKey, targetEmail);
    }
  }

  /** Removes the sign-in link's parameters from the address bar, so a reload doesn't retry a finished link. */
  function clearSignInLinkFromAddressBar(): void {
    if (typeof window === "undefined" || typeof window.history?.replaceState !== "function") return;
    try {
      const url = new URL(window.location.href);
      for (const key of ["apiKey", "oobCode", "mode", "lang", "continueUrl", "tenantId", "email"]) {
        url.searchParams.delete(key);
      }
      window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
    } catch {}
  }

  /**
   * Completes a magic sign-in link (`href`, default: the current page) and reports the outcome; call it when the app
   * starts. The email comes only from `email` (typed by the user) or the one this device stored when it requested the
   * link, never from the link itself: otherwise anyone could sign a visitor into their own account by sending them one
   * of their links. When neither is available, or the stored email belongs to a different link, it resolves
   * `{ status: "needs-email" }` and the app should ask the user for the address the link was sent to (never prefilled)
   * and call this again with `{ email }`. If someone is already signed in, it doesn't replace their session; it resolves
   * `{ status: "signed-in-as-other" }` so the app can ask before switching accounts (sign out, then call this again;
   * signing out forgets any email this device saved, so expect `needs-email` and ask the user for it).
   *
   * Throws `EmailLinkMismatchError` when a typed email doesn't match the link (the link stays usable) and
   * `EmailLinkInvalidError` when the link has expired or was already used.
   */
  async function completePasswordlessSignIn(
    options: { email?: string; href?: string } = {}
  ): Promise<PasswordlessSignInResult> {
    if (!auth) throw new Error("Firebase Auth is not initialized");
    const fromAddressBar = !options.href;
    const targetHref = options.href || (typeof window !== "undefined" ? window.location.href : "");
    if (!targetHref || !isSignInWithEmailLink(auth, targetHref)) return { status: "not-a-link" };

    // On page load currentUser stays null until Firebase restores the saved session, so wait for it before deciding
    // nobody is signed in (otherwise the link would replace a signed-in user's session)
    await auth.authStateReady();
    const currentEmail = auth.currentUser?.email;
    if (auth.currentUser) {
      return { status: "signed-in-as-other", currentEmail: currentEmail ? currentEmail.toLowerCase().trim() : "" };
    }

    const typedEmail = options.email?.toLowerCase().trim();
    const storedEmail = typeof localStorage !== "undefined" ? localStorage.getItem(emailForSignInKey) : null;
    const email = typedEmail || storedEmail?.toLowerCase().trim();
    if (!email) return { status: "needs-email" };

    let result: Awaited<ReturnType<typeof signInWithEmailLink>>;
    try {
      result = await signInWithEmailLink(auth, email, targetHref);
    } catch (error: any) {
      if (error?.code === "auth/invalid-email") {
        if (typedEmail) throw new EmailLinkMismatchError();
        // This device's stored email belongs to a different link (e.g. someone else's): forget it and ask the user
        if (typeof localStorage !== "undefined") localStorage.removeItem(emailForSignInKey);
        return { status: "needs-email" };
      }
      if (error?.code === "auth/invalid-action-code" || error?.code === "auth/expired-action-code") {
        if (fromAddressBar) clearSignInLinkFromAddressBar();
        throw new EmailLinkInvalidError();
      }
      throw error;
    }
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(emailForSignInKey);
    }
    if (fromAddressBar) clearSignInLinkFromAddressBar();
    let claims: Record<string, any> = {};
    try {
      const tokenResult = await result.user.getIdTokenResult();
      claims = tokenResult?.claims || {};
    } catch {}
    const normalized = normalizeFirebaseUser(result.user, claims);
    setActiveUser(normalized);
    return { status: "signed-in", user: normalized };
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
      typeof window !== "undefined" ? `${window.location.origin}${window.location.pathname}` : "http://localhost:5173/";

    await verifyBeforeUpdateEmail(auth.currentUser, targetEmail, {
      url: redirectUrl ? validateRedirectUrl(redirectUrl) : defaultUrl,
      handleCodeInApp: true
    });
  }

  /**
   * Emails a Firebase verification link for the signed-in user's current address, for users whose provider (such as
   * GitHub, or Microsoft work accounts) doesn't vouch for their email. It never takes an address, so it can't be used
   * to verify an email the user doesn't already have. By default the link returns to the current page. Resolves
   * `false` without sending when the address is already verified. Call `refreshEmailVerification` once the user has
   * clicked the link.
   */
  async function sendEmailVerificationLink(redirectUrl?: string): Promise<boolean> {
    if (!auth || !auth.currentUser) throw new Error("No authenticated user.");
    const user = auth.currentUser;
    if (!user.email) throw new Error("The signed-in user has no email address to verify.");
    const url = redirectUrl
      ? validateRedirectUrl(redirectUrl)
      : typeof window !== "undefined"
        ? `${window.location.origin}${window.location.pathname}${window.location.hash}`
        : undefined;
    if (user.emailVerified) return false;
    await sendEmailVerification(user, url ? { url } : undefined);
    return true;
  }

  /**
   * Reloads the signed-in user and forces a fresh ID token, so a verification completed elsewhere (another tab or
   * device) reaches both `authStore` and the `email_verified` claim the server checks. Resolves whether the email is
   * now verified.
   */
  async function refreshEmailVerification(): Promise<boolean> {
    if (!auth || !auth.currentUser) throw new Error("No authenticated user.");
    const user = auth.currentUser;
    await user.reload();
    const tokenResult = await user.getIdTokenResult(true);
    const normalized = normalizeFirebaseUser(auth.currentUser || user, tokenResult?.claims || {});
    setActiveUser(normalized);
    return normalized.emailVerified;
  }

  // --- Authorized API Requests ---

  /** Forces a token refresh and publishes the refreshed claims (e.g. `isAdmin` after a demotion) to `authStore`. */
  async function refreshTokenAndClaims(user: User): Promise<string> {
    const tokenResult = await user.getIdTokenResult(true);
    const current = authStoreInternal.get().user;
    if (current && current.uid === user.uid) {
      const refreshed = normalizeFirebaseUser(user, tokenResult?.claims || {});
      if (refreshed.isAdmin !== current.isAdmin) {
        authStoreInternal.set({ user: { ...current, isAdmin: refreshed.isAdmin }, isReady: true });
      }
    }
    return tokenResult.token;
  }

  async function errorCodeOf(res: Response): Promise<string | undefined> {
    if (res.status !== 401) return undefined;
    try {
      const body = await res.clone().json();
      return typeof body?.code === "string" ? body.code : undefined;
    } catch {
      return undefined;
    }
  }

  function withBearer(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    token: string
  ): [RequestInfo | URL, RequestInit | undefined] {
    if (typeof Request !== "undefined" && input instanceof Request) {
      const headers = new Headers(input.headers);
      if (init?.headers) new Headers(init.headers).forEach((value, key) => headers.set(key, value));
      headers.set("Authorization", `Bearer ${token}`);
      return [new Request(input, { ...init, headers }), undefined];
    }
    const headers = new Headers(init?.headers);
    headers.set("Authorization", `Bearer ${token}`);
    return [input, { ...init, headers }];
  }

  /**
   * `fetch` with the signed-in user's ID token attached, handling Lanyard's auth responses so apps don't compare
   * strings:
   * - `401 auth/token-stale` (the token predates a revocation, e.g. a demotion): forces a token refresh, publishes the
   *   refreshed claims to `authStore`, and retries. If the new token shares a second with the revocation and is still
   *   stale, it waits `staleTokenRetryDelayMs` and tries once more, then throws `TokenStaleError`.
   * - `401 auth/session-revoked`: signs the user out locally and throws `SessionRevokedError`.
   * - `401 auth/email-not-verified`: throws `EmailNotVerifiedError`.
   *
   * Every other response is returned as-is. Request bodies must be replayable (strings, `FormData`, `Blob`, or a
   * `Request`, which is cloned before sending), because a stale-token retry sends them again.
   */
  async function authorizedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const user = auth?.currentUser;
    if (!auth || !user) throw new Error("No authenticated user.");
    const original = typeof Request !== "undefined" && input instanceof Request ? input.clone() : input;

    let token = await user.getIdToken();
    for (let attempt = 0; ; attempt++) {
      const requestInput = typeof Request !== "undefined" && original instanceof Request ? original.clone() : original;
      const res = await fetch(...withBearer(requestInput, init, token));
      const code = await errorCodeOf(res);
      if (code === SESSION_REVOKED_ERROR_CODE) {
        await firebaseSignOut(auth);
        throw new SessionRevokedError();
      }
      if (code === EMAIL_NOT_VERIFIED_ERROR_CODE) throw new EmailNotVerifiedError();
      if (code !== TOKEN_STALE_ERROR_CODE) return res;
      if (attempt === 2) throw new TokenStaleError();
      if (attempt === 1) await new Promise((resolve) => setTimeout(resolve, staleTokenRetryDelayMs));
      token = await refreshTokenAndClaims(user);
    }
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
        writeCachedPreferences(activePrefStorageKey(), updated);
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

    scopePreferences.set(scopeId, { ...(scopePreferences.get(scopeId) || {}), ...cleanPatch });
    publishMemberships(membershipsStoreInternal.get().isLoading);

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

  /** The roles the signed-in user may assign in `scopeId` (mirrors the server's ceiling), e.g. for a role picker. */
  function getAssignableRoles(scopeId: ScopeId): readonly TRole[] {
    const currentUser = authStoreInternal.get().user;
    if (!currentUser || !policy) return [];
    return policy.getAssignableRoles(resolveTargetSubject(scopeId), Boolean(currentUser.isAdmin));
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
      if (isAdmin) {
        return [...policy.capabilities];
      }
      if (Array.isArray(subject?.roles)) {
        for (const role of subject.roles) {
          if (typeof role === "string" && Object.hasOwn(policy.roleCapabilities, role)) {
            const roleCaps = policy.roleCapabilities[role];
            if (Array.isArray(roleCaps)) {
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
   * The attributes tier is readable by self, scope staff (`staffCapability`), and system admins; keys placed on
   * the card via `cardFields.attributes` are additionally readable by anyone who can read the card.
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
      const canReadCard = policy.canReadTier(subject, "card", {
        isSystemAdmin: isAdmin,
        isSelf,
        isGlobal: scopeId === GLOBAL_SCOPE,
        isScopeMember: scopeId !== GLOBAL_SCOPE && Boolean(subject)
      });
      return policy.canReadAttribute(subject, key, { isSystemAdmin: isAdmin, isSelf, canReadCard });
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
    cb: (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void,
    options?: SubscribeToMembersOptions
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
    if (options?.include?.includes("attributes")) assertCanReadOthersAttributes(scopeId, 'include: ["attributes"]');
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
      cb as (members: ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]) => void,
      options?.include ? { include: options.include } : undefined
    );
  }

  /** The signed-in user's own record in `scopeId` (their global record for `GLOBAL_SCOPE`), for policy checks. */
  function currentActorRecord(
    scopeId: ScopeId
  ):
    | UserRecord<TRole, TCapability, TPreferences, TAttributes>
    | ScopedMember<TRole, TCapability, TPreferences, TAttributes>
    | null {
    return scopeId === GLOBAL_SCOPE
      ? userRecordStoreInternal.get()
      : membershipsStoreInternal.get().memberships.find((m) => m.scopeId === scopeId) || null;
  }

  function scopeLabel(scopeId: ScopeId): string {
    return scopeId === GLOBAL_SCOPE ? "the global scope" : `scope '${scopeId}'`;
  }

  /**
   * Throws unless the signed-in user may read other users' `attributes` tier in `scopeId` (system admins, and
   * staff per the policy's `staffCapability`), so forbidden reads fail clearly instead of returning `[]`.
   */
  function assertCanReadOthersAttributes(scopeId: ScopeId, operation: string): void {
    const currentUser = authStoreInternal.get().user;
    const isSystemAdmin = Boolean(currentUser?.isAdmin);
    const allowed =
      isSystemAdmin || Boolean(currentUser && policy?.canReadTier(currentActorRecord(scopeId), "attributes"));
    if (!allowed) throw new Error(`Forbidden: ${operation} requires staff access in ${scopeLabel(scopeId)}`);
  }

  /**
   * Throws unless the signed-in user may `mode` the policy's custom document `name` belonging to `targetUid` in
   * `scopeId` (per `customDocs[name].read` / `.write`). Scoped access also requires membership (or system admin).
   */
  function assertCustomDocAccess(scopeId: ScopeId, name: string, targetUid: string, mode: "read" | "write"): void {
    if (!policy || !Object.hasOwn(policy.customDocs, name)) throw new Error(`Unknown custom doc '${name}'`);
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) throw new Error("Invalid scopeId");
    if (!isValidResourceId(targetUid)) throw new Error("Invalid targetUid");
    const currentUser = authStoreInternal.get().user;
    if (!currentUser?.uid) throw new Error("No authenticated user.");
    const actor = currentActorRecord(scopeId);
    const isSystemAdmin = Boolean(currentUser.isAdmin);
    if (scopeId !== GLOBAL_SCOPE && !actor && !isSystemAdmin) {
      throw new Error(`Forbidden: not a member of ${scopeLabel(scopeId)}`);
    }
    const options = { isSystemAdmin, isSelf: currentUser.uid === targetUid };
    const allowed =
      mode === "read" ? policy.canReadCustomDoc(actor, name, options) : policy.canWriteCustomDoc(actor, name, options);
    if (!allowed)
      throw new Error(`Forbidden: cannot ${mode} custom doc '${name}' of this user in ${scopeLabel(scopeId)}`);
  }

  function requireCustomDocStore<K extends "getCustomDoc" | "subscribeToCustomDoc" | "updateCustomDoc">(
    method: K
  ): NonNullable<LanyardClientStore<TRole, TCapability, TPreferences, TAttributes>[K]> {
    const fn = store[method];
    if (typeof fn !== "function") throw new Error(`Backing store does not implement ${method}`);
    return fn.bind(store) as NonNullable<LanyardClientStore<TRole, TCapability, TPreferences, TAttributes>[K]>;
  }

  /** Reads the policy's custom document `name` of `targetUid` (default: the signed-in user) in `scopeId`. */
  async function readCustomDoc(scopeId: ScopeId, name: string, targetUid?: string): Promise<Record<string, any>> {
    const uid = targetUid ?? authStoreInternal.get().user?.uid ?? "";
    assertCustomDocAccess(scopeId, name, uid, "read");
    return requireCustomDocStore("getCustomDoc")(name, uid, scopeId === GLOBAL_SCOPE ? null : scopeId);
  }

  /** Subscribes to the policy's custom document `name` of `targetUid` in `scopeId` (emits `{}` while missing). */
  function subscribeToCustomDoc(
    scopeId: ScopeId,
    name: string,
    targetUid: string,
    cb: (values: Record<string, any>) => void
  ): () => void {
    assertCustomDocAccess(scopeId, name, targetUid, "read");
    return requireCustomDocStore("subscribeToCustomDoc")(
      name,
      targetUid,
      scopeId === GLOBAL_SCOPE ? null : scopeId,
      cb
    );
  }

  /** Merges `patch` into the policy's custom document `name` of `targetUid` in `scopeId`. */
  async function updateCustomDoc(
    scopeId: ScopeId,
    name: string,
    targetUid: string,
    patch: Record<string, any>
  ): Promise<void> {
    assertCustomDocAccess(scopeId, name, targetUid, "write");
    await requireCustomDocStore("updateCustomDoc")(name, targetUid, scopeId === GLOBAL_SCOPE ? null : scopeId, patch);
  }

  /**
   * Returns the uids of members of `scopeId` (or global users for `GLOBAL_SCOPE`) whose attributes equal every
   * value in `filter.attributes`. Filters on `attributes`-tier keys require staff access; filters on keys placed
   * on the card (`cardFields.attributes`) require card access. Keys from both locations can't be combined.
   * In Firestore, each combination of filtered keys needs a composite index (see the README).
   */
  async function queryMembers(scopeId: ScopeId, filter: { attributes: Partial<TAttributes> }): Promise<string[]> {
    if (scopeId !== GLOBAL_SCOPE && !isValidResourceId(scopeId)) throw new Error("Invalid scopeId");
    if (typeof store.queryMemberUids !== "function") {
      throw new Error("Backing store does not implement queryMemberUids");
    }
    const location = resolveAttributeQueryLocation(filter?.attributes, resolveCardFields(policy));
    if (location === "attributes") {
      assertCanReadOthersAttributes(scopeId, "queryMembers on attributes-tier keys");
    } else {
      const currentUser = authStoreInternal.get().user;
      const actor = currentActorRecord(scopeId);
      const isSystemAdmin = Boolean(currentUser?.isAdmin);
      const canReadCards =
        isSystemAdmin ||
        Boolean(
          currentUser &&
          policy?.canReadTier(actor, "card", { isGlobal: scopeId === GLOBAL_SCOPE, isScopeMember: Boolean(actor) })
        );
      if (!canReadCards) {
        throw new Error(`Forbidden: queryMembers on card-placed keys requires card access in ${scopeLabel(scopeId)}`);
      }
    }
    return store.queryMemberUids(scopeId === GLOBAL_SCOPE ? null : scopeId, filter.attributes);
  }

  /**
   * Subscribes to active system administrators (`isSystemAdmin === true`) in `usersCollection`.
   * Uses an indexed `where("isSystemAdmin", "==", true)` query in `FirestoreClientStore` so only
   * system admin documents are read from Firestore.
   */
  function subscribeToSystemAdmins(
    cb: (admins: SystemAdminProfile[]) => void,
    options?: SubscribeToMembersOptions
  ): () => void {
    return subscribeToUsers(
      GLOBAL_SCOPE,
      (users) => {
        cb(users.filter((u) => u.isSystemAdmin === true) as SystemAdminProfile[]);
      },
      { isSystemAdmin: true, ...(options?.include ? { include: options.include } : {}) }
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
    queryMembers,
    readCustomDoc,
    subscribeToCustomDoc,
    updateCustomDoc,
    loginWithSocialProvider,
    sendPasswordlessEmailLink,
    completePasswordlessSignIn,
    signOut,
    linkSocialProvider,
    unlinkSocialProvider,
    getSignInMethodsForEmail,
    sendEmailUpdateVerification,
    sendEmailVerificationLink,
    refreshEmailVerification,
    authorizedFetch,
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

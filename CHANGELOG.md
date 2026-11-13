# Changelog

## Unreleased

### New

- **`bootstrapFirstAdmin({ email })` on the server** creates the first system admin from a trusted setup script, since
  `setSystemAdminStatus` needs an admin actor. It promotes an existing, enabled account whose email is verified (never
  creating one), keeps its other claims, and adds the directory entry. It refuses once any account has the `admin`
  claim, which it checks by paging through `adminAuth.listUsers` (a new optional adapter method it requires; Firebase
  Admin's `Auth` has it); stale directory entries don't count. If the directory write fails after the claim is set, the
  new admin completes it with `setSystemAdminStatus`. Run it once: two bootstraps started at the same moment aren't
  guarded against each other.

- **`authorizedFetch(input, init)` on the client** sends a request with the signed-in user's ID token and handles
  Lanyard's auth responses, so apps don't compare strings or retry by hand:
  - `401 auth/token-stale`: forces a token refresh, publishes the refreshed claims (such as `isAdmin` after a demotion)
    to `authStore`, and retries; if the new token still shares a second with the revocation it waits
    `staleTokenRetryDelayMs` (default `REVOCATION_CLOCK_SKEW_MS + 1000`) and tries once more, then throws
    `TokenStaleError`;
  - `401 auth/session-revoked`: signs the user out locally and throws `SessionRevokedError`;
  - `401 auth/email-not-verified`: throws `EmailNotVerifiedError`.

  Other responses are returned as-is. Request bodies must be replayable. `EmailNotVerifiedError` moves to
  `lanyard/core` (still exported from `lanyard/server`) alongside the new `SessionRevokedError` and `TokenStaleError`,
  each with a `code`, so browser code can check `instanceof`.

- **Proactive refresh after revocations.** While a user is signed in, the client watches the revocation epoch and, as
  soon as a revocation supersedes their token, waits until a new token would be past it and refreshes, publishing the
  new claims to `authStore`. A demoted admin's UI, next request and Firestore access use `admin: false` without waiting
  for a 401. If the epoch can't be read, `authorizedFetch` still refreshes on demand. `createLanyardClient` now throws if
  the store lacks `subscribeToRevocationEpoch`.
- **Generated rules cover Lanyard's metadata collection.** Signed-in users may `get` the revocation epoch
  (`{metaCollection}/revocation`, needed for proactive refresh); everything else there, including session revocations,
  is server-only. `generateFirestoreRules` takes a `metaCollection` option and `lanyard-rules` a `--meta` flag (default
  `lanyard_meta`). Regenerate your rules.

### Breaking changes

- **The verified-email sync also updates scope memberships.** When `checkAuth` sees a user's verified email change, it
  now writes the new address to each of their scope memberships, then calls `onVerifiedEmailChange`, then updates
  their global record, so staff see the current address and scoped `deleteUser` confirms against it. (Member emails
  used to keep whatever was written at provisioning once clients could no longer write email.) If a write fails, the
  global record stays unchanged and the next request retries; a failure among the memberships doesn't call the hook,
  a membership removed meanwhile is skipped, and while the hook keeps failing, retries on the same server go straight
  to it without re-listing or re-writing memberships. Server stores must implement the new required
  `listUserMembershipScopeIds(uid)` (`createLanyardServer` checks for it); `FirestoreServerStore` uses the same
  collection-group query on the members subcollection as the client's membership listener, so no new index is needed,
  and keeps only documents directly under its scope collection. Member emails that went stale before upgrading are
  corrected the next time that user's email changes; to fix them sooner, rewrite them from the global records with
  `patchScopeMember`.

- **Stricter secret decryption.** The built-in AES-256-GCM cipher now pins the auth tag to 16 bytes (GCM otherwise
  accepts a shortened tag, as short as 4 bytes, which makes forging a secret far easier) and refuses envelopes whose IV
  isn't 24 hex characters, whose tag isn't 32, or whose ciphertext isn't even-length hex (`Buffer.from(…, "hex")`
  silently dropped invalid characters). Secrets Lanyard wrote already match. Stores also decrypt each secret
  separately: one that can't be decrypted is skipped with a `console.warn` instead of making the user's other secrets
  unreadable, and reads still throw if none can be decrypted, which usually means the wrong master key.

- **The client's preferences cache is per user and cleared when their session ends.** It used to keep every user's
  global preferences under one shared `localStorage` key that outlived sign-out, so on a shared browser the next
  visitor saw the previous user's preferences before signing in, and the next user's preferences were merged on top of
  them (keeping any the new user hadn't set). Now:
  - each signed-in user's cache lives at `{prefix}_user_preferences_{uid}` and is used only once auth says they're
    signed in;
  - when their session ends (sign-out, revocation, another tab, or switching accounts), their cache and any pending
    magic-link email (`{prefix}_emailForSignIn`) are removed, and whenever auth reports who is signed in (or that
    nobody is), any other user's cache under the prefix is removed too, including ones left by sessions that ended
    while no page was open (so with session or in-memory Auth persistence, where tabs can hold different users, each
    tab's sign-in removes the other user's cache);
  - signed-out visitors have their own `{prefix}_guest_preferences`, which doesn't carry into an account;
  - the old shared `{prefix}_user_preferences` key is deleted on startup.

  **Migrating:** nothing to change unless your app reads those keys directly. Preferences saved with
  `syncToStore: false` are now device-local per user and don't survive sign-out.

- **Role assignment has a ceiling.** Before, anyone holding `userCapabilities.assignRoles` could give any role to
  anyone who wasn't a system admin, including roles above their own and their own roles, so the capability was
  effectively the top role in its scope. `updateUserRoles` also wrote back the whole record it had read, so a
  concurrent change (such as a demotion clearing `isSystemAdmin`) could be undone. Now, for non-admin actors:
  - every role added or removed must be within the actor's rank: a role they hold, or one those roles inherit;
  - the target's current roles must all be within it, so nobody changes someone who outranks them; this also applies
    to `updateUserProfile` and `deleteUser`, since removing someone from a scope revokes every role they hold there;
  - nobody changes their own roles;
  - peers of equal rank may grant and remove each other's role.

  Rank comes only from `inherits`, never from matching capabilities, and `capabilities: "*"` doesn't imply it. When
  `assignRoles` or `write` is configured, `createPermissionPolicy` throws if a `"*"` role can't reach every other
  concrete role that isn't ranked above it (so two unrelated concrete `"*"` roles must be ordered by having one inherit
  the other; a role that inherits a `"*"` role, like a superowner above owner, is fine).
  New role flag `systemManaged: true` marks roles trusted server code owns (such as a roster-synced `volunteer`):
  `updateUserRoles` never adds them, for anyone, keeps them when other roles change, and ignores them when comparing
  rank; the trusted helpers still grant and revoke them. `updateUserRoles` now writes only the roles that change. New
  `policy.canAssignRole`, `policy.getAssignableRoles(actor, isAdmin)` and `policy.isSystemManagedRole`; the client's
  `getAssignableRoles(scopeId)` now takes a scope and returns only the roles the user may assign there (it used to
  return every concrete role).

  **Migrating:** make any role that should hand out, edit or delete holders of another role inherit it (directly or
  through another role); this includes "side" staff roles that hold `userCapabilities.write` but sit outside the
  hierarchy, which can no longer edit or delete people holding roles they don't. Pass a scope to
  `client.getAssignableRoles`, and mark roles that only server code assigns as `systemManaged`.

- **Secrets are closed-world: only keys declared in `secretCapabilities` exist.** Before:
  - `canWriteSecret` let a user write their own copy of any secret key the policy didn't mention, so a user could store
    arbitrary encrypted values under names that server code might later decrypt and trust;
  - self-writing was opt-out (`allowSelfWrite` defaulted to `true`), so `{ write: "cap" }` quietly let every user write
    their own copy too;
  - stores accepted and returned any key found in a secrets document.

  Now:
  - an undeclared key can't be written by anyone, including system admins, and stores refuse it even when called
    directly;
  - a rule is either a capability string or `{ self?, capability? }`: `self: true` lets the user (or member) write their
    own copy, `capability` lets holders write anyone's, `{}` leaves it to admins and trusted server code, and the string
    shorthand never grants self-writing;
  - the old `write` / `allowSelfWrite` keys throw when the policy is created, rather than silently changing meaning;
  - `FirestoreServerStore` and `InMemoryLanyardStore` need the policy (`new FirestoreServerStore({ db, policy })`) to
    write secrets at all, `createLanyardServer` throws if the store's declared keys differ from its policy's
    (`policy.secretKeys`), and reads drop undeclared keys already in storage with a `console.warn`.

  **Migrating:** rename `{ allowSelfWrite: true }` to `{ self: true }`, `{ write: X }` to `{ capability: X, self: true }`
  to keep its old behaviour (or `{ capability: X }` if users shouldn't write their own), and
  `{ write: X, allowSelfWrite: false }` to `{ capability: X }`. Declare every key your server writes, including ones only
  backend code writes (e.g. OAuth tokens, as `{}`), and pass the same policy to your store.

- **Default roles only seed a newly provisioned record; revoking every role leaves none.** Before:
  - the Firestore stores substituted their `defaultRoles` option whenever a stored `roles` field was empty or
    missing, so revoking all of a user's roles quietly gave them the defaults back on the server and the client,
    while the generated rules (which read stored roles) denied them;
  - a bare card a user created for themselves read as holding the defaults;
  - grants on a new doc and `upsertUserByEmail` persisted the substituted defaults;
  - `createPermissionPolicy` silently defaulted to the root role when `defaultRoles` was omitted, and fell back to it
    when every listed role was misspelled.

  Now:
  - the `defaultRoles` option is removed from `FirestoreServerStore` and `FirestoreClientStore`, and stores return
    roles exactly as stored (a user card with no `roles` field has `roles: undefined`, which grants nothing);
  - `policy.defaultRoles` defaults to `[]`, an unknown name throws, and it's applied only by `upsertUserByEmail` when
    it creates a record (or fills in a user card that has never had roles, atomically, so a concurrent grant isn't
    lost) without explicit roles;
  - grants never add defaults;
  - `upsertUserByEmail` writes only the fields it's given, never the roles or admin status it read;
  - `upsertScopeMember` accepts a member without `roles` (`ScopedMemberUpsert`), meaning "leave them as they are";
  - `shouldTrackPresence` no longer assumes defaults for a record without roles.

  **Migrating:** delete `defaultRoles` from your store configs; TypeScript flags it. If you relied on the implicit
  root-role default, list `defaultRoles` explicitly. Existing records whose roles were persisted from substituted
  defaults can't be told apart from real grants, so audit them if your stores had a non-empty `defaultRoles`.

- **The client's `authStore.user.isAdmin` is always the Firebase claim.** The client used to overwrite it with the
  user's stored `isSystemAdmin` whenever the record changed, so a stale directory entry made a non-admin (or a demoted
  admin) look like an admin in the UI until something refreshed it. The server and generated rules never trusted the
  record, so this affected only what the UI showed. Now a change to the record only prompts a token refresh, and
  `isAdmin` is whatever the refreshed claim says.

- **Non-admins can't manage system admins, judged by the Firebase claim.** The guards that stop a non-admin with
  `userCapabilities.write` / `assignRoles` from editing, re-roling or deleting a system admin used to check the
  store's `isSystemAdmin` flag, and only in `GLOBAL_SCOPE`. So an admin whose record lacked the flag (for example one
  promoted in the Firebase console or by a script) could be edited, re-roled, or deleted (including their Firebase
  Auth account) by staff, and the scoped paths had no guard at all.

  `updateUserProfile`, `updateUserRoles` and `deleteUser` now check the target's current admin claim, globally and in
  scopes. This fails closed: if the claim can't be read, the target is treated as an admin. A target with no Firebase
  account (`auth/user-not-found`) can't hold the claim, so it can still be managed. `AdminAuthAdapter.getUser` is now
  required (Firebase Admin's `Auth` has it), and `createLanyardServer` throws without it rather than quietly treating
  every hand-built actor as a non-admin and every target as an admin.

- **Only `checkAuth` produces `isAdmin`; nothing else can create or alter it.** Before:
  - `GoogleAuthService.verifyToken` returned `isAdmin` straight from the token claim, which isn't freshness-checked;
  - `createLanyardServer` returned its `authService`, so it was easy to build middleware that trusted a demoted or
    signed-out admin's still-valid token;
  - the server trusted a verified `req.user`'s _mutable_ `isAdmin` property, so app code that later set
    `req.user.isAdmin = true` (a mock-admin header, or a bug) passed `requireAdmin` and could promote anyone through
    `setSystemAdminStatus`.

  Now:
  - `AuthService.verifyToken` returns a `VerifiedToken`: `{ uid, email, emailVerified, name?, photoUrl?, adminClaim,
issuedAtSeconds, authTimeSeconds }`, all required except `name` and `photoUrl`. It has no `isAdmin`, and
    `tokenIssuedAtSeconds` is renamed to `issuedAtSeconds`;
  - `checkAuth` builds a new `AuthenticatedUser` (`{ uid, email, emailVerified, name?, photoUrl?, isAdmin }`, without
    the token times), and server methods judge it by the status `checkAuth` recorded for that object, never by its
    `isAdmin` property;
  - `LanyardActor` is just `{ uid }`: hand-built actors were already judged by their current Firebase claim, and now
    they can't claim otherwise in the type either;
  - `createLanyardServer` no longer returns `authService`;
  - `GoogleAuthService` takes `(adminAuth, { requireVerifiedEmail?, checkRevoked? })` instead of positional booleans,
    and rejects tokens without `iat`/`auth_time`;
  - a client `syncAvatar` on `InMemoryLanyardStore` no longer creates an `isSystemAdmin: true` record for an unknown
    user; like the Firestore client store, it creates a plain card.

- **Syncs and profile edits write only the fields they change, so they can't undo a revocation.** `checkAuth`'s
  verified-email sync, the avatar sync in `requireRole` / `requireCapability`, and `updateUserProfile` used to write
  back the whole record they had read. That record included `roles` and `isSystemAdmin`. If an admin revoked a role
  or demoted the user while the request was in flight, the stale copy restored them (and, with read-time default
  roles, persisted those).

  Server stores now require `patchUser(uid, fields)` and `patchScopeMember(scopeId, uid, fields)`:
  - they change only profile fields and email (`StoredProfileFieldsPatch`), never roles, admin status, attributes or
    preferences;
  - they throw if the record doesn't exist, rather than creating one;
  - `FirestoreServerStore` and `InMemoryLanyardStore` implement them, and `createLanyardServer` throws if a store
    lacks them.

- **Email is server-owned: clients never write it.** Only provisioning (`upsertUserByEmail`) and the server's
  verified-email sync in `checkAuth` write a user's stored email. Before, the client wrote it too, which caused two
  problems:
  - **A race that skipped the server hook.** When a user's verified email changed, their browser wrote the new address
    first. The server's `checkAuth` then saw no difference, so its `onVerifiedEmailChange` never fired, and anything
    the app did there (newsletter or CRM sync, migrating data keyed by email) was silently skipped.
  - **A spoofed `previousEmail`.** Profile updates accepted `email`, so a user could store someone else's address and
    have it passed to the hook as their `previousEmail`, and staff with `userCapabilities.write` could change other
    users' stored email. With `cardFields.email`, the rules let owners put any address on their card.

  Now:
  - the client's `onVerifiedEmailChange` option and its email write are removed, and `syncAvatar` no longer takes
    `email`;
  - `UserProfilePatch` has no `email`, and `updateUserProfile` (server, client store, in-memory store) throws if a
    patch includes one;
  - generated rules deny every client write of email: the owner write path to the `attributes` tier is gone, and
    `email` is never a client-writable card key, even with `cardFields.email`;
  - `checkAuth` fills in a missing stored email from the verified token without calling the hook;
  - `onVerifiedEmailChange` is documented as at-least-once, and `previousEmail` as the last stored value rather than
    proof of ownership;
  - a failing sync is logged with `console.warn` and retried on the next request, instead of being swallowed.

  Regenerate your rules.

- **Magic sign-in links never trust an email taken from the link, and are never completed automatically.** The
  client used to complete a sign-in link as soon as it was created, preferring an `email` query parameter (which
  `sendPasswordlessEmailLink` itself added to every link) over this device's stored email. So anyone could sign a
  visitor into their own account just by sending them one of their sign-in links (login CSRF). Now:
  - `sendPasswordlessEmailLink` and `sendEmailUpdateVerification` no longer put the address in the link;
  - nothing is completed on construction: call `completePasswordlessSignIn(options?: { email?, href? })` when the app
    starts. It takes the email only from `options.email` (typed by the user) or this device's stored one, and resolves
    a `PasswordlessSignInResult`: `{ status: "signed-in", user }`, `{ status: "needs-email" }` (ask for the address the
    link was sent to, never prefilled, then call again with `{ email }`), `{ status: "signed-in-as-other",
currentEmail }` (someone is already signed in; their session is left alone) or `{ status: "not-a-link" }`;
  - a typed email that doesn't match throws `EmailLinkMismatchError` (the link stays usable); an expired or used link
    throws `EmailLinkInvalidError`; both are in `lanyard/core` with `code`s `EMAIL_LINK_MISMATCH_ERROR_CODE` and
    `EMAIL_LINK_INVALID_ERROR_CODE`. A stored email that doesn't match the link is forgotten and reported as
    `needs-email`;
  - it no longer falls back to the signed-in user's email, and after completing from the address bar it removes the
    link's parameters from the URL.

  The positional `(providedEmail?, href?)` signature is gone, so old calls fail to compile instead of misbehaving.
  Cross-device sign-in now needs the email prompt.

- **`getOrProvisionUidByEmail` refuses existing accounts whose email isn't verified.** If an account for the address already exists in Firebase Auth (`getUserByEmail`), `getOrProvisionUidByEmail` (and therefore `upsertUserByEmail`, `grantRolesByEmail`, and `setSystemAdminStatus` when promoting) now requires `emailVerified === true` on that record and throws `EmailNotVerifiedError` otherwise. Without this, an attacker who registered someone else's email address with an unverified sign-in method before they were invited would receive the roles or admin claim meant for them. `AdminAuthAdapter.getUserByEmail` test doubles that return existing accounts must include `emailVerified: true`.

- **Generated Firestore rules enforce revocations on `isAdmin()` and require a verified email by default.**
  - `isAdmin()` now checks that the token was issued after the revocation epoch (`request.auth.token.iat * 1000 > revocationEpochMs() + 2000`) and that its session hasn't been revoked (`request.auth.token.auth_time * 1000 > sessionRevokedAtMs() + 2000`), so a demoted or signed-out admin loses Firestore admin access at once instead of when their token expires.
  - `isSignedIn()` now requires `request.auth.token.get('email_verified', false) == true` by default, matching `checkAuth`. Pass `requireVerifiedEmail: false` to `generateFirestoreRules` (or `--require-verified-email false` to `lanyard-rules`) only if your app deliberately serves unverified users.

  Regenerate your rules.

- **The Firebase `admin` claim is the only admin authority.** Admin status used to be resolved from the store first
  (`users/{uid}.isSystemAdmin`, then `system_admins`) with the token claim as a fallback, and `checkAuth`/`requireAdmin`
  auto-provisioned an admin record (`syncAdminProfileIfNeeded`) for anyone they judged an admin. Together those let a
  demoted admin's still-valid token re-create their admin record and undo the demotion permanently. Now:
  - `checkAuth` takes `req.user.isAdmin` from the verified token claim (kept current by the revocation checks) and
    never reads or writes admin records; admin status no longer depends on the store being reachable;
  - `requireAdmin` trusts `req.user.isAdmin` only on a `req.user` that `checkAuth` verified; for any other object it asks
    Firebase for the user's current claim (`AdminAuthAdapter.getUser`) and fails closed if it can't;
  - actor-based server methods do the same: `actor.isAdmin` on a hand-built actor is ignored in favor of the user's
    current Firebase claim (pass `req.user` to avoid the lookup);
  - `setSystemAdminStatus` demotions bump the revocation epoch after changing the claim, so the demoted user's existing
    `admin: true` tokens are refused as stale immediately.

  Store admin records (`isSystemAdmin`, `system_admins`) remain as a directory for listing admins, written only by
  `setSystemAdminStatus`; they grant nothing. This supersedes the store-based fail-closed admin check from earlier in
  this release: admin checks no longer touch the store at all.

- **`setSystemAdminStatus` requires an admin actor.** It used to validate only `actor.uid` (and block self-demotion), so
  an app route that forwarded the caller as the actor let any user grant themselves admin. It now checks, before
  provisioning an account or changing any claim, that the actor is an admin by the rules above (a verified `req.user`,
  or the user's current Firebase claim), and throws `Forbidden` otherwise. Demoting an email with no account is now a
  no-op that returns `null` instead of provisioning an account first.

- **`checkAuth` enforces revocations, and requires token times.** It now rejects, before any store lookup:
  - tokens from a session revoked after the user signed in (`auth_time` at or before the user's session revocation):
    `401 { error, code: "auth/session-revoked" }` (`SESSION_REVOKED_ERROR_CODE`); the user must sign in again;
  - tokens issued (`iat`) at or before the revocation epoch: `401 { error, code: "auth/token-stale" }`
    (`TOKEN_STALE_ERROR_CODE`); refreshing the token and retrying is enough.

  Both comparisons allow `REVOCATION_CLOCK_SKEW_MS` (2s) for clock differences and one-second token granularity.
  An `AuthService` reports `issuedAtSeconds` and `authTimeSeconds` on its `VerifiedToken` (see "Only `checkAuth`
  produces `isAdmin`" above); if they're missing, `checkAuth` fails closed with 401. Revocation data comes from
  the store's live subscriptions, held in memory, so the check adds no per-request lookup; until it first loads
  (`revocationLoadTimeoutMs`, default 5s) requests wait, and if it can't be loaded or a listener errors, `checkAuth`
  responds `503` and resubscribes with backoff (`revocationResubscribeDelayMs`). `createLanyardServer` throws if the
  store lacks the revocation methods, subscribes at construction, and returns a new `close()` to stop the
  subscriptions.

- **New `revokeUserSessions({ uid, actor })`** signs a user out everywhere: it revokes their Firebase refresh tokens,
  then records a session revocation that every server instance enforces at once. Users may revoke their own sessions;
  revoking someone else's requires an admin actor. Nothing is recorded if Firebase revocation fails.
  `AdminAuthAdapter` gains an optional `revokeRefreshTokens`, required by this method. Revocations made directly in
  Firebase (the console, or calling `revokeRefreshTokens` yourself) aren't seen by Lanyard; use this method.

- **Stores must implement the revocation epoch.** `LanyardServerStore` now requires `getRevocationEpoch()`,
  `bumpRevocationEpoch(atMs)` and `subscribeToRevocationEpoch(onChange, onError)`, and `LanyardClientStore` requires
  `subscribeToRevocationEpoch(onChange, onError)`. The epoch is the time (epoch milliseconds) of the most recent
  revocation, or `null` if there hasn't been one; it only moves forward and rejects anything but non-negative integer
  milliseconds. It is the foundation for immediate revocation: ID tokens issued before it will be treated as stale.
  `FirestoreServerStore`, `FirestoreClientStore` and `InMemoryLanyardStore` implement it (Firestore keeps it in
  `lanyard_meta/revocation`, configurable with the new `metaCollection` option, and a malformed stored value fails
  closed). Custom stores must add these methods; verify them with `assertRevocationEpochConformance` from the new
  `lanyard/testing` entry point.
- **Server stores must implement session revocations.** `LanyardServerStore` now also requires
  `getSessionRevocations()`, `recordSessionRevocation(uid, atMs)` and `subscribeToSessionRevocations(onChange, onError)`:
  a map of uid to the time that user's sessions were revoked (signed out everywhere or disabled). Firebase keys session
  revocation on a token's `auth_time` (sign-in time), which a refreshed token keeps, so the revocation epoch alone
  can't cut off a revoked session; this map will. Each user's entry only moves forward, and recording a revocation
  prunes entries older than 24 hours (`SESSION_REVOCATION_RETENTION_MS`) in the same atomic write, so the map holds
  only recent revocations. Firestore keeps it server-only in `lanyard_meta/session_revocations`; malformed entries fail
  closed. Verify custom stores with `assertSessionRevocationConformance` from `lanyard/testing`.

- **Admin checks fail closed when the backing store is unreachable.** `checkAuth` used to keep the token's `admin`
  claim as `req.user.isAdmin` if `store.getUser`/`store.getSystemAdmin` threw, and `requireAdmin` let the request
  through on the same claim. Because a demotion only lands in the token when it's refreshed (up to an hour later), a
  just-demoted admin was treated as an admin again during a store outage. Now `checkAuth` still authenticates the
  caller but sets `isAdmin: false`, and `requireAdmin` responds `503` with
  `{ error: "Service unavailable: unable to verify administrative access" }` without calling `next()`. Admin routes are
  unavailable during a store outage rather than trusting a possibly stale claim.

- **Missing `email_verified` now fails closed on the server.** `GoogleAuthService.verifyToken` used to reject a token
  only when its `email_verified` claim was exactly `false`, and reported `emailVerified: true` when the claim was
  absent. It now requires `email_verified === true` (when `requireVerifiedEmail` is on) and reports `emailVerified`
  as `true` only in that case. Likewise, `checkAuth` only syncs `users/{uid}.email` (and calls
  `onVerifiedEmailChange`) when the authenticated user has `emailVerified: true`, so a custom `AuthService` that
  omits `emailVerified` no longer counts as verified. This matches the generated Firestore rules, which already
  required `email_verified == true`. If you mint custom tokens that carry an `email` claim, also set
  `email_verified: true` on them when the email is genuinely verified.

### New

- **Email verification for providers that don't vouch for the address.** `client.sendEmailVerificationLink(redirectUrl?)`
  emails a Firebase verification link for the signed-in user's own address (it never takes an address, and resolves
  `false` without sending when the email is already verified). `client.refreshEmailVerification()` reloads the user and
  forces a fresh ID token, so a verification completed in another tab or on another device reaches `authStore` and the
  server's `email_verified` check.
- **A recognizable "email not verified" rejection.** `GoogleAuthService.verifyToken` now throws
  `EmailNotVerifiedError` (with `code: EMAIL_NOT_VERIFIED_ERROR_CODE`, `"auth/email-not-verified"`, exported from
  `lanyard/core` and `lanyard/server`), and `checkAuth` includes that `code` in its 401 JSON body alongside the existing
  `error` message.

## 0.2.1

### Breaking changes

- **Closed-world `capabilities` when using `"*"`.** Policies where any role sets `capabilities: "*"` must pass
  `capabilities: [...]` in `PermissionPolicyConfig` so `"*"` expands to a known closed capability set at runtime, in
  `client.getCapabilities()`, and in generated Firestore rules (undeclared capability strings return `false` and fail
  closed in `firestore.rules`). When `"*"` is unused, `policy.capabilities` is automatically inferred from referenced
  capabilities unless explicitly provided.

### New

- **Firestore Security Rules capability & role-inheritance helpers (`lanyard/rules`).** `generateFirestoreRules` now
  emits `hasScopeCapability(scopeId, capability)`, `hasUserCapability(capability)`, `hasScopeRole(scopeId, role)`, and
  `hasUserRole(role)` (backed by `rolesForCapability` and `rolesForRole`, including `abstract: true` roles) so your
  application's own collection rules can evaluate capabilities and inherited roles directly and fail closed on unknown
  names—even for system admins.

### Fixed

- `client.getCapabilities(scopeId)` now returns the full closed capability set for system admins and roles granted
  `capabilities: "*"`, instead of omitting capabilities held exclusively via `"*"`.

## 0.2.0

Lanyard 0.2.0 stores each user's data in **storage tiers**: one Firestore document per read audience, so security
rules can actually enforce who reads what. It also generates those rules from your `PermissionPolicy`.

### Breaking changes

- **Reads are governed by storage tier, not per key.** `attributeCapabilities` / `hiddenAttributeCapabilities`
  entries can no longer set `read` (a legacy `read` throws); writes are still gated per key. The `attributes` tier
  is readable by the user, scope staff, and system admins; `hiddenAttributes` by staff and admins.
- **`staffCapability` widens access when set.** Without it, only system admins count as staff (narrower than
  0.1.x). With it, holders of that capability can read the whole `attributes` and `hiddenAttributes` tiers of
  members in their scope, including keys that were admin-only under per-key reads. Choose it deliberately.
- **New document layout.** Everything except the card lives in the `private` subcollection, each document stamped
  with `_lanyard: { tier, uid, scopeId, updatedAt }`:

  | Data               | 0.1.x                              | 0.2.0                                                          |
  | :----------------- | :--------------------------------- | :------------------------------------------------------------- |
  | `preferences`      | `…/{uid}.preferences` (card)       | `…/{uid}/private/preferences`                                  |
  | `attributes`       | `…/{uid}.attributes` (card)        | `…/{uid}/private/attributes` (except `cardFields.attributes`)  |
  | `email`            | `…/{uid}.email` (card)             | `…/{uid}/private/attributes` (unless `cardFields.email: true`) |
  | `hiddenAttributes` | `…/{uid}/private/hiddenAttributes` | same path, now stamped with `_lanyard`                         |
  | `secrets`          | `…/{uid}/private/secrets`          | same path, now stamped with `_lanyard`                         |

  Lanyard 0.2.0 ignores inline `preferences`, `attributes`, and `email` left on cards, so existing data must be
  migrated (see below).

- **Stores take the policy.** Pass your policy to `FirestoreServerStore`, `FirestoreClientStore`, and
  `InMemoryLanyardStore` (`{ policy }`). `createLanyardServer` / `createLanyardClient` throw if a store's
  `cardFields` don't match the policy.
- **Reserved keys.** `_lanyard` can't be used as a preference, attribute, hidden attribute, secret, or custom doc
  key, and `email` can't be used as an attribute key. Writes using them throw.
- **Other users' private fields are off cards.** Rosters and directories return `email: ""` and only card-placed
  attributes for other users. Staff and admins can request them with `include: ["attributes"]`.
- **`savePreferences` no longer creates a `users/{uid}` card**, so it no longer gives a brand-new user the
  default role.
- **The hand-written reference rules are gone.** Generate your rules instead (below). The old README block let
  scope managers update member cards from the client, including their own `roles`; the generated rules allow
  members to update only their own profile fields and leave every other card write to your server.

### New

- `include: ["attributes"]` on `subscribeToUsers` / `subscribeToSystemAdmins` for staff and admins (one extra
  collection-group listener; needs a composite index, see the README).
- `queryMembers` (client and server) to look members up by attribute values.
- `readCustomDoc` / `subscribeToCustomDoc` / `updateCustomDoc` (client) and `getCustomDoc` / `updateCustomDoc`
  (server) for the policy's `customDocs`.
- `lanyard/rules`: `generateFirestoreRules`, `assertFirestoreRulesUpToDate`, and the `lanyard-rules` CLI.

### Upgrading from 0.1.x

1. **Update your policy and stores.** Remove any per-key `read` rules, choose `staffCapability`, `cardVisibility`,
   and `cardFields`, and pass `policy` to every Lanyard store.
2. **Generate your rules.** Add the `// <lanyard-rules>` / `// </lanyard-rules>` markers to `firestore.rules`, run
   `npx lanyard-rules --policy <compiled module> --export <name> --write firestore.rules` (with your collection
   names), and add `assertFirestoreRulesUpToDate` to your tests. Add the composite index if you use
   `include: ["attributes"]` or `queryMembers`.
3. **Migrate existing data** with a one-off Firebase Admin script, one transaction per card, for every user and
   member card:
   - move inline `preferences` into `private/preferences`;
   - move inline `attributes` (except `cardFields.attributes`) and `email` (unless `cardFields.email`) into
     `private/attributes`;
   - stamp `_lanyard: { tier, uid, scopeId, updatedAt }` on every private document (`scopeId` is `null` for
     `users/{uid}` documents);
   - delete the moved fields from the card.

   Do a dry run first, and treat a key present in both places with different values as a conflict to resolve by
   hand. Afterwards, check that no card still holds `preferences`, non-card attributes, or a private `email`.

4. **Deploy** the migrated data, the generated rules, and the 0.2.0 code together, migrating first so 0.2.0 never
   reads cards that still hold inline data.

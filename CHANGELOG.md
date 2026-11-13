# Changelog

## Unreleased

### New

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

- **The Firebase `admin` claim is the only admin authority.** Admin status used to be resolved from the store first
  (`users/{uid}.isSystemAdmin`, then `system_admins`) with the token claim as a fallback, and `checkAuth`/`requireAdmin`
  auto-provisioned an admin record (`syncAdminProfileIfNeeded`) for anyone they judged an admin. Together those let a
  demoted admin's still-valid token re-create their admin record and undo the demotion permanently. Now:
  - `checkAuth` takes `req.user.isAdmin` from the verified token claim (kept current by the revocation checks) and
    never reads or writes admin records; admin status no longer depends on the store being reachable;
  - `requireAdmin` trusts `req.user.isAdmin` only on a `req.user` that `checkAuth` verified; for any other object it asks
    Firebase for the user's current claim (`AdminAuthAdapter.getUser`, newly optional) and fails closed if it can't;
  - actor-based server methods do the same: `actor.isAdmin` on a hand-built actor is ignored in favor of the user's
    current Firebase claim (pass `req.user` to avoid the lookup);
  - `setSystemAdminStatus` demotions bump the revocation epoch after changing the claim, so the demoted user's existing
    `admin: true` tokens are refused as stale immediately.

  Store admin records (`isSystemAdmin`, `system_admins`) remain as a directory for listing admins, written only by
  `setSystemAdminStatus`; they grant nothing. This supersedes the store-based fail-closed admin check from earlier in
  this release: admin checks no longer touch the store at all.

- **`checkAuth` enforces revocations, and requires token times.** It now rejects, before any store lookup:
  - tokens from a session revoked after the user signed in (`auth_time` at or before the user's session revocation):
    `401 { error, code: "auth/session-revoked" }` (`SESSION_REVOKED_ERROR_CODE`); the user must sign in again;
  - tokens issued (`iat`) at or before the revocation epoch: `401 { error, code: "auth/token-stale" }`
    (`TOKEN_STALE_ERROR_CODE`); refreshing the token and retrying is enough.

  Both comparisons allow `REVOCATION_CLOCK_SKEW_MS` (2s) for clock differences and one-second token granularity.
  `AuthenticatedUser` gains `tokenIssuedAtSeconds` and `authTimeSeconds`, which `GoogleAuthService` fills from the
  token; **a custom `AuthService` must provide both**, or `checkAuth` fails closed with 401. Revocation data comes from
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

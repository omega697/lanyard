# Changelog

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

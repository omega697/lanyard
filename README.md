# `lanyard`

**`lanyard`** is a UID-first, user-focused, storage-agnostic authentication, presence tracking, avatar synchronization, and generic role/capability authorization library for TypeScript + Express + Svelte applications.

Like a conference or workplace lanyard, `lanyard` answers two questions everywhere in your stack:

1. **Identity & Presence**: _Who is this user, what is their avatar, and when were they last active?_
2. **Access Passes**: _What roles (`TRole[]`) and role-derived capabilities (`TCapability[]`) do they hold in the current scope (`GLOBAL_SCOPE` or tenant `scopeId`)?_

> [!IMPORTANT]
> **Upgrading from 0.1.x?** 0.2.0 moves preferences, attributes, and email into per-audience tier documents and
> generates your security rules. Existing data must be migrated; see [CHANGELOG.md](./CHANGELOG.md).

---

## Key Features

- **UID-First Identity & Pre-Provisioning**:
  - Uses Firebase Auth `uid` as the primary key across all collections, allowing users to link multiple OAuth providers (Google, Microsoft, GitHub, Magic Email Links) or update their email address without breaking foreign keys.
  - Includes `getOrProvisionUidByEmail()` on the server so applications that import or invite users by email _before_ they have ever signed in can deterministically resolve (or pre-create) a verified `uid` up front.
- **Explicit Scope Unification (`GLOBAL_SCOPE | string`)**:
  - Every role, capability, profile, preference, attribute, hidden attribute, secret, directory subscription, and presence API accepts an explicit `scopeId: ScopeId` (`GLOBAL_SCOPE` for app-wide/single-tenant operations, or a tenant `string` for multi-tenant operations).
  - Making `GLOBAL_SCOPE` explicit prevents accidental omission of a tenant `scopeId` from silently mutating or checking global user state.
- **One Way to Check & Authorize (`actor: LanyardActor`)**:
  - `checkAuth` reconciles `req.user.isAdmin` against live storage (`users/{uid}.isSystemAdmin` and `system_admins/{uid}`) on every request, immediately stripping stale admin claims if an admin was demoted.
  - All server user and property operations accept `actor: LanyardActor` (`{ uid: string; isAdmin?: boolean }`), allowing Express route handlers to pass `actor: req.user!` (or any `LanyardUser`, `UserRecord`, or `ScopedMember`) directly.
- **Unified Generic Multi-Role & Role-Only Capability Policy (`createPermissionPolicy<TRole, TCapability>`)**:
  - **Global System Admin (`admin: true`)**: Checked via Firebase Auth custom claims for zero-read security rules and fast JWT checks, mirrored on `users/{uid}` (`isSystemAdmin: true`) for single-query directory listing, instant revocation checks, avatars, and presence.
  - **Multiple Roles per User (`roles: TRole[]`) & Role-Only Capabilities**: Users and scoped members hold `roles: TRole[]` (one or more concrete roles), and capabilities are granted **exclusively** through roles—never via ad-hoc capability arrays on user documents.
  - **Explicit Role Inheritance (`inherits`) & Abstract Role Groupings (`abstract?: boolean`)**:
    - Each role in `TRole` defines its optional `inherits: readonly TRole[]` (supporting DAGs and sibling roles with cycle detection), implied `capabilities` (`"*"` or `readonly TCapability[]`), and `trackPresence` (`boolean`) in one place.
    - If a user holds role `A` and `A` transitively `inherits` from `B`, then `policy.hasRole(user, "B")` is `true` (`hasAnyRole` and `hasAllRoles` follow the same transitive inheritance).
    - Mark logical capability-bundle roles with `abstract: true` so they are excluded from `policy.assignableRoles` (and `client.getAssignableRoles()`), cannot be included in `defaultRoles`, and cannot be directly assigned to users—while concrete roles that inherit from them inherit all of their capabilities and satisfy `hasRole(user, abstractRole)`.
  - **Role-Based User Management, Role Assignment & Safe Deletion (`userCapabilities`)**:
    - Configure `userCapabilities: { read?: TCapability; write?: TCapability; assignRoles?: TCapability }` so non-admin roles with the appropriate capability can view other users' profiles (`getUser`, `listUsers`), update/delete non-admin users (`updateUserProfile`, `deleteUser`), or assign concrete roles to non-admin users (`updateUserRoles`).
    - Protects `deleteUser({ scopeId, actor, targetUid, confirmTargetEmail })` with case-insensitive `confirmTargetEmail` verification against `targetUid`'s stored email so swapped-UID mistakes are caught before any deletion occurs.
  - **Storage Tiers for Custom User & Member Properties (`preferences`, `attributes`, `hiddenAttributes`, `secrets`)**:
    - Each tier has one **read audience**, because Firestore security rules grant or deny whole documents (they can't hide individual fields). Reads are therefore configured **per tier**, while writes can still be gated **per key**.
    - **Card** (the `users/{uid}` / `{scope}/{scopeId}/members/{uid}` document itself): profile, avatar, presence, and `roles`, i.e. what anyone allowed to know the user exists may see. Scoped card visibility is configurable with `cardVisibility` (`"members"` by default, `"staff"`, or `{ capability }`); the global card follows `userCapabilities.read` (self + system admins by default).
    - **`preferences`** (`TPreferences`): readable and writable only by the user themselves (and system admins). Stored in a dedicated `users/{uid}/private/preferences` (or `{scope}/{scopeId}/members/{uid}/private/preferences`) document, never on the card. Lanyard stamps each private tier document with a `_lanyard: { tier, uid, scopeId, updatedAt }` metadata field (`scopeId` is `null` for global documents), so `_lanyard` is the one name that can't be used as a preference key (writes using it throw).
    - **`attributes`** (`TAttributes`): readable by the user themselves, scope staff (holders of `staffCapability`), and system admins; writable only by system admins or roles holding the per-key write capability in `attributeCapabilities` (e.g., points, badges, quotas). Stored in a dedicated `users/{uid}/private/attributes` (or `{scope}/{scopeId}/members/{uid}/private/attributes`) document. Keys listed in `cardFields.attributes` are placed on the card instead (opt-in exposure to every card reader; moved, never copied). Reads merge both locations, so `getAttributes`, `attributesStore`, and server records have the same shape either way. Pass the same policy to the store (`new FirestoreServerStore({ db, policy })`, `new FirestoreClientStore({ db, policy })`, `new InMemoryLanyardStore({ policy })`) so it knows the placement; `createLanyardServer`/`createLanyardClient` throw if the store and policy disagree.
    - **`hiddenAttributes`** (`THiddenAttributes`): properties _about_ a user that **not even the user themselves can read or write**, readable only by scope staff and system admins, writable per key via `hiddenAttributeCapabilities` (stored in isolated `users/{uid}/private/hiddenAttributes` and `{scope}/{scopeId}/members/{uid}/private/hiddenAttributes` subdocuments).
    - **`secrets`** (`TSecrets`): **Write-only AES-256-GCM encrypted user secrets** (e.g., BYOK AI API keys or personal OAuth tokens). Stored encrypted at rest (`{ ciphertext, iv, tag }`) in `private/secrets`, never readable back out to any client, with boolean status checks (`getUserSecretsStatus`) for the UI and server-only decryption (`getDecryptedUserSecrets(scopeId, uid)`) for backend API calls.
    - **Custom private documents** (`customDocs`): app-defined documents with their own read/write audiences (`self`, `staff`, or a `capability`) for cases the built-in tiers don't cover. Each lives at `…/{uid}/private/{name}` (stamped with `_lanyard: { tier: name, … }`), is read and written through `readCustomDoc` / `subscribeToCustomDoc` / `updateCustomDoc` (client) and `getCustomDoc` / `updateCustomDoc` (server), and is deleted with its user/member.
    - > [!WARNING]
    - **`email`** is private by default: it's stored in the `attributes` tier document (so `email` is a reserved attribute key) and merged back into `UserRecord.email` / `ScopedMember.email` for readers of that tier (the user, staff, admins, and the server). Other readers see `email: ""`. Set `cardFields.email: true` to store it on the card instead. Users change their email through Firebase Auth (`sendEmailUpdateVerification`); once verified, Lanyard syncs the stored copy from the client and the server, and the generated security rules accept a client write only for the owner's own verified email.
  - **Single-Listener Multiplexing**: `FirestoreClientStore` multiplexes `onSnapshot` listeners on `users/{uid}` so repeated subscriptions to the user profile, `attributes`, and admin status only ever open **1 Firestore document listener**. Preferences and private attributes use one more listener each on the user's own `private/preferences` and `private/attributes` documents, plus one of each per scope membership.
- **Smart Avatar Tracking & Fallback Resolution**:
  - **Provider Fallback**: When a user signs up via Magic Email Link (`user.photoURL === null`) and later links Google or GitHub, `normalizeFirebaseUser` automatically extracts their avatar from `user.providerData[].photoURL` and sanitizes the URL.
  - **Pre-Provisioned Member & Admin Sync**: When a user who was pre-provisioned by email (`photoUrl: null`) later signs in with OAuth, both the client (`createLanyardClient`) and server middleware (`requireAdmin`, `requireRole`, `requireCapability`) automatically sync their `photoUrl` to their existing member/admin record (deduplicated per session).
  - **Pure Avatar Helpers (`resolveAvatar`, `resolveAvatarUrl`, `getAvatarInitials`)**: Prevents active-user avatar bleed when viewing other users and computes 1–2 Unicode-safe initials, display names, and deterministic badge color indices.
- **Storage-Agnostic Architecture**:
  - Core client and server engines operate against clean `LanyardClientStore` and `LanyardServerStore` interfaces with **zero** direct Firestore imports.
  - Ships with **`FirestoreClientStore`** (`/client/firestore`), **`FirestoreServerStore`** (`/server/firestore`), and **`InMemoryLanyardStore`** (`/core`)—and allows any consumer to supply a custom storage adapter (PostgreSQL, SQLite, Data Connect, REST, etc.).
- **Headless Svelte Ergonomics**:
  - Exposes state via lightweight `{ subscribe, get }` stores that work natively with Svelte's `$store` reactive syntax without requiring `svelte` as a runtime dependency.
- **Throttled Presence Heartbeats**:
  - Built-in `localStorage`-throttled 5-minute heartbeat (`HEARTBEAT_INTERVAL_MS`) with tab-unload flushing, gated by each role's `trackPresence` setting (and always enabled for system admins).

---

## Package Entrypoints

| Import Path                | Environment    | Description                                                                                                                                                                                                                                                                                     |
| :------------------------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lanyard/core`             | Universal      | Generic types (`TRole`, `TCapability`, `GLOBAL_SCOPE`, `ScopeId`, `LanyardActor`), `createPermissionPolicy`, avatar/time formatters (`resolveAvatar`, `formatLastSeen`), observable store, and `InMemoryLanyardStore`. Zero runtime dependencies.                                               |
| `lanyard/client`           | Browser        | Multi-provider OAuth, Passwordless Magic Email Link, Account Linking, reactive stores, self-service `updatePreferences` / `updateProfile`, directory subscriptions (`subscribeToUsers`), deduplicated avatar sync, and presence tracker.                                                        |
| `lanyard/client/firestore` | Browser        | `FirestoreClientStore` implementation of `LanyardClientStore` (peer dependency: `firebase` `^11.0.0 \|\| ^12.0.0 \|\| ^13.0.0`).                                                                                                                                                                |
| `lanyard/server`           | Node / Express | `GoogleAuthService`, Express middleware (`checkAuth`, `requireAdmin`, `requireRole`, `requireCapability`), UID/role provisioning, and capability-gated `attributes`/`hiddenAttributes`/`secrets`/user management with `actor: LanyardActor` (peer dependency: `express` `^4.18.0 \|\| ^5.0.0`). |
| `lanyard/server/firestore` | Node / Express | `FirestoreServerStore` implementation of `LanyardServerStore` (peer dependency: `firebase-admin` `^13.0.0 \|\| ^14.0.0`).                                                                                                                                                                       |
| `lanyard/rules`            | Build / Test   | `generateFirestoreRules(policy, options)`: Firestore security rules for every Lanyard tier, custom doc, and collection-group query, generated from your `PermissionPolicy`, plus `assertFirestoreRulesUpToDate` and the `lanyard-rules` CLI. Zero runtime dependencies.                         |

---

## Installation

### From GitHub (Recommended for CI & Multi-Machine Consistency)

Use `git+https://` so `package-lock.json` always records an HTTPS URL that works seamlessly across developer machines, GitHub Actions (`npm ci`), and Cloud Run builds:

```json
{
  "dependencies": {
    "lanyard": "git+https://github.com/omega697/lanyard.git#main"
  }
}
```

To pull the latest `lanyard` updates into a consuming project and update `package-lock.json`:

```bash
npm update lanyard
```

---

## Usage Guide

### 1. Defining Roles, Capabilities & Presence Policy (`lanyard/core`)

Define your application's `TRole` and `TCapability` types once in a shared module and configure your `PermissionPolicy`:

```ts
import { createPermissionPolicy, resolveAvatar, type ScopedMember } from "lanyard/core";

export type WorkspaceRole = "base_staff" | "owner" | "manager" | "billing_manager" | "member";
export type WorkspaceCapability = "edit_content" | "invite_members" | "assign_roles" | "billing";

export const workspacePolicy = createPermissionPolicy<WorkspaceRole, WorkspaceCapability>({
  roles: {
    base_staff: {
      abstract: true, // Abstract role: groups capabilities & presence, never directly assigned or shown in UI
      capabilities: ["edit_content"],
      trackPresence: true
    },
    owner: {
      inherits: ["manager", "billing_manager"],
      capabilities: "*", // Owners automatically hold all capabilities
      trackPresence: true
    },
    manager: {
      inherits: ["base_staff", "member"],
      capabilities: ["invite_members", "assign_roles"] // Inherits 'edit_content' + trackPresence from 'base_staff'
    },
    billing_manager: {
      inherits: ["base_staff", "member"],
      capabilities: ["billing"]
    },
    member: {
      capabilities: []
    }
  },
  defaultRoles: ["member"],
  userCapabilities: {
    read: "edit_content", // Roles with 'edit_content' can view other users' profiles
    write: "invite_members", // Roles with 'invite_members' can update/delete non-admin users
    assignRoles: "assign_roles" // Roles with 'assign_roles' can update non-admin users' roles
  },
  // Scope staff: holders of 'invite_members' (manager, owner) can read members' attributes & hiddenAttributes tiers
  staffCapability: "invite_members",
  // Who can read scoped member cards: "members" (default), "staff", or { capability }
  cardVisibility: "members",
  // Opt-in: store these attributes on the card so every card reader can see them (moved, never copied)
  cardFields: { attributes: ["badges"] },
  attributeCapabilities: {
    pointsAllTime: "edit_content" // Per-key WRITE rule; reads follow the attributes tier (self + staff + admins)
  },
  hiddenAttributeCapabilities: {
    internalNotes: { write: "edit_content" } // Per-key WRITE rule; reads follow the hiddenAttributes tier (staff + admins)
  },
  secretCapabilities: {
    geminiKey: { allowSelfWrite: true }, // User-owned write-only encrypted secret
    workspaceOpenaiKey: { write: "billing", allowSelfWrite: false } // Role-gated write-only encrypted user secret
  },
  // App-defined private documents with their own audiences (names may not reuse built-in tier names)
  customDocs: {
    shiftNotes: { read: { self: true, staff: true }, write: { capability: "edit_content" } }
  }
});

const manager: ScopedMember<WorkspaceRole, WorkspaceCapability> = {
  uid: "user-1",
  email: "manager@example.com",
  firstName: "Accenty",
  lastName: "McÉccent",
  roles: ["manager"]
};

workspacePolicy.assignableRoles; // ["owner", "manager", "billing_manager", "member"] ('base_staff' is excluded)
workspacePolicy.hasRole(manager, "manager"); // true (direct role)
workspacePolicy.hasRole(manager, "base_staff"); // true (transitively inherited abstract role!)
workspacePolicy.hasRole(manager, "member"); // true (transitively inherited concrete role!)
workspacePolicy.hasCapability(manager, "invite_members"); // true (from 'manager')
workspacePolicy.hasCapability(manager, "edit_content"); // true (inherited from 'base_staff')
workspacePolicy.hasCapability(manager, "billing"); // false (neither held nor inherited)
workspacePolicy.shouldTrackPresence(manager); // true (inherited from 'base_staff')

// Storage-tier reads (per tier, not per key):
workspacePolicy.isStaff(manager); // true (holds staffCapability 'invite_members')
workspacePolicy.canReadTier(manager, "attributes"); // true (scope staff)
workspacePolicy.canReadTier(manager, "preferences"); // false (another user's preferences: self + admins only)
workspacePolicy.canReadTier(manager, "card", { isScopeMember: true }); // true (cardVisibility: "members")
workspacePolicy.canReadAttribute(manager, "badges", { canReadCard: true }); // true (placed on the card)
workspacePolicy.canReadCustomDoc(manager, "shiftNotes"); // true (staff)

// Resolve avatar URL, Unicode-safe initials ("AM"), displayName ("Accenty McÉccent"), and badge color index (0..7)
const avatar = resolveAvatar(manager);
```

---

### 2. Browser Setup (`lanyard/client` + `/client/firestore`)

```ts
import { auth, db } from "./firebase.js";
import { createLanyardClient, GLOBAL_SCOPE } from "lanyard/client";
import { FirestoreClientStore } from "lanyard/client/firestore";
import { workspacePolicy, type WorkspaceRole, type WorkspaceCapability } from "../core/policy.js";

export interface UserPrefs {
  themePreference: "light" | "dark" | "system";
  use12h: boolean;
}

const store = new FirestoreClientStore<WorkspaceRole, WorkspaceCapability, UserPrefs>({
  db,
  policy: workspacePolicy, // Field placement (cardFields) must match the client's policy
  defaultRoles: workspacePolicy.defaultRoles,
  scopeCollection: "workspaces",
  membersSubcollection: "members"
});

export const lanyard = createLanyardClient<WorkspaceRole, WorkspaceCapability, UserPrefs>({
  auth,
  store,
  policy: workspacePolicy,
  storageKeyPrefix: "myapp",
  defaultPreferences: {
    themePreference: "system",
    use12h: true
  },
  // Optional: notified once per verified email change ({ uid, email, previousEmail }) before users/{uid}.email is updated
  onVerifiedEmailChange: async ({ uid, email, previousEmail }) => {
    console.log(`User ${uid} changed verified email from ${previousEmail} to ${email}`);
  }
});

// In a Svelte component, use native $store syntax directly:
// const { authStore, userRecordStore, attributesStore, membershipsStore, preferencesStore } = lanyard;
// $: currentUser = $authStore.user;
// $: workspaces = $membershipsStore.memberships;
```

#### Unified Client Accessors & Field-Level Permission Helpers (`GLOBAL_SCOPE | string`)

All role, capability, preference, profile, attribute, directory, and field-level permission methods on `createLanyardClient` take an explicit `scopeId: ScopeId` (`GLOBAL_SCOPE` for app-wide/single-tenant or a tenant `string` for multi-tenant):

```ts
// Role & capability checks:
const globalRoles = lanyard.getRoles(GLOBAL_SCOPE);
const workspaceRoles = lanyard.getRoles(activeWorkspaceId);
const assignableRoleOptions = lanyard.getAssignableRoles(); // Concrete (!abstract) roles for UI dropdowns

const isManager = lanyard.hasRole("manager", activeWorkspaceId); // True if user holds 'manager' or 'owner' (which inherits 'manager')
const isStaff = lanyard.hasRole("base_staff", activeWorkspaceId); // True for any role inheriting from abstract 'base_staff'
const canInvite = lanyard.hasCapability("invite_members", activeWorkspaceId);
const canEditOrBill = lanyard.hasAnyCapability(["edit_content", "billing"], activeWorkspaceId);
const canAssignUserRoles = lanyard.canAssignRoles(activeWorkspaceId);

// Preferences, Profile & Attributes (GLOBAL_SCOPE or tenant scopeId):
const globalPrefs = lanyard.getPreferences(GLOBAL_SCOPE);
const workspacePrefs = lanyard.getPreferences(activeWorkspaceId);
await lanyard.updatePreferences(GLOBAL_SCOPE, { themePreference: "dark" });
await lanyard.updatePreferences(activeWorkspaceId, { use12h: false });

await lanyard.updateProfile(GLOBAL_SCOPE, { firstName: "Jane", lastName: "Doe" });
await lanyard.updateProfile(activeWorkspaceId, { firstName: "Jane", lastName: "Doe" });

const globalAttrs = lanyard.getAttributes(GLOBAL_SCOPE);
const workspaceAttrs = lanyard.getAttributes(activeWorkspaceId);

// Field-level UI permission checks across all 4 custom property tiers
// (attribute reads are per tier: self, staff, admins, plus card readers for card-placed keys):
const canSeeTheirPoints = lanyard.canReadAttribute(activeWorkspaceId, "pointsAllTime", { isSelf: false });
const canEditPoints = lanyard.canWriteAttribute(activeWorkspaceId, "pointsAllTime");
const canViewNotes = lanyard.canReadHiddenAttribute(activeWorkspaceId, "internalNotes"); // staff + admins
const canEditNotes = lanyard.canWriteHiddenAttribute(activeWorkspaceId, "internalNotes");
const canConfigureGeminiKey = lanyard.canWriteSecret(activeWorkspaceId, "geminiKey");

// Indexed subscription to active system administrators (`where("isSystemAdmin", "==", true)` in Firestore):
const unsubAdmins = lanyard.subscribeToSystemAdmins((admins) => {
  console.log("System admins:", admins);
});

// Rosters and directories carry only card fields by default (other users' private email is ""). Staff and
// system admins can merge in each member's `attributes` tier, including private emails:
const unsubRoster = lanyard.subscribeToUsers(
  activeWorkspaceId,
  (members) => console.log(members.map((m) => [m.email, m.attributes])),
  { include: ["attributes"] } // throws for callers who aren't staff in this scope (or admins)
);
```

Staff can also look members up by attribute values without loading the roster. Filters on `attributes`-tier keys
require staff access; filters on card-placed keys (`cardFields.attributes`) require card access, and the two
can't be mixed in one query. The server has the same API (`lanyardServer.queryMembers({ scopeId, actor, attributes })`):

```typescript
const uids = await lanyard.queryMembers(activeWorkspaceId, { attributes: { canvasserId: "c-123" } });
```

With Firestore, each combination of filtered attributes-tier keys needs a collection-group index on `private`
over `_lanyard.tier`, `_lanyard.scopeId`, and the filtered keys (Firestore's error message links to create it).

App-defined custom documents (`customDocs`) are read and written with the audiences their policy entry grants
(the client checks them up front; security rules must enforce the same audiences):

```typescript
// customDocs: { shiftNotes: { read: { self: true, staff: true }, write: { staff: true } } }
await lanyard.updateCustomDoc(activeWorkspaceId, "shiftNotes", memberUid, { note: "Great shift!" }); // staff
const myNotes = await lanyard.readCustomDoc(activeWorkspaceId, "shiftNotes"); // the member themselves
const unsubNotes = lanyard.subscribeToCustomDoc(activeWorkspaceId, "shiftNotes", memberUid, (notes) => {});
```

> [!NOTE]
> With `FirestoreClientStore`, `include: ["attributes"]` adds a single collection-group listener on `private`
> (`_lanyard.tier == "attributes"` and `_lanyard.scopeId == scopeId`, or `null` for global users). It needs this
> composite index in `firestore.indexes.json`, plus the collection-group `list` rule that `generateFirestoreRules` emits (see section 5):
>
> ```json
> {
>   "collectionGroup": "private",
>   "queryScope": "COLLECTION_GROUP",
>   "fields": [
>     { "fieldPath": "_lanyard.tier", "order": "ASCENDING" },
>     { "fieldPath": "_lanyard.scopeId", "order": "ASCENDING" }
>   ]
> }
> ```

#### Authentication & Magic Links

```ts
// Social OAuth (Google, Microsoft, GitHub)
await lanyard.loginWithSocialProvider("google");

// Passwordless Magic Email Link
await lanyard.sendPasswordlessEmailLink("user@example.com");
// On redirect landing page (also auto-detected on boot):
await lanyard.completePasswordlessSignIn();

// Account Linking
await lanyard.linkSocialProvider("github");
```

#### Presence Tracking

```ts
// Automatically records user activity and syncs to the backing store at most once every 5 minutes
// for system admins and roles with trackPresence: true in workspacePolicy
const stopHeartbeat = lanyard.startPresenceHeartbeat(activeWorkspaceId); // or GLOBAL_SCOPE

// Flush unsynced activity on page unload:
window.addEventListener("beforeunload", () => {
  lanyard.syncPresence(activeWorkspaceId, { isUnloading: true });
});
```

---

### 3. Express Backend Setup (`lanyard/server` + `/server/firestore`)

```ts
import express from "express";
import { adminAuth, db } from "./firestoreAdmin.js";
import { createLanyardServer, GLOBAL_SCOPE, type AuthenticatedRequest } from "lanyard/server";
import { FirestoreServerStore } from "lanyard/server/firestore";
import { workspacePolicy, type WorkspaceRole, type WorkspaceCapability } from "../core/policy.js";

const store = new FirestoreServerStore<WorkspaceRole, WorkspaceCapability>({
  db,
  policy: workspacePolicy, // Field placement (cardFields) must match the server's policy
  defaultRoles: workspacePolicy.defaultRoles,
  scopeCollection: "workspaces",
  membersSubcollection: "members",
  encryptionKey: process.env.LANYARD_ENCRYPTION_KEY // Master key for AES-256-GCM encrypted secrets
});

export const lanyardServer = createLanyardServer<WorkspaceRole, WorkspaceCapability>({
  adminAuth,
  store,
  policy: workspacePolicy,
  defaultScopeParam: "workspaceId",
  // Optional: notified in checkAuth when an authenticated user's verified token email differs from users/{uid}.email
  onVerifiedEmailChange: async ({ uid, email, previousEmail }) => {
    console.log(`Server synced verified email change for ${uid}: ${previousEmail} -> ${email}`);
  }
});

const router = express.Router();

// Single-tenant route protection (checks users/{uid} using explicit GLOBAL_SCOPE):
router.post(
  "/events/scan",
  lanyardServer.checkAuth,
  lanyardServer.requireCapability("edit_content", GLOBAL_SCOPE),
  async (req, res) => {
    res.json({ ok: true });
  }
);

// Multi-tenant route protection by role (includes concrete or abstract roles via transitive inheritance):
router.put(
  "/workspaces/:workspaceId/settings",
  lanyardServer.checkAuth,
  lanyardServer.requireRole("manager", { param: "workspaceId" }),
  async (req, res) => {
    res.json({ ok: true });
  }
);

// Multi-tenant route protection by capability:
router.post(
  "/workspaces/:workspaceId/invitations",
  lanyardServer.checkAuth,
  lanyardServer.requireCapability("invite_members", { param: "workspaceId" }),
  async (req: AuthenticatedRequest, res) => {
    res.json({ invitedBy: req.user!.uid });
  }
);
```

#### Pre-Provisioning Users & Granting Multiple Roles by Email (`GLOBAL_SCOPE | string`)

When adding a user by email (e.g., via CSV import or an invite form) before they have ever signed in:

```ts
// Single-tenant user provisioning / additive role grants on users/{uid}:
const user = await lanyardServer.grantRolesByEmail({
  scopeId: GLOBAL_SCOPE,
  email: "collaborator@example.com",
  firstName: "Accenty",
  lastName: "McÉccent",
  roles: ["manager"]
});

// Multi-tenant member provisioning / additive role grants on workspaces/{workspaceId}/members/{uid}
// without overwriting any other roles (such as 'billing_manager') they already hold:
const member = await lanyardServer.grantRolesByEmail({
  scopeId: workspaceId,
  email: "collaborator@example.com",
  firstName: "Accenty",
  lastName: "McÉccent",
  roles: ["manager"],
  scopeName: "Acme Workspace"
});
```

#### Managing `attributes`, `hiddenAttributes`, Encrypted `secrets`, and Users (`actor: LanyardActor`)

Because `checkAuth` reconciles `req.user.isAdmin` against live storage on every request, route handlers simply pass `actor: req.user!` directly into `lanyardServer` operations:

```ts
// 1. attributes (readable by self, scope staff, and system admins; per-key capability-gated writes).
//    Other callers receive only keys placed on the card via cardFields.attributes:
await lanyardServer.updateUserAttributes({
  scopeId: GLOBAL_SCOPE, // or workspaceId
  actor: req.user!,
  targetUid: attendeeUid,
  patch: { pointsAllTime: 150 }
});
const visibleAttrs = await lanyardServer.readUserAttributes({
  scopeId: GLOBAL_SCOPE,
  actor: req.user!,
  targetUid: attendeeUid
});

// 2. hiddenAttributes (stored in private/hiddenAttributes; hidden from the target user; readable by staff + admins):
await lanyardServer.updateUserHiddenAttributes({
  scopeId: GLOBAL_SCOPE,
  actor: req.user!,
  targetUid: attendeeUid,
  patch: { internalNotes: "Verified badge at registration desk" }
});
const visibleHidden = await lanyardServer.readUserHiddenAttributes({
  scopeId: GLOBAL_SCOPE,
  actor: req.user!,
  targetUid: attendeeUid
});

// 3. secrets (write-only AES-256-GCM encrypted in private/secrets; pass "" or null to delete a key):
const secretStatus = await lanyardServer.updateUserSecrets({
  scopeId: GLOBAL_SCOPE, // or workspaceId for per-scope user secrets
  actor: req.user!,
  targetUid: req.user!.uid,
  patch: { geminiKey: "AIzaSy..." }
}); // Returns { geminiKey: true } — never the plaintext or ciphertext!

// Decrypt on the server only when making an outbound API call:
const decrypted = await lanyardServer.getDecryptedUserSecrets(GLOBAL_SCOPE, req.user!.uid);

// 4. Role-based user management, role assignment, & email-confirmed user deletion:
const targetProfile = await lanyardServer.getUser({
  scopeId: GLOBAL_SCOPE,
  actor: req.user!,
  targetUid: attendeeUid
});
await lanyardServer.updateUserProfile({
  scopeId: GLOBAL_SCOPE,
  actor: req.user!,
  targetUid: attendeeUid,
  patch: { firstName: "Updated", lastName: "Name" }
});
await lanyardServer.updateUserRoles({
  scopeId: GLOBAL_SCOPE,
  actor: req.user!,
  targetUid: attendeeUid,
  roles: ["manager", "billing_manager"] // Concrete roles only; abstract roles are rejected
});
// Deleting a user (self or another user) verifies confirmTargetEmail matches targetUid's email:
await lanyardServer.deleteUser({
  scopeId: GLOBAL_SCOPE,
  actor: req.user!,
  targetUid: attendeeUid,
  confirmTargetEmail: "attendee@example.com"
});
```

---

### 4. Supplying a Custom Storage Implementation

To use `lanyard` with a non-Firestore database (PostgreSQL, SQLite, REST, etc.), implement `LanyardClientStore` and/or `LanyardServerStore` from `lanyard/core`:

```ts
import type {
  EncryptedSecretMap,
  LanyardServerStore,
  LanyardUserRecord,
  ScopedMember,
  SystemAdminProfile
} from "lanyard/core";

class PostgresServerStore<
  TRole extends string = string,
  TCapability extends string = string,
  TPreferences extends Record<string, any> = Record<string, any>,
  TAttributes extends Record<string, any> = Record<string, any>,
  THiddenAttributes extends Record<string, any> = Record<string, any>
> implements LanyardServerStore<TRole, TCapability, TPreferences, TAttributes, THiddenAttributes> {
  // System Admin methods
  async getSystemAdmin(uid: string): Promise<SystemAdminProfile | null> {
    /* ... */
  }
  async listSystemAdmins(): Promise<SystemAdminProfile[]> {
    /* ... */
  }
  async upsertSystemAdmin(profile: SystemAdminProfile): Promise<void> {
    /* ... */
  }
  async deleteSystemAdmin(uid: string): Promise<void> {
    /* ... */
  }

  // Unscoped (Single-Tenant) User methods
  async getUser(uid: string): Promise<LanyardUserRecord<TRole, TCapability, TPreferences, TAttributes> | null> {
    /* ... */
  }
  async listUsers(): Promise<LanyardUserRecord<TRole, TCapability, TPreferences, TAttributes>[]> {
    /* ... */
  }
  async upsertUser(user: LanyardUserRecord<TRole, TCapability, TPreferences, TAttributes>): Promise<void> {
    /* ... */
  }
  async grantUserRoles(
    uid: string,
    roles: readonly TRole[],
    fallback?: Omit<LanyardUserRecord<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<LanyardUserRecord<TRole, TCapability, TPreferences, TAttributes>> {
    /* ... */
  }
  async revokeUserRoles(uid: string, roles: readonly TRole[]): Promise<void> {
    /* ... */
  }
  async deleteUser(uid: string): Promise<void> {
    /* ... */
  }

  // Scoped (Multi-Tenant) Member methods
  async getScopeMember(
    scopeId: string,
    uid: string
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes> | null> {
    /* ... */
  }
  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>[]> {
    /* ... */
  }
  async upsertScopeMember(
    scopeId: string,
    member: ScopedMember<TRole, TCapability, TPreferences, TAttributes>
  ): Promise<void> {
    /* ... */
  }
  async grantScopeRoles(
    scopeId: string,
    uid: string,
    roles: readonly TRole[],
    fallback?: Omit<ScopedMember<TRole, TCapability, TPreferences, TAttributes>, "roles">
  ): Promise<ScopedMember<TRole, TCapability, TPreferences, TAttributes>> {
    /* ... */
  }
  async revokeScopeRoles(scopeId: string, uid: string, roles: readonly TRole[]): Promise<void> {
    /* ... */
  }
  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    /* ... */
  }

  // Hidden Attributes & Encrypted User Secrets methods
  async getUserHiddenAttributes(uid: string): Promise<Partial<THiddenAttributes>> {
    /* ... */
  }
  async updateUserHiddenAttributes(
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    /* ... */
  }
  async getScopeMemberHiddenAttributes(scopeId: string, uid: string): Promise<Partial<THiddenAttributes>> {
    /* ... */
  }
  async updateScopeMemberHiddenAttributes(
    scopeId: string,
    uid: string,
    patch: Partial<THiddenAttributes>
  ): Promise<Partial<THiddenAttributes>> {
    /* ... */
  }
  async getUserSecrets(uid: string): Promise<EncryptedSecretMap> {
    /* ... */
  }
  async updateUserSecrets(uid: string, patch: EncryptedSecretMap): Promise<EncryptedSecretMap> {
    /* ... */
  }
  async getScopeMemberSecrets(scopeId: string, uid: string): Promise<EncryptedSecretMap> {
    /* ... */
  }
  async updateScopeMemberSecrets(scopeId: string, uid: string, patch: EncryptedSecretMap): Promise<EncryptedSecretMap> {
    /* ... */
  }
}
```

For unit tests, use the built-in **`InMemoryLanyardStore<TRole, TCapability, TPreferences>`** from `lanyard/core`, which implements both `LanyardClientStore` and `LanyardServerStore` out of the box with zero mocks required.

---

### 5. Firestore Security Rules (generated from your policy)

Generate the rules for everything Lanyard stores from the same `PermissionPolicy` your app uses, so they always
match the storage tiers, `cardFields`, `cardVisibility`, `staffCapability`, and `customDocs`:

```typescript
import { generateFirestoreRules } from "lanyard/rules";
import { workspacePolicy } from "./policy.js";

const lanyardRules = generateFirestoreRules(workspacePolicy, {
  usersCollection: "users", // must match the collections passed to the Firestore stores
  scopeCollection: "workspaces",
  membersSubcollection: "members"
});
```

Place the generated block between marker comments inside `match /databases/{database}/documents { … }` in
`firestore.rules`, next to your app's own rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // <lanyard-rules>
    // </lanyard-rules>

    match /appData/{docId} { /* your rules */ }
  }
}
```

Then fill (or refresh) the block with the CLI, pointing it at your compiled policy module:

```bash
npx lanyard-rules --policy ./dist/policy.js --export workspacePolicy --scopes workspaces --write firestore.rules
npx lanyard-rules --policy ./dist/policy.js --export workspacePolicy --scopes workspaces --check firestore.rules
```

and keep it from going stale by checking it in your tests:

```typescript
import { readFileSync } from "node:fs";
import { assertFirestoreRulesUpToDate } from "lanyard/rules";

it("keeps the Lanyard rules in firestore.rules in sync with the policy", () => {
  assertFirestoreRulesUpToDate(readFileSync("firestore.rules", "utf8"), workspacePolicy, {
    scopeCollection: "workspaces"
  });
});
```

The generated block contains:

- Helper functions (`isOwner`, `isAdmin`, `isScopeMember`, `hasScopeRole`, `hasUserRole`, `isTierDoc`,
  `isOwnVerifiedEmailWrite`). Role checks use `get()` without a preceding `exists()` so Firestore caches the single
  document read across a query.
- **Cards** (`users/{uid}`, `{scope}/{scopeId}/members/{uid}`): readable per `userCapabilities.read` (global) and
  `cardVisibility` (scoped). Owners may update only their own profile fields (`firstName`, `lastName`,
  `displayName`, `photoUrl`, `lastSeen`, plus `email` when `cardFields.email` is set); roles, attributes, and
  memberships are written by your server through the Admin SDK (or by system admins).
- **Private tiers**: self-only `preferences` (stamped with `_lanyard` metadata), self + staff `attributes`
  (server-written, except owners syncing their own verified email), staff-only `hiddenAttributes`, server-only
  `secrets`, and one block per `customDocs` entry with its read/write audiences.
- **Collection-group rules** for listing your own memberships and for staff listing a scope's attributes tiers
  (`include: ["attributes"]`, `queryMembers`).

> [!IMPORTANT]
> Firestore rules can't evaluate role inheritance or capabilities, so the generator expands each capability-based
> audience into the roles that hold it (e.g. `staffCapability: "manage_members"` becomes
> `hasScopeRole(scopeId, ['lead', 'owner'])`). **Regenerate the rules whenever roles or capabilities change**;
> `assertFirestoreRulesUpToDate` (or `lanyard-rules --check`) fails until you do.

Lanyard's own emulator tests run against generated rules, covering every tier, custom documents, the
collection-group queries, and the `cardVisibility` modes.

---

## Development & Testing

```bash
# Run unit tests + real Firebase Auth & Cloud Firestore Emulator integration tests
npm test

# Typecheck
npm run typecheck

# Build dist/
npm run build

# Format source files
npm run format
```

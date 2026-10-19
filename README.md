# `lanyard`

**`lanyard`** is a UID-first, storage-agnostic authentication, presence tracking, avatar synchronization, and generic role/capability authorization library for TypeScript + Express + Svelte applications.

Like a conference or workplace lanyard, `lanyard` answers two questions everywhere in your stack:

1. **Identity & Presence**: _Who is this user, what is their avatar, and when were they last active?_
2. **Access Passes**: _What role (`TRole`) and orthogonal capabilities (`TCapability[]`) do they hold in the current workspace?_

---

## Key Features

- **UID-First Identity & Pre-Provisioning**:
  - Uses Firebase Auth `uid` as the primary key across all collections, allowing users to link multiple OAuth providers (Google, Microsoft, GitHub, Magic Email Links) or update their email address without breaking foreign keys.
  - Includes `getOrProvisionUidByEmail()` on the server so applications that import or invite users by email _before_ they have ever signed in can deterministically resolve (or pre-create) a verified `uid` up front.
- **Unified Generic Role & Capability Policy (`createPermissionPolicy<TRole, TCapability>`)**:
  - **Global System Admin (`admin: true`)**: Checked via Firebase Auth custom claims for zero-read security rules and fast JWT checks, mirrored in `system_admins/{uid}` for directory listing, avatars, and presence.
  - **Per-Role Definition (`roles`)**: Zero hardcoded role or capability names. Each role in `TRole` defines its hierarchy `weight`, its implied `capabilities` (`"*"` or `readonly TCapability[]`), and `trackPresence` (`boolean`) in one place.
  - **Per-Member Explicit Capabilities**: Alongside capabilities implied by a user's `role`, each `ScopedMember<TRole, TCapability>` can be granted additional capabilities in `capabilities: TCapability[]` (e.g., a `"member"` granted both `["edit_content", "invite_members"]`).
- **Smart Avatar Tracking & Fallback Resolution**:
  - **Provider Fallback**: When a user signs up via Magic Email Link (`user.photoURL === null`) and later links Google or GitHub, `normalizeFirebaseUser` automatically extracts their avatar from `user.providerData[].photoURL` and sanitizes the URL.
  - **Pre-Provisioned Member & Admin Sync**: When a user who was pre-provisioned by email (`photoUrl: null`) later signs in with OAuth, both the client (`createLanyardClient`) and server middleware (`requireAdmin`, `requireScopeRole`, `requireScopeCapability`) automatically sync their `photoUrl` to their existing member/admin record (deduplicated per session).
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

| Import Path                | Environment    | Description                                                                                                                                                                                                   |
| :------------------------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `lanyard/core`             | Universal      | Generic types (`TRole`, `TCapability`), `createPermissionPolicy`, avatar/time formatters (`resolveAvatar`, `formatLastSeen`), observable store, and `InMemoryLanyardStore`. Zero runtime dependencies.        |
| `lanyard/client`           | Browser        | Multi-provider OAuth, Passwordless Magic Email Link, Anonymous sign-in, Account Linking, reactive stores, deduplicated avatar sync, and presence tracker.                                                     |
| `lanyard/client/firestore` | Browser        | `FirestoreClientStore` implementation of `LanyardClientStore` (peer dependency: `firebase`).                                                                                                                  |
| `lanyard/server`           | Node / Express | `GoogleAuthService`, emulator `FakeAuthService` (with production safeguard), Express middleware (`checkAuth`, `requireAdmin`, `requireScopeRole`, `requireScopeCapability`), and UID/capability provisioning. |
| `lanyard/server/firestore` | Node / Express | `FirestoreServerStore` implementation of `LanyardServerStore` (peer dependency: `firebase-admin`).                                                                                                            |

---

## Installation

### From GitHub

```json
{
  "dependencies": {
    "lanyard": "github:omega697/lanyard#main"
  }
}
```

### Local Development (`file:` or `npm link`)

```bash
npm link ../lanyard
```

---

## Usage Guide

### 1. Defining Roles, Capabilities & Presence Policy (`lanyard/core`)

Define your application's `TRole` and `TCapability` types once in a shared module and configure your `PermissionPolicy`:

```ts
import { createPermissionPolicy, resolveAvatar, type ScopedMember } from "lanyard/core";

export type WorkspaceRole = "owner" | "manager" | "member";
export type WorkspaceCapability = "edit_content" | "invite_members" | "billing";

export const workspacePolicy = createPermissionPolicy<WorkspaceRole, WorkspaceCapability>({
  roles: {
    owner: {
      weight: 30,
      capabilities: "*", // Owners automatically hold all capabilities
      trackPresence: true
    },
    manager: {
      weight: 20,
      capabilities: ["edit_content", "invite_members"], // Managers automatically get 'edit_content' + 'invite_members'
      trackPresence: true
    },
    member: {
      weight: 10,
      capabilities: [], // Members only hold capabilities explicitly listed in member.capabilities
      trackPresence: false
    }
  },
  defaultRole: "member"
});

const manager: ScopedMember<WorkspaceRole, WorkspaceCapability> = {
  uid: "user-1",
  email: "manager@example.com",
  firstName: "Accenty",
  lastName: "McÉccent",
  role: "manager",
  capabilities: []
};

workspacePolicy.hasMinimumRole(manager, "manager"); // true
workspacePolicy.hasCapability(manager, "invite_members"); // true (implied by 'manager' role)
workspacePolicy.hasCapability(manager, "billing"); // false (neither implied nor explicitly granted)
workspacePolicy.shouldTrackPresence(manager); // true

// Resolve avatar URL, Unicode-safe initials ("AM"), displayName ("Accenty McÉccent"), and badge color index (0..7)
const avatar = resolveAvatar(manager);
```

---

### 2. Browser Setup (`lanyard/client` + `/client/firestore`)

```ts
import { auth, db } from "./firebase.js";
import { createLanyardClient } from "lanyard/client";
import { FirestoreClientStore } from "lanyard/client/firestore";
import { workspacePolicy, type WorkspaceRole, type WorkspaceCapability } from "../core/policy.js";

export interface UserPrefs {
  themePreference: "light" | "dark" | "system";
  use12h: boolean;
}

const store = new FirestoreClientStore<WorkspaceRole, WorkspaceCapability, UserPrefs>({
  db,
  defaultRole: workspacePolicy.defaultRole,
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
  }
});

// In a Svelte component, use native $store syntax directly:
// const { authStore, membershipsStore, preferencesStore } = lanyard;
// $: currentUser = $authStore.user;
// $: workspaces = $membershipsStore.memberships;
```

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
const stopHeartbeat = lanyard.startPresenceHeartbeat({ scopeId: activeWorkspaceId });

// Flush unsynced activity on page unload:
window.addEventListener("beforeunload", () => {
  lanyard.syncPresence({ scopeId: activeWorkspaceId, isUnloading: true });
});
```

---

### 3. Express Backend Setup (`lanyard/server` + `/server/firestore`)

```ts
import express from "express";
import { adminAuth, db } from "./firestoreAdmin.js";
import { createLanyardServer } from "lanyard/server";
import { FirestoreServerStore } from "lanyard/server/firestore";
import { workspacePolicy, type WorkspaceRole, type WorkspaceCapability } from "../core/policy.js";

const store = new FirestoreServerStore<WorkspaceRole, WorkspaceCapability>({
  db,
  defaultRole: workspacePolicy.defaultRole,
  scopeCollection: "workspaces",
  membersSubcollection: "members"
});

export const lanyardServer = createLanyardServer<WorkspaceRole, WorkspaceCapability>({
  adminAuth,
  store,
  policy: workspacePolicy,
  defaultScopeParam: "workspaceId"
});

const router = express.Router();

// Protect routes by hierarchical role tier ('owner' | 'manager' | 'member')
router.put(
  "/workspaces/:workspaceId/settings",
  lanyardServer.checkAuth,
  lanyardServer.requireScopeRole("manager"),
  async (req, res) => {
    res.json({ ok: true });
  }
);

// Protect routes by capability (roles whose capabilities include 'invite_members' or '*',
// members with 'invite_members' in member.capabilities, and system admins automatically pass)
router.post(
  "/workspaces/:workspaceId/invitations",
  lanyardServer.checkAuth,
  lanyardServer.requireScopeCapability("invite_members"),
  async (req, res) => {
    res.json({ invitedBy: req.user!.uid });
  }
);
```

#### Pre-Provisioning Users & Granting Multiple Capabilities by Email

When adding a user by email (e.g., via CSV import or an invite form) before they have ever signed in:

```ts
// Additively grants 'edit_content' capability (and creates/resolves their Firebase Auth UID)
// without overwriting any other capabilities (such as 'invite_members') they already hold:
const member = await lanyardServer.grantScopeCapabilitiesByEmail({
  scopeId: workspaceId,
  email: "collaborator@example.com",
  firstName: "Accenty",
  lastName: "McÉccent",
  capabilities: ["edit_content"],
  scopeName: "Acme Workspace"
});
```

---

### 4. Supplying a Custom Storage Implementation

To use `lanyard` with a non-Firestore database (PostgreSQL, SQLite, REST, etc.), implement `LanyardClientStore<TRole, TCapability, TPreferences>` and/or `LanyardServerStore<TRole, TCapability>` from `lanyard/core`:

```ts
import type { LanyardServerStore, ScopedMember, SystemAdminProfile } from "lanyard/core";

class PostgresServerStore<
  TRole extends string = string,
  TCapability extends string = string
> implements LanyardServerStore<TRole, TCapability> {
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
  async getScopeMember(scopeId: string, uid: string): Promise<ScopedMember<TRole, TCapability> | null> {
    /* ... */
  }
  async listScopeMembers(scopeId: string): Promise<ScopedMember<TRole, TCapability>[]> {
    /* ... */
  }
  async upsertScopeMember(scopeId: string, member: ScopedMember<TRole, TCapability>): Promise<void> {
    /* ... */
  }
  async grantScopeCapabilities(
    scopeId: string,
    uid: string,
    caps: readonly TCapability[],
    fallback?: Omit<ScopedMember<TRole, TCapability>, "capabilities">
  ): Promise<ScopedMember<TRole, TCapability>> {
    /* ... */
  }
  async revokeScopeCapabilities(scopeId: string, uid: string, caps: readonly TCapability[]): Promise<void> {
    /* ... */
  }
  async deleteScopeMember(scopeId: string, uid: string): Promise<void> {
    /* ... */
  }
}
```

For unit tests, use the built-in **`InMemoryLanyardStore<TRole, TCapability, TPreferences>`** from `lanyard/core`, which implements both `LanyardClientStore` and `LanyardServerStore` out of the box with zero mocks required.

---

### 5. Reference Firestore Security Rules (Single-Read Optimized)

When using `FirestoreClientStore` and `FirestoreServerStore`, use the following helper functions in `firestore.rules`. Note that `hasScopeRole` and `hasScopeCapability` use `get()` without a preceding `exists()` call so Firestore caches the single document read across an entire query:

```javascript
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

function hasScopeRole(scopeId, allowedRoles) {
  return isAdmin() || (
    isSignedIn() &&
    get(memberPath(scopeId)).data != null &&
    get(memberPath(scopeId)).data.role in allowedRoles
  );
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

// Example member rules preventing self-role/capability escalation on presence & avatar sync:
match /workspaces/{scopeId}/members/{memberUid} {
  allow read: if isScopeMember(scopeId);
  allow create, delete: if hasScopeCapability(scopeId, 'invite_members', ['owner', 'manager']);
  allow update: if hasScopeCapability(scopeId, 'invite_members', ['owner', 'manager']) || (
    isOwner(memberUid) &&
    request.resource.data.diff(resource.data).affectedKeys().hasOnly(['lastSeen', 'photoUrl'])
  );
}
```

---

## Development & Testing

```bash
# Run unit tests
npm test

# Typecheck
npm run typecheck

# Build dist/
npm run build

# Format source files
npm run format
```

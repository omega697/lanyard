# `lanyard`

UID-first, storage-agnostic authentication, presence tracking, and multi-capability authorization library for TypeScript + Express + Svelte applications.

## Entrypoints

- `lanyard/core` — Models, role & capability evaluators (`hasMinimumRole`, `hasCapability`, `hasAnyCapability`, `hasAllCapabilities`), formatters (`formatLastSeen`, `formatExistingAccountError`), Svelte-compatible observable stores, and `InMemoryClientStore` / `InMemoryServerStore` for unit tests.
- `lanyard/client` — Browser authentication flows (Google, Microsoft, GitHub, Magic Link, Anonymous, Account Linking), reactive stores, `localStorage`-throttled presence heartbeat, and `FirestoreClientStore`.
- `lanyard/server` — Express middleware (`checkAuth`, `requireAdmin`, `requireScopeRole`, `requireScopeCapability`, `requireOidcToken`), Firebase Admin user/capability provisioning (`getOrProvisionUidByEmail`, `upsertScopeMemberByEmail`, `grantScopeCapabilitiesByEmail`), and `FirestoreServerStore`.

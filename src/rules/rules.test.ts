import { describe, expect, it } from "vitest";
import { createPermissionPolicy } from "../core/index.js";
import { generateFirestoreRules } from "./index.js";

const CAPS = ["view_roster", "manage_members", "view_notes", "everything"] as const;
type Role = "viewer" | "volunteer" | "lead" | "director";
type Cap = (typeof CAPS)[number];

function makePolicy(overrides: Parameters<typeof createPermissionPolicy<Role, Cap>>[0] = {}) {
  return createPermissionPolicy<Role, Cap>({
    capabilities: CAPS,
    roles: {
      viewer: { capabilities: ["view_roster"] },
      volunteer: { capabilities: [] },
      lead: { inherits: ["volunteer", "viewer"], capabilities: ["manage_members", "view_notes"] },
      director: { inherits: ["lead"], capabilities: "*" }
    },
    staffCapability: "manage_members",
    userCapabilities: { read: "view_roster" },
    ...overrides
  });
}

/** Returns the body of the first `match <path> {` block (up to its closing brace at the same indentation). */
function matchBlock(rules: string, path: string): string {
  const start = rules.indexOf(`match ${path} {`);
  expect(start).toBeGreaterThanOrEqual(0);
  const indent = rules.lastIndexOf("\n", start);
  const pad = rules.slice(indent + 1, start);
  const end = rules.indexOf(`\n${pad}}`, start);
  return rules.slice(start, end);
}

describe("generateFirestoreRules", () => {
  /** Returns the body of a generated rules function, e.g. `isAdmin`. */
  function fnBody(rules: string, name: string): string {
    const start = rules.indexOf(`function ${name}(`);
    expect(start).toBeGreaterThanOrEqual(0);
    return rules.slice(start, rules.indexOf("\n    }", start));
  }

  it("makes isAdmin() refuse admin tokens issued before the revocation epoch or from a revoked session", () => {
    const rules = generateFirestoreRules(makePolicy(), { metaCollection: "app_meta" });
    const isAdmin = fnBody(rules, "isAdmin");
    expect(isAdmin).toContain("request.auth.token.get('admin', false) == true");
    expect(isAdmin).toContain("request.auth.token.iat * 1000 > revocationEpochMs() + 2000");
    expect(isAdmin).toContain("request.auth.token.auth_time * 1000 > sessionRevokedAtMs() + 2000");
    expect(fnBody(rules, "revocationEpochMs")).toContain("/databases/$(database)/documents/app_meta/revocation");
    expect(fnBody(rules, "revocationEpochMs")).toContain("'lastRevocationAtMs'");
    expect(fnBody(rules, "sessionRevokedAtMs")).toContain(
      "/databases/$(database)/documents/app_meta/session_revocations"
    );
    expect(fnBody(rules, "sessionRevokedAtMs")).toContain("'revokedAtMs'");
  });

  it("requires a verified email in isSignedIn() by default, with an explicit opt-out", () => {
    expect(fnBody(generateFirestoreRules(makePolicy()), "isSignedIn")).toContain(
      "request.auth.token.get('email_verified', false) == true"
    );
    const lenient = fnBody(generateFirestoreRules(makePolicy(), { requireVerifiedEmail: false }), "isSignedIn");
    expect(lenient).not.toContain("email_verified");
    expect(lenient).toContain("request.auth != null");
  });
  it("lets signed-in clients read only the revocation epoch from Lanyard's metadata collection", () => {
    const rules = generateFirestoreRules(makePolicy());
    expect(matchBlock(rules, "/lanyard_meta/revocation")).toContain("allow get: if isSignedIn();");
    expect(matchBlock(rules, "/lanyard_meta/{document}")).toContain("allow read, write: if false;");
    expect(rules).not.toMatch(/match \/lanyard_meta\/session_revocations/);

    const custom = generateFirestoreRules(makePolicy(), { metaCollection: "app_meta" });
    expect(matchBlock(custom, "/app_meta/revocation")).toContain("allow get: if isSignedIn();");
    expect(() => generateFirestoreRules(makePolicy(), { metaCollection: "bad/name" })).toThrow(/metaCollection/);
  });

  it("emits closed-world role inheritance and capability lookup maps and capability-based tier rules", () => {
    const rules = generateFirestoreRules(makePolicy());
    // Role inheritance map expands every role to the sorted concrete roles that satisfy it
    expect(rules).toContain("'director': ['director']");
    expect(rules).toContain("'lead': ['director', 'lead']");
    expect(rules).toContain("'viewer': ['director', 'lead', 'viewer']");
    expect(rules).toContain("'volunteer': ['director', 'lead', 'volunteer']");
    // Capability map includes capabilities granted directly, via inheritance, and via closed-world "*"
    expect(rules).toContain("'everything': ['director']");
    expect(rules).toContain("'manage_members': ['director', 'lead']");
    expect(rules).toContain("'view_notes': ['director', 'lead']");
    expect(rules).toContain("'view_roster': ['director', 'lead', 'viewer']");
    // Strict map indexing (`}[role];` / `}[capability];`) rather than `.get(...)` so typos fail closed
    expect(rules).toContain("}[role];");
    expect(rules).toContain("}[capability];");
    expect(rules).toContain("function hasScopeCapability(scopeId, capability)");
    expect(rules).toContain("function hasUserCapability(capability)");

    // Staff & user read tiers invoke capability helpers directly
    expect(matchBlock(rules, "/private/attributes")).toContain("hasUserCapability('manage_members')");
    expect(rules).toContain("hasScopeCapability(scopeId, 'manage_members')");
    expect(matchBlock(rules, "/users/{uid}")).toContain(
      "allow read: if isOwner(uid) || hasUserCapability('view_roster');"
    );
  });

  it("gives no one but admins staff or global user read access when those capabilities are unset", () => {
    const rules = generateFirestoreRules(makePolicy({ staffCapability: undefined, userCapabilities: undefined }));
    expect(matchBlock(rules, "/users/{uid}")).toContain("allow read: if isOwner(uid) || isAdmin();");
    expect(matchBlock(rules, "/private/attributes")).toContain("allow read: if isOwner(uid) || isAdmin();");
    expect(rules).not.toContain("hasScopeCapability(scopeId, '");
    expect(rules).not.toContain("hasUserCapability('");
  });

  it("expands abstract roles to their concrete inheritors and handles empty role/capability policies", () => {
    type AbsRole = "staff_base" | "unused_abstract" | "lead" | "owner";
    const absPolicy = createPermissionPolicy<AbsRole, "edit">({
      roles: {
        staff_base: { abstract: true, capabilities: ["edit"] },
        unused_abstract: { abstract: true },
        lead: { inherits: ["staff_base"] },
        owner: { inherits: ["lead"] }
      }
    });
    const absRules = generateFirestoreRules(absPolicy);
    expect(absRules).toContain("'staff_base': ['lead', 'owner']");
    expect(absRules).toContain("'unused_abstract': []");
    expect(absRules).toContain("'edit': ['lead', 'owner']");

    const emptyRules = generateFirestoreRules(createPermissionPolicy({ roles: {} as any }));
    expect(emptyRules).toContain("return {}[role];");
    expect(emptyRules).toContain("return {}[capability];");
  });

  it("emits the scoped card read rule for each cardVisibility mode", () => {
    const memberCard = (cardVisibility: any) =>
      matchBlock(generateFirestoreRules(makePolicy({ cardVisibility })), "/workspaces/{scopeId}/members/{memberUid}");
    expect(memberCard(undefined)).toContain("allow read: if isOwner(memberUid) || isScopeMember(scopeId);");
    expect(memberCard("staff")).toContain(
      "allow read: if isOwner(memberUid) || hasScopeCapability(scopeId, 'manage_members');"
    );
    expect(memberCard({ capability: "view_roster" })).toContain(
      "allow read: if isOwner(memberUid) || hasScopeCapability(scopeId, 'view_roster');"
    );
  });

  it("lets owners self-write card email only when cardFields.email places it on the card", () => {
    const privateEmail = generateFirestoreRules(makePolicy());
    expect(matchBlock(privateEmail, "/users/{uid}")).not.toContain("'email'");
    const cardEmail = generateFirestoreRules(makePolicy({ cardFields: { email: true } }));
    expect(matchBlock(cardEmail, "/users/{uid}")).toContain("'uid', 'email', 'firstName'");
    expect(matchBlock(cardEmail, "/workspaces/{scopeId}/members/{memberUid}")).toContain("['email', 'firstName'");
  });

  it("never lets non-admin clients create, delete, or change roles on member cards", () => {
    const memberCard = matchBlock(generateFirestoreRules(makePolicy()), "/workspaces/{scopeId}/members/{memberUid}");
    expect(memberCard).toContain("allow create, delete: if isAdmin();");
    expect(memberCard).toContain(
      "affectedKeys().hasOnly(['firstName', 'lastName', 'displayName', 'lastSeen', 'photoUrl', 'updatedAt'])"
    );
    expect(memberCard).not.toMatch(/'roles'|'attributes'|'isSystemAdmin'/);
  });

  it("emits read/write rules with metadata checks for each custom doc, globally and per scope", () => {
    const rules = generateFirestoreRules(
      makePolicy({
        customDocs: {
          shiftNotes: { read: { self: true, capability: "view_notes" }, write: { staff: true } },
          adminOnly: { read: {}, write: {} }
        }
      })
    );
    const scopedNotes = matchBlock(
      matchBlock(rules, "/workspaces/{scopeId}/members/{memberUid}"),
      "/private/shiftNotes"
    );
    expect(scopedNotes).toContain(
      "allow read: if isAdmin() || isOwner(memberUid) || hasScopeCapability(scopeId, 'view_notes');"
    );
    expect(scopedNotes).toContain("allow write: if (isAdmin() || hasScopeCapability(scopeId, 'manage_members')) &&");
    expect(scopedNotes).toContain("isTierDoc('shiftNotes', memberUid, scopeId);");
    const globalNotes = matchBlock(matchBlock(rules, "/users/{uid}"), "/private/shiftNotes");
    expect(globalNotes).toContain("allow read: if isAdmin() || isOwner(uid) || hasUserCapability('view_notes');");
    expect(globalNotes).toContain("isTierDoc('shiftNotes', uid, null);");
    const adminOnly = matchBlock(rules, "/private/adminOnly");
    expect(adminOnly).toContain("allow read: if isAdmin();");
    expect(adminOnly).toContain("allow write: if (isAdmin()) &&");
  });

  it("requires membership for self writes to scoped custom docs", () => {
    const rules = generateFirestoreRules(
      makePolicy({ customDocs: { journal: { read: { self: true }, write: { self: true } } } })
    );
    const scopedJournal = matchBlock(
      matchBlock(rules, "/workspaces/{scopeId}/members/{memberUid}"),
      "/private/journal"
    );
    expect(scopedJournal).toContain("allow read: if isAdmin() || isOwner(memberUid);");
    expect(scopedJournal).toContain("allow write: if (isAdmin() || (isOwner(memberUid) && isScopeMember(scopeId))) &&");
  });

  it("uses the configured collection names and rejects unsafe ones", () => {
    const rules = generateFirestoreRules(makePolicy(), {
      usersCollection: "people",
      scopeCollection: "campaigns",
      membersSubcollection: "crew"
    });
    expect(rules).toContain("match /people/{uid} {");
    expect(rules).toContain("match /campaigns/{scopeId}/crew/{memberUid} {");
    expect(rules).toContain("/databases/$(database)/documents/campaigns/$(scopeId)/crew/$(request.auth.uid)");
    expect(rules).toContain("match /{path=**}/crew/{memberUid} {");
    expect(rules).not.toMatch(/workspaces|\/users\//);
    expect(() => generateFirestoreRules(makePolicy(), { scopeCollection: "a/b" })).toThrow(/Invalid scopeCollection/);
    expect(() => generateFirestoreRules(makePolicy(), { usersCollection: "x'y" })).toThrow(/Invalid usersCollection/);
  });

  it("is deterministic and quotes role and capability names safely", () => {
    const quirky = createPermissionPolicy<"it's" | "plain", "st'aff">({
      roles: { "it's": { capabilities: ["st'aff"] }, plain: {} },
      staffCapability: "st'aff"
    });
    const rules = generateFirestoreRules(quirky);
    expect(rules).toContain("'st\\'aff': ['it\\'s']");
    expect(rules).toContain("hasScopeCapability(scopeId, 'st\\'aff')");
    expect(generateFirestoreRules(quirky)).toBe(rules);
  });
});

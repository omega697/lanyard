import { describe, expect, it } from "vitest";
import { createPermissionPolicy } from "../core/index.js";
import { generateFirestoreRules } from "./index.js";

type Role = "viewer" | "volunteer" | "lead" | "director";
type Cap = "view_roster" | "manage_members" | "view_notes" | "everything";

function makePolicy(overrides: Parameters<typeof createPermissionPolicy<Role, Cap>>[0] = {}) {
  return createPermissionPolicy<Role, Cap>({
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
  it("expands capability audiences into role lists, following inheritance and wildcard capabilities", () => {
    const rules = generateFirestoreRules(makePolicy());
    // Staff: lead (direct) and director (inherits lead, and "*") — never viewer or volunteer
    expect(matchBlock(rules, "/private/attributes")).toContain("hasUserRole(['director', 'lead'])");
    expect(rules).toContain("hasScopeRole(scopeId, ['director', 'lead'])");
    // Global profile readers: viewer (direct), lead (inherits viewer), director ("*")
    expect(matchBlock(rules, "/users/{uid}")).toContain(
      "allow read: if isOwner(uid) || hasUserRole(['director', 'lead', 'viewer']);"
    );
  });

  it("gives no one but admins staff access when the policy has no staffCapability", () => {
    const rules = generateFirestoreRules(makePolicy({ staffCapability: undefined }));
    expect(rules).toContain("hasScopeRole(scopeId, [])");
    expect(rules).not.toContain("['director', 'lead']");
  });

  it("emits the scoped card read rule for each cardVisibility mode", () => {
    const memberCard = (cardVisibility: any) =>
      matchBlock(generateFirestoreRules(makePolicy({ cardVisibility })), "/workspaces/{scopeId}/members/{memberUid}");
    expect(memberCard(undefined)).toContain("allow read: if isOwner(memberUid) || isScopeMember(scopeId);");
    expect(memberCard("staff")).toContain(
      "allow read: if isOwner(memberUid) || hasScopeRole(scopeId, ['director', 'lead']);"
    );
    expect(memberCard({ capability: "view_roster" })).toContain(
      "allow read: if isOwner(memberUid) || hasScopeRole(scopeId, ['director', 'lead', 'viewer']);"
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
      "allow read: if isAdmin() || isOwner(memberUid) || hasScopeRole(scopeId, ['director', 'lead']);"
    );
    expect(scopedNotes).toContain("allow write: if (isAdmin() || hasScopeRole(scopeId, ['director', 'lead'])) &&");
    expect(scopedNotes).toContain("isTierDoc('shiftNotes', memberUid, scopeId);");
    const globalNotes = matchBlock(matchBlock(rules, "/users/{uid}"), "/private/shiftNotes");
    expect(globalNotes).toContain("allow read: if isAdmin() || isOwner(uid) || hasUserRole(['director', 'lead']);");
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

  it("is deterministic and quotes role names safely", () => {
    const quirky = createPermissionPolicy<"it's" | "plain", "staff">({
      roles: { "it's": { capabilities: ["staff"] }, plain: {} },
      staffCapability: "staff"
    });
    const rules = generateFirestoreRules(quirky);
    expect(rules).toContain("hasScopeRole(scopeId, ['it\\'s'])");
    expect(generateFirestoreRules(quirky)).toBe(rules);
  });
});

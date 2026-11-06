import type { CustomDocAccessRule, PermissionPolicy } from "../core/index.js";

/** Collection names the generated rules match (they must equal the ones passed to the Firestore stores). */
export interface FirestoreRulesOptions {
  /** Canonical users collection (defaults to `"users"`). */
  usersCollection?: string;
  /** Scope (tenant) collection (defaults to `"workspaces"`). */
  scopeCollection?: string;
  /** Members subcollection under each scope (defaults to `"members"`). */
  membersSubcollection?: string;
}

const COLLECTION_NAME = /^[A-Za-z0-9_-]+$/;

function assertCollectionName(name: string, label: string): string {
  if (!COLLECTION_NAME.test(name)) throw new Error(`Invalid ${label} '${name}': use letters, digits, '_' or '-'.`);
  return name;
}

/** Quotes a string for a Firestore rules string literal. */
function quote(value: string): string {
  return `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
}

function roleList(roles: readonly string[]): string {
  return `[${roles.map(quote).join(", ")}]`;
}

function rulesMapLiteral(entries: readonly [string, readonly string[]][], indent: string): string {
  if (entries.length === 0) return "{}";
  const body = entries.map(([key, values]) => `${indent}  ${quote(key)}: ${roleList(values)}`).join(",\n");
  return `{\n${body}\n${indent}}`;
}

/**
 * Generates the Firestore security rules for everything Lanyard stores, from the app's `PermissionPolicy`.
 *
 * Emits closed-world lookup maps (`rolesForRole` and `rolesForCapability`) and first-class helpers
 * (`hasScopeRole`, `hasUserRole`, `hasScopeCapability`, `hasUserCapability`) so both Lanyard's generated rules
 * and your app's own collection rules evaluate transitive role inheritance (including `abstract` roles) and
 * capabilities directly, while failing closed on any misspelled role or capability name.
 * Regenerate the rules whenever roles or capabilities change.
 *
 * The result is a block of functions and `match` statements to place inside
 * `match /databases/{database}/documents { … }`. Cards and the built-in tiers are written by trusted server code
 * (Admin SDK); clients may only update their own profile fields, their own preferences, their own verified email,
 * and custom documents whose `write` audience includes them.
 */
export function generateFirestoreRules<TRole extends string, TCapability extends string>(
  policy: PermissionPolicy<TRole, TCapability>,
  options: FirestoreRulesOptions = {}
): string {
  const usersCollection = assertCollectionName(options.usersCollection ?? "users", "usersCollection");
  const scopeCollection = assertCollectionName(options.scopeCollection ?? "workspaces", "scopeCollection");
  const membersSubcollection = assertCollectionName(options.membersSubcollection ?? "members", "membersSubcollection");

  const allRoles = (Object.keys(policy.roles) as TRole[]).sort();
  const concreteRoles = [...policy.assignableRoles].sort();
  const concreteRolesWhere = (predicate: (subject: { roles: TRole[] }) => boolean): string[] =>
    concreteRoles.filter((role) => predicate({ roles: [role] }));

  const roleMapEntries: [string, readonly string[]][] = allRoles.map((role) => [
    role,
    concreteRolesWhere((s) => policy.hasRole(s, role))
  ]);
  const allCapabilities = [...policy.capabilities].sort();
  const capabilityMapEntries: [string, readonly string[]][] = allCapabilities.map((capability) => [
    capability,
    concreteRolesWhere((s) => policy.hasCapability(s, capability))
  ]);

  const capabilityCheck = (capability: TCapability | undefined, scoped: boolean, scopeExpr = "scopeId"): string => {
    if (!capability) return "isAdmin()";
    return scoped
      ? `hasScopeCapability(${scopeExpr}, ${quote(capability)})`
      : `hasUserCapability(${quote(capability)})`;
  };

  const userReadExpr = capabilityCheck(policy.userCapabilities.read, false);
  const globalStaffExpr = capabilityCheck(policy.staffCapability, false);
  const scopedStaffExpr = (scopeExpr = "scopeId") => capabilityCheck(policy.staffCapability, true, scopeExpr);

  const scopedCardRead =
    policy.cardVisibility === "members"
      ? "isScopeMember(scopeId)"
      : policy.cardVisibility === "staff"
        ? scopedStaffExpr()
        : capabilityCheck(policy.cardVisibility.capability, true);

  const emailOnCard = policy.cardFields.email;
  const userCreateKeys = [
    "uid",
    ...(emailOnCard ? ["email"] : []),
    "firstName",
    "lastName",
    "displayName",
    "photoUrl",
    "lastSeen",
    "createdAt",
    "updatedAt"
  ];
  const userUpdateKeys = userCreateKeys.filter((key) => key !== "createdAt");
  const memberUpdateKeys = [
    ...(emailOnCard ? ["email"] : []),
    "firstName",
    "lastName",
    "displayName",
    "lastSeen",
    "photoUrl",
    "updatedAt"
  ];

  /** Rule expression for a custom doc audience; `scoped` selects member vs global capability checks. */
  const customAudience = (rule: Readonly<CustomDocAccessRule<TCapability>>, scoped: boolean, write: boolean) => {
    const ownerCheck = scoped ? "isOwner(memberUid)" : "isOwner(uid)";
    const terms = ["isAdmin()"];
    if (rule.self) terms.push(scoped && write ? `(${ownerCheck} && isScopeMember(scopeId))` : ownerCheck);
    if (rule.staff && policy.staffCapability) terms.push(capabilityCheck(policy.staffCapability, scoped));
    if (rule.capability) terms.push(capabilityCheck(rule.capability, scoped));
    return terms.join(" || ");
  };
  const customDocBlocks = (scoped: boolean) =>
    Object.entries(policy.customDocs).map(([name, def]) => {
      const uidVar = scoped ? "memberUid" : "uid";
      const scopeArg = scoped ? "scopeId" : "null";
      return `
      // Custom doc '${name}' (customDocs.${name})
      match /private/${name} {
        allow read: if ${customAudience(def.read, scoped, false)};
        allow write: if (${customAudience(def.write, scoped, true)}) &&
          isTierDoc(${quote(name)}, ${uidVar}, ${scopeArg});
      }`;
    });

  const membersPath = `/databases/$(database)/documents/${scopeCollection}/$(scopeId)/${membersSubcollection}/$(request.auth.uid)`;
  const userPath = `/databases/$(database)/documents/${usersCollection}/$(request.auth.uid)`;
  const roleMapExpr = rulesMapLiteral(roleMapEntries, "      ");
  const capabilityMapExpr = rulesMapLiteral(capabilityMapEntries, "      ");

  return `    // Generated by lanyard generateFirestoreRules(); do not edit by hand. Regenerate when the policy changes.
    function isSignedIn() {
      return request.auth != null;
    }

    function isOwner(uid) {
      return isSignedIn() && request.auth.uid == uid;
    }

    function isAdmin() {
      return isSignedIn() && request.auth.token.get('admin', false) == true;
    }

    function memberPath(scopeId) {
      return ${membersPath};
    }

    function isScopeMember(scopeId) {
      return isAdmin() || (isSignedIn() && exists(memberPath(scopeId)));
    }

    function rolesForRole(role) {
      return ${roleMapExpr}[role];
    }

    function rolesForCapability(capability) {
      return ${capabilityMapExpr}[capability];
    }

    function hasAnyScopeRole(scopeId, roles) {
      return isAdmin() || (
        isSignedIn() &&
        get(memberPath(scopeId)).data != null &&
        get(memberPath(scopeId)).data.get('roles', []).hasAny(roles)
      );
    }

    function hasAnyUserRole(roles) {
      return isAdmin() || (
        isSignedIn() &&
        get(${userPath}).data != null &&
        get(${userPath}).data.get('roles', []).hasAny(roles)
      );
    }

    function hasScopeRole(scopeId, role) {
      return rolesForRole(role) is list && hasAnyScopeRole(scopeId, rolesForRole(role));
    }

    function hasUserRole(role) {
      return rolesForRole(role) is list && hasAnyUserRole(rolesForRole(role));
    }

    function hasScopeCapability(scopeId, capability) {
      return rolesForCapability(capability) is list && hasAnyScopeRole(scopeId, rolesForCapability(capability));
    }

    function hasUserCapability(capability) {
      return rolesForCapability(capability) is list && hasAnyUserRole(rolesForCapability(capability));
    }

    // Lanyard stamps every private tier document with _lanyard: { tier, uid, scopeId (null when global), updatedAt }
    function isTierDoc(tier, uid, scopeId) {
      return request.resource.data._lanyard.tier == tier &&
        request.resource.data._lanyard.uid == uid &&
        request.resource.data._lanyard.scopeId == scopeId;
    }

    // Owners may write only their own verified Firebase Auth email (plus Lanyard metadata) to their attributes tier
    function isOwnVerifiedEmailWrite(uid, scopeId) {
      return request.auth.token.email_verified == true &&
        request.resource.data.email == request.auth.token.email.lower() &&
        isTierDoc('attributes', uid, scopeId) &&
        (resource == null
          ? request.resource.data.keys().hasOnly(['email', '_lanyard'])
          : request.resource.data.diff(resource.data).affectedKeys().hasOnly(['email', '_lanyard']));
    }

    match /${usersCollection}/{uid} {
      allow read: if isOwner(uid) || ${userReadExpr};
      allow create: if isAdmin() || (
        isOwner(uid) &&
        request.resource.data.keys().hasOnly(${roleList(userCreateKeys)}) &&
        (!('uid' in request.resource.data) || request.resource.data.uid == uid)
      );
      allow update: if isAdmin() || (
        isOwner(uid) &&
        request.resource.data.diff(resource.data).affectedKeys().hasOnly(${roleList(userUpdateKeys)}) &&
        (!('uid' in request.resource.data) || request.resource.data.uid == uid)
      );
      allow delete: if isAdmin();

      // Self-only preferences tier
      match /private/preferences {
        allow read: if isOwner(uid) || isAdmin();
        allow write: if (isOwner(uid) || isAdmin()) && isTierDoc('preferences', uid, null);
      }

      // Self + staff attributes tier (server-written, except owners syncing their verified email)
      match /private/attributes {
        allow read: if isOwner(uid) || ${globalStaffExpr};
        allow write: if isOwner(uid) && isOwnVerifiedEmailWrite(uid, null);
      }

      // Staff-only hidden attributes tier (server-written)
      match /private/hiddenAttributes {
        allow read: if ${globalStaffExpr};
        allow write: if false;
      }

      // Encrypted secrets are server-only
      match /private/secrets {
        allow read, write: if false;
      }
${customDocBlocks(false).join("\n")}
    }

    match /${scopeCollection}/{scopeId}/${membersSubcollection}/{memberUid} {
      allow read: if isOwner(memberUid) || ${scopedCardRead};
      allow create, delete: if isAdmin();
      allow update: if isAdmin() || (
        isOwner(memberUid) &&
        request.resource.data.diff(resource.data).affectedKeys().hasOnly(${roleList(memberUpdateKeys)})
      );

      // Self-only preferences tier (writable only while the user is a member of the scope)
      match /private/preferences {
        allow read: if isOwner(memberUid) || isAdmin();
        allow write: if ((isOwner(memberUid) && isScopeMember(scopeId)) || isAdmin()) &&
          isTierDoc('preferences', memberUid, scopeId);
      }

      // Self + staff attributes tier (server-written, except members syncing their verified email)
      match /private/attributes {
        allow read: if isOwner(memberUid) || ${scopedStaffExpr()};
        allow write: if isOwner(memberUid) && isScopeMember(scopeId) && isOwnVerifiedEmailWrite(memberUid, scopeId);
      }

      // Staff-only hidden attributes tier (server-written)
      match /private/hiddenAttributes {
        allow read: if ${scopedStaffExpr()};
        allow write: if false;
      }

      // Encrypted secrets are server-only
      match /private/secrets {
        allow read, write: if false;
      }
${customDocBlocks(true).join("\n")}
    }

    // Users can list their own memberships across scopes (collectionGroup('${membersSubcollection}') where uid == theirs)
    match /{path=**}/${membersSubcollection}/{memberUid} {
      allow read: if isSignedIn() && (resource.data.uid == request.auth.uid || isAdmin());
    }

    // Staff list every attributes tier of their scope (or of global users) with one collection-group query
    // (include: ["attributes"] and queryMembers); the equality filters on _lanyard.tier/scopeId make this provable.
    match /{path=**}/private/{tierDoc} {
      allow list: if resource.data._lanyard.tier == 'attributes' && (
        resource.data._lanyard.scopeId == null
          ? ${globalStaffExpr}
          : ${scopedStaffExpr("resource.data._lanyard.scopeId")});
    }
`;
}

/** Comment line that starts the generated block in `firestore.rules`. */
export const LANYARD_RULES_BEGIN = "// <lanyard-rules>";
/** Comment line that ends the generated block in `firestore.rules`. */
export const LANYARD_RULES_END = "// </lanyard-rules>";

/** Finds the marker lines, throwing unless each appears exactly once and in order. */
function locateMarkers(rulesText: string): { beginLineEnd: number; endLineStart: number } {
  const lines = rulesText.split("\n");
  const beginIndexes = lines.flatMap((line, i) => (line.trim() === LANYARD_RULES_BEGIN ? [i] : []));
  const endIndexes = lines.flatMap((line, i) => (line.trim() === LANYARD_RULES_END ? [i] : []));
  if (beginIndexes.length !== 1 || endIndexes.length !== 1 || endIndexes[0] < beginIndexes[0]) {
    throw new Error(
      `firestore.rules must contain exactly one '${LANYARD_RULES_BEGIN}' line followed by one '${LANYARD_RULES_END}' ` +
        "line, inside match /databases/{database}/documents { … }"
    );
  }
  const offsetOfLine = (index: number) => lines.slice(0, index).reduce((sum, line) => sum + line.length + 1, 0);
  return {
    beginLineEnd: offsetOfLine(beginIndexes[0]) + lines[beginIndexes[0]].length,
    endLineStart: offsetOfLine(endIndexes[0])
  };
}

/** Returns the text between the `LANYARD_RULES_BEGIN` and `LANYARD_RULES_END` marker lines. */
export function extractLanyardRulesBlock(rulesText: string): string {
  const { beginLineEnd, endLineStart } = locateMarkers(rulesText);
  return rulesText.slice(beginLineEnd + 1, endLineStart);
}

/** Returns `rulesText` with the text between the marker lines replaced by `generatedBlock`. */
export function replaceLanyardRulesBlock(rulesText: string, generatedBlock: string): string {
  const { beginLineEnd, endLineStart } = locateMarkers(rulesText);
  const block = generatedBlock.endsWith("\n") ? generatedBlock : `${generatedBlock}\n`;
  return `${rulesText.slice(0, beginLineEnd + 1)}${block}${rulesText.slice(endLineStart)}`;
}

/** Normalizes line endings and trailing whitespace so formatting-only differences don't count as stale. */
function normalizeRules(text: string): string[] {
  return text
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .trim()
    .split("\n");
}

/**
 * Throws if the generated block in `rulesText` (between the marker lines) doesn't match what
 * `generateFirestoreRules(policy, options)` produces now, e.g. after roles, capabilities, `cardFields`,
 * `cardVisibility`, or `customDocs` changed. Call it from your app's tests so stale rules fail CI.
 */
export function assertFirestoreRulesUpToDate<TRole extends string, TCapability extends string>(
  rulesText: string,
  policy: PermissionPolicy<TRole, TCapability>,
  options: FirestoreRulesOptions = {}
): void {
  const actual = normalizeRules(extractLanyardRulesBlock(rulesText));
  const expected = normalizeRules(generateFirestoreRules(policy, options));
  const length = Math.max(actual.length, expected.length);
  for (let i = 0; i < length; i++) {
    if (actual[i] !== expected[i]) {
      throw new Error(
        `The Lanyard rules block is out of date with the policy (first difference at line ${i + 1} of ` +
          `the generated block).\n  expected: ${expected[i] ?? "<end of block>"}\n  actual:   ${actual[i] ?? "<end of block>"}\n` +
          "Regenerate them with `npx lanyard-rules --policy <module> --export <name> --write firestore.rules`."
      );
    }
  }
}

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

/**
 * Generates the Firestore security rules for everything Lanyard stores, from the app's `PermissionPolicy`.
 *
 * Firestore rules can't evaluate the policy's role inheritance or capabilities, so every capability-based audience
 * (`staffCapability`, `userCapabilities.read`, `cardVisibility: { capability }`, custom-doc capabilities) is
 * expanded into the list of roles that hold it. Regenerate the rules whenever roles or capabilities change.
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

  const allRoles = Object.keys(policy.roles) as TRole[];
  const rolesWhere = (predicate: (subject: { roles: TRole[] }) => boolean): string[] =>
    allRoles.filter((role) => predicate({ roles: [role] })).sort();
  const rolesWithCapability = (capability: TCapability) => rolesWhere((s) => policy.hasCapability(s, capability));
  const staffRoles = rolesWhere((s) => policy.isStaff(s));
  const userReadRoles = rolesWhere((s) => policy.canReadUser(s));

  const scopedCardRead =
    policy.cardVisibility === "members"
      ? "isScopeMember(scopeId)"
      : policy.cardVisibility === "staff"
        ? `hasScopeRole(scopeId, ${roleList(staffRoles)})`
        : `hasScopeRole(scopeId, ${roleList(rolesWithCapability(policy.cardVisibility.capability))})`;

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

  /** Rule expression for a custom doc audience; `scoped` selects member vs global role checks. */
  const customAudience = (rule: Readonly<CustomDocAccessRule<TCapability>>, scoped: boolean, write: boolean) => {
    const ownerCheck = scoped ? "isOwner(memberUid)" : "isOwner(uid)";
    const roleCheck = (roles: string[]) =>
      scoped ? `hasScopeRole(scopeId, ${roleList(roles)})` : `hasUserRole(${roleList(roles)})`;
    const terms = ["isAdmin()"];
    if (rule.self) terms.push(scoped && write ? `(${ownerCheck} && isScopeMember(scopeId))` : ownerCheck);
    if (rule.staff) terms.push(roleCheck(staffRoles));
    if (rule.capability) terms.push(roleCheck(rolesWithCapability(rule.capability)));
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

    function hasScopeRole(scopeId, roles) {
      return isAdmin() || (
        isSignedIn() &&
        get(memberPath(scopeId)).data != null &&
        get(memberPath(scopeId)).data.get('roles', []).hasAny(roles)
      );
    }

    function hasUserRole(roles) {
      return isAdmin() || (
        isSignedIn() &&
        get(${userPath}).data != null &&
        get(${userPath}).data.get('roles', []).hasAny(roles)
      );
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
      allow read: if isOwner(uid) || hasUserRole(${roleList(userReadRoles)});
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
        allow read: if isOwner(uid) || hasUserRole(${roleList(staffRoles)});
        allow write: if isOwner(uid) && isOwnVerifiedEmailWrite(uid, null);
      }

      // Staff-only hidden attributes tier (server-written)
      match /private/hiddenAttributes {
        allow read: if hasUserRole(${roleList(staffRoles)});
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
        allow read: if isOwner(memberUid) || hasScopeRole(scopeId, ${roleList(staffRoles)});
        allow write: if isOwner(memberUid) && isScopeMember(scopeId) && isOwnVerifiedEmailWrite(memberUid, scopeId);
      }

      // Staff-only hidden attributes tier (server-written)
      match /private/hiddenAttributes {
        allow read: if hasScopeRole(scopeId, ${roleList(staffRoles)});
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
          ? hasUserRole(${roleList(staffRoles)})
          : hasScopeRole(resource.data._lanyard.scopeId, ${roleList(staffRoles)}));
    }
`;
}

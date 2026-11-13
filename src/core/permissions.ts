import type {
  CardVisibilityRule,
  CustomDocAccessRule,
  CustomDocDefinition,
  FieldCapabilityRule,
  LanyardTier,
  PermissionPolicy,
  PermissionPolicyConfig,
  PolicySubject,
  RoleDefinition
} from "./models.js";

const FORBIDDEN_PROTOTYPE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Built-in storage tier names; app-defined `customDocs` may not reuse them. */
const RESERVED_TIER_NAMES = new Set<string>(["card", "preferences", "attributes", "hiddenAttributes", "secrets"]);

function isSafeKey<T extends string = string>(key: unknown): key is T {
  return typeof key === "string" && key.trim().length > 0 && !FORBIDDEN_PROTOTYPE_KEYS.has(key);
}

interface NormalizedFieldRule<TCapability extends string> {
  write?: TCapability;
}

interface NormalizedUserRule<TCapability extends string> {
  read?: TCapability;
  write?: TCapability;
  assignRoles?: TCapability;
}

interface NormalizedSecretRule<TCapability extends string> {
  self?: boolean;
  capability?: TCapability;
}

/**
 * Normalizes per-key `attributeCapabilities` / `hiddenAttributeCapabilities` WRITE rules.
 * Throws if a legacy per-key `read` rule is present: reads are governed by storage tiers, because
 * Firestore security rules can only grant or deny whole documents.
 */
function normalizeFieldWriteRules<TCapability extends string>(
  configKey: "attributeCapabilities" | "hiddenAttributeCapabilities",
  input: Record<string, FieldCapabilityRule<TCapability>> | undefined
): Record<string, NormalizedFieldRule<TCapability>> {
  const rules = Object.create(null) as Record<string, NormalizedFieldRule<TCapability>>;
  if (!input || typeof input !== "object") return rules;
  for (const [key, rule] of Object.entries(input)) {
    if (!isSafeKey(key) || !rule) continue;
    if (typeof rule === "string") {
      rules[key] = Object.freeze({ write: rule as TCapability });
    } else if (typeof rule === "object") {
      if ("read" in rule) {
        throw new Error(
          `Invalid ${configKey}.${key}: per-key 'read' rules are not supported. ` +
            `Reads are governed by storage tiers (see staffCapability and cardFields).`
        );
      }
      rules[key] = Object.freeze(rule.write ? { write: rule.write } : {});
    }
  }
  return rules;
}

function normalizeCustomDocRule<TCapability extends string>(
  rule: CustomDocAccessRule<TCapability> | undefined
): Readonly<CustomDocAccessRule<TCapability>> {
  if (!rule || typeof rule !== "object") return Object.freeze({});
  return Object.freeze({
    ...(rule.self ? { self: true } : {}),
    ...(rule.staff ? { staff: true } : {}),
    ...(rule.capability && isSafeKey(rule.capability) ? { capability: rule.capability } : {})
  });
}

/**
 * Creates a reusable `PermissionPolicy<TRole, TCapability>` that defines an application's
 * explicit role inheritance (`inherits`), role-implied capabilities (`capabilities`),
 * role-level presence heartbeat tracking (`trackPresence`), user access (`userCapabilities`),
 * and field-level `attributes` / `secrets` rules.
 */
export function createPermissionPolicy<TRole extends string = string, TCapability extends string = string>(
  config: PermissionPolicyConfig<TRole, TCapability>
): PermissionPolicy<TRole, TCapability> {
  const { roles: inputRoles } = config;
  const entries = Object.entries(inputRoles || {}).filter(([role]) => !FORBIDDEN_PROTOTYPE_KEYS.has(role)) as [
    TRole,
    RoleDefinition<TRole, TCapability>
  ][];

  const rawRoles = Object.create(null) as Record<TRole, RoleDefinition<TRole, TCapability>>;

  for (const [role, def] of entries) {
    if (!def || typeof def !== "object") {
      throw new Error(`Invalid definition for role '${role}'.`);
    }
    if (def.capabilities === "*" && !Array.isArray(config.capabilities)) {
      throw new Error(
        `Role '${role}' uses capabilities: "*" — provide 'capabilities: [...]' in PermissionPolicyConfig ` +
          `so the closed capability set is known at runtime and in generated security rules.`
      );
    }
    if (def.abstract && def.systemManaged) {
      throw new Error(`Role '${role}' can't be both abstract and systemManaged: abstract roles are never held.`);
    }
    rawRoles[role] = def;
  }

  let explicitCapabilities: TCapability[] | undefined;
  let explicitCapabilitySet: Set<TCapability> | undefined;
  if (config.capabilities !== undefined) {
    if (!Array.isArray(config.capabilities)) {
      throw new Error("Invalid capabilities: expected an array of capability names.");
    }
    explicitCapabilitySet = new Set<TCapability>();
    for (const cap of config.capabilities) {
      if (!isSafeKey<TCapability>(cap)) {
        throw new Error(`Invalid capability '${String(cap)}' in capabilities.`);
      }
      explicitCapabilitySet.add(cap);
    }
    explicitCapabilities = Array.from(explicitCapabilitySet);
  }

  const referencedCapabilitySet = new Set<TCapability>();
  const registerReferencedCapability = (cap: TCapability | undefined): void => {
    if (!cap || !isSafeKey<TCapability>(cap)) return;
    if (explicitCapabilitySet && !explicitCapabilitySet.has(cap)) {
      throw new Error(`Capability '${cap}' referenced in policy is not listed in 'capabilities'.`);
    }
    referencedCapabilitySet.add(cap);
  };

  for (const [, def] of entries) {
    if (Array.isArray(def.capabilities)) {
      for (const cap of def.capabilities) {
        if (!isSafeKey<TCapability>(cap)) {
          throw new Error(`Invalid capability '${String(cap)}' in role capabilities.`);
        }
        registerReferencedCapability(cap);
      }
    }
  }

  // Validate explicit `inherits` references and compute transitive closure with cycle detection (DFS)
  const roleInherits = Object.create(null) as Record<TRole, readonly TRole[]>;
  const resolvedCapabilities = Object.create(null) as Partial<Record<TRole, readonly TCapability[]>>;
  const resolvedTrackPresence = Object.create(null) as Record<TRole, boolean>;
  const visitState = new Map<TRole, "visiting" | "visited">();
  const wildcardRoles = new Set<TRole>();

  function resolveRoleGraph(role: TRole, chain: TRole[]): void {
    const state = visitState.get(role);
    if (state === "visited") return;
    if (state === "visiting") {
      throw new Error(`Circular role inheritance detected: ${[...chain, role].join(" -> ")}`);
    }

    visitState.set(role, "visiting");
    const def = rawRoles[role];
    const directParents = Array.isArray(def.inherits) ? def.inherits : [];
    const ancestors = new Set<TRole>();

    for (const parent of directParents) {
      if (typeof parent !== "string" || FORBIDDEN_PROTOTYPE_KEYS.has(parent) || !Object.hasOwn(rawRoles, parent)) {
        throw new Error(`Role '${role}' inherits from unknown role '${String(parent)}'.`);
      }
      const parentRole = parent as TRole;
      if (parentRole === role) {
        throw new Error(`Circular role inheritance detected: ${role} -> ${role}`);
      }
      resolveRoleGraph(parentRole, [...chain, role]);
      ancestors.add(parentRole);
      for (const grandParent of roleInherits[parentRole] || []) {
        ancestors.add(grandParent);
      }
    }

    roleInherits[role] = Object.freeze(Array.from(ancestors));

    // Resolve implied capabilities (direct + inherited)
    let hasWildcard = def.capabilities === "*";
    const capSet = new Set<TCapability>(Array.isArray(def.capabilities) ? def.capabilities : []);
    for (const ancestor of ancestors) {
      if (wildcardRoles.has(ancestor)) {
        hasWildcard = true;
      }
      const ancCaps = resolvedCapabilities[ancestor];
      if (Array.isArray(ancCaps)) {
        for (const c of ancCaps) {
          capSet.add(c);
        }
      }
    }

    if (hasWildcard) {
      wildcardRoles.add(role);
      resolvedCapabilities[role] = Object.freeze([...(explicitCapabilities ?? [])]);
    } else if (def.capabilities !== undefined || capSet.size > 0) {
      resolvedCapabilities[role] = Object.freeze(Array.from(capSet));
    }

    // Resolve trackPresence: explicit boolean on `role` wins; otherwise inherits `true` from any ancestor
    if (def.trackPresence !== undefined) {
      resolvedTrackPresence[role] = Boolean(def.trackPresence);
    } else {
      let inheritedTrack = false;
      for (const ancestor of ancestors) {
        if (resolvedTrackPresence[ancestor]) {
          inheritedTrack = true;
          break;
        }
      }
      resolvedTrackPresence[role] = inheritedTrack;
    }

    visitState.set(role, "visited");
  }

  for (const [role] of entries) {
    resolveRoleGraph(role, []);
  }

  const roles = Object.create(null) as Record<TRole, Readonly<RoleDefinition<TRole, TCapability>>>;
  for (const [role, def] of entries) {
    roles[role] = Object.freeze({
      ...(def.inherits !== undefined ? { inherits: Object.freeze([...def.inherits]) } : {}),
      ...(resolvedCapabilities[role] !== undefined ? { capabilities: resolvedCapabilities[role] } : {}),
      trackPresence: resolvedTrackPresence[role],
      ...(def.abstract !== undefined ? { abstract: Boolean(def.abstract) } : {}),
      ...(def.systemManaged !== undefined ? { systemManaged: Boolean(def.systemManaged) } : {})
    });
  }

  const assignableEntries = entries.filter(([, def]) => !def.abstract);
  if (entries.length > 0 && assignableEntries.length === 0) {
    throw new Error("PermissionPolicyConfig requires at least one concrete (non-abstract) role in roles.");
  }
  const assignableRoles = Object.freeze(assignableEntries.map(([r]) => r));

  if (Array.isArray(config.defaultRoles)) {
    for (const r of config.defaultRoles) {
      if (typeof r === "string" && Object.hasOwn(roles, r) && roles[r as TRole].abstract) {
        throw new Error(`Invalid defaultRoles '${r}': abstract roles cannot be used in defaultRoles.`);
      }
    }
  }

  // Normalize userCapabilities, attributeCapabilities, hiddenAttributeCapabilities & secretCapabilities
  let userRule: NormalizedUserRule<TCapability> = Object.freeze({});
  if (config.userCapabilities) {
    if (typeof config.userCapabilities === "string" && isSafeKey(config.userCapabilities)) {
      userRule = Object.freeze({
        read: config.userCapabilities as TCapability,
        write: config.userCapabilities as TCapability,
        assignRoles: config.userCapabilities as TCapability
      });
    } else if (typeof config.userCapabilities === "object" && !Array.isArray(config.userCapabilities)) {
      userRule = Object.freeze({
        ...(config.userCapabilities.read && isSafeKey(config.userCapabilities.read)
          ? { read: config.userCapabilities.read }
          : {}),
        ...(config.userCapabilities.write && isSafeKey(config.userCapabilities.write)
          ? { write: config.userCapabilities.write }
          : {}),
        ...(config.userCapabilities.assignRoles && isSafeKey(config.userCapabilities.assignRoles)
          ? { assignRoles: config.userCapabilities.assignRoles }
          : {})
      });
    }
  }

  // When non-admins can assign roles or manage users, rank (which comes only from `inherits`) limits whom they can act
  // on. A role with every capability is clearly meant to be top rank, so refuse one that couldn't assign or manage some
  // role rather than letting those actions fail at runtime.
  if (userRule.assignRoles || userRule.write) {
    for (const role of wildcardRoles) {
      if (rawRoles[role].abstract) continue;
      for (const [other, def] of entries) {
        // Roles ranked above this one (they inherit it, like a superowner over owner) are meant to be out of its reach
        if (
          other === role ||
          def.abstract ||
          def.systemManaged ||
          roleInherits[role].includes(other) ||
          roleInherits[other].includes(role)
        ) {
          continue;
        }
        throw new Error(
          `Role '${role}' has every capability but can't assign or manage '${other}': rank follows inherits, ` +
            `so add '${other}' to ${role}'s inherits (directly or through a role it inherits), or rank '${other}' ` +
            `above it by having '${other}' inherit '${role}'.`
        );
      }
    }
  }

  const attrRules = normalizeFieldWriteRules("attributeCapabilities", config.attributeCapabilities);
  const hiddenAttrRules = normalizeFieldWriteRules("hiddenAttributeCapabilities", config.hiddenAttributeCapabilities);

  const secretRules = Object.create(null) as Record<string, NormalizedSecretRule<TCapability>>;
  if (config.secretCapabilities && typeof config.secretCapabilities === "object") {
    for (const [key, rule] of Object.entries(config.secretCapabilities)) {
      if (!isSafeKey(key)) throw new Error(`Invalid secretCapabilities key '${key}'.`);
      if (typeof rule === "string") {
        if (!isSafeKey(rule)) throw new Error(`Invalid secretCapabilities.${key}: invalid capability '${rule}'.`);
        secretRules[key] = Object.freeze({ capability: rule as TCapability });
      } else if (rule && typeof rule === "object" && !Array.isArray(rule)) {
        // The old shape defaulted to self-writable; reject it so the flipped default can't pass unnoticed
        if ("write" in rule || "allowSelfWrite" in rule) {
          throw new Error(
            `Invalid secretCapabilities.${key}: 'write' and 'allowSelfWrite' were replaced by ` +
              `{ capability?, self? } (self-writing is now opt-in with self: true; {} means server-only).`
          );
        }
        secretRules[key] = Object.freeze({
          ...(rule.self ? { self: true } : {}),
          ...(rule.capability && isSafeKey(rule.capability) ? { capability: rule.capability } : {})
        });
      } else {
        throw new Error(`Invalid secretCapabilities.${key}: expected a capability or { capability?, self? }.`);
      }
    }
  }
  const secretKeys: readonly string[] = Object.freeze(Object.keys(secretRules));

  Object.freeze(roles);
  Object.freeze(resolvedCapabilities);
  Object.freeze(roleInherits);

  // Normalize storage-tier configuration: staff capability, scoped card visibility, card field placement, custom docs
  const staffCapability: TCapability | undefined =
    config.staffCapability && isSafeKey(config.staffCapability) ? config.staffCapability : undefined;

  let cardVisibility: CardVisibilityRule<TCapability> = "members";
  if (config.cardVisibility === "members" || config.cardVisibility === "staff") {
    cardVisibility = config.cardVisibility;
  } else if (config.cardVisibility !== undefined) {
    const capability =
      typeof config.cardVisibility === "object" && config.cardVisibility !== null
        ? config.cardVisibility.capability
        : undefined;
    if (!capability || !isSafeKey(capability)) {
      throw new Error('Invalid cardVisibility: expected "members", "staff", or { capability }.');
    }
    cardVisibility = Object.freeze({ capability });
  }

  const cardAttributeKeys = Array.isArray(config.cardFields?.attributes)
    ? Array.from(new Set(config.cardFields!.attributes.filter(isSafeKey)))
    : [];
  if (cardAttributeKeys.includes("email")) {
    throw new Error("Invalid cardFields.attributes: 'email' is not an attribute; use cardFields.email instead.");
  }
  const cardFields = Object.freeze({
    email: Boolean(config.cardFields?.email),
    attributes: Object.freeze(cardAttributeKeys)
  });
  const cardAttributeSet = new Set<string>(cardAttributeKeys);

  const customDocs = Object.create(null) as Record<string, Readonly<CustomDocDefinition<TCapability>>>;
  if (config.customDocs && typeof config.customDocs === "object") {
    for (const [name, def] of Object.entries(config.customDocs)) {
      if (!isSafeKey(name) || !/^[A-Za-z0-9_-]+$/.test(name)) {
        throw new Error(`Invalid customDocs name '${name}': use letters, digits, '_' or '-'.`);
      }
      if (RESERVED_TIER_NAMES.has(name)) {
        throw new Error(`Invalid customDocs name '${name}': reserved for a built-in storage tier.`);
      }
      if (!def || typeof def !== "object") {
        throw new Error(`Invalid definition for customDocs '${name}'.`);
      }
      customDocs[name] = Object.freeze({
        read: normalizeCustomDocRule(def.read),
        write: normalizeCustomDocRule(def.write)
      });
    }
  }
  Object.freeze(customDocs);

  registerReferencedCapability(userRule.read);
  registerReferencedCapability(userRule.write);
  registerReferencedCapability(userRule.assignRoles);
  registerReferencedCapability(staffCapability);
  if (typeof cardVisibility === "object") {
    registerReferencedCapability(cardVisibility.capability);
  }
  for (const key of Object.keys(attrRules)) {
    registerReferencedCapability(attrRules[key].write);
  }
  for (const key of Object.keys(hiddenAttrRules)) {
    registerReferencedCapability(hiddenAttrRules[key].write);
  }
  for (const key of Object.keys(secretRules)) {
    registerReferencedCapability(secretRules[key].capability);
  }
  for (const name of Object.keys(customDocs)) {
    registerReferencedCapability(customDocs[name].read.capability);
    registerReferencedCapability(customDocs[name].write.capability);
  }

  const capabilities: readonly TCapability[] = Object.freeze(
    explicitCapabilities ?? Array.from(referencedCapabilitySet)
  );

  // Default roles are only what a newly provisioned record starts with: exactly the listed roles, or none
  const resolvedDefaultRoles: TRole[] = [];
  for (const r of Array.isArray(config.defaultRoles) ? config.defaultRoles : []) {
    if (typeof r !== "string" || !Object.hasOwn(roles, r)) {
      throw new Error(`Invalid defaultRoles '${String(r)}': role is not defined in roles.`);
    }
    if (!resolvedDefaultRoles.includes(r as TRole)) resolvedDefaultRoles.push(r as TRole);
  }
  const defaultRoles: readonly TRole[] = Object.freeze(resolvedDefaultRoles);

  function isAssignableRole(role: TRole): boolean {
    if (typeof role !== "string" || !Object.hasOwn(roles, role)) return false;
    return !roles[role].abstract;
  }

  function hasRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    requiredRole: TRole,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !Array.isArray(member.roles) || typeof requiredRole !== "string") return false;
    if (!Object.hasOwn(roles, requiredRole)) return false;
    return member.roles.some(
      (role: TRole) =>
        typeof role === "string" &&
        Object.hasOwn(roles, role) &&
        (role === requiredRole || roleInherits[role as TRole].includes(requiredRole))
    );
  }

  function hasAnyRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    requiredRoles: readonly TRole[],
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !Array.isArray(requiredRoles) || requiredRoles.length === 0) return false;
    return requiredRoles.some((req) => hasRole(member, req, false));
  }

  function hasAllRoles(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    requiredRoles: readonly TRole[],
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !Array.isArray(requiredRoles)) return false;
    return requiredRoles.every((req) => hasRole(member, req, false));
  }

  function roleImpliesCapability(role: TRole, capability: TCapability): boolean {
    if (typeof role !== "string" || !Object.hasOwn(resolvedCapabilities, role)) return false;
    const implied = resolvedCapabilities[role];
    return Array.isArray(implied) && implied.includes(capability);
  }

  function hasCapability(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    capability: TCapability,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !isSafeKey(capability) || !Array.isArray(member.roles)) return false;
    return member.roles.some((role) => roleImpliesCapability(role, capability));
  }

  function hasAnyCapability(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !Array.isArray(capabilities) || capabilities.length === 0) return false;
    return capabilities.some((cap) => hasCapability(member, cap, false));
  }

  function hasAllCapabilities(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !Array.isArray(capabilities)) return false;
    return capabilities.every((cap) => hasCapability(member, cap, false));
  }

  function shouldTrackPresence(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || typeof member !== "object") return false;
    const effectiveRoles = Array.isArray(member.roles) ? member.roles : [];
    return effectiveRoles.some(
      (role: TRole) =>
        typeof role === "string" && Object.hasOwn(roles, role) && Boolean(roles[role as TRole]?.trackPresence)
    );
  }

  function canReadUser(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    options: { isSystemAdmin?: boolean; isSelf?: boolean } = {}
  ): boolean {
    const { isSystemAdmin = false, isSelf = false } = options;
    if (isSystemAdmin || isSelf) return true;
    if (!userRule.read) return false;
    return hasCapability(actor, userRule.read, false);
  }

  function canWriteUser(actor: PolicySubject<TRole, TCapability> | null | undefined, isSystemAdmin = false): boolean {
    if (isSystemAdmin) return true;
    if (!userRule.write) return false;
    return hasCapability(actor, userRule.write, false);
  }

  function canAssignRoles(actor: PolicySubject<TRole, TCapability> | null | undefined, isSystemAdmin = false): boolean {
    if (isSystemAdmin) return true;
    if (!userRule.assignRoles) return false;
    return hasCapability(actor, userRule.assignRoles, false);
  }

  function isSystemManagedRole(role: TRole): boolean {
    return typeof role === "string" && Object.hasOwn(roles, role) && Boolean(roles[role].systemManaged);
  }

  function canAssignRole(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    role: TRole,
    isSystemAdmin = false
  ): boolean {
    if (!isAssignableRole(role) || isSystemManagedRole(role)) return false;
    if (isSystemAdmin) return true;
    return canAssignRoles(actor, false) && hasRole(actor, role, false);
  }

  function getAssignableRoles(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    isSystemAdmin = false
  ): readonly TRole[] {
    return assignableRoles.filter((role) => canAssignRole(actor, role, isSystemAdmin));
  }

  function isStaff(actor: PolicySubject<TRole, TCapability> | null | undefined, isSystemAdmin = false): boolean {
    if (isSystemAdmin) return true;
    if (!staffCapability) return false;
    return hasCapability(actor, staffCapability, false);
  }

  function canReadTier(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    tier: LanyardTier,
    options: { isSystemAdmin?: boolean; isSelf?: boolean; isGlobal?: boolean; isScopeMember?: boolean } = {}
  ): boolean {
    const { isSystemAdmin = false, isSelf = false, isGlobal = false, isScopeMember = false } = options;
    switch (tier) {
      case "card":
        if (isSystemAdmin || isSelf) return true;
        if (isGlobal) return canReadUser(actor);
        if (cardVisibility === "members") return isScopeMember;
        if (cardVisibility === "staff") return isStaff(actor);
        return hasCapability(actor, cardVisibility.capability, false);
      case "preferences":
        return isSystemAdmin || isSelf;
      case "attributes":
        return isSystemAdmin || isSelf || isStaff(actor);
      case "hiddenAttributes":
        return isStaff(actor, isSystemAdmin);
      case "secrets":
        return false;
      default:
        return false;
    }
  }

  function isCardAttribute(key: string): boolean {
    return isSafeKey(key) && cardAttributeSet.has(key);
  }

  function evaluateCustomDocRule(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    rule: Readonly<CustomDocAccessRule<TCapability>>,
    isSystemAdmin: boolean,
    isSelf: boolean
  ): boolean {
    if (isSystemAdmin) return true;
    if (rule.self && isSelf) return true;
    if (rule.staff && isStaff(actor)) return true;
    if (rule.capability && hasCapability(actor, rule.capability, false)) return true;
    return false;
  }

  function canReadCustomDoc(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    name: string,
    options: { isSystemAdmin?: boolean; isSelf?: boolean } = {}
  ): boolean {
    if (!isSafeKey(name) || !Object.hasOwn(customDocs, name)) return false;
    return evaluateCustomDocRule(actor, customDocs[name].read, Boolean(options.isSystemAdmin), Boolean(options.isSelf));
  }

  function canWriteCustomDoc(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    name: string,
    options: { isSystemAdmin?: boolean; isSelf?: boolean } = {}
  ): boolean {
    if (!isSafeKey(name) || !Object.hasOwn(customDocs, name)) return false;
    return evaluateCustomDocRule(
      actor,
      customDocs[name].write,
      Boolean(options.isSystemAdmin),
      Boolean(options.isSelf)
    );
  }

  function canReadAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    options: { isSystemAdmin?: boolean; isSelf?: boolean; canReadCard?: boolean } = {}
  ): boolean {
    if (!isSafeKey(key)) return false;
    if (canReadTier(actor, "attributes", options)) return true;
    return Boolean(options.canReadCard) && cardAttributeSet.has(key);
  }

  function canWriteAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    isSystemAdmin = false
  ): boolean {
    if (!isSafeKey(key)) return false;
    if (isSystemAdmin) return true;
    const rule = Object.hasOwn(attrRules, key) ? attrRules[key] : undefined;
    if (!rule?.write) return false;
    return hasCapability(actor, rule.write, false);
  }

  function extractPatchKeys(patch: Record<string, any>): string[] | null {
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return null;
    // Detect own `__proto__`, `constructor`, or `prototype` properties even if defined via Object.defineProperty
    const ownNames = Object.getOwnPropertyNames(patch);
    if (ownNames.length === 0) return null;
    for (const k of ownNames) {
      if (!isSafeKey(k)) return null;
    }
    return ownNames;
  }

  function canWriteAttributesPatch(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    patch: Record<string, any>,
    isSystemAdmin = false
  ): boolean {
    const keys = extractPatchKeys(patch);
    if (!keys) return false;
    return keys.every((k) => canWriteAttribute(actor, k, isSystemAdmin));
  }

  function canReadHiddenAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    isSystemAdmin = false
  ): boolean {
    if (!isSafeKey(key)) return false;
    return canReadTier(actor, "hiddenAttributes", { isSystemAdmin });
  }

  function canWriteHiddenAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    isSystemAdmin = false
  ): boolean {
    if (!isSafeKey(key)) return false;
    if (isSystemAdmin) return true;
    const rule = Object.hasOwn(hiddenAttrRules, key) ? hiddenAttrRules[key] : undefined;
    if (!rule?.write) return false;
    return hasCapability(actor, rule.write, false);
  }

  function canWriteHiddenAttributesPatch(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    patch: Record<string, any>,
    isSystemAdmin = false
  ): boolean {
    const keys = extractPatchKeys(patch);
    if (!keys) return false;
    return keys.every((k) => canWriteHiddenAttribute(actor, k, isSystemAdmin));
  }

  function canWriteSecret(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    options: boolean | { isSystemAdmin?: boolean; isSelf?: boolean } = false
  ): boolean {
    if (!isSafeKey(key)) return false;
    const isSystemAdmin = typeof options === "boolean" ? options : Boolean(options?.isSystemAdmin);
    const isSelf = typeof options === "object" && options !== null ? Boolean(options.isSelf) : false;

    // Closed world: an undeclared key doesn't exist, so nobody (not even a system admin) can write it
    const rule = Object.hasOwn(secretRules, key) ? secretRules[key] : undefined;
    if (!rule) return false;
    if (isSystemAdmin) return true;
    if (isSelf && rule.self) return true;
    return Boolean(rule.capability && hasCapability(actor, rule.capability, false));
  }

  function canWriteSecretsPatch(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    patch: Record<string, any>,
    options: boolean | { isSystemAdmin?: boolean; isSelf?: boolean } = false
  ): boolean {
    const keys = extractPatchKeys(patch);
    if (!keys) return false;
    return keys.every((k) => canWriteSecret(actor, k, options));
  }

  function filterReadableAttributes<TAttributes extends Record<string, any>>(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    attributes: Partial<TAttributes> | null | undefined,
    options: { isSystemAdmin?: boolean; isSelf?: boolean; canReadCard?: boolean } = {}
  ): Partial<TAttributes> {
    const result: Record<string, any> = {};
    if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) {
      return result as Partial<TAttributes>;
    }
    for (const [k, v] of Object.entries(attributes)) {
      if (canReadAttribute(actor, k, options)) {
        result[k] = v;
      }
    }
    return result as Partial<TAttributes>;
  }

  function filterReadableHiddenAttributes<THiddenAttributes extends Record<string, any>>(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    hiddenAttributes: Partial<THiddenAttributes> | null | undefined,
    isSystemAdmin = false
  ): Partial<THiddenAttributes> {
    const result: Record<string, any> = {};
    if (!hiddenAttributes || typeof hiddenAttributes !== "object" || Array.isArray(hiddenAttributes)) {
      return result as Partial<THiddenAttributes>;
    }
    for (const [k, v] of Object.entries(hiddenAttributes)) {
      if (canReadHiddenAttribute(actor, k, isSystemAdmin)) {
        result[k] = v;
      }
    }
    return result as Partial<THiddenAttributes>;
  }

  return Object.freeze({
    capabilities,
    roles,
    roleCapabilities: resolvedCapabilities,
    roleInherits,
    assignableRoles,
    defaultRoles,
    secretKeys,
    userCapabilities: userRule,
    staffCapability,
    cardVisibility,
    cardFields,
    customDocs,
    isAssignableRole,
    isSystemManagedRole,
    canAssignRole,
    getAssignableRoles,
    hasRole,
    hasAnyRole,
    hasAllRoles,
    hasCapability,
    hasAnyCapability,
    hasAllCapabilities,
    shouldTrackPresence,
    canReadUser,
    canWriteUser,
    canAssignRoles,
    isStaff,
    canReadTier,
    isCardAttribute,
    canReadCustomDoc,
    canWriteCustomDoc,
    canReadAttribute,
    canWriteAttribute,
    canWriteAttributesPatch,
    canReadHiddenAttribute,
    canWriteHiddenAttribute,
    canWriteHiddenAttributesPatch,
    canWriteSecret,
    canWriteSecretsPatch,
    filterReadableAttributes,
    filterReadableHiddenAttributes
  });
}

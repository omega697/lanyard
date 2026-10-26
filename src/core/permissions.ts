import type {
  FieldCapabilityRule,
  PermissionPolicy,
  PermissionPolicyConfig,
  PolicySubject,
  RoleDefinition
} from "./models.js";

const FORBIDDEN_PROTOTYPE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isSafeKey(key: unknown): key is string {
  return typeof key === "string" && key.trim().length > 0 && !FORBIDDEN_PROTOTYPE_KEYS.has(key);
}

interface NormalizedFieldRule<TCapability extends string> {
  read?: TCapability;
  write?: TCapability;
}

interface NormalizedUserRule<TCapability extends string> extends NormalizedFieldRule<TCapability> {
  assignRoles?: TCapability;
}

interface NormalizedSecretRule<TCapability extends string> {
  write?: TCapability;
  allowSelfWrite?: boolean;
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
    rawRoles[role] = def;
  }

  // Validate explicit `inherits` references and compute transitive closure with cycle detection (DFS)
  const roleInherits = Object.create(null) as Record<TRole, readonly TRole[]>;
  const resolvedCapabilities = Object.create(null) as Partial<Record<TRole, readonly TCapability[] | "*">>;
  const resolvedTrackPresence = Object.create(null) as Record<TRole, boolean>;
  const visitState = new Map<TRole, "visiting" | "visited">();

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
      const ancCaps = resolvedCapabilities[ancestor];
      if (ancCaps === "*") {
        hasWildcard = true;
      } else if (Array.isArray(ancCaps)) {
        for (const c of ancCaps) {
          capSet.add(c);
        }
      }
    }

    if (hasWildcard) {
      resolvedCapabilities[role] = "*";
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
      ...(def.abstract !== undefined ? { abstract: Boolean(def.abstract) } : {})
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

  const attrRules = Object.create(null) as Record<string, NormalizedFieldRule<TCapability>>;
  if (config.attributeCapabilities && typeof config.attributeCapabilities === "object") {
    for (const [key, rule] of Object.entries(config.attributeCapabilities)) {
      if (!isSafeKey(key) || !rule) continue;
      if (typeof rule === "string") {
        // String shorthand on attributeCapabilities gates writes while leaving reads open to self/readers
        attrRules[key] = Object.freeze({ write: rule as TCapability });
      } else if (typeof rule === "object") {
        attrRules[key] = Object.freeze({
          ...(rule.read ? { read: rule.read } : {}),
          ...(rule.write ? { write: rule.write } : {})
        });
      }
    }
  }

  const hiddenAttrRules = Object.create(null) as Record<string, NormalizedFieldRule<TCapability>>;
  if (config.hiddenAttributeCapabilities && typeof config.hiddenAttributeCapabilities === "object") {
    for (const [key, rule] of Object.entries(config.hiddenAttributeCapabilities)) {
      if (!isSafeKey(key) || !rule) continue;
      if (typeof rule === "string") {
        // String shorthand on hiddenAttributeCapabilities gates BOTH read and write
        hiddenAttrRules[key] = Object.freeze({ read: rule as TCapability, write: rule as TCapability });
      } else if (typeof rule === "object") {
        hiddenAttrRules[key] = Object.freeze({
          ...(rule.read ? { read: rule.read } : {}),
          ...(rule.write ? { write: rule.write } : {})
        });
      }
    }
  }

  const secretRules = Object.create(null) as Record<string, NormalizedSecretRule<TCapability>>;
  if (config.secretCapabilities && typeof config.secretCapabilities === "object") {
    for (const [key, rule] of Object.entries(config.secretCapabilities)) {
      if (!isSafeKey(key) || !rule) continue;
      if (typeof rule === "string") {
        secretRules[key] = Object.freeze({ write: rule as TCapability });
      } else if (typeof rule === "object") {
        secretRules[key] = Object.freeze({
          ...(rule.write ? { write: rule.write } : {}),
          ...(rule.allowSelfWrite !== undefined ? { allowSelfWrite: Boolean(rule.allowSelfWrite) } : {})
        });
      }
    }
  }

  Object.freeze(roles);
  Object.freeze(resolvedCapabilities);
  Object.freeze(roleInherits);

  // Default to explicit config.defaultRoles or [rootConcreteRole] (or [] when no roles are defined)
  const rootConcreteRole =
    assignableEntries.length > 0
      ? (assignableEntries.find(([, def]) => !Array.isArray(def.inherits) || def.inherits.length === 0)?.[0] ??
        assignableEntries[0][0])
      : undefined;
  let resolvedDefaultRoles: TRole[];
  if (Array.isArray(config.defaultRoles)) {
    const valid = Array.from(
      new Set(config.defaultRoles.filter((r): r is TRole => typeof r === "string" && Object.hasOwn(roles, r)))
    );
    if (config.defaultRoles.length === 0) {
      resolvedDefaultRoles = [];
    } else if (valid.length > 0) {
      resolvedDefaultRoles = valid;
    } else {
      resolvedDefaultRoles = rootConcreteRole !== undefined ? [rootConcreteRole] : [];
    }
  } else {
    resolvedDefaultRoles = rootConcreteRole !== undefined ? [rootConcreteRole] : [];
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
    if (!implied) return false;
    if (implied === "*") return true;
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
    const effectiveRoles = member.roles === undefined ? defaultRoles : Array.isArray(member.roles) ? member.roles : [];
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

  function canReadAttribute(
    actor: PolicySubject<TRole, TCapability> | null | undefined,
    key: string,
    options: { isSystemAdmin?: boolean; isSelf?: boolean } = {}
  ): boolean {
    if (!isSafeKey(key)) return false;
    const { isSystemAdmin = false, isSelf = false } = options;
    if (isSystemAdmin || isSelf) return true;
    const rule = Object.hasOwn(attrRules, key) ? attrRules[key] : undefined;
    if (rule?.read) {
      return hasCapability(actor, rule.read, false);
    }
    return true;
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
    if (isSystemAdmin) return true;
    const rule = Object.hasOwn(hiddenAttrRules, key) ? hiddenAttrRules[key] : undefined;
    if (!rule?.read) return false;
    return hasCapability(actor, rule.read, false);
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

    if (isSystemAdmin) return true;
    const rule = Object.hasOwn(secretRules, key) ? secretRules[key] : undefined;
    if (!rule) {
      // Unconfigured secret keys default to user-owned (`isSelf === true`)
      return isSelf;
    }
    if (isSelf && rule.allowSelfWrite !== false) {
      return true;
    }
    if (rule.write && hasCapability(actor, rule.write, false)) {
      return true;
    }
    return false;
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
    options: { isSystemAdmin?: boolean; isSelf?: boolean } = {}
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
    roles,
    roleCapabilities: resolvedCapabilities,
    roleInherits,
    assignableRoles,
    defaultRoles,
    isAssignableRole,
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

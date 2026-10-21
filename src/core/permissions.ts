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

interface NormalizedSecretRule<TCapability extends string> {
  write?: TCapability;
  allowSelfWrite?: boolean;
}

/**
 * Creates a reusable `PermissionPolicy<TRole, TCapability>` that defines an application's
 * role hierarchy (`weight`), explicit role inheritance (`inherits`), role-implied capabilities (`capabilities`),
 * role-level presence heartbeat tracking (`trackPresence`), and field-level `attributes` / `secrets` rules.
 */
export function createPermissionPolicy<TRole extends string = string, TCapability extends string = string>(
  config: PermissionPolicyConfig<TRole, TCapability>
): PermissionPolicy<TRole, TCapability> {
  const { roles: inputRoles } = config;
  const entries = Object.entries(inputRoles || {}).filter(([role]) => !FORBIDDEN_PROTOTYPE_KEYS.has(role)) as [
    TRole,
    RoleDefinition<TRole, TCapability>
  ][];
  if (entries.length === 0) {
    throw new Error("PermissionPolicyConfig requires at least one role in roles.");
  }

  const rawRoles = Object.create(null) as Record<TRole, RoleDefinition<TRole, TCapability>>;
  const roleWeights = Object.create(null) as Record<TRole, number>;

  for (const [role, def] of entries) {
    if (!def || typeof def.weight !== "number" || Number.isNaN(def.weight)) {
      throw new Error(`Invalid weight for role '${role}'.`);
    }
    rawRoles[role] = def;
    roleWeights[role] = def.weight;
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
      weight: def.weight,
      ...(def.inherits !== undefined ? { inherits: Object.freeze([...def.inherits]) } : {}),
      ...(resolvedCapabilities[role] !== undefined ? { capabilities: resolvedCapabilities[role] } : {}),
      trackPresence: resolvedTrackPresence[role]
    });
  }

  // Normalize attributeCapabilities, hiddenAttributeCapabilities & secretCapabilities
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
  Object.freeze(roleWeights);
  Object.freeze(resolvedCapabilities);
  Object.freeze(roleInherits);

  const usesExplicitInheritance = entries.some(([, def]) => Array.isArray(def.inherits) && def.inherits.length > 0);

  // Default to explicit config.defaultRole or the lowest-weighted role
  const lowestRole = entries.reduce((min, cur) => (cur[1].weight < min[1].weight ? cur : min))[0];
  const defaultRole: TRole =
    config.defaultRole && Object.hasOwn(roles, config.defaultRole) ? config.defaultRole : lowestRole;

  function inheritsRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    targetRole: TRole,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || typeof member.role !== "string" || typeof targetRole !== "string") return false;
    if (!Object.hasOwn(roles, member.role) || !Object.hasOwn(roles, targetRole)) return false;
    if (member.role === targetRole) return true;
    return roleInherits[member.role].includes(targetRole);
  }

  function hasMinimumRole(
    member: PolicySubject<TRole, TCapability> | null | undefined,
    minimumRole: TRole,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || typeof member.role !== "string" || typeof minimumRole !== "string") return false;
    if (!Object.hasOwn(roleWeights, member.role) || !Object.hasOwn(roleWeights, minimumRole)) return false;
    if (inheritsRole(member, minimumRole, false)) return true;
    if (usesExplicitInheritance) return false;
    const userWeight = roleWeights[member.role];
    const requiredWeight = roleWeights[minimumRole];
    return userWeight > requiredWeight;
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
    if (!member || !isSafeKey(capability)) return false;
    if (member.role && roleImpliesCapability(member.role, capability)) {
      return true;
    }
    return Array.isArray(member.capabilities) && member.capabilities.includes(capability);
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
    if (!member || typeof member.role !== "string" || !Object.hasOwn(roles, member.role)) return false;
    return Boolean(roles[member.role]?.trackPresence);
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
    roleWeights,
    roleCapabilities: resolvedCapabilities,
    roleInherits,
    defaultRole,
    hasMinimumRole,
    inheritsRole,
    hasCapability,
    hasAnyCapability,
    hasAllCapabilities,
    shouldTrackPresence,
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

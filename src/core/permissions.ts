import type { PermissionPolicy, PermissionPolicyConfig, RoleDefinition, ScopedMember } from "./models.js";

const FORBIDDEN_PROTOTYPE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Creates a reusable `PermissionPolicy<TRole, TCapability>` that defines an application's
 * role hierarchy (`weight`), role-implied capabilities (`capabilities`), and role-level
 * presence heartbeat tracking (`trackPresence`).
 */
export function createPermissionPolicy<TRole extends string = string, TCapability extends string = string>(
  config: PermissionPolicyConfig<TRole, TCapability>
): PermissionPolicy<TRole, TCapability> {
  const { roles: inputRoles } = config;
  const entries = Object.entries(inputRoles).filter(([role]) => !FORBIDDEN_PROTOTYPE_KEYS.has(role)) as [
    TRole,
    RoleDefinition<TCapability>
  ][];
  if (entries.length === 0) {
    throw new Error("PermissionPolicyConfig requires at least one role in roles.");
  }

  const roles = Object.create(null) as Record<TRole, RoleDefinition<TCapability>>;
  const roleWeights = Object.create(null) as Record<TRole, number>;
  const roleCapabilities = Object.create(null) as Partial<Record<TRole, readonly TCapability[] | "*">>;

  for (const [role, def] of entries) {
    roles[role] = Object.freeze({
      weight: def.weight,
      ...(def.capabilities !== undefined
        ? { capabilities: Array.isArray(def.capabilities) ? Object.freeze([...def.capabilities]) : def.capabilities }
        : {}),
      ...(def.trackPresence !== undefined ? { trackPresence: Boolean(def.trackPresence) } : {})
    });
    roleWeights[role] = def.weight;
    if (def.capabilities !== undefined) {
      roleCapabilities[role] = roles[role].capabilities;
    }
  }

  Object.freeze(roles);
  Object.freeze(roleWeights);
  Object.freeze(roleCapabilities);

  // Default to explicit config.defaultRole or the lowest-weighted role
  const lowestRole = entries.reduce((min, cur) => (cur[1].weight < min[1].weight ? cur : min))[0];
  const defaultRole: TRole =
    config.defaultRole && Object.hasOwn(roles, config.defaultRole) ? config.defaultRole : lowestRole;

  function hasMinimumRole(
    member: Pick<ScopedMember<TRole, TCapability>, "role"> | null | undefined,
    minimumRole: TRole,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || typeof member.role !== "string" || typeof minimumRole !== "string") return false;
    if (!Object.hasOwn(roleWeights, member.role) || !Object.hasOwn(roleWeights, minimumRole)) return false;
    const userWeight = roleWeights[member.role];
    const requiredWeight = roleWeights[minimumRole];
    return userWeight >= requiredWeight;
  }

  function roleImpliesCapability(role: TRole, capability: TCapability): boolean {
    if (typeof role !== "string" || !Object.hasOwn(roleCapabilities, role)) return false;
    const implied = roleCapabilities[role];
    if (!implied) return false;
    if (implied === "*") return true;
    return Array.isArray(implied) && implied.includes(capability);
  }

  function hasCapability(
    member: Pick<ScopedMember<TRole, TCapability>, "role" | "capabilities"> | null | undefined,
    capability: TCapability,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || typeof capability !== "string") return false;
    if (member.role && roleImpliesCapability(member.role, capability)) {
      return true;
    }
    return Array.isArray(member.capabilities) && member.capabilities.includes(capability);
  }

  function hasAnyCapability(
    member: Pick<ScopedMember<TRole, TCapability>, "role" | "capabilities"> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !Array.isArray(capabilities) || capabilities.length === 0) return false;
    return capabilities.some((cap) => hasCapability(member, cap, false));
  }

  function hasAllCapabilities(
    member: Pick<ScopedMember<TRole, TCapability>, "role" | "capabilities"> | null | undefined,
    capabilities: readonly TCapability[],
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || !Array.isArray(capabilities)) return false;
    return capabilities.every((cap) => hasCapability(member, cap, false));
  }

  function shouldTrackPresence(
    member: Pick<ScopedMember<TRole, TCapability>, "role"> | null | undefined,
    isSystemAdmin = false
  ): boolean {
    if (isSystemAdmin) return true;
    if (!member || typeof member.role !== "string" || !Object.hasOwn(roles, member.role)) return false;
    return Boolean(roles[member.role]?.trackPresence);
  }

  return Object.freeze({
    roles,
    roleWeights,
    roleCapabilities,
    defaultRole,
    hasMinimumRole,
    hasCapability,
    hasAnyCapability,
    hasAllCapabilities,
    shouldTrackPresence
  });
}

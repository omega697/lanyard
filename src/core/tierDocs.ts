import { TIER_METADATA_KEY, type LanyardTier, type TierDocMetadata } from "./models.js";

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Throws if `patch` uses the key reserved for private tier document metadata (`_lanyard`).
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function assertNoReservedTierKeys(patch: Record<string, any>, label: string): void {
  if (Object.prototype.hasOwnProperty.call(patch, TIER_METADATA_KEY)) {
    throw new Error(`Invalid ${label} key '${TIER_METADATA_KEY}': reserved for Lanyard tier document metadata`);
  }
}

/**
 * Builds the metadata field Lanyard stamps on a private tier document write.
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function tierDocMetadata(
  tier: LanyardTier,
  uid: string,
  scopeId: string | null
): { [TIER_METADATA_KEY]: TierDocMetadata } {
  return { [TIER_METADATA_KEY]: { tier, uid, scopeId, updatedAt: new Date().toISOString() } };
}

/**
 * Extracts the user-defined values from a private tier document, dropping metadata and unsafe keys.
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function readTierDocValues<T extends Record<string, any>>(data: Record<string, any> | undefined): Partial<T> {
  const clean: Record<string, any> = {};
  for (const [k, v] of Object.entries(data || {})) {
    if (!FORBIDDEN_KEYS.has(k) && k !== TIER_METADATA_KEY && v !== undefined) {
      clean[k] = v;
    }
  }
  return clean as Partial<T>;
}

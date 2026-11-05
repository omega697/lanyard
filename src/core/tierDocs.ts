import {
  TIER_METADATA_KEY,
  type CardFieldsPlacement,
  type LanyardStorePlacementSource,
  type LanyardTier,
  type TierDocMetadata
} from "./models.js";

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Card placement used when a store is constructed without a policy: every field stays in its private tier. */
const NO_CARD_FIELDS: CardFieldsPlacement = Object.freeze({ email: false, attributes: Object.freeze([]) });

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

/**
 * Returns the store's card placement from its optional `policy`, defaulting to no card fields.
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function resolveCardFields(policy: LanyardStorePlacementSource | undefined): CardFieldsPlacement {
  return policy ? policy.cardFields : NO_CARD_FIELDS;
}

/**
 * Splits an `attributes` object into the keys placed on the card and the keys stored in the `attributes` tier.
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function splitAttributesByPlacement<T extends Record<string, any>>(
  attributes: Partial<T>,
  cardFields: CardFieldsPlacement
): { card: Partial<T>; tier: Partial<T> } {
  const card: Record<string, any> = {};
  const tier: Record<string, any> = {};
  for (const [k, v] of Object.entries(attributes)) {
    if (cardFields.attributes.includes(k)) card[k] = v;
    else tier[k] = v;
  }
  return { card: card as Partial<T>, tier: tier as Partial<T> };
}

/**
 * Throws if a store routes fields by a different card placement than the policy it is used with, which would
 * otherwise silently store fields where the policy (and generated security rules) don't expect them.
 * Stores that don't declare `cardFields` (custom implementations) are trusted to follow the policy.
 * @internal Used by `createLanyardServer` and `createLanyardClient`.
 */
export function assertStoreMatchesPolicyPlacement(
  store: { readonly cardFields?: CardFieldsPlacement },
  policyCardFields: CardFieldsPlacement
): void {
  const storeCardFields = store.cardFields;
  if (!storeCardFields) return;
  const sameAttributes =
    storeCardFields.attributes.length === policyCardFields.attributes.length &&
    storeCardFields.attributes.every((key) => policyCardFields.attributes.includes(key));
  if (storeCardFields.email !== policyCardFields.email || !sameAttributes) {
    throw new Error(
      "Store cardFields do not match the policy's cardFields. Pass the same policy to the store (e.g. " +
        "new FirestoreServerStore({ db, policy })) and to createLanyardServer/createLanyardClient."
    );
  }
}

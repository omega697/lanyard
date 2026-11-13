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
 * Throws if an `attributes` patch uses a reserved key: `_lanyard`, or `email` (stored alongside attributes in the
 * `attributes` tier document and written only through profile/email APIs).
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function assertNoReservedAttributeKeys(patch: Record<string, any>): void {
  assertNoReservedTierKeys(patch, "attributes");
  if (Object.prototype.hasOwnProperty.call(patch, "email")) {
    throw new Error("Invalid attributes key 'email': reserved for the user's email address");
  }
}

/**
 * Splits the values of an `attributes` tier document into its attributes and the stored `email`, if any.
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function splitAttributesTierValues<T extends Record<string, any>>(
  values: Record<string, any>
): { attributes: Partial<T>; email: string | undefined } {
  const { email, ...attributes } = values;
  return { attributes: attributes as Partial<T>, email: typeof email === "string" && email ? email : undefined };
}

/**
 * Builds the metadata field Lanyard stamps on a private tier document write.
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function tierDocMetadata(
  tier: LanyardTier | (string & {}),
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

const BUILT_IN_TIER_DOCS = new Set(["preferences", "attributes", "hiddenAttributes", "secrets"]);

/**
 * Throws unless `name` is a valid custom document name (letters, digits, `_` or `-`, and not a built-in tier).
 * @internal Shared by the Lanyard stores; not part of the public API.
 */
export function assertCustomDocName(name: unknown): string {
  if (typeof name !== "string" || !/^[A-Za-z0-9_-]+$/.test(name) || FORBIDDEN_KEYS.has(name)) {
    throw new Error(`Invalid custom doc name '${String(name)}'`);
  }
  if (BUILT_IN_TIER_DOCS.has(name) || name === "card") {
    throw new Error(`Invalid custom doc name '${name}': reserved for a built-in storage tier`);
  }
  return name;
}

/**
 * Validates a `queryMembers` attribute filter and returns where it must run: on cards (every key placed on the
 * card via `cardFields.attributes`) or in the `attributes` tier (no card-placed keys). Throws for empty filters,
 * reserved keys, and filters mixing both locations (Firestore can't query two documents at once).
 * @internal Shared by the Lanyard stores and facades; not part of the public API.
 */
export function resolveAttributeQueryLocation(
  attributes: Record<string, any> | null | undefined,
  cardFields: CardFieldsPlacement
): "card" | "attributes" {
  if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) {
    throw new Error("Invalid attributes filter: expected an object of attribute values");
  }
  const keys = Object.keys(attributes);
  if (keys.length === 0) throw new Error("Invalid attributes filter: at least one attribute is required");
  for (const key of keys) {
    if (FORBIDDEN_KEYS.has(key) || key === TIER_METADATA_KEY || key === "email") {
      throw new Error(`Invalid attributes filter key '${key}'`);
    }
    if (attributes[key] === undefined) throw new Error(`Invalid attributes filter: '${key}' is undefined`);
  }
  const onCard = keys.filter((key) => cardFields.attributes.includes(key));
  if (onCard.length === keys.length) return "card";
  if (onCard.length === 0) return "attributes";
  throw new Error(
    `Invalid attributes filter: card-placed keys (${onCard.join(", ")}) can't be combined with attributes-tier keys`
  );
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

/**
 * Throws if a server store's declared secret keys differ from the policy's, which would let the store write keys
 * the policy doesn't govern (or refuse ones it does). Stores that don't declare `secretKeys` (custom implementations)
 * are trusted to follow the policy.
 * @internal Used by `createLanyardServer`.
 */
export function assertStoreMatchesPolicySecretKeys(
  store: { readonly secretKeys?: readonly string[] },
  policySecretKeys: readonly string[]
): void {
  if (store.secretKeys === undefined) return;
  const same =
    store.secretKeys.length === policySecretKeys.length && store.secretKeys.every((k) => policySecretKeys.includes(k));
  if (!same) {
    throw new Error(
      "Store secret keys do not match the policy's secretCapabilities. Pass the same policy to the store (e.g. " +
        "new FirestoreServerStore({ db, policy })) and to createLanyardServer."
    );
  }
}

/** Resolves a store's declared secret keys from the policy it was given (none if it wasn't given one). */
export function resolveSecretKeys(source: { readonly secretKeys?: readonly string[] } | undefined): readonly string[] {
  return Object.freeze([...(source?.secretKeys ?? [])]);
}

/** Throws unless every key in a secrets patch is declared (stores are closed-world for secrets). */
export function assertDeclaredSecretKeys(secretKeys: readonly string[], patch: Record<string, unknown>): void {
  for (const key of Object.keys(patch || {})) {
    if (!secretKeys.includes(key)) {
      throw new Error(
        secretKeys.length === 0
          ? `Secret key '${key}' is not declared: pass a policy with secretCapabilities to the store to write secrets`
          : `Secret key '${key}' is not declared in policy.secretCapabilities`
      );
    }
  }
}

// Undeclared stored keys already warned about, as "location\0key", so a stray key doesn't log on every read. Bounded:
// once it holds MAX entries it starts over, so a store with stray keys on many users can't grow it without limit.
const MAX_WARNED_UNDECLARED_SECRET_KEYS = 1000;
const warnedUndeclaredSecretKeys = new Set<string>();

/**
 * Drops stored secret keys the policy doesn't declare, so nothing trusts them, warning once per location and key.
 */
export function withoutUndeclaredSecretKeys<T>(
  secretKeys: readonly string[],
  values: Record<string, T>,
  where: string
): Record<string, T> {
  const kept: Record<string, T> = {};
  for (const [key, value] of Object.entries(values)) {
    if (secretKeys.includes(key)) {
      kept[key] = value;
    } else if (!warnedUndeclaredSecretKeys.has(`${where}\0${key}`)) {
      if (warnedUndeclaredSecretKeys.size >= MAX_WARNED_UNDECLARED_SECRET_KEYS) warnedUndeclaredSecretKeys.clear();
      warnedUndeclaredSecretKeys.add(`${where}\0${key}`);
      console.warn(`[lanyard] Ignoring undeclared secret key '${key}' stored at ${where}`);
    }
  }
  return kept;
}

/**
 * Decrypts each stored secret separately, so one unreadable value (corrupted, or tampered with) is skipped with a
 * warning instead of hiding the user's other secrets. If none of the encrypted values can be decrypted, it throws,
 * because that usually means the master key is wrong rather than that every value is damaged.
 */
export function decryptSecretEntries(
  entries: readonly (readonly [string, unknown])[],
  decryptOne: (value: unknown) => string,
  where: string
): Record<string, string> {
  const out: Record<string, string> = {};
  let attempted = 0;
  let failed = 0;
  for (const [key, value] of entries) {
    if (typeof value === "string") {
      if (value.length > 0) out[key] = value;
      continue;
    }
    attempted += 1;
    try {
      out[key] = decryptOne(value);
    } catch (error) {
      failed += 1;
      console.warn(
        `[lanyard] Couldn't decrypt secret '${key}' stored at ${where}; skipping it: ` +
          (error instanceof Error ? error.message : String(error))
      );
    }
  }
  if (attempted > 0 && failed === attempted) {
    throw new Error(
      `Couldn't decrypt any secret stored at ${where}; check that the master encryption key matches the one they were written with`
    );
  }
  return out;
}

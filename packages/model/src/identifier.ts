/**
 * L0 identity (the UniDPP design framework invariant I1, I3): one subject, one identity, never
 * re-minted. Identifiers are scheme-agnostic (ISO/IEC 15459 primary; bridges
 * to GS1, Handle, Ecode, MA). Dormant identifiers are first-class: absorption
 * records at finest available granularity, future regimes adopt them.
 */

/** Registered identifier schemes (extensible via registry items). */
export type IdentifierScheme =
  | "iso-15459"
  | "gs1"
  | "gbt-33993"
  | "handle"
  | "ecode"
  | "ma"
  | (string & {}); // extension point: registry-registered schemes

/** EN 18219 granularity model/batch/item, plus lot for material batches. */
export type IdentifierGranularity = "model" | "type" | "batch" | "lot" | "item";

/**
 * I1 lifecycle state of an identifier. `dormant` -> `live` adoption only;
 * minting a fresh identifier where a dormant one exists orphans the record.
 */
export type IdentifierState = "dormant" | "live" | "consumed" | "retired";

export interface ProductIdentifier {
  /** Registry-registered scheme name, e.g. "iso-15459" or "gs1". */
  scheme: IdentifierScheme;
  /** Normalized value canonical for the scheme (see resolver/carrier). */
  value: string;
  granularity: IdentifierGranularity;
  state: IdentifierState;
}

/** Identity lattice (the UniDPP design framework "type-configuration lattice"). */
export interface TypeReference {
  /** Registered type (model) identifier. */
  typeId: ProductIdentifier;
  /** Exact type version — hardware revisions visible, no silent revision. */
  typeVersion: string;
  /** Configuration vector (CTO = model + options, each itself a model). */
  configurationVector?: string[];
}

export function identifierEquals(a: ProductIdentifier, b: ProductIdentifier): boolean {
  return a.scheme === b.scheme && a.value === b.value;
}

export function sameIdentity(a: ProductIdentifier, b: ProductIdentifier): boolean {
  // Granularity/state may differ across records of the same minted identity.
  return identifierEquals(a, b);
}

/**
 * L1 neutral core + L2 profile manifest (PLAN.md stream 11). The core is a
 * minimal skeleton; every regional requirement is a *profile*: a registered,
 * versioned object bound by dated applicability. Profile-set growth is dated
 * binding, never new identity (source invariant 9).
 */

import type { ProductIdentifier, TypeReference } from "./identifier.js";

/** Profile axis: jurisdiction x sector x characteristic (three-axial). */
export interface ProfileAxis {
  jurisdiction?: string; // ISO 3166-1 alpha-2 or region code, e.g. "EU", "JP"
  sector?: string; // e.g. "electronics", "batteries", "textiles"
  characteristic?: string; // predicate-triggered, e.g. "cites", "end-of-waste"
}

/** Characteristic-profile trigger predicate on twin facts (incl. time). */
export interface TriggerPredicate {
  kind: "regulatory" | "voluntary";
  /** Free-form predicate expression; Primmel-bound in the full registry. */
  expression?: string;
  /** Clock-fired applicability, e.g. age > 100 years. */
  timePredicate?: string;
}

/** A profile = registered, versioned object (FERIN/ISO 19135 item). */
export interface ProfileDefinition {
  profileId: string; // registry URI, e.g. "urn:unidpp:profile:eu-espr-electronics"
  version: string;
  owner: string; // regulator / NSB / scheme operator
  legalBasis?: string; // legal citation
  axis: ProfileAxis;
  trigger?: TriggerPredicate;
  /** Data-point list: references into the L3 semantic registry. */
  dataPoints: RegistryItemRef[];
  /** Registered transform bindings (Primmel packages, deterministic). */
  transforms?: RegistryItemRef[];
  languages: string[];
  trustRequirements?: TrustRequirements;
  resolution?: ProfileResolution;
}

export interface RegistryItemRef {
  register: string; // FERIN register URI
  item: string;
  version: string;
}

export interface TrustRequirements {
  /** Jurisdiction-bound crypto suites (PLAN.md L4): profile, not platform. */
  suites: string[]; // e.g. ["ecdsa-p256-sha256", "sm2-sm3", "ml-dsa-65"]
  trustList: string; // trust-list / master-list reference URI
  /** Minimum trust marker per data class; safety-critical must be attested. */
  minimumMarker?: import("./trust.js").TrustMarker;
}

/** Dark-identity / export-control-aware fields (confidential profiles). */
export interface ProfileResolution {
  confidential?: boolean;
  resolution: "none" | "national" | "restricted" | "public";
  edgeVisibility?: EdgeVisibilityClass;
  traversal: "none" | "authorityOnly" | "roleScoped" | "public";
}

/** Dated applicability window for a profile binding. */
export interface EffectiveWindow {
  from: string; // ISO 8601 date-time
  until?: string;
  retroactive?: boolean;
}

/** A profile bound to a passport at a point in time (manifest entry). */
export interface ProfileBinding {
  profileId: string;
  version: string;
  effective: EffectiveWindow;
  /** Registry applicability event that added this binding. */
  bindingEventId?: string;
}

export type PassportStatus =
  | "draft"
  | "active"
  | "suspended"
  | "non-conformant-pending-reevaluation"
  | "invalid"
  | "archived";

/** R3 child reference in the parent manifest (composition by reference). */
export interface ChildReference {
  childId: string; // resolvable URI, possibly at a different national register
  relationship: "installation" | "membership" | "derivation";
  slotId?: string;
  pairing?: PairingMode;
  binding?: InstallationBinding;
  visibility: VisibilityClause;
  /** True when the child reference points at a dormant identifier. */
  dormant?: boolean;
}

export type PairingMode = "none" | "firmware" | "key" | "module";

export interface InstallationBinding {
  method: string; // e.g. "socketed", "soldered", "bolted", "welded"
  recoverability: "restorable" | "harvestable" | "destructive" | "absorbing";
}

export type EdgeVisibilityClass = "public" | "restricted" | "blind" | "escrowed";

/** I12 enumeration resistance: edge visibility on every relationship. */
export interface VisibilityClause {
  edge: EdgeVisibilityClass;
  escrow?: "none" | "trustee";
  audiences?: string[]; // role-qualified audiences for `restricted`
}

/**
 * The neutral-core passport manifest (L1). EU fields do NOT live here; they
 * live in the EU profile. EN 18223 `contentSpecificationIds` is the EU's
 * proto-version of `profiles`; we generalize it.
 */
export interface PassportManifest {
  passportId: ProductIdentifier;
  subjectId: ProductIdentifier;
  /** Nullable for one-offs/prototypes and commissioned orphan objects. */
  typeRef?: TypeReference;
  status: PassportStatus;
  profiles: ProfileBinding[];
  children: ChildReference[];
  /** Pointer to the distributed event log + its current commitment. */
  eventLog: { logUri: string; commitment: string; height: number };
  /** Capability class of the subject (S0-S3; see capability.ts). */
  capabilityClass: import("./capability.js").CapabilityClass;
  asOf: string; // when this manifest view was rendered
}

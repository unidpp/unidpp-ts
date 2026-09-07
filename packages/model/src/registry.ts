/**
 * L3 semantic registry: FERIN federated registers per ISO 19135. Item
 * references are (register, item, version); statuses follow the 19135 item
 * lifecycle (simplified here to the operational core: valid / superseded /
 * retired, plus proposal for pre-validation states).
 */

export type RegistryItemStatus =
  | "proposal"
  | "under-review"
  | "valid"
  | "superseded"
  | "retired"
  | "invalid";

/** Simplified ISO 19135 register item (full 19135:2025 field set in spec). */
export interface RegistryItem {
  register: string; // FERIN register URI
  item: string; // item identifier within the register
  version: string;
  itemClass:
    | "data-element"
    | "profile"
    | "cryptographic-suite"
    | "trust-anchor"
    | "unit"
    | "transform"
    | "code-list";
  status: RegistryItemStatus;
  /** Governance dates (19135 lifecycle). */
  dates: { proposed: string; registered?: string; superseded?: string; retired?: string };
  supersededBy?: { register: string; item: string; version: string };
  /** Log-anchored definition content (CDDAL canonicalization host-stable). */
  definition: { uri: string; mediaType: "application/cddal" | "application/json" | "text/xml"; checksum: string };
}

/** Is the item usable for a binding effective at time `at`? */
export function itemEffectiveAt(item: RegistryItem, at: string): boolean {
  if (item.status === "invalid") return false;
  const registered = item.dates.registered ?? item.dates.proposed;
  if (at < registered) return false;
  const off = item.dates.superseded ?? item.dates.retired;
  return off === undefined ? true : at < off;
}

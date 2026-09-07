/**
 * I5 typed relationship algebra: passports are nodes, edges are typed
 * (R1-R7), and the types carry different legal/lifecycle semantics.
 * EXPRESS core shape: PassportLink {type, direction, interval,
 * binding: {method, recoverability}, slotId, pairing, alteration[]}.
 */
import type {
  EdgeVisibilityClass,
  InstallationBinding,
  PairingMode,
  VisibilityClause,
} from "./manifest.js";

export type RelationshipType =
  | "association" // R1 loose: navigational only, free add/remove
  | "derivation" // R2 ancestral: input->output transformation edges
  | "installation" // R3 structural: parent<->child, temporal
  | "type-lineage" // R4 identity lattice: type versioning, derived types
  | "custody" // R6 social/control: orthogonal to structure
  | "membership"; // R7 group nodes: shipments, kits, recall sets

export interface PassportLink {
  type: RelationshipType;
  from: string; // passport URI
  to: string; // passport URI
  direction: "up" | "down" | "symmetric";
  /** Temporal interval; R3/R7 are temporal, R2 historical, R1 point-in-time. */
  interval: { from: string; until?: string };
  /** R3 only: installation binding + slot identity. */
  binding?: InstallationBinding;
  slotId?: string;
  pairing?: PairingMode;
  /** Permanent alteration record (soldered, welded, potted...). */
  alteration?: string[];
  /** I12: every edge carries a visibility class. */
  visibility: VisibilityClause;
  /**
   * R3 proof-of-binding != knowledge-of-parent: salted commitment to the
   * parent (+ optional escrow envelope) in the child's log.
   */
  parentCommitment?: string;
}

export function isVisibleTo(link: PassportLink, audience: string): boolean {
  switch (link.visibility.edge) {
    case "public":
      return true;
    case "restricted":
      return (link.visibility.audiences ?? []).includes(audience);
    case "blind":
    case "escrowed":
      return false; // disclosure only by ceremony
  }
}

/**
 * Recall routing over the provenance DAG: downstream traversal
 * (trace-down: where did A's remainder go). Direction-aware: `up` edges
 * point child->parent, `down` edges parent->child, `symmetric` both ways.
 * Predicate-based by design — the recall set is never enumerated
 * centrally (I12).
 */
export function downstreamOf(links: PassportLink[], root: string): Set<string> {
  const out = new Set<string>();
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.pop()!;
    for (const link of links) {
      const targets: string[] =
        link.direction === "up"
          ? link.to === current
            ? [link.from]
            : []
          : link.direction === "down"
            ? link.from === current
              ? [link.to]
              : []
            : link.from === current
              ? [link.to]
              : link.to === current
                ? [link.from]
                : [];
      for (const target of targets) {
        if (!out.has(target)) {
          out.add(target);
          queue.push(target);
        }
      }
    }
  }
  return out;
}

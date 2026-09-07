/**
 * Tier-A pack (I13): carrier-embedded minimum viable passport — product ID,
 * resolver URI, EO ID, status, critical safety/recall flag, validity,
 * multi-suite compressed signatures. Offline-verifiable with pre-cached
 * trust anchors (EN 18246 VDS/DigSig precedent). The standard fixes exactly
 * which subset is Tier A; here we model the neutral-core Tier-A set.
 */
import type { ProductIdentifier } from "./identifier.js";
import type { PassportStatus } from "./manifest.js";
import type { SignatureFraming } from "./trust.js";
import type { TierId } from "./verdict.js";

/** Approximate carrier budgets (EN 18220 QR/data-matrix classes, bytes). */
export const CARRIER_BUDGETS: Readonly<Record<string, number>> = {
  "qr-version-15": 1098, // low-error QR byte capacity
  "qr-version-25": 1853,
  "qr-version-40": 2953,
  "data-matrix-144x144": 1558,
  "nfc-ntag424": 256, // conservative NDEF payload budget
};

export interface TierAPack {
  kind: "unidpp.tier-a";
  version: "1";
  /** L0 identity as embedded on the carrier. */
  subjectId: ProductIdentifier;
  passportId: ProductIdentifier;
  /** Federated resolver URI — resolution is reproducible, carrier retains identity. */
  resolverUri: string;
  /** Economic operator ID (issuer). */
  operatorId: string;
  status: PassportStatus;
  /** Critical safety / recall flag — the one field that must never go stale silently. */
  criticalSafety: { recall: boolean; campaignRef?: string };
  validity: { notBefore: string; notAfter: string };
  /** Minimal profile identification (full views are Tier B). */
  profiles: Array<{ profileId: string; version: string }>;
  /** Event-log head commitment (age drives freshness verdicts). */
  logCommitment: { commitment: string; height: number; asOf: string };
  /** Multi-suite signature framings; verifiers check their acceptance policy. */
  signatures: SignatureFraming[];
}

export function tierOf(pack: { kind?: string }): TierId | "unknown" {
  if (pack.kind === "unidpp.tier-a") return "A";
  return "unknown";
}

/** Estimated serialized size (canonical JSON, pre-compression), bytes. */
export function packSize(pack: TierAPack): number {
  return new TextEncoder().encode(JSON.stringify(pack)).length;
}

/** Does the pack fit a carrier budget (guidance; compression is Tier-A out of scope here)? */
export function fitsCarrier(pack: TierAPack, carrier: string): boolean {
  const budget = CARRIER_BUDGETS[carrier];
  if (budget === undefined) throw new Error(`unknown carrier: ${carrier}`);
  return packSize(pack) <= budget;
}

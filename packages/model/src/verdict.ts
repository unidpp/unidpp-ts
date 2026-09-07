/**
 * I13 degradation ladder + I9 verdicts with coverage reports. Freshness
 * verdicts degrade explicitly, never silently pass.
 */
import type { TrustMarker, VerificationReading } from "./trust.js";

export type TierId = "A" | "B" | "C";

/** Freshness verdict for as-of-stamped data (Pimmel `fresh_within` doctrine). */
export type Freshness =
  | "fresh" // within required freshness window
  | "stale" // outside window — degraded, not failed
  | "unknown"; // no freshness requirement declared

export type VerdictOutcome = "pass" | "degraded" | "fail";

export interface Finding {
  severity: "info" | "warning" | "error";
  code: string;
  message: string;
}

/** Coverage reports: verification is coverage-based, not boolean (I9). */
export interface CoverageReport {
  /** Total checks performed. */
  checks: number;
  /** Checks that passed. */
  passed: number;
  /** Signature framings present / verified / unsupported by available crypto. */
  signatures: { total: number; verified: number; failed: number; unsupported: number };
  /** Share of signed key material resolved against known anchors [0,1]. */
  anchorCoverage: number;
  /** Share of payload elements meeting the minimum trust marker [0,1]. */
  trustCoverage: number;
}

export function coverageRatio(report: CoverageReport): number {
  return report.checks === 0 ? 1 : report.passed / report.checks;
}

export interface Verdict {
  reading: VerificationReading;
  outcome: VerdictOutcome;
  freshness: Freshness;
  coverage: CoverageReport;
  findings: Finding[];
  /** When the verdict was computed (as-of stamp of the verification itself). */
  asOf: string;
  /** Trust marker achieved by the strongest verified framing. */
  achievedMarker: TrustMarker;
}

export function combineOutcome(outcomes: VerdictOutcome[]): VerdictOutcome {
  if (outcomes.includes("fail")) return "fail";
  if (outcomes.includes("degraded")) return "degraded";
  return "pass";
}

/**
 * I13: stale/offline data degrades explicitly, never silently passes.
 * A fail verdict is reserved for integrity failures (tamper, taint, voided
 * signatures); staleness and partial coverage are degradation. "unknown"
 * means no freshness requirement was declared — informational, not degraded
 * (the acceptance policy chose not to demand freshness).
 */
export function outcomeForFreshness(freshness: Freshness): VerdictOutcome {
  switch (freshness) {
    case "fresh":
      return "pass";
    case "stale":
      return "degraded";
    case "unknown":
      return "pass";
  }
}

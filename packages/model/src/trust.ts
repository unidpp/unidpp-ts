/**
 * I9 graded trust: every element/event carries a trust marker; signatures are
 * multi-suite (SIGNATIF co-signature model); revocation reason determines
 * retroactivity; taint propagates through the graph.
 */

/** Trust markers, weakest to strongest. */
export type TrustMarker =
  | "unsigned"
  | "self-declared"
  | "third-party-attested"
  | "multi-signed"
  | "log-anchored";

const MARKER_ORDER: readonly TrustMarker[] = [
  "unsigned",
  "self-declared",
  "third-party-attested",
  "multi-signed",
  "log-anchored",
];

export function markerAtLeast(marker: TrustMarker, minimum: TrustMarker): boolean {
  return MARKER_ORDER.indexOf(marker) >= MARKER_ORDER.indexOf(minimum);
}

/**
 * Multi-suite signature framing (L4): the same payload carries multiple
 * signatures side by side; verifiers check only what their profile-scoped
 * acceptance policy requires.
 */
export type SuiteId =
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ed25519"
  | "sm2-sm3"
  | "ml-dsa-65"
  | (string & {}); // agility registry may add suites

export interface SignatureFraming {
  suite: SuiteId;
  /** Key identifier resolved against the profile's trust list / anchors. */
  keyId: string;
  /** Signing time (ISO 8601) — load-bearing for evidentiary readings. */
  signedAt: string;
  /** Signature value over the canonical payload (base64). */
  value: string;
}

/** Revocation reason determines retroactivity (the UniDPP design framework distrust doctrine). */
export type RevocationReason =
  | "key-compromise" // prospective from detection time
  | "cessation"
  | "supersession"
  | "affiliation-change"
  | "misissuance" // retroactive: void ab initio
  | "fraudulent-issuance" // retroactive: void ab initio
  | "authority-compromised"; // retroactive over the stated window

export const RETROACTIVE_REASONS: ReadonlySet<RevocationReason> = new Set([
  "misissuance",
  "fraudulent-issuance",
  "authority-compromised",
]);

export interface RevocationRecord {
  keyId: string;
  reason: RevocationReason;
  /** When the revocation was declared. */
  declaredAt: string;
  /**
   * Distrust window [start, end]: artifacts inside the window are voided,
   * outside it re-validated. For prospective reasons start == declaredAt.
   */
  window: { start: string; end?: string };
}

/**
 * Three verification readings, because law needs all three: evidentiary
 * (what could a diligent verifier know at T), current-state (fraud voids
 * ab initio), cryptographic (signature/chain validity alone).
 */
export type VerificationReading = "evidentiary" | "current-state" | "cryptographic";

/** Is a signature made at `signedAt` void under this revocation record? */
export function signatureVoided(rec: RevocationRecord, signedAt: string, reading: VerificationReading): boolean {
  const inWindow =
    signedAt >= rec.window.start && (rec.window.end === undefined || signedAt <= rec.window.end);
  if (reading === "cryptographic") {
    // Cryptographic reading ignores legal retroactivity entirely.
    return false;
  }
  if (!RETROACTIVE_REASONS.has(rec.reason)) {
    // Prospective: protects as-of-T verifications before the event.
    if (reading === "evidentiary") return false;
    return inWindow;
  }
  if (reading === "evidentiary") {
    // Evidentiary protects good-faith verifiers: only signatures the
    // diligent verifier *should have known* were bad are void — i.e. those
    // signed after the declaration became visible.
    return signedAt >= rec.declaredAt;
  }
  return inWindow || signedAt >= rec.window.start;
}

/** Taint: marking a passport fraudulent is a graph event, not a list entry. */
export interface TaintRecord {
  passportId: string;
  cause: string;
  sourceEventId?: string;
}

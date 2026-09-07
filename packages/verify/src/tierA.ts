/**
 * Tier-A browser verification (I13): validate a pack's signature framings
 * against pre-cached trust anchors, check validity/freshness, apply
 * revocation semantics per verification reading, and produce a verdict with
 * a coverage report. Stale/offline data degrades explicitly — never silently
 * passes.
 */
import type { RevocationRecord, SignatureFraming, TierAPack, TrustMarker, VerificationReading } from "@unidpp/model";
import { canonicalJson, fromBase64, validateTierAPack, markerAtLeast, signatureVoided } from "@unidpp/model";
import type { CoverageReport, Finding, Freshness, Verdict, VerdictOutcome } from "@unidpp/model";
import { combineOutcome, outcomeForFreshness } from "@unidpp/model";
import type { CryptoSlots, TrustAnchors } from "./crypto.js";
import { defaultSlots } from "./crypto.js";

export interface VerifyOptions {
  /** Pre-cached trust anchors (offline Tier-A doctrine). */
  anchors: TrustAnchors;
  /** Pluggable slots; defaults to WebCrypto ECDSA. */
  slots?: CryptoSlots;
  /** Verification reading (default "current-state"). */
  reading?: VerificationReading;
  /** Revocation records to apply. */
  revocations?: RevocationRecord[];
  /** Taint records: passport-level graph events (fail any reading). */
  taintedPassportIds?: string[];
  /** Required freshness window (ISO 8601 duration) over the log commitment. */
  requiredFreshness?: string;
  /** Minimum trust marker the acceptance policy demands. */
  minimumMarker?: TrustMarker;
  /** Verification clock (ISO 8601); default now. */
  now?: string;
}

/**
 * The signed payload: canonical pack with the signature set removed —
 * framings sign the bare pack, so any number of framings (multi-suite
 * co-signature model) cover byte-identical content.
 */
export function signedPayload(pack: Record<string, unknown>): Uint8Array {
  const bare = { ...pack, signatures: [] };
  return new TextEncoder().encode(canonicalJson(bare));
}

/** Freshness of the pack's log commitment relative to `now`. */
export function assessFreshness(asOf: string, required: string | undefined, now: string): Freshness {
  if (required === undefined) return "unknown";
  const ageMs = Date.parse(now) - Date.parse(asOf);
  const budgetMs = durationToMs(required);
  if (Number.isNaN(ageMs) || Number.isNaN(budgetMs)) return "unknown";
  return ageMs <= budgetMs ? "fresh" : "stale";
}

function durationToMs(duration: string): number {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$/.exec(duration);
  if (m === null) return Number.NaN;
  const days = Number(m[1] ?? 0);
  const hours = Number(m[2] ?? 0);
  const minutes = Number(m[3] ?? 0);
  const seconds = Number(m[4] ?? 0);
  return ((days * 24 + hours) * 60 + minutes) * 60 * 1000 + seconds * 1000;
}

export async function verifyTierAPack(pack: unknown, options: VerifyOptions): Promise<Verdict> {
  const now = options.now ?? new Date().toISOString();
  const reading = options.reading ?? "current-state";
  const slots = options.slots ?? defaultSlots();
  const findings: Finding[] = [];

  const schema = validateTierAPack(pack);
  if (!schema.valid) {
    return {
      reading,
      outcome: "fail",
      freshness: "unknown",
      coverage: { checks: 1, passed: 0, signatures: { total: 0, verified: 0, failed: 0, unsupported: 0 }, anchorCoverage: 0, trustCoverage: 0 },
      findings: schema.issues.map((issue) => ({ severity: "error", code: "schema", message: `${issue.path}: ${issue.message}` })),
      asOf: now,
      achievedMarker: "unsigned",
    };
  }

  const typed = pack as TierAPack;
  const payload = signedPayload(typed as unknown as Record<string, unknown>);

  let outcomes: VerdictOutcome[] = [];
  let passed = 1; // schema check
  let checks = 1;
  let verified = 0;
  let failed = 0;
  let unsupported = 0;
  let anchoredKeys = 0;
  let strongest: TrustMarker = "unsigned";

  // Taint is a graph event: fails under every reading.
  if ((options.taintedPassportIds ?? []).includes(typed.passportId.value)) {
    findings.push({ severity: "error", code: "tainted", message: `passport ${typed.passportId.value} is tainted` });
    outcomes.push("fail");
  }

  // Validity window.
  checks += 1;
  if (now < typed.validity.notBefore || now > typed.validity.notAfter) {
    findings.push({ severity: "error", code: "validity-window", message: `pack outside validity window [${typed.validity.notBefore}, ${typed.validity.notAfter}]` });
    outcomes.push("fail");
  } else {
    passed += 1;
  }

  // Critical safety flag cannot silently degrade: recall packs fail when stale.
  const freshness = assessFreshness(typed.logCommitment.asOf, options.requiredFreshness, now);
  if (typed.criticalSafety.recall && freshness === "stale") {
    findings.push({ severity: "error", code: "recall-stale", message: "recall flag present but data is stale — cannot pass" });
    outcomes.push("fail");
  }
  outcomes.push(outcomeForFreshness(freshness));
  checks += 1;
  if (freshness === "fresh") passed += 1;

  // Signature framings.
  for (const framing of typed.signatures) {
    const slot = slots.get(framing.suite);
    const key = options.anchors.get(framing.keyId);
    if (slot === undefined) {
      unsupported += 1;
      findings.push({
        severity: "warning",
        code: "suite-unsupported",
        message: `no crypto slot for suite ${framing.suite} (profile-bound suite; register the binding)`,
      });
      outcomes.push("degraded");
      continue;
    }
    if (key === undefined) {
      failed += 1;
      findings.push({ severity: "error", code: "key-unanchored", message: `keyId ${framing.keyId} not in cached trust anchors` });
      outcomes.push("fail");
      continue;
    }
    anchoredKeys += 1;
    checks += 1;
    // Revocation semantics per reading.
    const voided = (options.revocations ?? []).some((rec) => rec.keyId === framing.keyId && signatureVoided(rec, framing.signedAt, reading));
    if (voided) {
      failed += 1;
      findings.push({
        severity: "error",
        code: "signature-voided",
        message: `signature by ${framing.keyId} voided under ${reading} reading`,
      });
      outcomes.push("fail");
      continue;
    }
    const ok = await slot.verify({ suite: framing.suite, payload, signature: fromBase64(framing.value), publicKey: key });
    if (ok) {
      verified += 1;
      passed += 1;
      const marker: TrustMarker = framing.suite.includes("testmac") ? "self-declared" : "third-party-attested";
      if (strongest === "unsigned" || markerAtLeast(marker, strongest)) strongest = marker;
    } else {
      failed += 1;
      findings.push({ severity: "error", code: "signature-invalid", message: `signature by ${framing.keyId} (${framing.suite}) failed verification` });
      outcomes.push("fail");
    }
  }

  const minimum = options.minimumMarker ?? "unsigned";
  const trustCoverage = minimum === "unsigned" ? 1 : markerAtLeast(strongest, minimum) ? 1 : 0;
  if (trustCoverage === 0) {
    findings.push({ severity: "warning", code: "below-minimum-marker", message: `achieved ${strongest}, policy requires ${minimum}` });
    outcomes.push("degraded");
  }

  const coverage: CoverageReport = {
    checks,
    passed,
    signatures: { total: typed.signatures.length, verified, failed, unsupported },
    anchorCoverage: typed.signatures.length === 0 ? 0 : anchoredKeys / typed.signatures.length,
    trustCoverage,
  };

  return {
    reading,
    outcome: combineOutcome(outcomes),
    freshness,
    coverage,
    findings,
    asOf: now,
    achievedMarker: strongest,
  };
}

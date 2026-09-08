/**
 * Tier-A browser verification (I13): validate a pack's signature framings
 * against pre-cached trust anchors, check validity/freshness, apply
 * revocation semantics per verification reading, and produce a verdict with
 * a coverage report. Stale/offline data degrades explicitly — never silently
 * passes.
 *
 * Multi-suite packs (the sovereign co-signature model): every filled slot
 * is graded by the per-suite policy in `slotPolicy.ts` — P-256 verifies
 * via WebCrypto where available; SM2/ML-DSA slots defer with an explicit
 * reason; an unpinned key id degrades that slot only. Degrade, never
 * fake, never crash.
 */
import type { RevocationRecord, SignatureFraming, TierAPack, TrustMarker, VerificationReading } from "@unidpp/model";
import { canonicalJson, validateTierAPack, markerAtLeast, signatureVoided } from "@unidpp/model";
import type { CoverageReport, Finding, Freshness, Verdict, VerdictOutcome } from "@unidpp/model";
import { combineOutcome, outcomeForFreshness } from "@unidpp/model";
import type { CryptoSlots, TrustAnchors } from "./crypto.js";
import { defaultSlots } from "./crypto.js";
import type { SlotCheck } from "./slotPolicy.js";
import { checkSlot } from "./slotPolicy.js";

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

  // Signature framings: each filled slot goes through the per-suite
  // honesty ladder (`checkSlot`) — deferred suites and unpinned key ids
  // degrade that slot only; only a signature failing under its pinned
  // anchor fails. The mapping from `SlotCheck` to verdict vocabulary
  // lives in this one loop; the slot policy itself lives in one place.
  for (const framing of typed.signatures) {
    const voided = (options.revocations ?? []).some((rec) => rec.keyId === framing.keyId && signatureVoided(rec, framing.signedAt, reading));
    const check = await checkSlot({
      framing,
      payload,
      slots,
      anchors: options.anchors,
      voided,
      voidedReason: `signature by ${framing.keyId} voided under ${reading} reading`,
    });
    if (check.kind !== "deferred" && check.kind !== "unknown-key" && (check.kind !== "invalid" || options.anchors.has(framing.keyId))) {
      anchoredKeys += 1;
    }
    switch (check.kind) {
      case "verified": {
        verified += 1;
        checks += 1;
        passed += 1;
        const marker: TrustMarker = framing.suite.includes("testmac") ? "self-declared" : "third-party-attested";
        if (strongest === "unsigned" || markerAtLeast(marker, strongest)) strongest = marker;
        break;
      }
      case "unknown-key": {
        const pinned = check.anchorKeyIds.length === 0 ? "nothing" : check.anchorKeyIds.join(",");
        findings.push({
          severity: "warning",
          code: "key-unanchored",
          message: `slot names key ${check.keyId} but the anchor set pins ${pinned}: the verifier's trust configuration does not cover this signer`,
        });
        outcomes.push("degraded");
        break;
      }
      case "invalid": {
        failed += 1;
        checks += 1;
        findings.push({
          severity: "error",
          code: "signature-invalid",
          message: `signature by ${framing.keyId} (${framing.suite}) failed verification: ${check.why}`,
        });
        outcomes.push("fail");
        break;
      }
      case "deferred": {
        unsupported += 1;
        findings.push({
          severity: "warning",
          code: "suite-unsupported",
          message: `suite ${check.suite} deferred in this build: ${check.reason}`,
        });
        outcomes.push("degraded");
        break;
      }
      case "voided": {
        failed += 1;
        checks += 1;
        findings.push({ severity: "error", code: "signature-voided", message: check.reason });
        outcomes.push("fail");
        break;
      }
    }
  }

  // Whole-degradation honesty: when every slot deferred (nothing this
  // build computes — e.g. a pure-SM2 pack in an EU-classical browser),
  // say so at verdict level instead of leaving the reader to sum the
  // per-slot findings.
  if (typed.signatures.length > 0 && verified === 0 && failed === 0 && unsupported === typed.signatures.length) {
    const suites = [...new Set(typed.signatures.map((f) => f.suite))].join(", ");
    findings.push({
      severity: "warning",
      code: "no-computed-suite",
      message: `no anchor/computed suite for ${suites} in this build: no slot could be verified, the verdict degrades wholly`,
    });
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

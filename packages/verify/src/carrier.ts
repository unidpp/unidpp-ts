/** The Tier-A carrier verifier (R11's unification): the offline
 *  verdict over a DECODED native carrier — the framing issuers mint
 *  and the CLI decodes. The ladder mirrors verifyTierAPack's (taint,
 *  validity, freshness, the recall guard, the per-slot honesty
 *  ladder, the minimum-marker policy) with the native payload's
 *  fields; the slots' signatures cover the signing body the model's
 *  codec reconstructs.
 */

import {
  decodeTierAHex,
  tierASigningBody,
  type DecodedTierAPayload,
  type DecodedTierASignature,
} from "@unidpp/model";
import type {
  CoverageReport,
  Finding,
  RevocationRecord,
  SignatureFraming,
  SuiteId,
  TrustMarker,
  Verdict,
  VerdictOutcome,
  VerificationReading,
} from "@unidpp/model";
import { combineOutcome, markerAtLeast, outcomeForFreshness, toBase64 } from "@unidpp/model";
import { assessFreshness } from "./tierA.js";
import type { CryptoSlots, TrustAnchors } from "./crypto.js";
import { defaultSlots } from "./crypto.js";
import { checkSlot } from "./slotPolicy.js";

/** The SPKI wrapper around a SEC1 uncompressed EC point (the issuer
 *  keyrings publish SEC1; WebCrypto imports SPKI). */
const P256_SPKI_PREFIX = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

function sec1ToSpki(publicKeyHex: string): Uint8Array | null {
  const bytes = new Uint8Array((publicKeyHex.match(/../g) ?? []).map((b) => parseInt(b, 16)));
  if (bytes.length !== 65 || bytes[0] !== 0x04) return null;
  const spki = new Uint8Array(P256_SPKI_PREFIX.length + bytes.length);
  spki.set(P256_SPKI_PREFIX);
  spki.set(bytes, P256_SPKI_PREFIX.length);
  return spki;
}

/** The carrier verifier's options: the same policy inputs the pack
 *  verifier takes, over the decoded payload. */
export interface CarrierVerifyOptions {
  anchors: TrustAnchors;
  slots?: CryptoSlots;
  reading?: VerificationReading;
  revocations?: RevocationRecord[];
  taintedPassportIds?: string[];
  requiredFreshness?: string;
  minimumMarker?: TrustMarker;
  now?: string;
}

/** The fixture's SEC1 anchor and key id, wrapped for the slots. */
export function carrierAnchors(
  entries: { keyId: string; publicKeyHex: string }[],
): TrustAnchors {
  const map = new Map();
  for (const entry of entries) {
    const spki = sec1ToSpki(entry.publicKeyHex);
    if (spki) map.set(entry.keyId, { format: "spki", bytes: spki });
  }
  return map;
}

const SLOT_SUITE: Record<string, SuiteId> = {
  "ecdsa-p256": "ecdsa-p256-sha256",
  "ecdsa-p384": "ecdsa-p384-sha384",
};

function framingOf(
  slot: DecodedTierASignature,
  body: Uint8Array,
  asOf: string,
): SignatureFraming | null {
  if (slot.signature === null) return null;
  const suite = SLOT_SUITE[slot.suite];
  if (suite === undefined) return null;
  return {
    suite,
    keyId: slot.keyId,
    signedAt: asOf,
    value: toBase64(slot.signature),
  };
}

/** Verify a decoded native carrier. The payload rides the model's
 *  decodeTierA / decodeTierAHex. */
export async function verifyTierACarrier(
  payload: DecodedTierAPayload,
  options: CarrierVerifyOptions,
): Promise<Verdict> {
  const now = options.now ?? new Date().toISOString();
  const reading: VerificationReading = options.reading ?? "current-state";
  const slots = options.slots ?? defaultSlots();
  const findings: Finding[] = [];
  const outcomes: VerdictOutcome[] = [];
  let checks = 1;
  let passed = 1; // the framing decoded
  let verified = 0;
  let failed = 0;
  let unsupported = 0;
  let anchoredKeys = 0;
  let strongest: TrustMarker = "unsigned";

  if ((options.taintedPassportIds ?? []).includes(payload.passportId)) {
    findings.push({
      severity: "error",
      code: "tainted",
      message: `passport ${payload.passportId} is tainted`,
    });
    outcomes.push("fail");
  }

  checks += 1;
  const openEnded = payload.validity.to === null;
  if (now < payload.validity.from || (!openEnded && now > (payload.validity.to as string))) {
    findings.push({
      severity: "error",
      code: "validity-window",
      message: `carrier outside validity window [${payload.validity.from}, ${payload.validity.to ?? "open"}]`,
    });
    outcomes.push("fail");
  } else {
    passed += 1;
  }

  const freshness = assessFreshness(payload.asOf, options.requiredFreshness, now);
  if (payload.safety === "recall-active" && freshness === "stale") {
    findings.push({
      severity: "error",
      code: "recall-stale",
      message: "recall flag present but data is stale — cannot pass",
    });
    outcomes.push("fail");
  }
  outcomes.push(outcomeForFreshness(freshness));
  checks += 1;
  if (freshness === "fresh") passed += 1;

  // The slots sign the signing body FRAMED IN THE SIGNING DOMAIN
  // (signatif's domain_framed: tag bytes, a 0 separator, the body).
  const rawBody = tierASigningBody(payload);
  const domainTag = new TextEncoder().encode("UNIDPP-SIGNATIF/ARTIFACT-EVENT");
  const body = new Uint8Array(domainTag.length + 1 + rawBody.length);
  body.set(domainTag);
  body[domainTag.length] = 0;
  body.set(rawBody, domainTag.length + 1);
  for (const slot of payload.signatures) {
    const voided = (options.revocations ?? []).some(
      (rec) => rec.keyId === slot.keyId,
    );
    const framing = framingOf(slot, body, payload.asOf);
    if (framing === null) {
      unsupported += 1;
      findings.push({
        severity: "warning",
        code: "suite-unsupported",
        message: `suite ${slot.suite} deferred in this build: the carrier's framing is not computable here`,
      });
      outcomes.push("degraded");
      continue;
    }
    const check = await checkSlot({
      framing,
      payload: body,
      slots,
      anchors: options.anchors,
      voided,
      voidedReason: `signature by ${slot.keyId} voided under ${reading} reading`,
    });
    if (
      check.kind !== "deferred" &&
      check.kind !== "unknown-key" &&
      (check.kind !== "invalid" || options.anchors.has(slot.keyId))
    ) {
      anchoredKeys += 1;
    }
    switch (check.kind) {
      case "verified": {
        verified += 1;
        checks += 1;
        passed += 1;
        const marker: TrustMarker =
          slot.suite === "ecdsa-p256" || slot.suite === "sm2"
            ? "third-party-attested"
            : "self-declared";
        if (strongest === "unsigned" || markerAtLeast(marker, strongest)) {
          strongest = marker;
        }
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
          message: `signature by ${slot.keyId} (${slot.suite}) failed verification: ${check.why}`,
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

  if (
    payload.signatures.length > 0 &&
    verified === 0 &&
    failed === 0 &&
    unsupported === payload.signatures.length
  ) {
    const suites = [...new Set(payload.signatures.map((s) => s.suite))].join(", ");
    findings.push({
      severity: "warning",
      code: "no-computed-suite",
      message: `no anchor/computed suite for ${suites} in this build: no slot could be verified, the verdict degrades wholly`,
    });
  }

  const minimum = options.minimumMarker ?? "unsigned";
  const trustCoverage = minimum === "unsigned" ? 1 : markerAtLeast(strongest, minimum) ? 1 : 0;
  if (trustCoverage === 0) {
    findings.push({
      severity: "warning",
      code: "below-minimum-marker",
      message: `achieved ${strongest}, policy requires ${minimum}`,
    });
    outcomes.push("degraded");
  }

  const coverage: CoverageReport = {
    checks,
    passed,
    signatures: { total: payload.signatures.length, verified, failed, unsupported },
    anchorCoverage: payload.signatures.length === 0 ? 0 : anchoredKeys / payload.signatures.length,
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

/** The whole offline journey in one call: the mint response's hex in,
 *  the verdict out. */
export async function verifyTierACarrierHex(
  hex: string,
  options: CarrierVerifyOptions,
): Promise<Verdict> {
  return verifyTierACarrier(decodeTierAHex(hex), options);
}

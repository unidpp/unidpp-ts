import { describe, expect, it } from "vitest";
import type { RevocationRecord, TierAPack } from "@unidpp/model";
import { buildLaptop } from "@unidpp/model/fixtures";
import { CryptoSlots, HmacSha256Slot, WebCryptoEcdsaSlot } from "../src/crypto.js";
import { generateEcdsaKey, hmacKey, signPack } from "../src/signer.js";
import { verifyTierAPack } from "../src/tierA.js";

const NOW = "2027-06-01T12:00:00Z";
const LOG_AS_OF = "2027-05-30T00:00:00Z"; // 2 days old

async function buildPack(signatures: TierAPack["signatures"]): Promise<TierAPack> {
  const { manifest } = await buildLaptop();
  return {
    kind: "unidpp.tier-a",
    version: "1",
    subjectId: manifest.subjectId,
    passportId: manifest.passportId,
    resolverUri: "https://resolver.unidpp.org/",
    operatorId: "urn:unidpp:actor:oem-nordwave",
    status: "active",
    criticalSafety: { recall: false },
    validity: { notBefore: "2026-08-03T00:00:00Z", notAfter: "2036-08-03T00:00:00Z" },
    profiles: manifest.profiles.map((p) => ({ profileId: p.profileId, version: p.version })),
    logCommitment: { commitment: manifest.eventLog.commitment, height: manifest.eventLog.height, asOf: LOG_AS_OF },
    signatures,
  };
}

describe("tier-a verification (browser demo path)", () => {
  it("verifies a WebCrypto ECDSA-signed pack: pass with full coverage", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "urn:unidpp:key:oem-nordwave-1", "2027-05-30T00:00:00Z");
    const signed = { ...pack, signatures: [framing] };

    const verdict = await verifyTierAPack(signed, {
      anchors: new Map([["urn:unidpp:key:oem-nordwave-1", key.toAnchor()]]),
      reading: "current-state",
      now: NOW,
      requiredFreshness: "P30D",
    });
    expect(verdict.outcome).toBe("pass");
    expect(verdict.freshness).toBe("fresh");
    expect(verdict.coverage.signatures).toEqual({ total: 1, verified: 1, failed: 0, unsupported: 0 });
    expect(verdict.coverage.anchorCoverage).toBe(1);
    expect(verdict.achievedMarker).toBe("third-party-attested");
    expect(verdict.findings).toEqual([]);
  });

  it("fails on tampered payload (integrity, not staleness)", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "k1", "2027-05-30T00:00:00Z");
    const tampered = { ...pack, signatures: [framing], operatorId: "urn:unidpp:actor:attacker" };
    const verdict = await verifyTierAPack(tampered, {
      anchors: new Map([["k1", key.toAnchor()]]),
      now: NOW,
    });
    expect(verdict.outcome).toBe("fail");
    expect(verdict.coverage.signatures.failed).toBe(1);
    expect(verdict.findings.some((f) => f.code === "signature-invalid")).toBe(true);
  });

  it("fails schema-invalid packs with report", async () => {
    const verdict = await verifyTierAPack({ kind: "unidpp.tier-a" }, { anchors: new Map(), now: NOW });
    expect(verdict.outcome).toBe("fail");
    expect(verdict.findings.some((f) => f.code === "schema")).toBe(true);
  });

  it("degrades (not fails) on stale data; recall + stale fails", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "k1", "2027-01-01T00:00:00Z");
    const signed = { ...pack, signatures: [framing] };
    const verdict = await verifyTierAPack(signed, {
      anchors: new Map([["k1", key.toAnchor()]]),
      now: NOW,
      requiredFreshness: "P30D", // log as-of is 2 days old -> fresh
    });
    // Use a stricter window to force staleness.
    const stale = await verifyTierAPack(signed, {
      anchors: new Map([["k1", key.toAnchor()]]),
      now: NOW,
      requiredFreshness: "P1D",
    });
    expect(verdict.outcome).toBe("pass");
    expect(stale.outcome).toBe("degraded");
    expect(stale.freshness).toBe("stale");

    const recalled = { ...signed, criticalSafety: { recall: true, campaignRef: "urn:eu:recall:x" } };
    // Re-sign so only the recall+stale rule fires.
    const reSigned = { ...recalled, signatures: [await signPack(key, recalled, "k1", "2027-05-30T00:00:00Z")] };
    const failVerdict = await verifyTierAPack(reSigned, {
      anchors: new Map([["k1", key.toAnchor()]]),
      now: NOW,
      requiredFreshness: "P1D",
    });
    expect(failVerdict.outcome).toBe("fail");
    expect(failVerdict.findings.some((f) => f.code === "recall-stale")).toBe(true);
  });

  it("degrades on unsupported profile-bound suites (pluggable slots)", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const ecdsaFraming = await signPack(key, pack, "k1", "2027-05-30T00:00:00Z");
    // SM2 framing carried alongside (multi-suite co-signature model) but no
    // SM2 slot registered in this browser: degraded, not failed.
    const signed = {
      ...pack,
      signatures: [ecdsaFraming, { suite: "sm2-sm3", keyId: "k2", signedAt: "2027-05-30T00:00:00Z", value: "QUJD" }],
    };
    const verdict = await verifyTierAPack(signed, {
      anchors: new Map([["k1", key.toAnchor()], ["k2", { format: "opaque", material: "sm2-k2" }]]),
      now: NOW,
    });
    expect(verdict.outcome).toBe("degraded");
    expect(verdict.coverage.signatures.unsupported).toBe(1);
    expect(verdict.coverage.signatures.verified).toBe(1);
    expect(verdict.findings.some((f) => f.code === "suite-unsupported")).toBe(true);
  });

  it("verifies with a plugged-in HMAC slot (slot pluggability, real MAC check)", async () => {
    const secret = new TextEncoder().encode("conformance-secret");
    const key = hmacKey(secret, "hmac:conf-1");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "urn:unidpp:key:conf-1", "2027-05-30T00:00:00Z");
    const slots = new CryptoSlots();
    slots.register(new WebCryptoEcdsaSlot());
    slots.register(new HmacSha256Slot(new Map([["hmac:conf-1", secret]])));
    const verdict = await verifyTierAPack({ ...pack, signatures: [framing] }, {
      anchors: new Map([["urn:unidpp:key:conf-1", key.toAnchor()]]),
      slots,
      now: NOW,
    });
    expect(verdict.outcome).toBe("pass");
    expect(verdict.achievedMarker).toBe("self-declared");
  });

  it("fails unanchored keys (unknown trust anchor)", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "k1", "2027-05-30T00:00:00Z");
    const verdict = await verifyTierAPack({ ...pack, signatures: [framing] }, {
      anchors: new Map(), // empty cache
      now: NOW,
    });
    expect(verdict.outcome).toBe("fail");
    expect(verdict.coverage.anchorCoverage).toBe(0);
    expect(verdict.findings.some((f) => f.code === "key-unanchored")).toBe(true);
  });

  it("applies revocation reason semantics across readings", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "k1", "2026-06-01T00:00:00Z");
    const signed = { ...pack, signatures: [framing] };
    const anchors = new Map([["k1", key.toAnchor()]]);

    const retroactive: RevocationRecord = {
      keyId: "k1",
      reason: "fraudulent-issuance",
      declaredAt: "2027-01-10T00:00:00Z",
      window: { start: "2026-01-01T00:00:00Z" },
    };
    const current = await verifyTierAPack(signed, { anchors, now: NOW, revocations: [retroactive], reading: "current-state" });
    expect(current.outcome).toBe("fail");
    const evidentiary = await verifyTierAPack(signed, { anchors, now: NOW, revocations: [retroactive], reading: "evidentiary" });
    expect(evidentiary.outcome).toBe("pass");
    const crypto = await verifyTierAPack(signed, { anchors, now: NOW, revocations: [retroactive], reading: "cryptographic" });
    expect(crypto.outcome).toBe("pass");

    const prospective: RevocationRecord = {
      keyId: "k1",
      reason: "key-compromise",
      declaredAt: "2027-01-10T00:00:00Z",
      window: { start: "2027-01-10T00:00:00Z" },
    };
    const after = await verifyTierAPack(signed, { anchors, now: NOW, revocations: [prospective], reading: "current-state" });
    expect(after.outcome).toBe("pass");
  });

  it("fails tainted passports under every reading", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "k1", "2027-05-30T00:00:00Z");
    const verdict = await verifyTierAPack({ ...pack, signatures: [framing] }, {
      anchors: new Map([["k1", key.toAnchor()]]),
      now: NOW,
      taintedPassportIds: [pack.passportId.value],
      reading: "cryptographic",
    });
    expect(verdict.outcome).toBe("fail");
    expect(verdict.findings.some((f) => f.code === "tainted")).toBe(true);
  });

  it("multi-signature: ECDSA P-256 + P-384 both verify (co-signature model)", async () => {
    const jp = await generateEcdsaKey("P-256");
    const eu = await generateEcdsaKey("P-384");
    const pack = await buildPack([]);
    const f1 = await signPack(jp, pack, "jp-key", "2027-05-30T00:00:00Z");
    const f2 = await signPack(eu, pack, "eu-key", "2027-05-30T00:00:00Z");
    const verdict = await verifyTierAPack({ ...pack, signatures: [f1, f2] }, {
      anchors: new Map([["jp-key", jp.toAnchor()], ["eu-key", eu.toAnchor()]]),
      now: NOW,
    });
    expect(verdict.outcome).toBe("pass");
    expect(verdict.coverage.signatures.verified).toBe(2);
    expect(verdict.coverage.anchorCoverage).toBe(1);
  });
});

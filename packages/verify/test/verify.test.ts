import { describe, expect, it, vi } from "vitest";
import type { RevocationRecord, TierAPack } from "@unidpp/model";
import { buildLaptop } from "@unidpp/model/fixtures";
import { CryptoSlots, HmacSha256Slot, WebCryptoEcdsaSlot } from "../src/crypto.js";
import { generateEcdsaKey, hmacKey, signPack } from "../src/signer.js";
import { keyIdOf } from "../src/slotPolicy.js";
import { verifyTierAPack } from "../src/tierA.js";
import { cosignedPack, fixture93Anchors, p256OnlyAnchors, pureSm2Pack } from "./fixtures.js";

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

  it("degrades on unanchored keys (UnknownKey: the trust configuration does not cover the signer)", async () => {
    const key = await generateEcdsaKey("P-256");
    const pack = await buildPack([]);
    const framing = await signPack(key, pack, "k1", "2027-05-30T00:00:00Z");
    const verdict = await verifyTierAPack({ ...pack, signatures: [framing] }, {
      anchors: new Map(), // empty cache
      now: NOW,
    });
    expect(verdict.outcome).toBe("degraded");
    expect(verdict.coverage.anchorCoverage).toBe(0);
    expect(verdict.coverage.signatures.verified).toBe(0);
    const finding = verdict.findings.find((f) => f.code === "key-unanchored");
    expect(finding?.severity).toBe("warning");
    expect(finding?.message).toContain("pins nothing");
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

describe("multi-suite slot policy (sovereign co-signature model, TODO 93)", () => {
  it("co-signed pack: the P-256 slot verifies, the SM2 slot degrades with an explicit reason", async () => {
    const verdict = await verifyTierAPack(cosignedPack(), { anchors: fixture93Anchors(), now: NOW });
    expect(verdict.outcome).toBe("degraded");
    expect(verdict.coverage.signatures).toEqual({ total: 2, verified: 1, failed: 0, unsupported: 1 });
    expect(verdict.coverage.anchorCoverage).toBe(0.5);
    expect(verdict.achievedMarker).toBe("third-party-attested");
    const deferred = verdict.findings.find((f) => f.code === "suite-unsupported");
    expect(deferred?.severity).toBe("warning");
    expect(deferred?.message).toContain("sm2-sm3");
    expect(deferred?.message).toContain("GM/T 0003");
    expect(verdict.findings.some((f) => f.code === "signature-invalid")).toBe(false);
  });

  it("a strictly EU-classical anchor subset degrades the same SM2 slot — degradation is scoped per suite, not global", async () => {
    const verdict = await verifyTierAPack(cosignedPack(), { anchors: p256OnlyAnchors(), now: NOW });
    expect(verdict.outcome).toBe("degraded");
    expect(verdict.coverage.signatures).toEqual({ total: 2, verified: 1, failed: 0, unsupported: 1 });
  });

  it("pure-SM2 pack degrades wholly: no anchor/computed suite for sm2 in this build, never a broken verdict", async () => {
    const verdict = await verifyTierAPack(pureSm2Pack(), { anchors: fixture93Anchors(), now: NOW });
    expect(verdict.outcome).toBe("degraded");
    expect(verdict.coverage.signatures).toEqual({ total: 1, verified: 0, failed: 0, unsupported: 1 });
    expect(verdict.achievedMarker).toBe("unsigned");
    const finding = verdict.findings.find((f) => f.code === "no-computed-suite");
    expect(finding?.message).toContain("no anchor/computed suite for sm2-sm3 in this build");
    expect(verdict.findings.some((f) => f.code === "signature-invalid")).toBe(false);
  });

  it("tampered co-signed body fails on the P-256 slot (integrity, not degradation)", async () => {
    const tampered = { ...cosignedPack(), operatorId: "urn:unidpp:actor:attacker" };
    const verdict = await verifyTierAPack(tampered, { anchors: fixture93Anchors(), now: NOW });
    expect(verdict.outcome).toBe("fail");
    expect(verdict.coverage.signatures.failed).toBe(1); // the P-256 slot; the SM2 slot still defers
    expect(verdict.coverage.signatures.unsupported).toBe(1);
    expect(verdict.findings.some((f) => f.code === "signature-invalid" && f.message.includes("ecdsa-p256-sha256"))).toBe(true);
  });

  it("an unpinned P-256 key id degrades (UnknownKey) while the SM2 slot still defers", async () => {
    const other = await generateEcdsaKey("P-256");
    const verdict = await verifyTierAPack(cosignedPack(), {
      anchors: new Map([["urn:unidpp:key:other", other.toAnchor()]]),
      now: NOW,
    });
    expect(verdict.outcome).toBe("degraded");
    expect(verdict.coverage.signatures.verified).toBe(0);
    expect(verdict.coverage.signatures.unsupported).toBe(1);
    expect(verdict.coverage.anchorCoverage).toBe(0);
    const unknown = verdict.findings.find((f) => f.code === "key-unanchored");
    expect(unknown?.message).toContain("k-9fdf5285b4a26c6e"); // names the unpinned slot key
  });

  it("anchor key ids derive in the Rust KeyId::of form (k- + sha256(suite code || raw point)[..16])", async () => {
    const anchors = fixture93Anchors();
    const p256 = anchors.get("k-9fdf5285b4a26c6e");
    expect(p256).toBeDefined();
    expect(await keyIdOf("ecdsa-p256-sha256", p256!)).toBe("k-9fdf5285b4a26c6e");
    const sm2 = anchors.get("k-86f1d8653227e4ad");
    expect(sm2).toBeDefined();
    expect(await keyIdOf("sm2-sm3", sm2!)).toBeUndefined(); // opaque anchor material derives no id
  });

  it("without WebCrypto every slot defers explicitly — never a crash, never a fake pass", async () => {
    vi.stubGlobal("crypto", { subtle: undefined });
    try {
      const verdict = await verifyTierAPack(cosignedPack(), { anchors: fixture93Anchors(), now: NOW });
      expect(verdict.outcome).toBe("degraded");
      expect(verdict.coverage.signatures).toEqual({ total: 2, verified: 0, failed: 0, unsupported: 2 });
      expect(verdict.findings.some((f) => f.code === "no-computed-suite")).toBe(true);
      expect(verdict.findings.some((f) => f.severity === "error")).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

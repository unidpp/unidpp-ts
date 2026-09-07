import { describe, expect, it } from "vitest";
import { validateEvent, validateIdentifier, validateLink, validateManifest, validateTierAPack } from "../src/schemas.js";
import { buildLaptop } from "../src/fixtures/laptop.js";
import { buildCar } from "../src/fixtures/car.js";
import { appendEvent, blindEdgeCommitment, logHead, verifyChain } from "../src/events.js";
import { commitment } from "../src/canonical.js";
import { freshnessSatisfiable, CLASS_CAPABILITY } from "../src/capability.js";
import { markerAtLeast, signatureVoided } from "../src/trust.js";
import { downstreamOf, isVisibleTo } from "../src/links.js";
import type { TierAPack } from "../src/tier.js";
import { fitsCarrier, packSize } from "../src/tier.js";
import type { ProductIdentifier } from "../src/identifier.js";

const id: ProductIdentifier = {
  scheme: "iso-15459",
  value: "urn:iso:std:iso-iec:15459:unidpp:inst:1",
  granularity: "item",
  state: "live",
};

describe("json schema validation", () => {
  it("accepts a well-formed identifier and rejects a bad state", () => {
    expect(validateIdentifier(id).valid).toBe(true);
    expect(validateIdentifier({ ...id, state: "zombie" }).valid).toBe(false);
    expect(validateIdentifier({ ...id, value: "" }).valid).toBe(false);
  });

  it("validates the laptop fixture manifest against the schema", async () => {
    const { manifest } = await buildLaptop();
    const result = validateManifest(manifest);
    expect(result.valid, JSON.stringify(result.issues)).toBe(true);
  });

  it("validates the car fixture manifests (parent + battery child)", async () => {
    const { car, battery, links } = await buildCar();
    expect(validateManifest(car.manifest).valid).toBe(true);
    expect(validateManifest(battery.manifest).valid).toBe(true);
    for (const link of links) expect(validateLink(link).valid).toBe(true);
  });

  it("validates events against the event schema", async () => {
    const { events } = await buildLaptop();
    for (const event of events) expect(validateEvent(event).valid).toBe(true);
  });

  it("validates the laptop fixture links against the schema (parentCommitment is real, not a placeholder)", async () => {
    const { links } = await buildLaptop();
    for (const link of links) {
      const result = validateLink(link);
      expect(result.valid, JSON.stringify(result.issues)).toBe(true);
    }
    expect(links[0]!.parentCommitment).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a manifest with a bad commitment pattern", async () => {
    const { manifest } = await buildLaptop();
    const broken = structuredClone(manifest);
    broken.eventLog.commitment = "not-a-hash";
    expect(validateManifest(broken).valid).toBe(false);
  });

  it("validates a tier-a pack", async () => {
    const pack: TierAPack = {
      kind: "unidpp.tier-a",
      version: "1",
      subjectId: id,
      passportId: id,
      resolverUri: "https://resolver.unidpp.org/",
      operatorId: "urn:unidpp:actor:oem-nordwave",
      status: "active",
      criticalSafety: { recall: false },
      validity: { notBefore: "2026-01-01T00:00:00Z", notAfter: "2036-01-01T00:00:00Z" },
      profiles: [{ profileId: "urn:unidpp:profile:eu-espr-electronics", version: "1.3.0" }],
      logCommitment: { commitment: "a".repeat(64), height: 3, asOf: "2026-08-03T09:15:00Z" },
      signatures: [{ suite: "ecdsa-p256-sha256", keyId: "k1", signedAt: "2026-08-03T09:15:00Z", value: "AA==" }],
    };
    expect(validateTierAPack(pack).valid).toBe(true);
    expect(packSize(pack)).toBeGreaterThan(100);
    expect(fitsCarrier(pack, "qr-version-40")).toBe(true);
    expect(fitsCarrier(pack, "nfc-ntag424")).toBe(false);
  });
});

describe("event log (I4 append-only)", () => {
  it("verifies the laptop chain and detects tampering", async () => {
    const { events } = await buildLaptop();
    expect(await verifyChain(events)).toBe(true);
    const tampered = structuredClone(events);
    tampered[2]!.payload = { ...tampered[2]!.payload, conveyance: "gift" };
    expect(await verifyChain(tampered)).toBe(false);
  });

  it("appends with stamped chain and rejects a conflicting prevCommitment", async () => {
    const { events } = await buildLaptop();
    const head = logHead(events);
    expect(head.height).toBe(5);
    expect(head.commitment).toMatch(/^[0-9a-f]{64}$/);
    const extended = await appendEvent(events, {
      eventId: "evt-lap-006",
      type: "inspection.stamp",
      subject: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      occurredAt: "2027-03-01T00:00:00Z",
      actor: { actorId: "urn:unidpp:actor:verifier-1", role: "verifier" },
      payload: { lensId: "urn:unidpp:profile:jp-meti-pse", lensVersion: "2026.2", mode: "live", verdictSummary: "pass" },
      trustMarker: "self-declared",
      prevCommitment: "",
    });
    expect(await verifyChain(extended)).toBe(true);
    await expect(
      appendEvent(events, {
        eventId: "evt-lap-007",
        type: "inspection.stamp",
        subject: "x",
        occurredAt: "2027-03-01T00:00:00Z",
        actor: { actorId: "a", role: "verifier" },
        payload: {},
        trustMarker: "self-declared",
        prevCommitment: "f".repeat(64),
      }),
    ).rejects.toThrow(/append-only/);
  });

  it("car and battery logs verify", async () => {
    const { car, battery } = await buildCar();
    expect(await verifyChain(car.events)).toBe(true);
    expect(await verifyChain(battery.events)).toBe(true);
  });
});

describe("capability classes (S0-S3)", () => {
  it("S0 is testimony-only; demanding live freshness is unsatisfiable", () => {
    expect(CLASS_CAPABILITY.S0.truthModes).toEqual(["attest-sampled"]);
    expect(freshnessSatisfiable("PT1H", "S0")).toBe(false);
    expect(freshnessSatisfiable("unknown", "S0")).toBe(true);
    expect(freshnessSatisfiable("PT1H", "S3")).toBe(true);
    expect(freshnessSatisfiable("P7D", "S2")).toBe(true);
  });
});

describe("trust markers and revocation semantics", () => {
  it("orders trust markers", () => {
    expect(markerAtLeast("third-party-attested", "self-declared")).toBe(true);
    expect(markerAtLeast("self-declared", "log-anchored")).toBe(false);
  });

  it("prospective reasons protect evidentiary readings; retroactive void ab initio", () => {
    const prospective = {
      keyId: "k1",
      reason: "key-compromise" as const,
      declaredAt: "2027-01-10T00:00:00Z",
      window: { start: "2027-01-10T00:00:00Z" },
    };
    // Signed before the compromise was declared: evidentiary protects it.
    expect(signatureVoided(prospective, "2026-12-01T00:00:00Z", "evidentiary")).toBe(false);
    expect(signatureVoided(prospective, "2026-12-01T00:00:00Z", "current-state")).toBe(false);
    expect(signatureVoided(prospective, "2027-02-01T00:00:00Z", "current-state")).toBe(true);
    expect(signatureVoided(prospective, "2027-02-01T00:00:00Z", "cryptographic")).toBe(false);

    const retroactive = {
      keyId: "k1",
      reason: "fraudulent-issuance" as const,
      declaredAt: "2027-01-10T00:00:00Z",
      window: { start: "2026-01-01T00:00:00Z" },
    };
    // Fraud voids ab initio: current-state reading voids even old signatures.
    expect(signatureVoided(retroactive, "2026-06-01T00:00:00Z", "current-state")).toBe(true);
    expect(signatureVoided(retroactive, "2026-06-01T00:00:00Z", "evidentiary")).toBe(false);
    expect(signatureVoided(retroactive, "2027-02-01T00:00:00Z", "evidentiary")).toBe(true);
  });
});

describe("relationship algebra", () => {
  it("visibility classes gate audiences", () => {
    const blind = { visibility: { edge: "blind" as const } };
    const restricted = { visibility: { edge: "restricted" as const, audiences: ["repairer"] } };
    expect(isVisibleTo(blind as never, "repairer")).toBe(false);
    expect(isVisibleTo(restricted as never, "repairer")).toBe(true);
    expect(isVisibleTo(restricted as never, "consumer")).toBe(false);
  });

  it("downstream traversal covers recall routing", async () => {
    const { links } = await buildCar();
    const down = downstreamOf(links, "urn:iso:std:iso-iec:15459:unidpp:passport:car-wvwzzz1jzxw000841");
    expect(down.has("urn:iso:std:iso-iec:15459:unidpp:passport:battery-pack-bp52-000841")).toBe(true);
  });
});

describe("blind edges (R3 proof-of-binding ≠ knowledge-of-parent)", () => {
  it("laptop battery edge commitment is salted (matches the Python port byte-for-byte)", async () => {
    const { links } = await buildLaptop();
    const link = links[0]!;
    const expected = await commitment(
      { parent: "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345", slot: "battery-bay-1" },
      "salt-bp52-000841",
    );
    expect(link.parentCommitment).toBe(expected);
    // The unsalted commitment differs: no log operator can correlate edges.
    const unsalted = await commitment({
      parent: "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345",
      slot: "battery-bay-1",
    });
    expect(link.parentCommitment).not.toBe(unsalted);
    expect(link.parentCommitment).toMatch(/^[0-9a-f]{64}$/);
  });

  it("blindEdgeCommitment is deterministic and salt-sensitive", async () => {
    const c1 = await blindEdgeCommitment("urn:x:parent", "slot-1", "salt");
    const c2 = await blindEdgeCommitment("urn:x:parent", "slot-1", "salt");
    const c3 = await blindEdgeCommitment("urn:x:parent", "slot-1", "other-salt");
    expect(c1).toBe(c2);
    expect(c1).not.toBe(c3);
    expect(c1).toMatch(/^[0-9a-f]{64}$/);
  });
});

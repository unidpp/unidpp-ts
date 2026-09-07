/**
 * Worked pilot fixture (the UniDPP design framework stream 11 deliverable): a laptop with EU and
 * JP jurisdiction profiles on ONE neutral core — no region is the universal
 * envelope. Child references compose by identity reference, never data
 * copying. Deterministic timestamps; commitments computed on build.
 */
import type { DomainEvent } from "../events.js";
import { appendEvent, blindEdgeCommitment, logHead } from "../events.js";
import type { PassportLink } from "../links.js";
import type { ChildReference, PassportManifest, ProfileDefinition } from "../manifest.js";
import type { ProductIdentifier } from "../identifier.js";

export const LAPTOP_TYPE_ID: ProductIdentifier = {
  scheme: "iso-15459",
  value: "urn:iso:std:iso-iec:15459:unidpp:type:lat-7",
  granularity: "model",
  state: "live",
};

export const LAPTOP_INSTANCE_ID: ProductIdentifier = {
  scheme: "iso-15459",
  value: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
  granularity: "item",
  state: "live",
};

export const LAPTOP_PASSPORT_ID: ProductIdentifier = {
  scheme: "iso-15459",
  value: "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345",
  granularity: "item",
  state: "live",
};

export const EU_ELECTRONICS_PROFILE: ProfileDefinition = {
  profileId: "urn:unidpp:profile:eu-espr-electronics",
  version: "1.3.0",
  owner: "eu:espr:commission",
  legalBasis: "ESPR 2024/1781, electronics delegated act",
  axis: { jurisdiction: "EU", sector: "electronics" },
  dataPoints: [
    { register: "urn:unidpp:register:core", item: "de.dpp.operator-id", version: "1.0.0" },
    { register: "urn:unidpp:register:core", item: "de.dpp.reparability-score", version: "1.1.0" },
    { register: "urn:unidpp:register:core", item: "de.dpp.carbon-footprint", version: "1.2.0" },
  ],
  languages: ["en", "fr", "de"],
  trustRequirements: {
    suites: ["ecdsa-p384-sha384", "ml-dsa-65"],
    trustList: "urn:unidpp:trustlist:eu",
    minimumMarker: "third-party-attested",
  },
  resolution: { resolution: "public", traversal: "public" },
};

export const JP_PSE_PROFILE: ProfileDefinition = {
  profileId: "urn:unidpp:profile:jp-meti-pse",
  version: "2026.2",
  owner: "jp:meti",
  legalBasis: "電気用品安全法 (Denki-Yōhin-Anzen-Hō) technical requirements",
  axis: { jurisdiction: "JP", sector: "electronics" },
  dataPoints: [
    { register: "urn:unidpp:register:core", item: "de.dpp.operator-id", version: "1.0.0" },
    { register: "urn:unidpp:register:jp", item: "de.jp.pse-mark", version: "2.0.0" },
    { register: "urn:unidpp:register:jp", item: "de.jp.top-runner-class", version: "2026.1" },
  ],
  transforms: [
    {
      register: "urn:unidpp:register:jp",
      item: "tr.jp.top-runner-binning",
      version: "2026.1",
    },
  ],
  languages: ["ja", "en"],
  trustRequirements: {
    suites: ["ecdsa-p256-sha256"],
    trustList: "urn:unidpp:trustlist:jp",
    minimumMarker: "self-declared",
  },
  resolution: { resolution: "public", traversal: "roleScoped" },
};

/** Child references: composition by reference, each child resolvable elsewhere. */
export const LAPTOP_CHILDREN: ChildReference[] = [
  {
    childId: "urn:unidpp:passport:battery-pack-bp52-000841",
    relationship: "installation",
    slotId: "battery-bay-1",
    pairing: "firmware",
    binding: { method: "socketed-latch", recoverability: "harvestable" },
    visibility: { edge: "blind" }, // consumer install edge: personal data by default
  },
  {
    childId: "urn:unidpp:passport:sodimm-16g-aa117-0042",
    relationship: "installation",
    slotId: "sodimm-0",
    binding: { method: "socketed", recoverability: "restorable" },
    visibility: { edge: "restricted", audiences: ["repairer", "regulator"] },
  },
  {
    childId: "urn:unidpp:passport:sodimm-16g-aa117-0043",
    relationship: "installation",
    slotId: "sodimm-1",
    binding: { method: "socketed", recoverability: "restorable" },
    visibility: { edge: "restricted", audiences: ["repairer", "regulator"] },
  },
  {
    // Absorbed under the current regime: glued display module, lot-recorded
    // dormant identifier — issuable by adoption when a display regime lands.
    childId: "urn:unidpp:id:display-lot-d14-2026q3",
    relationship: "installation",
    slotId: "display-lid-1",
    binding: { method: "bonded-adhesive", recoverability: "absorbing" },
    visibility: { edge: "restricted", audiences: ["regulator"] },
    dormant: true,
  },
];

export async function buildLaptopEventLog(): Promise<DomainEvent[]> {
  let log: DomainEvent[] = [];
  log = await appendEvent(log, {
    eventId: "evt-lap-001",
    type: "passport.created",
    subject: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
    occurredAt: "2026-08-03T09:15:00Z",
    actor: { actorId: "urn:unidpp:actor:oem-nordwave", role: "economic-operator" },
    payload: {
      typeRef: "urn:iso:std:iso-iec:15459:unidpp:type:lat-7@hw-rev-b",
      profileIds: ["urn:unidpp:profile:eu-espr-electronics"],
    },
    trustMarker: "third-party-attested",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-lap-002",
    type: "profile.binding",
    subject: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
    occurredAt: "2026-08-03T09:15:01Z",
    actor: { actorId: "urn:unidpp:actor:oem-nordwave", role: "economic-operator" },
    payload: {
      profileId: "urn:unidpp:profile:jp-meti-pse",
      version: "2026.2",
      from: "2026-10-01T00:00:00Z",
    },
    trustMarker: "third-party-attested",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-lap-003",
    type: "custody.transfer",
    subject: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
    occurredAt: "2026-08-20T14:02:00Z",
    actor: { actorId: "urn:unidpp:actor:retailer-kyoto-denshi", role: "custodian" },
    payload: {
      fromActor: { actorId: "urn:unidpp:actor:oem-nordwave", role: "economic-operator" },
      toActor: { actorId: "urn:unidpp:actor:consumer-anon-1", role: "custodian" },
      conveyance: "retail-sale",
    },
    trustMarker: "self-declared",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-lap-004",
    type: "software.update",
    subject: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
    occurredAt: "2026-11-05T02:30:00Z",
    actor: { actorId: "urn:unidpp:actor:oem-nordwave", role: "economic-operator" },
    payload: { component: "system-firmware", fromVersion: "1.04", toVersion: "1.07" },
    trustMarker: "self-declared",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-lap-005",
    type: "part.replace",
    subject: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
    occurredAt: "2027-02-11T10:44:00Z",
    actor: { actorId: "urn:unidpp:actor:repair-shibuya", role: "repairer" },
    payload: {
      removedChildId: "urn:unidpp:passport:sodimm-16g-aa117-0042",
      installedChildId: "urn:unidpp:passport:sodimm-32g-aa119-0007",
      likeForLike: false,
      slotId: "sodimm-0",
    },
    trustMarker: "third-party-attested",
    prevCommitment: "",
  });
  return log;
}

export interface LaptopFixture {
  manifest: PassportManifest;
  events: DomainEvent[];
  profiles: ProfileDefinition[];
  links: PassportLink[];
}

export async function buildLaptop(): Promise<LaptopFixture> {
  const events = await buildLaptopEventLog();
  const manifest: PassportManifest = {
    passportId: LAPTOP_PASSPORT_ID,
    subjectId: LAPTOP_INSTANCE_ID,
    typeRef: { typeId: LAPTOP_TYPE_ID, typeVersion: "hw-rev-b", configurationVector: ["ram-2x16g", "ssd-512g", "display-14"] },
    status: "active",
    profiles: [
      {
        profileId: "urn:unidpp:profile:eu-espr-electronics",
        version: "1.3.0",
        effective: { from: "2027-01-01T00:00:00Z" },
        bindingEventId: "evt-lap-001",
      },
      {
        profileId: "urn:unidpp:profile:jp-meti-pse",
        version: "2026.2",
        effective: { from: "2026-10-01T00:00:00Z" },
        bindingEventId: "evt-lap-002",
      },
    ],
    children: LAPTOP_CHILDREN,
    eventLog: { logUri: "https://logs.unidpp.org/84120099012345", ...logHead(events) },
    capabilityClass: "S0",
    asOf: "2027-02-11T10:44:00Z",
  };
  // R3 edge: proof-of-binding without knowledge-of-parent — real salted
  // blind-edge commitment (same discipline as the car fixture and the
  // Python port), not a decorative placeholder. Satisfies the wire schema's
  // ^[0-9a-f]{64}$ pattern; verifiable against the py port byte-for-byte.
  const parentCommitment = await blindEdgeCommitment(LAPTOP_PASSPORT_ID.value, "battery-bay-1", "salt-bp52-000841");

  const links: PassportLink[] = [
    {
      type: "installation",
      from: "urn:unidpp:passport:battery-pack-bp52-000841",
      to: "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345",
      direction: "up",
      interval: { from: "2026-08-03T09:15:00Z" },
      binding: { method: "socketed-latch", recoverability: "harvestable" },
      slotId: "battery-bay-1",
      pairing: "firmware",
      visibility: { edge: "blind" },
      parentCommitment,
    },
  ];
  return { manifest, events, profiles: [EU_ELECTRONICS_PROFILE, JP_PSE_PROFILE], links };
}

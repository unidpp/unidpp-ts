/**
 * Car example (PLAN.md P4 pilot core): composite products are a federation of
 * passports, not one mega-passport. The car has one passport; the battery —
 * independently regulated — has its own, joined by typed child references.
 * The single QR on the car resolves the car's identity; children join by
 * identity reference, never by data copying. Dormant cell-lot identifiers
 * record absorption at finest available granularity (I3).
 */
import type { DomainEvent } from "../events.js";
import { appendEvent, logHead } from "../events.js";
import type { PassportLink } from "../links.js";
import type { ChildReference, PassportManifest, ProfileDefinition } from "../manifest.js";
import type { ProductIdentifier } from "../identifier.js";
import { commitment } from "../canonical.js";

export const CAR_INSTANCE_ID: ProductIdentifier = {
  scheme: "vin",
  value: "WVWZZZ1JZXW000841",
  granularity: "item",
  state: "live",
};

export const CAR_PASSPORT_ID: ProductIdentifier = {
  scheme: "iso-15459",
  value: "urn:iso:std:iso-iec:15459:unidpp:passport:car-wvwzzz1jzxw000841",
  granularity: "item",
  state: "live",
};

export const BATTERY_SUBJECT_ID: ProductIdentifier = {
  scheme: "gs1",
  value: "(01)09506000134352(21)BP52-000841",
  granularity: "item",
  state: "live",
};

export const BATTERY_PASSPORT_ID: ProductIdentifier = {
  scheme: "iso-15459",
  value: "urn:iso:std:iso-iec:15459:unidpp:passport:battery-pack-bp52-000841",
  granularity: "item",
  state: "live",
};

export const EU_VEHICLE_PROFILE: ProfileDefinition = {
  profileId: "urn:unidpp:profile:eu-vehicle-type-approval",
  version: "2.1.0",
  owner: "eu:commission-dg-grow",
  legalBasis: "Reg (EU) 2018/858 type approval + ESPR 2024/1781 vehicle carve-outs",
  axis: { jurisdiction: "EU", sector: "automotive" },
  dataPoints: [
    { register: "urn:unidpp:register:core", item: "de.dpp.operator-id", version: "1.0.0" },
    { register: "urn:unidpp:register:core", item: "de.vehicle.type-approval-no", version: "1.0.0" },
  ],
  languages: ["en"],
  trustRequirements: {
    suites: ["ecdsa-p384-sha384"],
    trustList: "urn:unidpp:trustlist:eu",
    minimumMarker: "third-party-attested",
  },
  resolution: { resolution: "public", traversal: "roleScoped" },
};

export const EU_BATTERY_PROFILE: ProfileDefinition = {
  profileId: "urn:unidpp:profile:eu-battery-2023-1542",
  version: "1.0.0",
  owner: "eu:commission-dg-env",
  legalBasis: "Reg (EU) 2023/1542 battery passport, Art. 77",
  axis: { jurisdiction: "EU", sector: "batteries" },
  dataPoints: [
    { register: "urn:unidpp:register:core", item: "de.dpp.operator-id", version: "1.0.0" },
    { register: "urn:unidpp:register:core", item: "de.battery.chemistry", version: "1.0.0" },
    { register: "urn:unidpp:register:core", item: "de.battery.carbon-footprint", version: "1.3.0" },
    { register: "urn:unidpp:register:core", item: "de.battery.recycled-content", version: "1.1.0" },
    { register: "urn:unidpp:register:core", item: "de.battery.due-diligence", version: "1.0.0" },
  ],
  languages: ["en", "fr", "de"],
  trustRequirements: {
    suites: ["ecdsa-p384-sha384", "ml-dsa-65"],
    trustList: "urn:unidpp:trustlist:eu",
    minimumMarker: "third-party-attested",
  },
  resolution: { resolution: "public", traversal: "roleScoped" },
};

/** Battery's own manifest: cells absorbed (no passport under the current
 * regime), lot-recorded dormant identifiers for future adoption (I3). */
export const BATTERY_CHILDREN: ChildReference[] = [
  {
    childId: "urn:unidpp:id:cell-lot-c75-2026b-0001",
    relationship: "derivation",
    binding: { method: "welded-module-assembly", recoverability: "absorbing" },
    visibility: { edge: "restricted", audiences: ["regulator", "recycler"] },
    dormant: true,
  },
  {
    childId: "urn:unidpp:id:cell-lot-c75-2026b-0002",
    relationship: "derivation",
    binding: { method: "welded-module-assembly", recoverability: "absorbing" },
    visibility: { edge: "restricted", audiences: ["regulator", "recycler"] },
    dormant: true,
  },
];

export async function buildCarEventLog(): Promise<DomainEvent[]> {
  let log: DomainEvent[] = [];
  log = await appendEvent(log, {
    eventId: "evt-car-001",
    type: "passport.created",
    subject: "urn:unidpp:subject:car-wvwzzz1jzxw000841",
    occurredAt: "2026-09-12T08:00:00Z",
    actor: { actorId: "urn:unidpp:actor:oem-autowerke", role: "economic-operator" },
    payload: { profileIds: ["urn:unidpp:profile:eu-vehicle-type-approval"] },
    trustMarker: "third-party-attested",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-car-002",
    type: "upgrade.install",
    subject: "urn:unidpp:subject:car-wvwzzz1jzxw000841",
    occurredAt: "2026-09-12T08:05:00Z",
    actor: { actorId: "urn:unidpp:actor:oem-autowerke", role: "installer" },
    payload: {
      childId: "urn:iso:std:iso-iec:15459:unidpp:passport:battery-pack-bp52-000841",
      parentSlot: "traction-battery-1",
      pairing: "firmware",
      method: "bolted-busbar",
      recoverability: "harvestable",
      visibilityEdge: "blind",
    },
    trustMarker: "third-party-attested",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-car-003",
    type: "custody.transfer",
    subject: "urn:unidpp:subject:car-wvwzzz1jzxw000841",
    occurredAt: "2026-10-01T16:20:00Z",
    actor: { actorId: "urn:unidpp:actor:dealer-lyon", role: "custodian" },
    payload: {
      fromActor: { actorId: "urn:unidpp:actor:oem-autowerke", role: "economic-operator" },
      toActor: { actorId: "urn:unidpp:actor:consumer-anon-2", role: "custodian" },
      conveyance: "retail-sale",
    },
    trustMarker: "self-declared",
    prevCommitment: "",
  });
  return log;
}

export async function buildBatteryEventLog(): Promise<DomainEvent[]> {
  let log: DomainEvent[] = [];
  log = await appendEvent(log, {
    eventId: "evt-bat-001",
    type: "passport.created",
    subject: "urn:unidpp:subject:battery-pack-bp52-000841",
    occurredAt: "2026-09-01T11:30:00Z",
    actor: { actorId: "urn:unidpp:actor:cellco-eu", role: "economic-operator" },
    payload: { profileIds: ["urn:unidpp:profile:eu-battery-2023-1542"] },
    trustMarker: "third-party-attested",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-bat-002",
    type: "milestone.record",
    subject: "urn:unidpp:subject:battery-pack-bp52-000841",
    occurredAt: "2027-03-04T06:12:00Z",
    actor: { actorId: "urn:unidpp:device:bms-bp52-000841", role: "device" },
    payload: {
      commitment: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
      deviceKeyId: "urn:unidpp:key:bms-bp52-000841",
      freshWithin: "P30D",
    },
    trustMarker: "self-declared",
    prevCommitment: "",
  });
  log = await appendEvent(log, {
    eventId: "evt-bat-003",
    type: "recall.campaign",
    subject: "urn:unidpp:subject:battery-pack-bp52-000841",
    occurredAt: "2027-06-15T09:00:00Z",
    actor: { actorId: "urn:unidpp:actor:eu-market-surveillance", role: "regulator" },
    payload: {
      campaignRef: "urn:eu:recall:2027-06-batt-bp52",
      // Predicate-based recall: evaluated locally by custodians, never
      // enumerated centrally (I12).
      predicate: "battery.firmware < 2.3.1 and cycle_count > 800",
    },
    trustMarker: "log-anchored",
    prevCommitment: "",
  });
  return log;
}

export interface CarFixture {
  car: { manifest: PassportManifest; events: DomainEvent[] };
  battery: { manifest: PassportManifest; events: DomainEvent[] };
  links: PassportLink[];
  profiles: ProfileDefinition[];
}

export async function buildCar(): Promise<CarFixture> {
  const carEvents = await buildCarEventLog();
  const batteryEvents = await buildBatteryEventLog();

  const carManifest: PassportManifest = {
    passportId: CAR_PASSPORT_ID,
    subjectId: CAR_INSTANCE_ID,
    typeRef: {
      typeId: { scheme: "iso-15459", value: "urn:iso:std:iso-iec:15459:unidpp:type:ev-c1", granularity: "model", state: "live" },
      typeVersion: "hw-rev-a",
    },
    status: "active",
    profiles: [
      {
        profileId: "urn:unidpp:profile:eu-vehicle-type-approval",
        version: "2.1.0",
        effective: { from: "2026-09-12T08:00:00Z" },
        bindingEventId: "evt-car-001",
      },
    ],
    children: [
      {
        childId: "urn:iso:std:iso-iec:15459:unidpp:passport:battery-pack-bp52-000841",
        relationship: "installation",
        slotId: "traction-battery-1",
        pairing: "firmware",
        binding: { method: "bolted-busbar", recoverability: "harvestable" },
        visibility: { edge: "blind" },
      },
    ],
    eventLog: { logUri: "https://logs.unidpp.org/car-wvwzzz1jzxw000841", ...logHead(carEvents) },
    capabilityClass: "S2",
    asOf: "2027-06-15T09:00:00Z",
  };

  const batteryManifest: PassportManifest = {
    passportId: BATTERY_PASSPORT_ID,
    subjectId: BATTERY_SUBJECT_ID,
    status: "active",
    profiles: [
      {
        profileId: "urn:unidpp:profile:eu-battery-2023-1542",
        version: "1.0.0",
        effective: { from: "2026-09-01T11:30:00Z" },
        bindingEventId: "evt-bat-001",
      },
    ],
    children: BATTERY_CHILDREN,
    eventLog: { logUri: "https://logs.unidpp.org/battery-pack-bp52-000841", ...logHead(batteryEvents) },
    capabilityClass: "S2",
    asOf: "2027-06-15T09:00:00Z",
  };

  // R3 edge: proof-of-binding without knowledge-of-parent — salted
  // commitment to the parent in the child's log.
  const parentCommitment = await commitment({ parent: CAR_PASSPORT_ID.value, slot: "traction-battery-1" }, "salt-bp52-000841");

  const links: PassportLink[] = [
    {
      type: "installation",
      from: "urn:iso:std:iso-iec:15459:unidpp:passport:battery-pack-bp52-000841",
      to: "urn:iso:std:iso-iec:15459:unidpp:passport:car-wvwzzz1jzxw000841",
      direction: "up",
      interval: { from: "2026-09-12T08:05:00Z" },
      binding: { method: "bolted-busbar", recoverability: "harvestable" },
      slotId: "traction-battery-1",
      pairing: "firmware",
      alteration: ["busbar-torque-marked"],
      visibility: { edge: "blind" },
      parentCommitment,
    },
    {
      type: "custody",
      from: "urn:unidpp:passport:car-wvwzzz1jzxw000841",
      to: "urn:unidpp:actor:consumer-anon-2",
      direction: "symmetric",
      interval: { from: "2026-10-01T16:20:00Z" },
      visibility: { edge: "blind" },
    },
  ];

  return {
    car: { manifest: carManifest, events: carEvents },
    battery: { manifest: batteryManifest, events: batteryEvents },
    links,
    profiles: [EU_VEHICLE_PROFILE, EU_BATTERY_PROFILE],
  };
}

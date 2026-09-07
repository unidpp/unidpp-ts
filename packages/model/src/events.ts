/**
 * I4 append-only event sourcing: the distributed, log-anchored event log is
 * the authoritative record. Nothing is edited in place; every post-first-sale
 * change is an appended event. The post-sale event taxonomy (E1-E15 below)
 * is the framework's core normative content; EN 18223's change log is the
 * EU profile's subset.
 */
import { commitment } from "./canonical.js";

export type EventType =
  | "passport.created" // issuance (manufacturer/transformer/registrar/attestor)
  | "profile.binding" // dated applicability binding (incl. retroactive flags)
  | "custody.transfer" // E1 resale, lease, inheritance, liquidation
  | "part.replace" // E2 uninstall + install; BoM-instance updated
  | "repair.perform" // E3 authorized / independent / DIY
  | "product.modify" // E4 may spawn derived type (E4b) + profile re-evaluation
  | "software.update" // E5 firmware/software version vector; feature.unlock
  | "upgrade.install" // E6 add component: new child reference
  | "refurbish.perform" // E7 condition grade; remanufacture may be transformation
  | "consumable.replace" // E8 tires, filters — recurring
  | "recall.campaign" // E9 campaign ref; DAG traversal + custodian notification
  | "correction.record" // E10 new corrected fact + reason; prior preserved
  | "status.change" // E11 suspend / invalidate / reinstate, authority-checked
  | "flag.security" // E12 theft / loss; blacklist entry
  | "material.decompose" // E13 inverse transformation 1->N -> material passports
  | "inspection.stamp" // E14 lens-scoped attestation by any verifier
  | "milestone.record"; // E15 edge-segment state commitment (device)

export type ActorRole =
  | "economic-operator"
  | "custodian"
  | "repairer"
  | "installer"
  | "refurbisher"
  | "recycler"
  | "regulator"
  | "device"
  | "verifier"
  | "registrar"
  | "qualified-attestor";

export interface Actor {
  actorId: string;
  role: ActorRole;
  /** Credential reference (18239 notified-actor pattern). */
  credentialRef?: string;
}

export interface JsonRecord {
  [key: string]: string | number | boolean | null | JsonRecord | JsonRecord[] | string[];
}

/** Typed payloads for the events the fixtures and verifiers exercise. */
export interface EventPayloads {
  "passport.created": { typeRef?: string; profileIds: string[] };
  "profile.binding": { profileId: string; version: string; from: string; until?: string; retroactive?: boolean };
  "custody.transfer": { fromActor: Actor; toActor: Actor; conveyance?: string };
  "part.replace": { removedChildId?: string; installedChildId?: string; likeForLike: boolean; slotId?: string };
  "repair.perform": { repairClass: "authorized" | "independent" | "diy"; recordRef?: string };
  "product.modify": { modification: string; spawnedDerivedType?: string };
  "software.update": { component: string; fromVersion: string; toVersion: string; featureUnlock?: boolean };
  "upgrade.install": {
    childId: string;
    parentSlot: string;
    pairing: "none" | "firmware" | "key" | "module";
    method: string;
    recoverability: "restorable" | "harvestable" | "destructive" | "absorbing";
    visibilityEdge: "public" | "restricted" | "blind" | "escrowed";
  };
  "refurbish.perform": { conditionGrade?: string; remanufactureToType?: string };
  "consumable.replace": { removedChildId?: string; installedChildId?: string };
  "recall.campaign": { campaignRef: string; /** Published predicate; evaluated locally by custodians. */ predicate: string };
  "correction.record": { field: string; reason: string; correctedTo: string };
  "status.change": { from: string; to: string; authority: string };
  "flag.security": { flag: "theft" | "loss"; reportRef?: string };
  "material.decompose": {
    outputs: Array<{ passportId: string; quantity: number; unit: string }>;
    /** inputReferences: (passport, quantity, as-of-state hash). */
    inputReferences?: Array<{ passportId: string; quantity: number; stateHash: string }>;
  };
  "inspection.stamp": { lensId: string; lensVersion: string; mode: "live" | "snapshot"; verdictSummary: string };
  "milestone.record": {
    /** Device commitment over its local append-only log prefix. */
    commitment: string;
    deviceKeyId: string;
    freshWithin: string;
  };
}

/** Discriminated event: type + typed payload. */
export type DomainEvent<T extends EventType = EventType> = {
  eventId: string;
  type: T;
  subject: string;
  occurredAt: string; // ISO 8601
  actor: Actor;
  payload: T extends keyof EventPayloads ? EventPayloads[T] : JsonRecord;
  /** I9: every event carries a trust marker. */
  trustMarker: "unsigned" | "self-declared" | "third-party-attested" | "multi-signed" | "log-anchored";
  /** Hash-link to the previous event's commitment ("" for genesis). */
  prevCommitment: string;
  /** Commitment over the canonical event body (computed by append). */
  commitment: string;
};

/** The log body that gets hashed: everything except the commitment itself. */
function eventBody(event: Omit<DomainEvent, "commitment">, salt: string): string {
  return JSON.stringify({ salt, event });
}

/** Append an event to a log, computing its commitment chain. */
export async function appendEvent(
  log: DomainEvent[],
  event: Omit<DomainEvent, "commitment">,
  salt = "",
): Promise<DomainEvent[]> {
  const prev = log.length === 0 ? "" : log[log.length - 1]!.commitment;
  // The chain is stamped by append: callers cannot know the head commitment
  // before it is computed; a caller-supplied prevCommitment is authoritative
  // only when it matches (fork detection).
  if (event.prevCommitment !== "" && event.prevCommitment !== prev) {
    throw new Error("prevCommitment does not match log head; append-only violated");
  }
  const chained = { ...event, prevCommitment: prev };
  const c = await commitment(JSON.parse(eventBody(chained, salt)), "");
  return [...log, { ...chained, commitment: c }];
}

/** Verify the commitment chain of a log (tamper detection). */
export async function verifyChain(log: DomainEvent[], salt = ""): Promise<boolean> {
  let prev = "";
  for (const event of log) {
    if (event.prevCommitment !== prev) return false;
    const { commitment: _c, ...body } = event;
    const expected = await commitment(JSON.parse(eventBody(body as Omit<DomainEvent, "commitment">, salt)), "");
    if (event.commitment !== expected) return false;
    prev = event.commitment;
  }
  return true;
}

export function logHead(log: DomainEvent[]): { commitment: string; height: number } {
  return {
    commitment: log.length === 0 ? "" : log[log.length - 1]!.commitment,
    height: log.length,
  };
}

/**
 * R3 blind edge: salted commitment to the parent (+slot) in the child's log.
 * Proof-of-binding without knowledge-of-parent — log operators cannot
 * correlate edges; the binding is provable when the salt is revealed.
 * Mirrors the Python port's ``blind_edge_commitment`` (eventlog.py).
 */
export async function blindEdgeCommitment(
  parentPassportValue: string,
  slot: string,
  salt: string,
): Promise<string> {
  return commitment({ parent: parentPassportValue, slot }, salt);
}

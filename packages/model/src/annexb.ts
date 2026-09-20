/**
 * The Annex B binary canonical encoding (TODO 237), written from the
 * specification: the framing rule (each field a little-endian u32
 * length prefix and its bytes, in the declared field order), the
 * domain tags, and the per-object derivations. The vendored golden
 * vectors carry the reference `canonical_hex` pins; the suite asserts
 * byte identity — this implementation agrees with the reference or
 * the suite fails. That is the cross-implementation contract.
 */

const encoder = new TextEncoder();

export const SEGMENT_COMMITMENT = encoder.encode("UNIDPP-GRID/SEGMENT-COMMITMENT");
export const SPINE_LEAF = encoder.encode("UNIDPP-GRID/SPINE-LEAF");
export const SPINE_NODE = encoder.encode("UNIDPP-GRID/SPINE-NODE");
export const SPINE_DIGEST = encoder.encode("UNIDPP-GRID/SPINE-DIGEST");

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", data as unknown as ArrayBuffer);
  return new Uint8Array(digest);
}

function text(value: string): Uint8Array {
  return encoder.encode(value);
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/** One canonical field: u32 little-endian length prefix + bytes. */
function part(bytes: Uint8Array): Uint8Array {
  return cat(leU32(bytes.length), bytes);
}

/** The canonical form: fields in declared order, each length-prefixed. */
export function canonicalFields(parts: Uint8Array[]): Uint8Array {
  return cat(...parts.map(part));
}

/** The one framing rule: tag || 0x00 || payload. */
export function domainFrame(tag: Uint8Array, payload: Uint8Array): Uint8Array {
  return cat(tag, new Uint8Array([0]), payload);
}

/** Hash in a domain: sha256 over the domain-framed canonical parts. */
export async function hashIn(domain: Uint8Array, parts: Uint8Array[]): Promise<Uint8Array> {
  return sha256(domainFrame(domain, canonicalFields(parts)));
}

export function leU64(value: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(value), true);
  return out;
}

export function leU32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, true);
  return out;
}

/** Wire forms carry hashes either hex-encoded or as byte arrays. */
function asBytes(value: string | number[]): Uint8Array {
  return typeof value === "string"
    ? new Uint8Array((value.match(/../g) ?? []).map((h) => parseInt(h, 16)))
    : new Uint8Array(value);
}

const REVEAL_TOKENS: Record<string, string> = {
  Open: "open",
  PairingGated: "pairing-gated",
  OriginSealed: "origin-sealed",
  Escrowed: "escrowed",
};

const CLAIM_TOKENS: Record<string, string> = {
  conformity: "conformity",
  "commitment-hash": "commitment-hash",
  freshness: "freshness",
};

const EVIDENCE_TOKENS: Record<string, string> = {
  "verified-direct": "verified-direct",
  "attested-by-authority": "attested-by-authority",
  "explicitly-unavailable": "explicitly-unavailable",
};

const LEVEL_ORDINALS: Record<string, number> = {
  l0: 0,
  l1: 1,
  l2: 2,
  l3: 3,
  l4: 4,
  l5: 5,
};

/** A sorted, deduplicated list joined with the unit separator (U+001F). */
function canonList(values: string[]): Uint8Array {
  const unique = [...new Set(values)].sort();
  return encoder.encode(unique.join("\x1f"));
}

export interface Policy {
  policy_id: string;
  version: number;
  authority: string;
  reveal: string;
  valid_from: string;
  valid_to?: string | null;
  superseded_by?: number | null;
  readers: string[];
  verifiers: string[];
  writers: string[];
  suites: string[];
}

export function policyCanonical(policy: Policy): Uint8Array {
  const parts = [
    text(policy.policy_id),
    leU64(policy.version),
    text(policy.authority),
    text(REVEAL_TOKENS[policy.reveal] ?? policy.reveal),
    text(policy.valid_from),
    canonList(policy.readers),
    canonList(policy.verifiers),
    canonList(policy.writers),
    canonList(policy.suites),
  ];
  if (policy.valid_to != null) parts.push(text(policy.valid_to));
  if (policy.superseded_by != null) parts.push(leU64(policy.superseded_by));
  return canonicalFields(parts);
}

async function hPair(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const [a, b] = [left, right].sort((x, y) => {
    const n = Math.min(x.length, y.length);
    for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
    return x.length - y.length;
  });
  return hashIn(SPINE_NODE, [a, b]);
}

export async function commitState(state: Uint8Array): Promise<Uint8Array> {
  return hashIn(SEGMENT_COMMITMENT, [state]);
}

export async function spineRoot(commitments: Record<string, string | number[]>): Promise<Uint8Array> {
  const ids = Object.keys(commitments).sort();
  let level: Uint8Array[] = [];
  for (const id of ids) {
    level.push(await hashIn(SPINE_LEAF, [text(id), asBytes(commitments[id]!)]));
  }
  if (level.length === 0) return new Uint8Array(32);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        i + 1 < level.length ? await hPair(level[i]!, level[i + 1]!) : await hPair(level[i]!, level[i]!),
      );
    }
    level = next;
  }
  return level[0]!;
}

export async function spineDigest(
  version: number,
  commitments: Record<string, string | number[]>,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [leU64(version), await spineRoot(commitments)];
  for (const id of Object.keys(commitments).sort()) {
    const idBytes = text(id);
    parts.push(leU32(idBytes.length), idBytes, asBytes(commitments[id]!));
  }
  return hashIn(SPINE_DIGEST, [cat(...parts)]);
}

export interface S13Request {
  verifier: string;
  subject: string;
  profile: string;
  segment: string;
  at: string;
}

export function requestCanonical(request: S13Request): Uint8Array {
  return canonicalFields([
    text(request.verifier),
    text(request.subject),
    text(request.profile),
    text(request.segment),
    text(request.at),
  ]);
}

export interface S13Outcome {
  outcome: string;
  [key: string]: unknown;
}

export interface S13Response {
  request_digest: string | number[];
  outcome: S13Outcome;
  governing_policy: string;
  governing_policy_version: number;
  custodian: string;
}

export function responseCanonical(response: S13Response): Uint8Array {
  const payload = { ...response.outcome } as Record<string, string>;
  delete payload.outcome;
  return canonicalFields([
    asBytes(response.request_digest),
    text(response.outcome.outcome),
    ...Object.values(payload).map(text),
    text(response.governing_policy),
    leU64(response.governing_policy_version),
    text(response.custodian),
  ]);
}

export interface RouteStep {
  step: string;
  [key: string]: unknown;
}

export interface VerificationRoute {
  steps: RouteStep[];
}

export function routeCanonical(route: VerificationRoute): Uint8Array {
  const parts: Uint8Array[] = [leU64(route.steps.length)];
  for (const step of route.steps) {
    parts.push(text(step.step));
    switch (step.step) {
      case "resolve":
        parts.push(text(step.subject as string));
        break;
      case "transport":
        parts.push(text(step.mode as string), text(step.counterpart as string));
        break;
      case "document":
        parts.push(text(step.kind as string), asBytes(step.digest as string | number[]));
        break;
      case "substitution":
        parts.push(text(step.data_class as string), text(step.service as string));
        break;
      case "classify": {
        const entry = step.entry as Record<string, string | number>;
        parts.push(
          text(entry.class as string),
          text(entry.element_set as string),
          text(EVIDENCE_TOKENS[entry.evidence as string] ?? (entry.evidence as string)),
          text(entry.governing_policy as string),
          leU64(entry.governing_policy_version as number),
          text(entry.reading as string),
          text(entry.as_of as string),
        );
        break;
      }
      case "gap":
        parts.push(text(step.data_class as string), text(step.reason as string));
        break;
    }
  }
  return canonicalFields(parts);
}

export async function routeDigest(route: VerificationRoute): Promise<Uint8Array> {
  return sha256(routeCanonical(route));
}

export interface CoverageEntry {
  class: string;
  element_set: string;
  evidence: string;
  governing_policy: string;
  governing_policy_version: number;
  reading: string;
  as_of: string;
}

export interface CoverageReport {
  subject: string;
  profile: string;
  verified_at: string;
  route?: VerificationRoute | null;
  entries: CoverageEntry[];
}

export async function reportCanonical(report: CoverageReport): Promise<Uint8Array> {
  const parts: Uint8Array[] = [
    text(report.subject),
    text(report.profile),
    text(report.verified_at),
    leU64(report.route != null ? 1 : 0),
  ];
  if (report.route != null) parts.push(await routeDigest(report.route));
  parts.push(leU64(report.entries.length));
  for (const entry of report.entries) {
    parts.push(
      text(entry.class),
      text(entry.element_set),
      text(EVIDENCE_TOKENS[entry.evidence] ?? entry.evidence),
      text(entry.governing_policy),
      leU64(entry.governing_policy_version),
      text(entry.reading),
      text(entry.as_of),
    );
  }
  return canonicalFields(parts);
}

export interface AttestationStatement {
  segment: string;
  state_commitment: string | number[];
  claim: string;
  value: string;
  as_of: string;
  governing_policy: string;
  governing_policy_version: number;
  subject: string;
}

export function statementCanonical(statement: AttestationStatement): Uint8Array {
  return canonicalFields([
    text(statement.segment),
    asBytes(statement.state_commitment),
    text(CLAIM_TOKENS[statement.claim] ?? statement.claim),
    text(statement.value),
    text(statement.as_of),
    text(statement.governing_policy),
    leU64(statement.governing_policy_version),
    text(statement.subject),
  ]);
}

export interface FrozenView {
  subject: string;
  descriptor: Record<string, string>;
  lens: {
    profile: string;
    transforms: { reference: string; version: number }[];
    input_segments: [string, string][];
  };
  payload: string | number[];
  inputs: { name: string; bytes: number[] | string }[];
  instructions: string[];
  notarized_at: string;
  bundle: { spine: { spine: { version: number; commitments: Record<string, string | number[]> } } };
}

function descriptorToken(descriptor: Record<string, string>): string {
  return [descriptor.temporal, descriptor.content, descriptor.derivation, descriptor.exchange, descriptor.granularity].join(
    "·",
  );
}

export async function frozenViewCanonical(view: FrozenView): Promise<Uint8Array> {
  const parts: Uint8Array[] = [
    text(view.subject),
    text(descriptorToken(view.descriptor)),
    text(view.lens.profile),
  ];
  for (const step of view.lens.transforms) {
    parts.push(text(step.reference), leU64(step.version));
  }
  for (const [name, segment] of view.lens.input_segments) {
    parts.push(text(name), text(segment));
  }
  parts.push(asBytes(view.payload));
  for (const input of view.inputs) {
    parts.push(text(input.name), await commitState(asBytes(input.bytes)));
  }
  for (const instruction of view.instructions) {
    parts.push(text(instruction));
  }
  parts.push(text(view.notarized_at));
  parts.push(await spineDigest(view.bundle.spine.spine.version, view.bundle.spine.spine.commitments));
  return canonicalFields(parts);
}

export interface InteropPosture {
  data_class: string;
  level: string;
  recognition: string;
  transports: string[];
  escalation?: string | null;
  reciprocity?: string | null;
}

export interface InteropDeclaration {
  declarer: string;
  counterpart: string;
  version: number;
  postures: InteropPosture[];
  valid_from: string;
  valid_to?: string | null;
}

export function declarationCanonical(declaration: InteropDeclaration): Uint8Array {
  const postures = [...declaration.postures].sort((a, b) =>
    a.data_class < b.data_class ? -1 : a.data_class > b.data_class ? 1 : 0,
  );
  const parts: Uint8Array[] = [
    text(declaration.declarer),
    text(declaration.counterpart),
    leU64(declaration.version),
  ];
  for (const posture of postures) {
    parts.push(
      text(posture.data_class),
      new Uint8Array([LEVEL_ORDINALS[posture.level] ?? 255]),
      text(posture.recognition),
    );
    for (const transport of [...posture.transports].sort()) parts.push(text(transport));
    parts.push(text(posture.escalation ?? ""), text(posture.reciprocity ?? ""));
  }
  parts.push(text(declaration.valid_from), text(declaration.valid_to ?? ""));
  return canonicalFields(parts);
}

export interface MappingKind {
  tier: string;
  transform?: string;
  scope?: string[];
  residual?: string;
  attester?: string;
  note?: string;
}

export interface MappingItem {
  source: string;
  target: string;
  version: number;
  kind: MappingKind;
}

export function mappingItemCanonical(item: MappingItem): Uint8Array {
  const parts: Uint8Array[] = [text(item.source), text(item.target), leU64(item.version)];
  if (item.kind.tier === "deterministic") {
    parts.push(text("tier-1"), text(item.kind.transform!));
  } else if (item.kind.tier === "correspondence") {
    parts.push(text("tier-2"));
    for (const scope of [...(item.kind.scope ?? [])].sort()) parts.push(text(scope));
    parts.push(text(item.kind.residual!), text(item.kind.attester!));
  } else if (item.kind.tier === "no-mapping") {
    parts.push(text("tier-3"), text(item.kind.note!));
  } else {
    throw new Error(`unknown mapping tier \`${item.kind.tier}\``);
  }
  return canonicalFields(parts);
}

export { equalBytes };

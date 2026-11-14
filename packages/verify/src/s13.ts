/** The S13 trust layer (XB-6/7): verify the seam's signed envelopes
 *  offline — the requester's, the custodian's and the authority's
 *  signatures all ride the S13-MESSAGE domain over canonical bytes,
 *  and the choreography journal replays from the envelopes alone.
 *  The graph is the caller's projection: node id → that node's
 *  anchored keys (the same resolution discipline the native
 *  TrustGraph applies — a valid signature from any other node's key
 *  is not this envelope).
 */

import {
  requestCanonical,
  responseCanonical,
  authorityPayloadCanonical,
  sha256,
  toHex,
  type S13Decision,
  type S13Journal,
  type S13JournalEntry,
  type S13NonRepudiableResponse,
  type S13Response,
  type SignedS13Request,
  type SignedS13Response,
} from "@unidpp/model";
import type { CryptoSlots, PublicKeyMaterial, TrustAnchors } from "./crypto.js";

/** The S13-message signing domain tag (Annex B Table B.2). */
export const S13_DOMAIN = "UNIDPP-SIGNATIF/S13-MESSAGE";

/** The graph projection: node id → the keys anchored for it. */
export type S13Graph = ReadonlyMap<string, TrustAnchors>;

function domainFramed(payload: Uint8Array): Uint8Array {
  const tag = new TextEncoder().encode(S13_DOMAIN);
  const framed = new Uint8Array(tag.length + 1 + payload.length);
  framed.set(tag);
  framed[tag.length] = 0;
  framed.set(payload, tag.length + 1);
  return framed;
}

const bytes = (value: number[] | Uint8Array): Uint8Array => new Uint8Array(value);

/** The digest rides JSON as either a byte array or its hex form. */
const digestBytes = (value: string | number[]): Uint8Array =>
  typeof value === "string"
    ? new Uint8Array((value.match(/../g) ?? []).map((b) => parseInt(b, 16)))
    : new Uint8Array(value);

async function verifyUnder(
  slots: CryptoSlots,
  graph: S13Graph,
  node: string,
  suite: string,
  keyId: string,
  payload: Uint8Array,
  signature: Uint8Array | null,
): Promise<{ ok: true } | { ok: false; why: string }> {
  const keys = graph.get(node);
  if (!keys) return { ok: false, why: `s13 node \`${node}\` has no such keys` };
  const key: PublicKeyMaterial | undefined = keys.get(keyId);
  if (!key) return { ok: false, why: `s13 node \`${node}\` has no such key \`${keyId}\`` };
  if (!signature) return { ok: false, why: "the slot is framed-only (nothing to verify)" };
  const slot = slots.get(suite);
  if (!slot) return { ok: false, why: `suite \`${suite}\` is not computable in this build` };
  const verified = await slot.verify({ suite, payload, signature, publicKey: key });
  return verified
    ? { ok: true }
    : { ok: false, why: `the signature does not verify under \`${node}\`'s key \`${keyId}\`` };
}

/** Verify the verifier's signed request under the graph. */
export async function verifyS13Request(
  signed: SignedS13Request,
  graph: S13Graph,
  slots: CryptoSlots,
): Promise<{ ok: true } | { ok: false; why: string }> {
  return verifyUnder(
    slots,
    graph,
    signed.requester,
    signed.signature.suite,
    signed.signature.key_id,
    domainFramed(requestCanonical(signed.request)),
    bytes(signed.signature.signature ?? []),
  );
}

/** Verify the custodian's signed answer under the graph. */
export async function verifyS13Response(
  signed: SignedS13Response,
  graph: S13Graph,
  slots: CryptoSlots,
): Promise<{ ok: true } | { ok: false; why: string }> {
  return verifyUnder(
    slots,
    graph,
    signed.response.custodian,
    signed.signature.suite,
    signed.signature.key_id,
    domainFramed(responseCanonical(signed.response)),
    bytes(signed.signature.signature ?? []),
  );
}

/** The non-repudiable answer (XB-7): the custodian's signature AND
 *  the authority's counter-signature over the answer's identity and
 *  place, at the exact expected sequence (a stale sequence is a
 *  replayed answer). */
export async function verifyNonRepudiable(
  nonRepudiable: S13NonRepudiableResponse,
  graph: S13Graph,
  slots: CryptoSlots,
  expectedSequence: number,
): Promise<{ ok: true } | { ok: false; why: string }> {
  const custodian = await verifyS13Response(nonRepudiable.signed, graph, slots);
  if (!custodian.ok) return custodian;
  if (nonRepudiable.sequence !== expectedSequence) {
    return {
      ok: false,
      why: `s13 non-repudiation: stale sequence ${nonRepudiable.sequence} (expected ${expectedSequence}) — a replayed answer`,
    };
  }
  const response: S13Response = nonRepudiable.signed.response;
  return verifyUnder(
    slots,
    graph,
    nonRepudiable.authority,
    nonRepudiable.authority_signature.suite,
    nonRepudiable.authority_signature.key_id,
    domainFramed(authorityPayloadCanonical(response, nonRepudiable.sequence)),
    bytes(nonRepudiable.authority_signature.signature ?? []),
  );
}

const isRequest = (e: S13JournalEntry): e is SignedS13Request => "request" in e;
const isResponse = (e: S13JournalEntry): e is SignedS13Response => "response" in e;

/** Replay the choreography from the journal alone (XB-6): every
 *  entry verifies under the graph, every answer binds to a journaled
 *  request's digest, and every counter-signature sits at its exact
 *  monotone place per (subject, custodian), from 1. The decisions
 *  come back in journal sequence. */
export async function replayS13Journal(
  journal: S13Journal,
  graph: S13Graph,
  slots: CryptoSlots,
): Promise<{ ok: true; decisions: S13Decision[] } | { ok: false; why: string }> {
  const decisions: S13Decision[] = [];
  const subjects = new Map<string, string>();
  const sequences = new Map<string, number>();
  let index = 0;
  for (const entry of journal.entries) {
    index += 1;
    if (isRequest(entry)) {
      const check = await verifyS13Request(entry, graph, slots);
      if (!check.ok) return { ok: false, why: `entry ${index}: ${check.why}` };
      // The binding is the request digest (what answers cite).
      const digest = toHex(await sha256(requestCanonical(entry.request)));
      subjects.set(digest, entry.request.subject);
      continue;
    }
    if (isResponse(entry)) {
      const check = await verifyS13Response(entry, graph, slots);
      if (!check.ok) return { ok: false, why: `entry ${index}: ${check.why}` };
      const digest = toHex(digestBytes(entry.response.request_digest));
      if (!subjects.has(digest)) {
        return { ok: false, why: `entry ${index}: an answer is bound to no journaled request` };
      }
      decisions.push(decisionOf(entry.response));
      continue;
    }
    const digest = toHex(digestBytes(entry.signed.response.request_digest));
    if (!subjects.has(digest)) {
      return { ok: false, why: `entry ${index}: an answer is bound to no journaled request` };
    }
    const subject = subjects.get(digest) ?? "";
    const key = `${subject}|${entry.signed.response.custodian}`;
    const expected = (sequences.get(key) ?? 0) + 1;
    const check = await verifyNonRepudiable(entry, graph, slots, expected);
    if (!check.ok) return { ok: false, why: `entry ${index}: ${check.why}` };
    sequences.set(key, entry.sequence);
    decisions.push(decisionOf(entry.signed.response));
  }
  return { ok: true, decisions };
}

function decisionOf(response: S13Response): S13Decision {
  return {
    request_digest_hex: toHex(digestBytes(response.request_digest)),
    outcome: response.outcome.outcome,
    governing_policy: response.governing_policy,
    governing_policy_version: response.governing_policy_version,
  };
}

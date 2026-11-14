/** The S13 trust layer's gates (XB-6/7): the F2 signed-exchange
 *  vector verifies through the graph projection (and fails on
 *  tampering), the countersigned vector verifies at its sequence and
 *  fails on a stale one or an unanchored authority, and the journal
 *  replays from the envelopes alone — refusing an answer bound to no
 *  journaled request. */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { keyIdFor } from "@unidpp/model";
import type { S13Journal, S13NonRepudiableResponse } from "@unidpp/model";
import { CryptoSlots, WebCryptoEd25519Slot } from "../src/crypto.js";
import {
  replayS13Journal,
  verifyNonRepudiable,
  verifyS13Request,
  verifyS13Response,
  type S13Graph,
} from "../src/s13.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = path.join(HERE, "..", "..", "..", "test-vectors");

const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(path.join(VECTORS, name), "utf8"));

const hexToBytes = (hex: string): Uint8Array =>
  new Uint8Array((hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));

const slots = (): CryptoSlots => {
  const registry = new CryptoSlots();
  registry.register(new WebCryptoEd25519Slot());
  return registry;
};

const graphOf = async (doc: Record<string, unknown>, ...roles: [string, string][]): Promise<S13Graph> => {
  const map = new Map();
  for (const [node, publicField] of roles) {
    const keyId = await keyIdFor("ed25519", hexToBytes(doc[publicField] as string));
    map.set(node, new Map([[keyId, { format: "raw-ed25519", bytes: hexToBytes(doc[publicField] as string) }]]));
  }
  return map;
};

describe("the S13 envelope verify", () => {
  const exchange = fixture("s13-signed-exchange.json");

  it("the F2 signed exchange verifies under its publics", async () => {
    const graph = await graphOf(
      exchange,
      ["de-zoll", "requester_public_hex"],
      ["weilian-shenzhen", "responder_public_hex"],
    );
    const request = await verifyS13Request(exchange.signed_request as never, graph, slots());
    expect(request).toEqual({ ok: true });
    const response = await verifyS13Response(exchange.signed_response as never, graph, slots());
    expect(response).toEqual({ ok: true });
  });

  it("a tampered subject fails the requester's slot", async () => {
    const graph = await graphOf(exchange, ["de-zoll", "requester_public_hex"]);
    const signed = JSON.parse(JSON.stringify(exchange.signed_request)) as {
      request: { subject: string };
      requester: string;
      signature: { suite: string; key_id: string; signature: number[] };
    };
    signed.request.subject = "urn:unidpp:passport:other";
    const verdict = await verifyS13Request(signed as never, graph, slots());
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.why).toContain("does not verify");
  });

  it("an unanchored node refuses before any crypto", async () => {
    const verdict = await verifyS13Request(exchange.signed_request as never, new Map(), slots());
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.why).toContain("no such keys");
  });
});

describe("the non-repudiable answer (XB-7)", () => {
  const doc = fixture("s13-countersigned.json");
  const countersigned = doc.countersigned as S13NonRepudiableResponse;

  it("verifies at its sequence under the authority's key", async () => {
    const graph = await graphOf(
      doc,
      ["de-zoll", "requester_public_hex"],
      ["weilian-shenzhen", "responder_public_hex"],
      ["cn-samr", "authority_public_hex"],
    );
    expect(await verifyNonRepudiable(countersigned, graph, slots(), 1)).toEqual({ ok: true });
  });

  it("a stale expected sequence refuses (a replayed answer)", async () => {
    const graph = await graphOf(
      doc,
      ["weilian-shenzhen", "responder_public_hex"],
      ["cn-samr", "authority_public_hex"],
    );
    const verdict = await verifyNonRepudiable(countersigned, graph, slots(), 2);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.why).toContain("stale sequence 1 (expected 2)");
  });

  it("an authority outside the graph refuses", async () => {
    const graph = await graphOf(doc, ["weilian-shenzhen", "responder_public_hex"]);
    const verdict = await verifyNonRepudiable(countersigned, graph, slots(), 1);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.why).toContain("cn-samr");
  });
});

describe("the choreography journal replay (XB-6)", () => {
  const exchange = fixture("s13-signed-exchange.json");
  const doc = fixture("s13-countersigned.json");

  const journal = (): S13Journal => ({
    side: "custodian",
    entries: [
      exchange.signed_request,
      exchange.signed_response,
      doc.countersigned,
    ] as S13Journal["entries"],
  });

  const fullGraph = async (): Promise<S13Graph> => {
    const graph = await graphOf(
      doc,
      ["de-zoll", "requester_public_hex"],
      ["weilian-shenzhen", "responder_public_hex"],
      ["cn-samr", "authority_public_hex"],
    );
    return graph;
  };

  it("replays to the decisions in journal sequence", async () => {
    const replayed = await replayS13Journal(journal(), await fullGraph(), slots());
    expect(replayed.ok).toBe(true);
    if (replayed.ok) {
      // The journaled answer and its counter-signed record each yield
      // the decision, in sequence.
      expect(replayed.decisions).toHaveLength(2);
      expect(replayed.decisions.every((d) => d.outcome === "attestation-offer")).toBe(true);
      expect(replayed.decisions.every((d) => d.governing_policy === "cn-dynamic-bms")).toBe(true);
    }
  });

  it("an answer bound to no journaled request refuses", async () => {
    // The signed answer replays alone: its slot verifies, but no
    // journaled request carries the digest it cites — the binding
    // catches what the signature alone cannot.
    const orphan: S13Journal = { side: "custodian", entries: [exchange.signed_response as S13Journal["entries"][number]] };
    const replayed = await replayS13Journal(orphan, await fullGraph(), slots());
    expect(replayed.ok).toBe(false);
    if (!replayed.ok) expect(replayed.why).toContain("bound to no journaled request");
  });
});

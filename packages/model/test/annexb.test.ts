// The Annex B binary canonical encodings against the vendored golden
// vectors (TODO 237): every fixture's object re-derives the reference
// `canonical_hex` pin byte for byte. An implementation we did not
// write reproduces the reference bytes or this suite fails — the
// cross-implementation contract (CN-1).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  declarationCanonical,
  frozenViewCanonical,
  mappingItemCanonical,
  policyCanonical,
  reportCanonical,
  requestCanonical,
  responseCanonical,
  statementCanonical,
  keyIdFor,
  authorityPayloadCanonical,
} from "../src/annexb.js";
import { decodeTierAHex, encodeTierA } from "../src/tierCarrier.js";
import { toHex } from "../src/canonical.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = path.join(here, "..", "..", "..", "test-vectors");


function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array((hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));
}

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path.join(vectorsDir, name), "utf8"));
}

function hex(bytes: Uint8Array): string {
  return toHex(bytes);
}

describe("the Annex B binary canonical encoding", () => {
  it("reproduces the S13 request", () => {
    const doc = fixture("request.json");
    expect(hex(requestCanonical(doc.request as never))).toBe(doc.canonical_hex);
  });

  it("reproduces the S13 response", () => {
    const doc = fixture("response.json");
    expect(hex(responseCanonical(doc.response as never))).toBe(doc.canonical_hex);
  });

  it("reproduces the coverage report (with its route digest)", async () => {
    const doc = fixture("coverage-report.json");
    expect(hex(await reportCanonical(doc.report as never))).toBe(doc.canonical_hex);
  });

  it("reproduces the grid policy", () => {
    const doc = fixture("policy.json");
    expect(hex(policyCanonical(doc.policy as never))).toBe(doc.canonical_hex);
  });

  it("reproduces the attestation statement", () => {
    const doc = fixture("attestation-statement.json");
    expect(hex(statementCanonical(doc.statement as never))).toBe(doc.canonical_hex);
  });

  it("reproduces the frozen view (with its spine digest)", async () => {
    const doc = fixture("frozen-view.json");
    expect(hex(await frozenViewCanonical(doc.view as never))).toBe(doc.canonical_hex);
  });

  it("reproduces the interop declaration", () => {
    const doc = fixture("interop-declaration.json");
    expect(hex(declarationCanonical(doc.declaration as never))).toBe(doc.canonical_hex);
  });

  it("reproduces the mapping correspondence", () => {
    const doc = fixture("mapping-chain.json");
    expect(hex(mappingItemCanonical(doc.correspondence as never))).toBe(
      doc.correspondence_canonical_hex,
    );
    expect(hex(mappingItemCanonical(doc.divergence as never))).toBe(
      doc.divergence_canonical_hex,
    );
  });
});

describe("the tier-a carrier codec (the native framing)", () => {
  it("decodes the corpus carrier and reproduces its bytes", () => {
    const doc = fixture("pack.json");
    const decoded = doc.decoded as {
      product_id: string;
      passport_id: string;
      eo_id: string;
      status: string;
      safety: string;
      validity: { from: string };
      signatures: { key_id: string }[];
    };
    const payload = decodeTierAHex(doc.hex as string);
    expect(payload.productId).toBe(decoded.product_id);
    expect(payload.passportId).toBe(decoded.passport_id);
    expect(payload.eoId).toBe(decoded.eo_id);
    expect(payload.status).toBe(decoded.status);
    expect(payload.safety).toBe(decoded.safety);
    expect(payload.validity.from).toBe(decoded.validity.from);
    expect(payload.validity.to).toBeNull();
    expect(payload.logHead).toBeNull();
    expect(payload.signatures).toHaveLength(1);
    expect(payload.signatures[0]!.suite).toBe("ecdsa-p256");
    expect(payload.signatures[0]!.keyId).toBe(decoded.signatures[0]!.key_id);
    expect(toHex(encodeTierA(payload))).toBe(doc.hex);
  });
});

describe("the S13 trust layer's derivations", () => {
  it("derives the F2 exchange's key ids (Annex B)", async () => {
    const exchange = fixture("s13-signed-exchange.json");
    const requester = hexToBytes(exchange.requester_public_hex as string);
    const responder = hexToBytes(exchange.responder_public_hex as string);
    expect(await keyIdFor("ed25519", requester)).toBe(
      (exchange.signed_request as { signature: { key_id: string } }).signature.key_id,
    );
    expect(await keyIdFor("ed25519", responder)).toBe(
      (exchange.signed_response as { signature: { key_id: string } }).signature.key_id,
    );
  });

  it("derives the countersigned vector's authority key id and payload", async () => {
    const doc = fixture("s13-countersigned.json");
    const countersigned = doc.countersigned as {
      authority: string;
      authority_signature: { key_id: string };
      signed: { response: Parameters<typeof authorityPayloadCanonical>[0] };
    };
    const authority = hexToBytes(doc.authority_public_hex as string);
    expect(await keyIdFor("ed25519", authority)).toBe(countersigned.authority_signature.key_id);
    expect(hex(authorityPayloadCanonical(countersigned.signed.response, doc.sequence as number))).toBe(
      doc.authority_payload_hex,
    );
  });
});

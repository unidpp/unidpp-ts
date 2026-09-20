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
} from "../src/annexb.js";
import { toHex } from "../src/canonical.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = path.join(here, "..", "..", "..", "test-vectors");

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

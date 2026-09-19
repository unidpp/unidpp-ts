// The family's golden vectors, consumed from the vendored corpus
// (TODO 234). Every fixture is the corpus Rust pinned, byte for byte
// (the manifest pins the digests; the e2e harness cross-checks them
// against unidpp-core's originals), and every fixture carries the
// pins of the Annex B binary canonical encoding — the layer the
// Python harness reproduces byte-identically. This suite holds the
// TypeScript half that exists today: the corpus identity and this
// package's JSON-canonicalizer being stable over the whole corpus
// (idempotent, and equal on re-parse). The binary canonical encoder
// for TypeScript is the named successor (TODO.complete/237); when it
// lands, the pin comparison joins here unchanged.

import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/canonical.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = path.join(here, "..", "..", "..", "test-vectors");

function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

describe("the vendored golden vectors", () => {
  it("carries the corpus the manifest pins", () => {
    const manifest = readFileSync(path.join(vectorsDir, "vectors.sha256"), "utf8");
    for (const line of manifest.trim().split("\n")) {
      const [digest, name] = line.split(/\s+/);
      const bytes = readFileSync(path.join(vectorsDir, name));
      expect(sha256(bytes)).toBe(digest);
    }
  });

  for (const name of readdirSync(vectorsDir).filter((f) => f.endsWith(".json"))) {
    it(`canonicalizes ${name} stably`, () => {
      const doc = JSON.parse(readFileSync(path.join(vectorsDir, name), "utf8"));
      const once = canonicalJson(doc);
      const twice = canonicalJson(JSON.parse(once));
      expect(twice).toBe(once);
    });
  }
});

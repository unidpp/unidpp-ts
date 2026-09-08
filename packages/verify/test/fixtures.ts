/**
 * Multi-suite fixture packs (the sovereign co-signature model, TODO 93).
 *
 * Provenance — every byte below comes from a real mint, none is invented:
 *
 * - Carrier packs (hex): minted 2026-09-08 with the Rust verifier's own
 *   code path (`unidpp-cli` src/packfile.rs `sign_pack_suites`), seed
 *   `fixture-93`, one body co-signed by `ecdsa-p256,sm2` and a second
 *   pack carrying the `sm2` slot alone. The Rust build links the real
 *   GM/T 0003 SM2 computation (RustCrypto `sm2`, deterministic signing).
 *   The pack hex is kept here as the provenance record; this TypeScript
 *   build does not decode the binary carrier — the browser model below
 *   is the JSON projection of the same mint.
 * - SM2 slot: the bytes minted above ride the `sm2-sm3` framing
 *   verbatim (key id, 64-byte r||s value, raw 65-byte anchor point).
 *   A browser (WebCrypto, no SM2) defers the slot with an explicit
 *   reason and never interprets these bytes — that is the point of the
 *   fixture.
 * - P-256 slot: WebCrypto ECDSA P-256 over the canonical-JSON body of
 *   the pack below (signatures stripped, RFC 8785-lite canonicalization,
 *   the same bytes `signedPayload` produces). The key id follows the
 *   Rust `KeyId::of` derivation (k- + sha256(suite code || raw
 *   point)[..16]) so browser and terminal vocabularies agree.
 */
import type { TierAPack } from "@unidpp/model";
import type { PublicKeyMaterial, TrustAnchors } from "../src/crypto.js";

/** The Rust-minted carrier packs (provenance record; not decoded in TS). */
export const COSIGNED_PACK_HEX =
  "011000000030312b34303036333831333333393331022800000068747470733a2f2f7265736f6c7665722e756e696470702e6f72672f722f666978747572652d3933031e00000075726e3a756e696470703a70617373706f72743a666978747572652d3933040d000000656f2d666978747572652d3933050600000069737375656406040000006e6f6e650714000000323032372d30312d31355430383a30303a30305a08000914000000323032372d30312d31355430383a30303a30305a0a01eb595ebcc060336f57eabc311610549779ec33e68a9f3ff65bd44cc7071503f30b020c01120000006b2d32613464623464653430303236643839400097ef8a428b91c55fc9f54d72712255bd2358c765b7414e198426b2e89f3683a4acb9f34129fda9d80d1b53db367031391c8fe3c258cc9050bd2982661a55522b0c02120000006b2d38366631643836353332323765346164400016b72c156f08694d29d66e3f5156a879ef5e06ed149e7548dd4ee9ce29e45576ade665e382e54e786c48e52e9472d993517dcd230fe33075397e0f34e95c657f" as const;

export const PURE_SM2_PACK_HEX =
  "011000000030312b34303036333831333333393331022800000068747470733a2f2f7265736f6c7665722e756e696470702e6f72672f722f666978747572652d3933031e00000075726e3a756e696470703a70617373706f72743a666978747572652d3933040d000000656f2d666978747572652d3933050600000069737375656406040000006e6f6e650714000000323032372d30312d31355430383a30303a30305a08000914000000323032372d30312d31355430383a30303a30305a0a01eb595ebcc060336f57eabc311610549779ec33e68a9f3ff65bd44cc7071503f30b010c02120000006b2d38366631643836353332323765346164400016b72c156f08694d29d66e3f5156a879ef5e06ed149e7548dd4ee9ce29e45576ade665e382e54e786c48e52e9472d993517dcd230fe33075397e0f34e95c657f" as const;

/** SM2 slot material as minted by the Rust build (seed `fixture-93`). */
const SM2_SLOT = {
  keyId: "k-86f1d8653227e4ad",
  /** 64-byte r||s over the carrier signing body. */
  value: "FrcsFW8IaU0p1m4/UVaoee9eBu0UnnVI3U7pzinkVXat5mXjguVOeGxI5S6UctmTUX3NIw/jMHU5fg806Vxlfw==",
  /** Raw 65-byte SM2 public point (04||X||Y), the anchor a CN-capable terminal pins. */
  anchorHex: "044233c0735dccf01b0288da5bafefed02eb87138943e88d025a8c5a30a9e35a0ca9b0e31ba809064adcbfd26766b59c86134d132bf6784d471c129156e2c01213",
} as const;

/** Browser P-256 slot material: WebCrypto ECDSA over the canonical-JSON body. */
const P256_SLOT = {
  keyId: "k-9fdf5285b4a26c6e",
  /** ECDSA P-256 (r||s, P1363) over signedPayload(pack). */
  value: "Gp8noM9LEFjVwMpjlaqiS1mjwpqQ74ufr247lzLirHmNshyGvavZIOy5ZPeqMlunKX8NW5enVa/mroSHA+X7VA==",
  /** SPKI (DER, hex) of the signing public key — the anchor this browser pins. */
  spkiHex: "3059301306072a8648ce3d020106082a8648ce3d0301070342000471159ca759ea0e3eabecc6aea876a45f76f3f402d2675aa2cf5094fb26462f307ab82d29e5a4e32fbb5a2932ef74f7c521e6d260fbc199ef3d1c80bc6c1590c4",
} as const;

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The shared pack body: one body, many sovereign suites. */
function fixture93Body(): TierAPack {
  return {
    kind: "unidpp.tier-a",
    version: "1",
    subjectId: { scheme: "gs1-gtin", value: "gtin:4006381333931", granularity: "batch", state: "live" },
    passportId: { scheme: "unidpp", value: "urn:unidpp:passport:fixture-93", granularity: "item", state: "live" },
    resolverUri: "https://resolver.unidpp.org/r/fixture-93",
    operatorId: "eo-fixture-93",
    status: "active",
    criticalSafety: { recall: false },
    validity: { notBefore: "2027-01-15T08:00:00Z", notAfter: "2037-01-15T08:00:00Z" },
    profiles: [{ profileId: "urn:unidpp:profile:multi-suite-demo", version: "1.0.0" }],
    logCommitment: {
      commitment: "eb595ebcc060336f57eabc311610549779ec33e68a9f3ff65bd44cc7071503f3",
      height: 1,
      asOf: "2027-01-15T08:00:00Z",
    },
    signatures: [],
  };
}

/** The co-signed pack: EU-classical P-256 + CN SM2 over one body. */
export function cosignedPack(): TierAPack {
  return {
    ...fixture93Body(),
    signatures: [
      { suite: "ecdsa-p256-sha256", keyId: P256_SLOT.keyId, signedAt: "2027-01-15T08:00:00Z", value: P256_SLOT.value },
      { suite: "sm2-sm3", keyId: SM2_SLOT.keyId, signedAt: "2027-01-15T08:00:00Z", value: SM2_SLOT.value },
    ],
  };
}

/** The pure-SM2 pack: a CN-anchored deployment's carrier. */
export function pureSm2Pack(): TierAPack {
  return {
    ...fixture93Body(),
    signatures: [{ suite: "sm2-sm3", keyId: SM2_SLOT.keyId, signedAt: "2027-01-15T08:00:00Z", value: SM2_SLOT.value }],
  };
}

/** The verifier's anchor set: both sovereign signers pinned by key id. */
export function fixture93Anchors(): TrustAnchors {
  const sm2Anchor: PublicKeyMaterial = { format: "opaque", material: `sm2:${SM2_SLOT.anchorHex}` };
  return new Map<string, PublicKeyMaterial>([
    [P256_SLOT.keyId, { format: "spki", bytes: hexBytes(P256_SLOT.spkiHex) }],
    [SM2_SLOT.keyId, sm2Anchor],
  ]);
}

/** Anchor set of a strictly EU-classical verifier (P-256 only). */
export function p256OnlyAnchors(): TrustAnchors {
  return new Map<string, PublicKeyMaterial>([[P256_SLOT.keyId, { format: "spki", bytes: hexBytes(P256_SLOT.spkiHex) }]]);
}

export const NOW = "2027-06-01T12:00:00Z";

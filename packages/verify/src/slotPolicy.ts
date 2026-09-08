/**
 * Per-suite slot policy (the multi-suite honesty ladder): the ONE place
 * that decides how a filled signature slot is graded in this build.
 *
 * Mirrors the Rust verifier's `SlotCheck` semantics (`unidpp-cli`
 * src/packfile.rs `check_slot_in`) so a browser verdict and an officer's
 * terminal verdict agree on the grading order:
 *
 * 1. a deferred suite degrades first — no anchor in this build could
 *    verify it, whatever bytes it carries (never fake, never crash);
 * 2. a malformed key id is invalid (fail);
 * 3. the anchor set routes by key id — an unlisted key id degrades
 *    (`unknown-key`: the verifier's trust configuration does not cover
 *    that signer; this is how a wrong or absent anchor surfaces);
 * 4. a voided signature fails under every reading that honors the
 *    revocation;
 * 5. only a signature that fails real verification under the pinned
 *    anchor fails outright — tampering.
 *
 * Which suites compute here is model-driven: a suite is computed exactly
 * when a crypto slot is registered for it (`CryptoSlots`, default
 * WebCrypto ECDSA P-256/P-384 where available). SM2 and ML-DSA are
 * documented deferrals — this package will not hand-roll their
 * cryptography in TypeScript.
 */
import type { SignatureFraming } from "@unidpp/model";
import { fromBase64 } from "@unidpp/model";
import type { CryptoSlots, PublicKeyMaterial, TrustAnchors } from "./crypto.js";

/** The graded outcome for one filled signature slot (CLI `SlotCheck`). */
export type SlotCheck =
  | { kind: "verified"; suite: string; keyId: string }
  | { kind: "unknown-key"; keyId: string; anchorKeyIds: string[] }
  | { kind: "invalid"; suite: string; why: string }
  | { kind: "deferred"; suite: string; reason: string }
  | { kind: "voided"; keyId: string; reason: string };

/**
 * Designed deferrals of this build, mirroring the SIGNATIF
 * `Suite::deferral()` texts. Suites absent from both this table and the
 * registered slots take the generic agility fallback.
 */
const DEFERRALS: Readonly<Record<string, string>> = {
  "sm2-sm3":
    "SM2 computation requires a GM/T 0003 binding; this browser build carries the framing (64-byte r||s slots) and refuses to fake verification",
  "ml-dsa-44":
    "ML-DSA (FIPS 204) computation requires a PQ binding; this browser build carries the framing and budget math only",
  "ml-dsa-65":
    "ML-DSA (FIPS 204) computation requires a PQ binding; this browser build carries the framing and budget math only",
  "ml-dsa-87":
    "ML-DSA (FIPS 204) computation requires a PQ binding; this browser build carries the framing and budget math only",
};

/** Why `suite` does not compute in this build (explicit, never silent). */
export function deferralReason(suite: string): string {
  return DEFERRALS[suite] ?? `no crypto binding for suite ${suite} in this build (agility suite; register a slot for it)`;
}

/**
 * Key-id grammar, mirroring the Rust `KeyId::new`: 1..=64 printable
 * ASCII graphic characters. Anything else is malformed and fails the
 * slot outright rather than being matched against anchors.
 */
export function wellFormedKeyId(keyId: string): boolean {
  if (keyId.length === 0 || keyId.length > 64) return false;
  return /^[\x21-\x7e]+$/.test(keyId);
}

/**
 * The suite wire code of a key-id derivation (`ecdsa-p256` 1, `sm2` 2 —
 * the core carrier table). Codes matter only for the anchor-derived
 * id form [`keyIdOf`]; agility suites without a carrier code derive
 * nothing.
 */
const SUITE_CODES: Readonly<Record<string, number>> = {
  "ecdsa-p256-sha256": 1,
  "sm2-sm3": 2,
};

/**
 * Derive the canonical key id of anchor material, mirroring the Rust
 * `KeyId::of`: `k-` + first 16 hex digits of sha256(suite code ||
 * raw public bytes). For EC points carried as SPKI the raw
 * uncompressed point is used (the SPKI header is transport, not key).
 * Opaque anchors (no derivable bytes) have no canonical id — the
 * declared id under which they are cached is authoritative.
 */
export async function keyIdOf(suite: string, material: PublicKeyMaterial): Promise<string | undefined> {
  const code = SUITE_CODES[suite];
  if (code === undefined || material.format !== "spki") return undefined;
  const raw = material.bytes.subarray(material.bytes.length - 65);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([code, ...raw])));
  return `k-${[...digest].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16)}`;
}

/** What one slot check needs (all inputs explicit; no ambient policy). */
export interface SlotCheckInput {
  framing: SignatureFraming;
  /** Canonical payload bytes the signature covers. */
  payload: Uint8Array;
  /** The build's slot registry — decides which suites compute here. */
  slots: CryptoSlots;
  /** Pre-cached trust anchors, routed by key id. */
  anchors: TrustAnchors;
  /** Revocation semantics flag, computed by the caller per reading. */
  voided?: boolean;
  /** Human-facing revocation reason when `voided` is set. */
  voidedReason?: string;
}

/**
 * Run the honesty ladder for one filled slot. Grading order is fixed
 * (see module docs); the call never throws on slot content — a failing
 * binding degrades or invalidates the slot, it does not break the
 * verdict pipeline.
 */
export async function checkSlot(input: SlotCheckInput): Promise<SlotCheck> {
  const { framing, payload, slots, anchors } = input;
  const slot = slots.get(framing.suite);
  if (slot === undefined) {
    return { kind: "deferred", suite: framing.suite, reason: deferralReason(framing.suite) };
  }
  if (!wellFormedKeyId(framing.keyId)) {
    return { kind: "invalid", suite: framing.suite, why: `malformed key id \`${framing.keyId}\`` };
  }
  const key = anchors.get(framing.keyId);
  if (key === undefined) {
    return {
      kind: "unknown-key",
      keyId: framing.keyId,
      anchorKeyIds: [...anchors.keys()],
    };
  }
  if (input.voided === true) {
    return { kind: "voided", keyId: framing.keyId, reason: input.voidedReason ?? "signature voided under this reading" };
  }
  let ok: boolean;
  try {
    ok = await slot.verify({ suite: framing.suite, payload, signature: fromBase64(framing.value), publicKey: key });
  } catch (err) {
    return {
      kind: "invalid",
      suite: framing.suite,
      why: `slot binding threw (${err instanceof Error ? err.message : String(err)})`,
    };
  }
  return ok
    ? { kind: "verified", suite: framing.suite, keyId: framing.keyId }
    : { kind: "invalid", suite: framing.suite, why: "signature check failed under the pinned anchor (tampering?)" };
}

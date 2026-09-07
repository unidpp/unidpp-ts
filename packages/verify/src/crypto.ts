/**
 * Pluggable crypto slots (I9 multi-suite): jurisdictional suites are part of
 * the profile, not the platform. This package ships WebCrypto ECDSA slots;
 * SM2/ML-DSA slots plug in the same interface via bindings (registry-governed
 * agility). No heavyweight dependencies.
 */
import type { SuiteId } from "@unidpp/model";

/** A raw public key as carried in pre-cached trust anchors. */
export type PublicKeyMaterial = { format: "spki"; bytes: Uint8Array } | { format: "raw-ed25519"; bytes: Uint8Array } | { format: "opaque"; material: string };

export interface SignatureInput {
  /** The framing's declared suite; slots match it against their own. */
  suite: string;
  /** Canonical payload bytes the signature covers. */
  payload: Uint8Array;
  signature: Uint8Array;
  publicKey: PublicKeyMaterial;
}

export interface CryptoSlot {
  readonly suites: readonly SuiteId[];
  verify(input: SignatureInput): Promise<boolean>;
}

/** Map of pre-cached trust anchors: keyId -> public key material. */
export type TrustAnchors = ReadonlyMap<string, PublicKeyMaterial>;

export function spkiKey(bytes: Uint8Array): PublicKeyMaterial {
  return { format: "spki", bytes };
}

const ALG_BY_SUITE: Record<string, { name: string; namedCurve?: string; hash: string }> = {
  "ecdsa-p256-sha256": { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
  "ecdsa-p384-sha384": { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" },
};

/** WebCrypto ECDSA slot (browser-native; P-256/P-384). */
export class WebCryptoEcdsaSlot implements CryptoSlot {
  readonly suites: readonly SuiteId[];

  constructor(suites: readonly SuiteId[] = ["ecdsa-p256-sha256", "ecdsa-p384-sha384"]) {
    this.suites = suites;
  }

  async verify(input: SignatureInput): Promise<boolean> {
    const params = ALG_BY_SUITE[input.suite];
    if (params === undefined) return false;
    if (!this.suites.includes(input.suite as SuiteId)) return false;
    if (input.publicKey.format !== "spki") return false;
    try {
      const key = await crypto.subtle.importKey("spki", input.publicKey.bytes as unknown as ArrayBuffer, params, false, ["verify"]);
      return await crypto.subtle.verify(
        { name: "ECDSA", hash: params.hash },
        key,
        input.signature as unknown as ArrayBuffer,
        input.payload as unknown as ArrayBuffer,
      );
    } catch {
      return false;
    }
  }
}

/**
 * HMAC-SHA-256 slot for tests and deterministic conformance runs: a real
 * symmetric verifier demonstrating slot pluggability (not a mock — it
 * performs actual MAC verification).
 */
export class HmacSha256Slot implements CryptoSlot {
  readonly suites: readonly SuiteId[] = ["testmac-sha256"];

  constructor(private readonly keys: ReadonlyMap<string, Uint8Array>) {}

  async verify(input: SignatureInput): Promise<boolean> {
    if (!this.suites.includes(input.suite as SuiteId)) return false;
    if (input.publicKey.format !== "opaque") return false;
    const secret = this.keys.get(input.publicKey.material);
    if (secret === undefined) return false;
    const key = await crypto.subtle.importKey("raw", secret as unknown as ArrayBuffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, input.payload as unknown as ArrayBuffer));
    if (mac.length !== input.signature.length) return false;
    let diff = 0;
    for (let i = 0; i < mac.length; i++) diff |= mac[i]! ^ input.signature[i]!;
    return diff === 0;
  }
}

/** Slot registry: profile acceptance policies check `suits(suite)`. */
export class CryptoSlots {
  readonly #slots = new Map<string, CryptoSlot>();

  register(slot: CryptoSlot): void {
    for (const suite of slot.suites) this.#slots.set(suite, slot);
  }

  suits(suite: string): boolean {
    return this.#slots.has(suite);
  }

  get(suite: string): CryptoSlot | undefined {
    return this.#slots.get(suite);
  }
}

export function defaultSlots(): CryptoSlots {
  const slots = new CryptoSlots();
  slots.register(new WebCryptoEcdsaSlot());
  return slots;
}

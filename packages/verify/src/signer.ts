/** Signing helpers for issuers, test harnesses, and conformance suites. */
import type { SignatureFraming, SuiteId, TierAPack } from "@unidpp/model";
import { toBase64 } from "@unidpp/model";
import type { PublicKeyMaterial } from "./crypto.js";
import { signedPayload } from "./tierA.js";

export interface SignerKey {
  readonly suite: SuiteId;
  /** Trust-anchor material to cache under the signer's keyId. */
  toAnchor(): PublicKeyMaterial;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** Generate a WebCrypto ECDSA keypair (P-256 default; P-384 for EU profile). */
export async function generateEcdsaKey(curve: "P-256" | "P-384" = "P-256"): Promise<SignerKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const hash = curve === "P-384" ? "SHA-384" : "SHA-256";
  return {
    suite: curve === "P-384" ? "ecdsa-p384-sha384" : "ecdsa-p256-sha256",
    toAnchor(): PublicKeyMaterial {
      return { format: "spki", bytes: spki };
    },
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash }, pair.privateKey, data as unknown as ArrayBuffer));
    },
  };
}

/**
 * Deterministic HMAC-SHA-256 signer (tests + conformance runs). The anchor
 * material is the opaque id; the verifying slot holds the matching secret.
 */
export function hmacKey(secret: Uint8Array, material: string, suite: SuiteId = "testmac-sha256"): SignerKey {
  return {
    suite,
    toAnchor(): PublicKeyMaterial {
      return { format: "opaque", material };
    },
    async sign(data: Uint8Array): Promise<Uint8Array> {
      const key = await crypto.subtle.importKey("raw", secret as unknown as ArrayBuffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      return new Uint8Array(await crypto.subtle.sign("HMAC", key, data as unknown as ArrayBuffer));
    },
  };
}

/** Produce a signature framing over the canonical Tier-A payload. */
export async function signPack(key: SignerKey, pack: TierAPack, keyId: string, signedAt: string): Promise<SignatureFraming> {
  const payload = signedPayload(pack as unknown as Record<string, unknown>);
  const value = await key.sign(payload);
  return { suite: key.suite, keyId, signedAt, value: toBase64(value) };
}

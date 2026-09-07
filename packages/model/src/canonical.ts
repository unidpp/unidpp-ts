/**
 * Canonical serialization + digests (I4 commitment hashing, S6 anchoring).
 * Logs anchor commitments (hashes), never facts — log operators cannot
 * correlate edges. WebCrypto-backed; browser- and Node-capable.
 */

/** RFC 8785-lite canonical JSON: sorted keys, no whitespace, strings kept. */
export function canonicalJson(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new Error(`non-finite number: ${value}`);
      return String(value);
    case "string":
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new Error(`cannot canonicalize: ${typeof value}`);
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${serialize((value as Record<string, unknown>)[k])}`);
  return `{${parts.join(",")}}`;
}

const encoder = new TextEncoder();

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? encoder.encode(input) : input;
  const subtle = crypto.subtle;
  if (subtle === undefined) {
    throw new Error("WebCrypto unavailable: this environment provides no crypto.subtle");
  }
  const digest = await subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return toHex(new Uint8Array(digest));
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Pure-JS base64 (RFC 4648): browser- and Node-capable, no Buffer. */
export function toBase64(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += alphabet[b0 >> 2];
    out += alphabet[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    out += b1 === undefined ? "=" : alphabet[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    out += b2 === undefined ? "=" : alphabet[b2 & 0x3f];
  }
  return out;
}

export function fromBase64(text: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const clean = text.replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error(`invalid base64 character: ${char}`);
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

/** Commitment over canonical JSON with a salt (S6 salt discipline). */
export async function commitment(value: unknown, salt = ""): Promise<string> {
  return sha256Hex(`${salt}:${canonicalJson(value)}`);
}

/** The Tier-A carrier codec (the native framing, R11's unification):
 *  the tag-length-value encoding the issuers mint and the offline
 *  CLI decodes, now readable in TypeScript. The decoder mirrors
 *  unidpp-core's tier_a packer byte for byte; the re-encoder exists
 *  for one purpose — reconstructing the signing body (the payload
 *  canonical bytes without its signature block) so a verifier checks
 *  each slot's signature over exactly what the issuer signed.
 */

export interface DecodedTierASignature {
  /** ecdsa-p256 | sm2 | ml-dsa-44 | ml-dsa-65 | ml-dsa-87 */
  suite: string;
  keyId: string;
  /** null while the slot rides the 0xFFFF placeholder (the budget's
   *  reserve, never emitted on a signed carrier). */
  signature: Uint8Array | null;
}

export interface DecodedTierAPayload {
  productId: string;
  resolverUri: string;
  passportId: string;
  eoId: string;
  status: string;
  safety: string;
  validity: { from: string; to: string | null };
  asOf: string;
  /** 64-char hex, or null when the log is empty. */
  logHead: string | null;
  signatures: DecodedTierASignature[];
}

const TAG_PRODUCT_ID = 0x01;
const TAG_RESOLVER_URI = 0x02;
const TAG_PASSPORT_ID = 0x03;
const TAG_EO_ID = 0x04;
const TAG_STATUS = 0x05;
const TAG_SAFETY = 0x06;
const TAG_VALIDITY_FROM = 0x07;
const TAG_VALIDITY_TO = 0x08;
const TAG_AS_OF = 0x09;
const TAG_LOG_HEAD = 0x0a;
const TAG_SIG_COUNT = 0x0b;
const TAG_SIG_SLOT = 0x0c;
const SIG_PLACEHOLDER = 0xffff;

const SUITE_BY_CODE: Record<number, string> = {
  1: "ecdsa-p256",
  2: "sm2",
  3: "ml-dsa-44",
  4: "ml-dsa-65",
  5: "ml-dsa-87",
};

const STATUSES = [
  "issued",
  "suspended",
  "invalidated",
  "non-conformant",
  "consumed",
  "transformed",
  "end-of-waste",
  "archived",
];
const SAFETIES = ["none", "recall-active", "security-flagged"];

class Reader {
  private pos = 0;
  constructor(private readonly bytes: Uint8Array) {}

  remaining(): number {
    return this.bytes.length - this.pos;
  }

  private take(n: number): Uint8Array {
    if (this.remaining() < n) {
      throw new Error(`canonical stream truncated at offset ${this.pos} (need ${n} bytes)`);
    }
    const out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  readTag(): number {
    return this.take(1)[0]!;
  }

  readU16(): number {
    const b = this.take(2);
    return b[0]! | (b[1]! << 8);
  }

  readU32(): number {
    const b = this.take(4);
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;
  }

  readBytes(): Uint8Array {
    return this.take(this.readU32());
  }

  readRaw(n: number): Uint8Array {
    return this.take(n);
  }

  readStr(): string {
    return new TextDecoder().decode(this.readBytes());
  }

  readOptStr(): string | null {
    const tag = this.readTag();
    if (tag === 0) return null;
    if (tag === 1) return this.readStr();
    throw new Error(`bad optional tag ${tag}`);
  }

  readOptHash(): string | null {
    const tag = this.readTag();
    if (tag === 0) return null;
    if (tag === 1) {
      return Array.from(this.take(32))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
    throw new Error(`bad optional tag ${tag}`);
  }
}

function requireString(value: string | undefined, field: string): string {
  if (value === undefined) throw new Error(`missing ${field}`);
  return value;
}

/** Decode the canonical carrier bytes into the payload document. */
export function decodeTierA(bytes: Uint8Array): DecodedTierAPayload {
  const r = new Reader(bytes);
  let productId: string | undefined;
  let resolverUri: string | undefined;
  let passportId: string | undefined;
  let eoId: string | undefined;
  let status: string | undefined;
  let safety: string | undefined;
  let validityFrom: string | undefined;
  let validityTo: string | null = null;
  let asOf: string | undefined;
  let logHead: string | null = null;
  const signatures: DecodedTierASignature[] = [];
  while (r.remaining() > 0) {
    const tag = r.readTag();
    switch (tag) {
      case TAG_PRODUCT_ID:
        productId = r.readStr();
        break;
      case TAG_RESOLVER_URI:
        resolverUri = r.readStr();
        break;
      case TAG_PASSPORT_ID:
        passportId = r.readStr();
        break;
      case TAG_EO_ID:
        eoId = r.readStr();
        break;
      case TAG_STATUS: {
        const token = r.readStr();
        if (!STATUSES.includes(token)) throw new Error(`unknown status \`${token}\``);
        status = token;
        break;
      }
      case TAG_SAFETY: {
        const token = r.readStr();
        if (!SAFETIES.includes(token)) throw new Error(`unknown safety \`${token}\``);
        safety = token;
        break;
      }
      case TAG_VALIDITY_FROM:
        validityFrom = r.readStr();
        break;
      case TAG_VALIDITY_TO:
        validityTo = r.readOptStr();
        break;
      case TAG_AS_OF:
        asOf = r.readStr();
        break;
      case TAG_LOG_HEAD:
        logHead = r.readOptHash();
        break;
      case TAG_SIG_COUNT: {
        const n = r.readTag();
        for (let i = 0; i < n; i += 1) {
          const slotTag = r.readTag();
          if (slotTag !== TAG_SIG_SLOT) {
            throw new Error(`expected the signature-slot tag, read ${slotTag}`);
          }
          const code = r.readTag();
          const suite = SUITE_BY_CODE[code];
          if (suite === undefined) throw new Error(`unknown suite code ${code}`);
          const keyId = new TextDecoder().decode(r.readBytes());
          const len = r.readU16();
          const signature = len === SIG_PLACEHOLDER ? null : r.readRaw(len);
          signatures.push({ suite, keyId, signature });
        }
        break;
      }
      default:
        throw new Error(`unknown field tag ${tag}`);
    }
  }
  return {
    productId: requireString(productId, "product_id"),
    resolverUri: requireString(resolverUri, "resolver_uri"),
    passportId: requireString(passportId, "passport_id"),
    eoId: requireString(eoId, "eo_id"),
    status: requireString(status, "status"),
    safety: requireString(safety, "safety"),
    validity: {
      from: requireString(validityFrom, "validity.from"),
      to: validityTo,
    },
    asOf: requireString(asOf, "as_of"),
    logHead,
    signatures,
  };
}

/** Decode the hex form the issuer's mint response carries. */
export function decodeTierAHex(hex: string): DecodedTierAPayload {
  if (hex.length % 2 !== 0) throw new Error("the carrier hex is odd-length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return decodeTierA(bytes);
}

const hexOf = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

class Writer {
  private parts: number[] = [];
  writeTag(tag: number): void {
    this.parts.push(tag);
  }
  writeU16(v: number): void {
    this.parts.push(v & 0xff, (v >> 8) & 0xff);
  }
  writeU32(v: number): void {
    this.parts.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff);
  }
  writeBytes(bytes: Uint8Array): void {
    this.writeU32(bytes.length);
    this.writeRaw(bytes);
  }
  /** Raw bytes without a length prefix (length framed by the caller). */
  writeRaw(bytes: Uint8Array): void {
    for (const b of bytes) this.parts.push(b);
  }
  writeStr(text: string): void {
    this.writeBytes(new TextEncoder().encode(text));
  }
  writeOptStr(text: string | null): void {
    if (text === null) {
      this.writeTag(0);
    } else {
      this.writeTag(1);
      this.writeStr(text);
    }
  }
  writeOptHash(hex: string | null): void {
    if (hex === null) {
      this.writeTag(0);
      return;
    }
    this.writeTag(1);
    for (let i = 0; i < hex.length; i += 2) {
      this.parts.push(parseInt(hex.slice(i, i + 2), 16));
    }
  }
  intoBytes(): Uint8Array {
    return new Uint8Array(this.parts);
  }
}

/** The signing body: the payload's canonical bytes with the
 *  signature block omitted — what every slot's signature covers. */
export function tierASigningBody(payload: DecodedTierAPayload): Uint8Array {
  const w = new Writer();
  w.writeTag(TAG_PRODUCT_ID);
  w.writeStr(payload.productId);
  w.writeTag(TAG_RESOLVER_URI);
  w.writeStr(payload.resolverUri);
  w.writeTag(TAG_PASSPORT_ID);
  w.writeStr(payload.passportId);
  w.writeTag(TAG_EO_ID);
  w.writeStr(payload.eoId);
  w.writeTag(TAG_STATUS);
  w.writeStr(payload.status);
  w.writeTag(TAG_SAFETY);
  w.writeStr(payload.safety);
  w.writeTag(TAG_VALIDITY_FROM);
  w.writeStr(payload.validity.from);
  w.writeTag(TAG_VALIDITY_TO);
  w.writeOptStr(payload.validity.to);
  w.writeTag(TAG_AS_OF);
  w.writeStr(payload.asOf);
  w.writeTag(TAG_LOG_HEAD);
  w.writeOptHash(payload.logHead);
  // The signature-count block rides the signing body too — empty (the
  // block the slots' signatures frame around).
  w.writeTag(TAG_SIG_COUNT);
  w.writeTag(0);
  return w.intoBytes();
}

/** The carrier's full canonical bytes (the round trip's mirror). */
export function encodeTierA(payload: DecodedTierAPayload): Uint8Array {
  const w = new Writer();
  w.writeTag(TAG_PRODUCT_ID);
  w.writeStr(payload.productId);
  w.writeTag(TAG_RESOLVER_URI);
  w.writeStr(payload.resolverUri);
  w.writeTag(TAG_PASSPORT_ID);
  w.writeStr(payload.passportId);
  w.writeTag(TAG_EO_ID);
  w.writeStr(payload.eoId);
  w.writeTag(TAG_STATUS);
  w.writeStr(payload.status);
  w.writeTag(TAG_SAFETY);
  w.writeStr(payload.safety);
  w.writeTag(TAG_VALIDITY_FROM);
  w.writeStr(payload.validity.from);
  w.writeTag(TAG_VALIDITY_TO);
  w.writeOptStr(payload.validity.to);
  w.writeTag(TAG_AS_OF);
  w.writeStr(payload.asOf);
  w.writeTag(TAG_LOG_HEAD);
  w.writeOptHash(payload.logHead);
  w.writeTag(TAG_SIG_COUNT);
  w.writeTag(Math.min(payload.signatures.length, 255));
  for (const slot of payload.signatures.slice(0, 255)) {
    w.writeTag(TAG_SIG_SLOT);
    const code = Object.entries(SUITE_BY_CODE).find(([, s]) => s === slot.suite)?.[0];
    if (code === undefined) throw new Error(`unknown suite \`${slot.suite}\``);
    w.writeTag(Number(code));
    w.writeBytes(new TextEncoder().encode(slot.keyId));
    if (slot.signature === null) {
      w.writeU16(SIG_PLACEHOLDER);
    } else {
      if (slot.signature.length > 0xffff) {
        throw new Error(`signature of ${slot.signature.length} bytes exceeds u16 framing`);
      }
      w.writeU16(slot.signature.length);
      w.writeRaw(slot.signature);
    }
  }
  return w.intoBytes();
}

export const tierAHexOf = hexOf;

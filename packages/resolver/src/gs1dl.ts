/**
 * GS1 Digital Link (EPCIS/GS1 DL 1.4) parsing: AIs 01 (GTIN), 10 (batch/lot),
 * 21 (serial) — in path and/or query position — normalized to UniDPP
 * identifiers (L0). S1 carrier<->resolver seam.
 */
import type { ProductIdentifier } from "@unidpp/model";

/** AIs supported by the neutral-core Tier-A/carrier subset. */
export const SUPPORTED_AIS = ["01", "10", "21"] as const;
export type SupportedAi = (typeof SUPPORTED_AIS)[number];

export interface Gs1ElementString {
  gtin: string; // canonical 14-digit GTIN
  lot?: string;
  serial?: string;
}

/** GS1 mod-10 check digit over the data digits (GTIN-8/12/13/14 forms). */
export function gs1CheckDigit(dataDigits: string): number {
  let sum = 0;
  const padded = dataDigits.padStart(17, "0"); // GS1 general rule: rightmost weight 3
  for (let i = padded.length - 1, weight = 3; i >= 0; i--, weight = weight === 3 ? 1 : 3) {
    sum += Number(padded[i]) * weight;
  }
  return (10 - (sum % 10)) % 10;
}

/** Validate a full GTIN (any length 8/12/13/14) including its check digit. */
export function validGtin(gtin: string): boolean {
  if (!/^\d{8}$|^\d{12,14}$/.test(gtin)) return false;
  const data = gtin.slice(0, -1);
  return gs1CheckDigit(data) === Number(gtin.slice(-1));
}

/** Normalize to canonical GS1 element string, e.g. (01)X(21)Y(10)Z — fixed AI order. */
export function canonicalElementString(el: Gs1ElementString): string {
  let s = `(01)${el.gtin}`;
  if (el.lot !== undefined) s += `(10)${el.lot}`;
  if (el.serial !== undefined) s += `(21)${el.serial}`;
  return s;
}

function granularityOf(el: Gs1ElementString): ProductIdentifier["granularity"] {
  if (el.serial !== undefined) return "item";
  if (el.lot !== undefined) return "batch";
  return "model";
}

export function toIdentifier(el: Gs1ElementString): ProductIdentifier {
  return {
    scheme: "gs1",
    value: canonicalElementString(el),
    granularity: granularityOf(el),
    state: "live",
  };
}

/**
 * Parse a GS1 Digital Link URI.
 * Path AIs come as /01/09506000134352/21/1234; key-value AIs (10, 21)
 * may also appear as query parameters (?10=ABC&21=1234). Returns null when
 * the URI carries no recognized GS1 AI structure.
 */
export function parseGs1DigitalLink(uri: string): Gs1ElementString | null {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(url.protocol)) return null;

  const pathAis: Record<string, string> = {};
  const segments = url.pathname.split("/").filter((s) => s.length > 0);
  for (let i = 0; i + 1 < segments.length; i += 2) {
    const ai = segments[i]!;
    const value = segments[i + 1]!;
    if (/^\d{2}$/.test(ai) && (SUPPORTED_AIS as readonly string[]).includes(ai)) {
      pathAis[ai] = decodeURIComponent(value);
    }
  }

  const queryAis: Record<string, string> = {};
  for (const [key, value] of url.searchParams.entries()) {
    if (/^\d{2}$/.test(key) && (SUPPORTED_AIS as readonly string[]).includes(key)) {
      queryAis[key] = value;
    }
  }

  const gtinRaw = pathAis["01"];
  if (gtinRaw === undefined) return null;
  const gtin = gtinRaw.padStart(14, "0");
  if (!/^\d{14}$/.test(gtin) || !validGtin(gtin)) return null;

  const lot = pathAis["10"] ?? queryAis["10"];
  const serial = pathAis["21"] ?? queryAis["21"];
  const check = (v: string | undefined): string | undefined =>
    v === undefined ? undefined : v.length > 20 ? undefined : /^[!%-?A-Z_a-z0-9]{1,20}$/.test(v) ? v : undefined;

  return { gtin, lot: check(lot), serial: check(serial) };
}

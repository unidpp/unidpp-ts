/**
 * Unified carrier entry point (S1 seam): translate whatever the physical
 * carrier encodes into a normalized L0 identifier, then resolve. The carrier
 * retains identity; resolution is reproducible (resolver-outage doctrine).
 */
import type { ProductIdentifier } from "@unidpp/model";
import { parseGs1DigitalLink, toIdentifier } from "./gs1dl.js";
import { parseGbt33993 } from "./gbt33993.js";

export type CarrierKind = "gs1-digital-link" | "gbt-33993" | "unknown";

export interface CarrierParse {
  kind: CarrierKind;
  identifier: ProductIdentifier;
  /** Resolver base URL when the carrier URI itself is the entry point. */
  resolverBaseUrl?: string;
  origin?: string;
}

/** ISO/IEC 15459 / EN 18219 URN carriers (our neutral primary scheme). */
const ISO15459_URN = /^urn:iso:std:iso-iec:15459[:#].+$/;

export function parseCarrier(scanned: string): CarrierParse | null {
  const trimmed = scanned.trim();

  // GS1 Digital Link first: a `/g/...` GDS path never matches the GS1 DL
  // AI grammar, but a plain GS1 DL URI must not be swallowed as a
  // GB/T custom code.
  const dl = parseGs1DigitalLink(trimmed);
  if (dl !== null) {
    return {
      kind: "gs1-digital-link",
      identifier: toIdentifier(dl),
      resolverBaseUrl: new URL(trimmed).origin,
    };
  }

  const gbt = parseGbt33993(trimmed);
  if (gbt !== null) {
    const resolverBaseUrl = URL.canParse(trimmed) ? new URL(trimmed).origin : undefined;
    return { kind: "gbt-33993", identifier: gbt.identifier, resolverBaseUrl, origin: gbt.origin };
  }

  if (ISO15459_URN.test(trimmed)) {
    return {
      kind: "unknown",
      identifier: { scheme: "iso-15459", value: trimmed, granularity: "item", state: "live" },
    };
  }

  return null;
}

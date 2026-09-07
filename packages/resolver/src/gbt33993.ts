/**
 * GB/T 33993-2017-style commodity QR codes (GS1-China 商品二维码 / gds.org.cn
 * pattern): a national wrapper over GS1 syntax. Cross-carrier translation
 * rules are registry content (PLAN.md interop lessons); this module
 * implements the documented subset of carrier shapes:
 *
 *   1. https://<host>/g/<13-digit GTIN>[/<serial-or-lot>]     (GDS-style)
 *   2. https://<host>/253/<...>  — NOT supported (AI out of Tier-A scope)
 *   3. a bare EAN-13/GTIN scanned from a legacy 1D code
 *      (GM2D transition: 1D->2D coexistence accepts legacy entry points)
 *
 * GTIN-bearing shapes normalize to the same gs1 identifiers as GS1 DL;
 * enterprise-custom codes normalize to scheme "gbt-33993".
 */
import type { ProductIdentifier } from "@unidpp/model";
import { validGtin } from "./gs1dl.js";

const GDS_PATH = /^\/g\/(\d{13})(?:\/([\w.-]{1,20}))?$/;

export interface GbtParseResult {
  identifier: ProductIdentifier;
  /** How the GTIN (if any) was carried. */
  origin: "gds-path" | "legacy-ean13" | "custom-code";
}

export function parseGbt33993(code: string): GbtParseResult | null {
  const trimmed = code.trim();
  if (trimmed === "") return null;

  // Shape 1: GDS-style URI path.
  try {
    const url = new URL(trimmed);
    if (/^https?:$/.test(url.protocol)) {
      const match = GDS_PATH.exec(url.pathname);
      if (match) {
        const gtin14 = match[1]!.padStart(14, "0");
        if (!validGtin(gtin14)) return null;
        const qualifier = match[2];
        // A qualifier segment is treated as serial when alphanumeric with a
        // letter, else as a lot (national practice; ambiguity resolved by
        // the registered translation rule, default documented here).
        const serial = qualifier !== undefined && /[A-Za-z]/.test(qualifier) ? qualifier : undefined;
        const lot = qualifier !== undefined && serial === undefined ? qualifier : undefined;
        return {
          identifier: {
            scheme: "gs1",
            value: `(01)${gtin14}${lot !== undefined ? `(10)${lot}` : ""}${serial !== undefined ? `(21)${serial}` : ""}`,
            granularity: serial !== undefined ? "item" : lot !== undefined ? "batch" : "model",
            state: "live",
          },
          origin: "gds-path",
        };
      }
      // Other GB/T 33993 carriers (enterprise custom codes) keep their scheme.
      return {
        identifier: {
          scheme: "gbt-33993",
          value: url.toString(),
          granularity: "item",
          state: "live",
        },
        origin: "custom-code",
      };
    }
  } catch {
    // fall through to non-URI shapes
  }

  // Shape 3: bare legacy EAN-13 / GTIN-14.
  if (/^\d{13}$|^\d{14}$/.test(trimmed)) {
    const gtin = trimmed.padStart(14, "0");
    if (!validGtin(gtin)) return null;
    return {
      identifier: { scheme: "gs1", value: `(01)${gtin}`, granularity: "model", state: "live" },
      origin: "legacy-ean13",
    };
  }

  return null;
}

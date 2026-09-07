import { describe, expect, it } from "vitest";
import {
  canonicalElementString,
  gs1CheckDigit,
  parseGs1DigitalLink,
  toIdentifier,
  validGtin,
} from "../src/gs1dl.js";
import { parseGbt33993 } from "../src/gbt33993.js";
import { parseCarrier } from "../src/carrier.js";
import { emitLinkset, parseLinkset, selectLink } from "../src/linkset.js";
import { contextKey, primarySubtag } from "../src/contextKey.js";

describe("gs1 digital link", () => {
  it("computes GS1 check digits", () => {
    expect(gs1CheckDigit("950600013435")).toBe(2);
    expect(validGtin("09506000134352")).toBe(true);
    expect(validGtin("09506000134353")).toBe(false);
    expect(validGtin("6901234567892")).toBe(true); // CN-prefix example
  });

  it("parses path-position AIs (01 + 21) into an item identifier", () => {
    const el = parseGs1DigitalLink("https://id.example.com/01/09506000134352/21/BP52-000841");
    expect(el).toEqual({ gtin: "09506000134352", serial: "BP52-000841" });
    const id = toIdentifier(el!);
    expect(id.granularity).toBe("item");
    expect(id.value).toBe("(01)09506000134352(21)BP52-000841");
  });

  it("parses query-position AI 10 into a batch identifier", () => {
    const el = parseGs1DigitalLink("https://id.example.com/01/09506000134352?10=LOT2026Q3");
    expect(el).toEqual({ gtin: "09506000134352", lot: "LOT2026Q3" });
    expect(toIdentifier(el!).granularity).toBe("batch");
  });

  it("combines path and query AIs", () => {
    const el = parseGs1DigitalLink("https://id.example.com/01/09506000134352/21/8765?10=ABC");
    expect(el).toMatchObject({ serial: "8765", lot: "ABC" });
    expect(canonicalElementString(el!)).toBe("(01)09506000134352(10)ABC(21)8765");
  });

  it("rejects bad check digits, missing AI 01, and non-URIs", () => {
    expect(parseGs1DigitalLink("https://id.example.com/01/09506000134353")).toBeNull();
    expect(parseGs1DigitalLink("https://id.example.com/10/LOT123")).toBeNull();
    expect(parseGs1DigitalLink("not-a-uri")).toBeNull();
  });
});

describe("gb/t 33993-style carriers", () => {
  it("parses a GDS-style path with serial qualifier", () => {
    const result = parseGbt33993("https://gds.example.cn/g/6901234567892/AB2026111");
    expect(result?.origin).toBe("gds-path");
    expect(result?.identifier.value).toBe("(01)06901234567892(21)AB2026111");
    expect(result?.identifier.granularity).toBe("item");
  });

  it("treats an all-numeric qualifier as a lot", () => {
    const result = parseGbt33993("https://gds.example.cn/g/6901234567892/20260901");
    expect(result?.identifier.value).toBe("(01)06901234567892(10)20260901");
    expect(result?.identifier.granularity).toBe("batch");
  });

  it("accepts a bare legacy EAN-13 (GM2D transition)", () => {
    const result = parseGbt33993("6901234567892");
    expect(result?.origin).toBe("legacy-ean13");
    expect(result?.identifier.granularity).toBe("model");
  });

  it("keeps custom enterprise codes on their own scheme", () => {
    const result = parseGbt33993("https://qr.enterprise.cn/x/MA-2026-8841");
    expect(result?.origin).toBe("custom-code");
    expect(result?.identifier.scheme).toBe("gbt-33993");
  });
});

describe("carrier unification", () => {
  it("routes GS1 DL and GB/T carriers to normalized identifiers", () => {
    const dl = parseCarrier("https://id.example.com/01/09506000134352/21/8765");
    expect(dl?.kind).toBe("gs1-digital-link");
    expect(dl?.resolverBaseUrl).toBe("https://id.example.com");
    const gbt = parseCarrier("https://gds.example.cn/g/6901234567892");
    expect(gbt?.kind).toBe("gbt-33993");
    expect(gbt?.identifier.value).toBe("(01)06901234567892");
  });

  it("passes through ISO/IEC 15459 URNs", () => {
    const iso = parseCarrier("urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345");
    expect(iso?.identifier.scheme).toBe("iso-15459");
    expect(parseCarrier("garbage")).toBeNull();
  });
});

describe("rfc 9264 linksets", () => {
  const links = [
    {
      anchor: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      uri: "https://dpp.unidpp.org/eu/84120099012345",
      rel: "dpp",
      hreflang: ["en", "fr"],
      type: "application/json",
      "unidpp:profile": "urn:unidpp:profile:eu-espr-electronics",
      "unidpp:role": "consumer",
      "unidpp:region": "EU",
    },
    {
      anchor: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      uri: "https://dpp-jp.meti.example.go.jp/passport/84120099012345",
      rel: "dpp",
      hreflang: ["ja"],
      "unidpp:profile": "urn:unidpp:profile:jp-meti-pse",
      "unidpp:role": "consumer",
      "unidpp:region": "JP",
    },
    {
      anchor: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      uri: "https://dpp.unidpp.org/generic/84120099012345",
      rel: "dpp",
      hreflang: ["*"],
      "unidpp:profile": "*",
      "unidpp:role": "*",
      "unidpp:region": "*",
    },
    {
      anchor: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      uri: "https://dpp.unidpp.org/recycler/84120099012345",
      rel: "dpp",
      hreflang: ["en"],
      "unidpp:profile": "*",
      "unidpp:role": "recycler",
      "unidpp:region": "*",
    },
  ];

  it("round-trips parse(emit(x))", () => {
    const doc = emitLinkset(links);
    const parsed = parseLinkset(doc);
    expect(parsed.linkset).toEqual(links);
  });

  it("accepts a single link object document", () => {
    const single = JSON.stringify(links[0]);
    expect(parseLinkset(single).linkset).toHaveLength(1);
  });

  it("rejects malformed linksets", () => {
    expect(() => parseLinkset("{")).toThrow(/invalid linkset JSON/);
    expect(() => parseLinkset('{"linkset":[{"uri":"x","rel":"dpp"}]}')).toThrow(/anchor/);
  });

  it("selects exact profile+region+language matches over wildcards", () => {
    const ls = parseLinkset(emitLinkset(links));
    const eu = selectLink(ls, {
      profile: "urn:unidpp:profile:eu-espr-electronics",
      role: "consumer",
      language: "fr",
      region: "EU",
    });
    expect(eu?.link.uri).toBe("https://dpp.unidpp.org/eu/84120099012345");
  });

  it("routes a JP customs query to the JP endpoint with language fallback", () => {
    const ls = parseLinkset(emitLinkset(links));
    const jp = selectLink(ls, {
      profile: "urn:unidpp:profile:jp-meti-pse",
      role: "consumer",
      language: "ja-JP",
      region: "JP",
    });
    expect(jp?.link.uri).toContain("meti.example.go.jp");
    // English-speaking consumer in JP: ja link rejected on language, generic wins
    const en = selectLink(ls, {
      profile: "urn:unidpp:profile:jp-meti-pse",
      role: "consumer",
      language: "en",
      region: "JP",
    });
    expect(en?.link.uri).toBe("https://dpp.unidpp.org/generic/84120099012345");
  });

  it("routes by role when no profile preference is given", () => {
    const ls = parseLinkset(emitLinkset(links));
    const recycler = selectLink(ls, { role: "recycler" });
    expect(recycler?.link.uri).toContain("/recycler/");
  });

  it("returns null when nothing matches", () => {
    const ls = parseLinkset(emitLinkset(links));
    expect(selectLink(ls, { role: "customs" }, "dss-archive")).toBeNull();
  });
});

describe("context routing key", () => {
  it("formats wildcards explicitly", () => {
    expect(contextKey({ profile: "urn:unidpp:profile:jp-meti-pse", language: "ja-JP" })).toBe(
      "profile=urn:unidpp:profile:jp-meti-pse;role=*;lang=ja-JP;region=*",
    );
    expect(primarySubtag("fr-CA")).toBe("fr");
  });
});

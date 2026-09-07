import { describe, expect, it } from "vitest";
import type { RegistryItem } from "@unidpp/model";
import { itemEffectiveAt } from "@unidpp/model";
import { buildLaptop } from "@unidpp/model/fixtures";
import { ApiError, type FetchLike } from "../src/http.js";
import { PassportClient, ResolverClient } from "../src/resolver.js";
import { RegistryClient } from "../src/registry.js";

/**
 * In-memory route server implementing the resolver/registry/passport API
 * contract. Real behavioral server — the clients exercise the same fetch
 * path a deployed host would.
 */
function makeServer(): FetchLike {
  return async (input: string) => new Response(JSON.stringify({ error: "not found", url: input }), { status: 404 });
}

async function laptopServer(): Promise<{ fetcher: FetchLike; manifest: Awaited<ReturnType<typeof buildLaptop>>["manifest"] }> {
  const laptop = await buildLaptop();
  const fetcher: FetchLike = async (input: string) => {
    const url = new URL(input);
    if (url.pathname === "/linksets" && url.searchParams.get("subject") !== null) {
      return new Response(
        JSON.stringify({
          linkset: [
            {
              anchor: "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
              uri: "https://dpp.unidpp.org/eu/84120099012345",
              rel: "dpp",
              hreflang: ["fr"],
              "unidpp:profile": "urn:unidpp:profile:eu-espr-electronics",
              "unidpp:role": "consumer",
              "unidpp:region": "EU",
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json", "x-as-of": "2027-02-11T10:44:00Z" } },
      );
    }
    if (url.pathname.startsWith("/passports/")) {
      expect(url.searchParams.get("profile")).toBe("urn:unidpp:profile:eu-espr-electronics");
      expect(url.searchParams.get("asOf")).toBe("2027-01-15T00:00:00Z");
      return new Response(
        JSON.stringify({ manifest: laptop.manifest, profileViews: { "urn:unidpp:profile:eu-espr-electronics": { "de.dpp.reparability-score": 7.1 } } }),
        { status: 200, headers: { "content-type": "application/json", "x-as-of": "2027-02-11T10:44:00Z" } },
      );
    }
    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  };
  return { fetcher, manifest: laptop.manifest };
}

const registryItems: Record<string, RegistryItem> = {
  "de.dpp.reparability-score@1.0.0": {
    register: "urn:unidpp:register:core",
    item: "de.dpp.reparability-score",
    version: "1.0.0",
    itemClass: "data-element",
    status: "superseded",
    dates: { proposed: "2026-01-01T00:00:00Z", registered: "2026-02-01T00:00:00Z", superseded: "2026-09-01T00:00:00Z" },
    supersededBy: { register: "urn:unidpp:register:core", item: "de.dpp.reparability-score", version: "1.1.0" },
    definition: { uri: "https://registry.unidpp.org/core/de.dpp.reparability-score/1.0.0.cddal", mediaType: "application/cddal", checksum: "aaaa" },
  },
  "de.dpp.reparability-score@1.1.0": {
    register: "urn:unidpp:register:core",
    item: "de.dpp.reparability-score",
    version: "1.1.0",
    itemClass: "data-element",
    status: "valid",
    dates: { proposed: "2026-08-01T00:00:00Z", registered: "2026-09-01T00:00:00Z" },
    definition: { uri: "https://registry.unidpp.org/core/de.dpp.reparability-score/1.1.0.cddal", mediaType: "application/cddal", checksum: "bbbb" },
  },
};

function registryServer(): FetchLike {
  return async (input: string) => {
    const url = new URL(input);
    const match = /^\/registers\/([^/]+)\/items\/([^/]+)$/.exec(url.pathname);
    if (match !== null) {
      const version = url.searchParams.get("version");
      const key = `${decodeURIComponent(match[2]!)}@${version ?? "1.0.0"}`;
      const item = registryItems[key];
      if (item === undefined) return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
      return new Response(JSON.stringify(item), { status: 200, headers: { "content-type": "application/json", "x-as-of": "2027-02-11T10:44:00Z" } });
    }
    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  };
}

describe("resolver client", () => {
  it("resolves a subject and routes by context, with as-of stamps", async () => {
    const { fetcher } = await laptopServer();
    const client = new ResolverClient({ baseUrl: "https://resolver.unidpp.org", fetch: fetcher });
    const result = await client.resolve("urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345", {
      profile: "urn:unidpp:profile:eu-espr-electronics",
      role: "consumer",
      language: "fr",
      region: "EU",
    });
    expect(result.asOf).toBe("2027-02-11T10:44:00Z");
    expect(result.source).toBe("https://resolver.unidpp.org");
    expect(result.data.selected?.uri).toBe("https://dpp.unidpp.org/eu/84120099012345");
  });

  it("surfaces 404s as typed ApiErrors", async () => {
    const client = new ResolverClient({ baseUrl: "https://resolver.unidpp.org", fetch: makeServer() });
    await expect(client.resolve("urn:x:unknown")).rejects.toBeInstanceOf(ApiError);
  });
});

describe("passport client", () => {
  it("fetches a profile-scoped as-of snapshot with stamps", async () => {
    const { fetcher, manifest } = await laptopServer();
    const client = new PassportClient({ baseUrl: "https://dpp.unidpp.org", fetch: fetcher });
    const result = await client.getPassport("urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345", {
      profile: "urn:unidpp:profile:eu-espr-electronics",
      asOf: "2027-01-15T00:00:00Z",
    });
    expect(result.data.manifest.subjectId.value).toBe(manifest.subjectId.value);
    expect(result.data.profileViews["urn:unidpp:profile:eu-espr-electronics"]).toMatchObject({ "de.dpp.reparability-score": 7.1 });
    expect(result.asOf).toBe("2027-02-11T10:44:00Z");
    expect(result.retrievedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

describe("registry client (FERIN/19135)", () => {
  it("looks up an item with version and status", async () => {
    const client = new RegistryClient({ baseUrl: "https://registry.unidpp.org", fetch: registryServer() });
    const item = await client.getItem("urn:unidpp:register:core", "de.dpp.reparability-score", { version: "1.1.0" });
    expect(item.data.status).toBe("valid");
    expect(item.data.itemClass).toBe("data-element");
    expect(item.asOf).toBe("2027-02-11T10:44:00Z");
  });

  it("follows supersession to the current version", async () => {
    const client = new RegistryClient({ baseUrl: "https://registry.unidpp.org", fetch: registryServer() });
    const current = await client.resolveCurrent("urn:unidpp:register:core", "de.dpp.reparability-score");
    expect(current.data.version).toBe("1.1.0");
    expect(current.data.status).toBe("valid");
  });

  it("reports 19135 lifecycle effectiveness windows", () => {
    const old = registryItems["de.dpp.reparability-score@1.0.0"]!;
    expect(itemEffectiveAt(old, "2026-06-01T00:00:00Z")).toBe(true);
    expect(itemEffectiveAt(old, "2026-12-01T00:00:00Z")).toBe(false);
  });

  it("rejects unknown versions with ApiError", async () => {
    const client = new RegistryClient({ baseUrl: "https://registry.unidpp.org", fetch: registryServer() });
    await expect(client.getItem("urn:unidpp:register:core", "de.nonexistent", { version: "9.9.9" })).rejects.toBeInstanceOf(ApiError);
  });
});

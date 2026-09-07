/**
 * Resolver + passport clients: carrier URI -> federated resolver -> linkset
 * (profile context x role x language x request region) -> hosting endpoint
 * -> render + manifest. Mirrors and caches carry as-of stamps.
 */
import type { Link, Linkset } from "@unidpp/resolver";
import { parseLinkset, selectLink } from "@unidpp/resolver";
import type { RequestContext } from "@unidpp/resolver";
import type { PassportManifest } from "@unidpp/model";
import type { Stamped } from "./asof.js";
import { nowIso, stamp } from "./asof.js";
import type { ClientConfig } from "./http.js";
import { getJson } from "./http.js";

export class ResolverClient {
  readonly #config: ClientConfig;

  constructor(config: ClientConfig) {
    this.#config = config;
  }

  /** GET /linksets?subject=<identifier value> -> as-of-stamped linkset. */
  async resolve(subjectValue: string, context?: RequestContext): Promise<Stamped<{ linkset: Linkset; selected?: Link }>> {
    const query = new URLSearchParams({ subject: subjectValue });
    if (context?.profile !== undefined) query.set("profile", context.profile);
    if (context?.role !== undefined) query.set("role", context.role);
    if (context?.language !== undefined) query.set("lang", context.language);
    if (context?.region !== undefined) query.set("region", context.region);
    const { body, headers } = await getJson(this.#config, `/linksets?${query.toString()}`);
    const linkset = parseLinkset(typeof body === "string" ? body : JSON.stringify(body));
    const selected = context !== undefined ? (selectLink(linkset, context)?.link ?? undefined) : undefined;
    return stamp({ linkset, selected }, asOfFrom(headers) ?? nowIso(), this.#config.baseUrl);
  }
}

export interface PassportRender {
  manifest: PassportManifest;
  /** Profile-scoped views keyed by profileId. */
  profileViews: Record<string, Record<string, unknown>>;
  /** Tier A pack when the host serves it inline (S11 seam). */
  tierA?: unknown;
}

export class PassportClient {
  readonly #config: ClientConfig;

  constructor(config: ClientConfig) {
    this.#config = config;
  }

  /**
   * GET /passports/{id} with optional profile scoping and as-of snapshot
   * query ("was this compliant when sold in 2028?").
   */
  async getPassport(
    passportId: string,
    options: { profile?: string; asOf?: string; endpoint?: string } = {},
  ): Promise<Stamped<PassportRender>> {
    const query = new URLSearchParams();
    if (options.profile !== undefined) query.set("profile", options.profile);
    if (options.asOf !== undefined) query.set("asOf", options.asOf);
    const qs = query.size > 0 ? `?${query.toString()}` : "";
    const path = options.endpoint !== undefined ? `${options.endpoint}${qs}` : `/passports/${encodeURIComponent(passportId)}${qs}`;
    const { body, headers } = await getJson(this.#config, path);
    return stamp(body as PassportRender, asOfFrom(headers) ?? options.asOf ?? nowIso(), this.#config.baseUrl);
  }
}

/** Server-side as-of: X-As-Of header, or body field on well-formed bodies. */
function asOfFrom(headers: Headers): string | undefined {
  const value = headers.get("x-as-of");
  return value === null ? undefined : value;
}

/**
 * FERIN / ISO 19135 registry client: item lookup with version and status,
 * supersession chains, register navigation. Per-version items are immutable
 * and mirrorable — only register status is mutable — so responses are
 * perfectly cacheable and always as-of stamped.
 */
import type { RegistryItem } from "@unidpp/model";
import type { Stamped } from "./asof.js";
import { nowIso, stamp } from "./asof.js";
import type { ClientConfig } from "./http.js";
import { getJson } from "./http.js";

export class RegistryClient {
  readonly #config: ClientConfig;

  constructor(config: ClientConfig) {
    this.#config = config;
  }

  /**
   * GET /registers/{register}/items/{item}[?version=] — resolve a
   * dictionaryReference (the EN 18223 4.3 vacancy): URI -> definition +
   * version + status + trust chain.
   */
  async getItem(
    register: string,
    item: string,
    options: { version?: string; asOf?: string } = {},
  ): Promise<Stamped<RegistryItem>> {
    const query = new URLSearchParams();
    if (options.version !== undefined) query.set("version", options.version);
    if (options.asOf !== undefined) query.set("asOf", options.asOf);
    const qs = query.size > 0 ? `?${query.toString()}` : "";
    const { body, headers } = await getJson(this.#config, `/registers/${encodeURIComponent(register)}/items/${encodeURIComponent(item)}${qs}`);
    const result = body as RegistryItem;
    return stamp(result, asOfFrom(headers) ?? nowIso(), this.#config.baseUrl);
  }

  /** Follow supersession chains to the currently valid item version. */
  async resolveCurrent(register: string, item: string, maxHops = 8): Promise<Stamped<RegistryItem>> {
    let current = await this.getItem(register, item);
    for (let hop = 0; current.data.status === "superseded" && hop < maxHops; hop++) {
      const next = current.data.supersededBy;
      if (next === undefined) break;
      current = await this.getItem(next.register, next.item, { version: next.version });
    }
    return current;
  }
}

function asOfFrom(headers: Headers): string | undefined {
  const value = headers.get("x-as-of");
  return value === null ? undefined : value;
}

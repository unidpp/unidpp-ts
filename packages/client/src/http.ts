/** Shared client plumbing: pluggable fetch, typed errors. */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ClientConfig {
  baseUrl: string;
  /** Pluggable transport — defaults to global fetch (browser/Node 18+). */
  fetch?: FetchLike;
  headers?: Record<string, string>;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
    message: string,
  ) {
    super(`API ${status} at ${url}: ${message}`);
    this.name = "ApiError";
  }
}

export async function getJson(config: ClientConfig, path: string): Promise<{ body: unknown; headers: Headers }> {
  const doFetch = config.fetch ?? ((input: string, init?: RequestInit) => fetch(input, init));
  const url = new URL(path, config.baseUrl).toString();
  const response = await doFetch(url, { headers: { accept: "application/json", ...config.headers } });
  if (!response.ok) {
    throw new ApiError(response.status, url, await response.text());
  }
  return { body: await response.json(), headers: response.headers };
}

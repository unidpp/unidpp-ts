/**
 * RFC 9264 linkset parse/emit (media type application/linkset+json) plus
 * UniDPP context routing over the linkset. RFC 9264 link parameters are
 * open; UniDPP routing uses `unidpp:profile`, `unidpp:role`, `unidpp:region`
 * alongside the standard `hreflang` for language.
 */
import type { RequestContext } from "./contextKey.js";
import { primarySubtag } from "./contextKey.js";

export interface Link {
  anchor: string;
  uri: string;
  rel: string;
  hreflang?: string[];
  title?: string;
  type?: string;
  /** UniDPP extension: profile context this target serves ("*" = any). */
  "unidpp:profile"?: string;
  /** UniDPP extension: verifier role this target serves ("*" = any). */
  "unidpp:role"?: string;
  /** UniDPP extension: request region this target serves ("*" = any). */
  "unidpp:region"?: string;
  [ext: string]: unknown;
}

export interface Linkset {
  linkset: Link[];
}

/** Emit a linkset document (RFC 9264 JSON serialization). */
export function emitLinkset(links: Link[]): string {
  return JSON.stringify({ linkset: links }, null, 2);
}

/**
 * Parse a linkset document. Accepts either a full { "linkset": [...] }
 * document or a single link object (RFC 9264 permits both as
 * representations).
 */
export function parseLinkset(document: string): Linkset {
  let parsed: unknown;
  try {
    parsed = JSON.parse(document);
  } catch (cause) {
    throw new Error(`invalid linkset JSON: ${String(cause)}`);
  }
  if (Array.isArray(parsed)) return { linkset: parsed.map(parseLink) };
  if (isRecord(parsed)) {
    if (Array.isArray(parsed["linkset"])) return { linkset: (parsed["linkset"] as unknown[]).map(parseLink) };
    return { linkset: [parseLink(parsed)] };
  }
  throw new Error("linkset document must be an object or array");
}

function parseLink(value: unknown): Link {
  if (!isRecord(value)) throw new Error("linkset entry must be an object");
  const anchor = value["anchor"];
  const uri = value["uri"];
  const rel = value["rel"];
  if (typeof anchor !== "string" || typeof uri !== "string" || typeof rel !== "string") {
    throw new Error("link requires string anchor, uri and rel");
  }
  return value as unknown as Link;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Specificity score of a link against a request context; null = no match. */
export function linkScore(link: Link, ctx: RequestContext, rel: string): number | null {
  if (link.rel !== rel) return null;
  let score = 0;
  // profile
  const lp = link["unidpp:profile"] ?? "*";
  if (ctx.profile === undefined || lp === "*") {
    score += lp === "*" ? 1 : 2;
  } else if (lp === ctx.profile) {
    score += 4;
  } else {
    return null;
  }
  // role
  const lr = link["unidpp:role"] ?? "*";
  if (ctx.role === undefined || lr === "*") {
    score += lr === "*" ? 1 : 2;
  } else if (lr === ctx.role) {
    score += 4;
  } else {
    return null;
  }
  // region
  const lrg = link["unidpp:region"] ?? "*";
  if (ctx.region === undefined || lrg === "*") {
    score += lrg === "*" ? 1 : 2;
  } else if (lrg === ctx.region) {
    score += 4;
  } else {
    return null;
  }
  // language (hreflang; "*" = any)
  const langs = link.hreflang ?? ["*"];
  if (ctx.language === undefined || langs.includes("*") || langs.length === 0) {
    score += langs.includes("*") || langs.length === 0 ? 1 : 2;
  } else if (langs.includes(ctx.language)) {
    score += 4;
  } else if (langs.some((l) => primarySubtag(l) === primarySubtag(ctx.language!))) {
    score += 3; // primary-subtag fallback
  } else {
    return null;
  }
  return score;
}

export interface LinkSelection {
  link: Link;
  score: number;
  candidates: number;
}

/**
 * Select the destination for a request context: exact matches outrank
 * wildcards; language falls back to the primary subtag. First-in-document
 * wins ties (deterministic).
 */
export function selectLink(linkset: Linkset, ctx: RequestContext, rel = "dpp"): LinkSelection | null {
  let best: LinkSelection | null = null;
  let candidates = 0;
  for (const link of linkset.linkset) {
    const score = linkScore(link, ctx, rel);
    if (score === null) continue;
    candidates += 1;
    if (best === null || score > best.score) best = { link, score, candidates };
  }
  return best === null ? null : { ...best, candidates };
}

/**
 * L5 context routing: resolver linksets are keyed by (profile context, role,
 * language, request region) — one QR, many destinations. Default by request
 * context, overridable.
 */

export interface RequestContext {
  /** Profile context; undefined = no preference (wildcard). */
  profile?: string;
  /** Verifier role (EN 18239 roles): consumer, recycler, repairer, customs... */
  role?: string;
  /** BCP-47 language tag. */
  language?: string;
  /** ISO 3166-1 alpha-2 request region (or "EU"-style region code). */
  region?: string;
}

export type RoutingDimension = "profile" | "role" | "language" | "region";

export function contextKey(ctx: RequestContext): string {
  return ["profile", "role", "lang", "region"]
    .map((dim, i) => {
      const value = [ctx.profile, ctx.role, ctx.language, ctx.region][i];
      return `${dim}=${value ?? "*"}`;
    })
    .join(";");
}

/** Primary subtag: "fr-CA" -> "fr". */
export function primarySubtag(language: string): string {
  return language.split("-")[0]!;
}

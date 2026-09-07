/**
 * As-of stamping: every response carries one. Two authoritative query modes
 * (source invariant 7): live view (freshness-labelled) and notarized as-of
 * snapshot (log-anchored) — legal purpose selects the mode.
 */

export interface Stamped<T> {
  data: T;
  /** The as-of instant the data represents (server-side state time). */
  asOf: string;
  /** When the response was produced (client-visible time). */
  retrievedAt: string;
  source: string;
}

export function stamp<T>(data: T, asOf: string, source: string, retrievedAt = new Date().toISOString()): Stamped<T> {
  return { data, asOf, source, retrievedAt };
}

export function nowIso(): string {
  return new Date().toISOString();
}

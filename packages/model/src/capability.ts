/**
 * Capability classes of subjects (the silent-object lesson): profiles'
 * freshness/verification requirements must be satisfiable by the class —
 * demanding live freshness from an S0 product is an unsatisfiable profile.
 */
export type CapabilityClass =
  | "S0" // silent: testimony-only (textiles, tires, most batteries)
  | "S1" // passive-auth: NFC chip / PUF / IEC 61406 identity link, no logs
  | "S2" // logged-contact: dumps on physical read, no comms (BMS-style)
  | "S3"; // connected: full edge segments, device commitments

export interface CapabilityProfile {
  capabilityClass: CapabilityClass;
  /** Maximum freshness achievable by this class; undefined = unbounded. */
  maxFreshness?: string; // ISO 8601 duration, e.g. "PT0S" (live) for S3
  /** Truth modes the class can contribute. */
  truthModes: TruthMode[];
}

/**
 * Truth mode per PLAN.md: the twin is testimonial by default, sensorial by
 * exception; profiles declare per data element the required truth mode.
 */
export type TruthMode = "attest-sampled" | "self-committed" | "both-with-precedence";

export const CLASS_CAPABILITY: Readonly<Record<CapabilityClass, CapabilityProfile>> = {
  S0: { capabilityClass: "S0", truthModes: ["attest-sampled"] },
  S1: { capabilityClass: "S1", truthModes: ["attest-sampled"] },
  S2: { capabilityClass: "S2", maxFreshness: "P365D", truthModes: ["attest-sampled", "self-committed"] },
  S3: { capabilityClass: "S3", maxFreshness: "PT1H", truthModes: ["attest-sampled", "self-committed", "both-with-precedence"] },
};

/** Is a freshness requirement satisfiable for this capability class? */
export function freshnessSatisfiable(required: string, klass: CapabilityClass): boolean {
  const cap = CLASS_CAPABILITY[klass];
  if (cap.maxFreshness === undefined) return required === "unknown";
  // A stricter (shorter) requirement than the class can deliver fails.
  return compareDurations(required, cap.maxFreshness) <= 0;
}

/** Lexicographic-ish ISO-8601 duration comparison (PnYnMnDTnHnMnS). */
export function compareDurations(a: string, b: string): number {
  const pa = parseDuration(a);
  const pb = parseDuration(b);
  const sa = pa.seconds + pa.minutes * 60 + pa.hours * 3600 + pa.days * 86400;
  const sb = pb.seconds + pb.minutes * 60 + pb.hours * 3600 + pb.days * 86400;
  return sa === sb ? 0 : sa < sb ? -1 : 1;
}

function parseDuration(d: string): { years: number; months: number; days: number; hours: number; minutes: number; seconds: number } {
  const m = /^(-)?P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$/.exec(d);
  if (!m) throw new Error(`invalid ISO 8601 duration: ${d}`);
  const sign = m[1] ? -1 : 1;
  return {
    years: Number(m[2] ?? 0) * sign,
    months: Number(m[3] ?? 0) * sign,
    days: Number(m[4] ?? 0) * sign,
    hours: Number(m[5] ?? 0) * sign,
    minutes: Number(m[6] ?? 0) * sign,
    seconds: Number(m[7] ?? 0) * sign,
  };
}

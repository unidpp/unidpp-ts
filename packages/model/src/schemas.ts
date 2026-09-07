/**
 * Schema registry: bundles the draft-2020-12 JSON Schema files with their
 * `$defs` flattened into one namespace so cross-file and intra-file `$ref`s
 * resolve for the dependency-free validator.
 */
import type { JsonSchema, ValidationResult } from "./validate.js";
import { validate } from "./validate.js";
import identifierSchema from "./schema/identifier.schema.json";
import manifestSchema from "./schema/passport-manifest.schema.json";
import linkSchema from "./schema/passport-link.schema.json";
import eventSchema from "./schema/event.schema.json";
import tierASchema from "./schema/tier-a.schema.json";

const FILES: Record<string, JsonSchema> = {
  "identifier.schema.json": identifierSchema as unknown as JsonSchema,
  "passport-manifest.schema.json": manifestSchema as unknown as JsonSchema,
  "passport-link.schema.json": linkSchema as unknown as JsonSchema,
  "event.schema.json": eventSchema as unknown as JsonSchema,
  "tier-a.schema.json": tierASchema as unknown as JsonSchema,
};

const FILE_TO_NS: Record<string, string> = {
  "identifier.schema.json": "identifier",
  "passport-manifest.schema.json": "manifest",
  "passport-link.schema.json": "link",
  "event.schema.json": "event",
  "tier-a.schema.json": "tierA",
};

/** All defs flattened as `<ns>:<name>`. */
const flatDefs: Record<string, JsonSchema> = {};
const processed: Record<string, JsonSchema> = {};

for (const [file, schema] of Object.entries(FILES)) {
  const ns = FILE_TO_NS[file]!;
  const clone = structuredClone(schema);
  rewriteRefs(clone, ns);
  processed[ns] = clone;
}

function rewriteRefs(node: unknown, ns: string): void {
  if (Array.isArray(node)) {
    for (const item of node) rewriteRefs(item, ns);
    return;
  }
  if (typeof node !== "object" || node === null) return;
  const record = node as Record<string, unknown>;
  for (const [key, value] of Object.entries(record)) {
    if (key === "$ref" && typeof value === "string") {
      record[key] = rewriteRef(value, ns);
    } else if (key === "$defs" && typeof value === "object" && value !== null) {
      for (const [name, def] of Object.entries(value as Record<string, unknown>)) {
        flatDefs[`${ns}:${name}`] = def as JsonSchema;
        rewriteRefs(def, ns);
      }
    } else {
      rewriteRefs(value, ns);
    }
  }
}

function rewriteRef(ref: string, ns: string): string {
  const external = /^([\w.-]+\.json)#\/\$defs\/([\w-]+)$/.exec(ref);
  if (external) {
    const targetNs = FILE_TO_NS[external[1]!];
    return targetNs ? `#/$defs/${targetNs}:${external[2]}` : ref;
  }
  const local = /^#\/\$defs\/([\w-]+)$/.exec(ref);
  if (local) return `#/$defs/${ns}:${local[1]}`;
  return ref;
}

const bundled: Record<string, JsonSchema> = {};
for (const [ns, schema] of Object.entries(processed)) {
  bundled[ns] = { ...schema, $defs: flatDefs };
}

export const schemas = {
  identifier: bundled["identifier"]!,
  manifest: bundled["manifest"]!,
  link: bundled["link"]!,
  event: bundled["event"]!,
  tierA: bundled["tierA"]!,
} as const;

export function validateIdentifier(instance: unknown): ValidationResult {
  return validate(instance, schemas.identifier);
}

export function validateManifest(instance: unknown): ValidationResult {
  return validate(instance, schemas.manifest);
}

export function validateLink(instance: unknown): ValidationResult {
  return validate(instance, schemas.link);
}

export function validateEvent(instance: unknown): ValidationResult {
  return validate(instance, schemas.event);
}

export function validateTierAPack(instance: unknown): ValidationResult {
  return validate(instance, schemas.tierA);
}

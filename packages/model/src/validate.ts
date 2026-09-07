/**
 * Minimal JSON Schema (draft 2020-12 subset) validator. Hand-rolled to keep
 * the SDK dependency-free: supports the keywords used by the @unidpp/model
 * schemas — $ref (local $defs), type, enum, const, required, properties,
 * additionalProperties, items, pattern, format (date-time, date, uri),
 * string/array length bounds, numeric bounds, allOf/anyOf/oneOf, $defs.
 */

export interface JsonSchema {
  $id?: string;
  $ref?: string;
  $defs?: Record<string, JsonSchema>;
  type?: string | string[];
  enum?: unknown[];
  const?: unknown;
  title?: string;
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: boolean | JsonSchema;
  items?: JsonSchema;
  pattern?: string;
  format?: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  minItems?: number;
  maxItems?: number;
  allOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
}

export interface ValidationIssue {
  path: string;
  keyword: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  issues: ValidationIssue[];
}

export function validate(instance: unknown, schema: JsonSchema, root: JsonSchema = schema): ValidationResult {
  const issues: ValidationIssue[] = [];
  check(instance, schema, root, "$", issues);
  return { valid: issues.length === 0, issues };
}

function check(instance: unknown, schema: JsonSchema, root: JsonSchema, path: string, issues: ValidationIssue[]): void {
  if (schema.$ref !== undefined) {
    const resolved = resolveRef(schema.$ref, root);
    if (resolved === undefined) {
      issues.push({ path, keyword: "$ref", message: `unresolvable $ref: ${schema.$ref}` });
      return;
    }
    check(instance, resolved, root, path, issues);
    return;
  }
  if (schema.allOf) for (const sub of schema.allOf) check(instance, sub, root, path, issues);
  if (schema.anyOf && !schema.anyOf.some((sub) => validate(instance, sub, root).valid)) {
    issues.push({ path, keyword: "anyOf", message: "value does not match any allowed schema" });
    return;
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((sub) => validate(instance, sub, root).valid).length;
    if (matches !== 1) {
      issues.push({ path, keyword: "oneOf", message: `value matches ${matches} schemas, expected exactly 1` });
      return;
    }
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => typeMatches(instance, t))) {
      issues.push({ path, keyword: "type", message: `expected ${types.join("|")}, got ${jsonType(instance)}` });
      return;
    }
  }
  if (schema.enum !== undefined && !schema.enum.some((v) => deepEqual(instance, v))) {
    issues.push({ path, keyword: "enum", message: `value not in enum: ${JSON.stringify(instance)}` });
  }
  if (schema.const !== undefined && !deepEqual(instance, schema.const)) {
    issues.push({ path, keyword: "const", message: `value !== const ${JSON.stringify(schema.const)}` });
  }
  if (typeof instance === "string") {
    if (schema.minLength !== undefined && [...instance].length < schema.minLength) {
      issues.push({ path, keyword: "minLength", message: `shorter than ${schema.minLength}` });
    }
    if (schema.maxLength !== undefined && [...instance].length > schema.maxLength) {
      issues.push({ path, keyword: "maxLength", message: `longer than ${schema.maxLength}` });
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(instance)) {
      issues.push({ path, keyword: "pattern", message: `does not match ${schema.pattern}` });
    }
    if (schema.format !== undefined && !formatMatches(instance, schema.format)) {
      issues.push({ path, keyword: "format", message: `not a valid ${schema.format}` });
    }
  }
  if (typeof instance === "number") {
    if (schema.minimum !== undefined && instance < schema.minimum) {
      issues.push({ path, keyword: "minimum", message: `${instance} < ${schema.minimum}` });
    }
    if (schema.maximum !== undefined && instance > schema.maximum) {
      issues.push({ path, keyword: "maximum", message: `${instance} > ${schema.maximum}` });
    }
  }
  if (Array.isArray(instance)) {
    if (schema.minItems !== undefined && instance.length < schema.minItems) {
      issues.push({ path, keyword: "minItems", message: `fewer than ${schema.minItems} items` });
    }
    if (schema.maxItems !== undefined && instance.length > schema.maxItems) {
      issues.push({ path, keyword: "maxItems", message: `more than ${schema.maxItems} items` });
    }
    if (schema.items) for (let i = 0; i < instance.length; i++) check(instance[i], schema.items, root, `${path}[${i}]`, issues);
  }
  if (isRecord(instance)) {
    if (schema.required) {
      for (const key of schema.required) {
        if (!(key in instance)) issues.push({ path, keyword: "required", message: `missing required property: ${key}` });
      }
    }
    if (schema.properties) {
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (key in instance) check(instance[key], sub, root, `${path}.${key}`, issues);
      }
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const key of Object.keys(instance)) {
        if (!(key in schema.properties)) {
          issues.push({ path, keyword: "additionalProperties", message: `unexpected property: ${key}` });
        }
      }
    } else if (isJsonSchema(schema.additionalProperties) && schema.properties) {
      for (const [key, value] of Object.entries(instance)) {
        if (!(key in schema.properties)) check(value, schema.additionalProperties, root, `${path}.${key}`, issues);
      }
    }
  }
}

function resolveRef(ref: string, root: JsonSchema): JsonSchema | undefined {
  if (!ref.startsWith("#")) return undefined;
  const segments = ref.slice(1).split("/").filter((s) => s.length > 0);
  let current: unknown = root;
  for (const segment of segments) {
    if (!isRecord(current)) return undefined;
    current = current[decodeURIComponent(segment)];
  }
  return isJsonSchema(current) ? current : undefined;
}

function typeMatches(instance: unknown, type: string): boolean {
  switch (type) {
    case "object": return isRecord(instance);
    case "array": return Array.isArray(instance);
    case "string": return typeof instance === "string";
    case "number": return typeof instance === "number";
    case "integer": return typeof instance === "number" && Number.isInteger(instance);
    case "boolean": return typeof instance === "boolean";
    case "null": return instance === null;
    default: return false;
  }
}

function jsonType(instance: unknown): string {
  if (instance === null) return "null";
  if (Array.isArray(instance)) return "array";
  if (isRecord(instance)) return "object";
  return typeof instance;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJsonSchema(value: unknown): value is JsonSchema {
  return isRecord(value);
}

function formatMatches(value: string, format: string): boolean {
  switch (format) {
    case "date-time": return !Number.isNaN(Date.parse(value)) && /T\d{2}:\d{2}/.test(value);
    case "date": return /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value));
    case "uri":
      try {
        new URL(value);
        return true;
      } catch {
        return false;
      }
    default: return true;
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  if (isRecord(a) && isRecord(b)) {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return ka.length === kb.length && ka.every((k, i) => k === kb[i] && deepEqual(a[k], b[k]));
  }
  return false;
}

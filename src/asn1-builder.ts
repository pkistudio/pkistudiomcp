import {
  bytesToHex,
  createInstance,
  parseAsn1Definition,
  validateInstance,
  validateSchemaModule,
  type Asn1SchemaModule,
  type SchemaDiagnostic,
  type InstanceDiagnostic,
} from "@pkistudio/asn1instancebuilder/core";

import { summarizeAsn1 } from "./pkistudio.js";

type OutputEncoding = "hex" | "base64";

type Diagnostic = SchemaDiagnostic | InstanceDiagnostic;

type SchemaInput = {
  definition?: string;
  schema?: unknown;
};

type ParseDefinitionInput = {
  definition: string;
};

type ValidateInstanceInput = SchemaInput & {
  typeName: string;
  input: unknown;
};

type CreateInstanceInput = ValidateInstanceInput & {
  encoding?: OutputEncoding;
  includeDerSummary?: boolean;
};

const SUPPORTED_FEATURES = {
  schemaKinds: [
    "BOOLEAN",
    "INTEGER",
    "BIT STRING",
    "OCTET STRING",
    "NULL",
    "OBJECT IDENTIFIER",
    "UTF8String",
    "PrintableString",
    "IA5String",
    "UTCTime",
    "GeneralizedTime",
    "ENUMERATED",
    "SEQUENCE",
    "SET",
    "CHOICE",
    "SEQUENCE OF",
    "SET OF",
    "defined type references",
    "low-form context-specific EXPLICIT and IMPLICIT tags",
    "EXPLICIT TAGS, IMPLICIT TAGS, and AUTOMATIC TAGS module defaults",
    "DEFAULT fields for BOOLEAN, INTEGER, and ENUMERATED values",
  ],
  inputShapes: [
    "Constructed values as JSON objects",
    "CHOICE values as { selected, value }",
    "SEQUENCE OF and SET OF values as arrays",
    "BIT STRING values as byte input or { bytes, unusedBits }",
    "OCTET STRING values as compact HEX, byte arrays, { hex }, { utf8 }, or { base64 }",
    "OBJECT IDENTIFIER values as dotted decimal text, built-in PKI names, or schema-provided oidNames",
  ],
  knownLimitations: [
    "constraints",
    "extension markers",
    "parameterized types",
    "value assignments",
    "ASN.1 macros",
    "full module imports",
    "high-tag-number forms above context-specific tag 30",
    "browser app embedding or viewer UI exposure",
  ],
};

export function parseAsn1DefinitionTool(input: ParseDefinitionInput) {
  const schema = parseAsn1Definition(input.definition);
  const schemaDiagnostics = validateSchemaModule(schema);

  return {
    schema,
    moduleName: schema.name,
    typeNames: getTypeNames(schema),
    schemaDiagnostics,
    hasErrors: hasDiagnosticErrors(schemaDiagnostics),
  };
}

export function validateAsn1Instance(input: ValidateInstanceInput) {
  const schema = readSchema(input);
  const schemaDiagnostics = validateSchemaModule(schema);
  const instanceDiagnostics = validateInstance(schema, input.typeName, input.input);

  return {
    moduleName: schema.name,
    typeName: input.typeName,
    typeNames: getTypeNames(schema),
    schemaDiagnostics,
    instanceDiagnostics,
    hasErrors: hasDiagnosticErrors([...schemaDiagnostics, ...instanceDiagnostics]),
  };
}

export function createAsn1Instance(input: CreateInstanceInput) {
  const schema = readSchema(input);
  const schemaDiagnostics = validateSchemaModule(schema);

  if (hasDiagnosticErrors(schemaDiagnostics)) {
    return {
      built: false,
      moduleName: schema.name,
      typeName: input.typeName,
      typeNames: getTypeNames(schema),
      schemaDiagnostics,
      instanceDiagnostics: [],
      hasErrors: true,
    };
  }

  const instanceDiagnostics = validateInstance(schema, input.typeName, input.input);

  if (hasDiagnosticErrors(instanceDiagnostics)) {
    return {
      built: false,
      moduleName: schema.name,
      typeName: input.typeName,
      typeNames: getTypeNames(schema),
      schemaDiagnostics,
      instanceDiagnostics,
      hasErrors: true,
    };
  }

  const document = createInstance(schema, input.typeName, input.input);
  const encoding = input.encoding ?? "hex";
  const data = encodeBytes(document.der, encoding);

  return {
    built: true,
    moduleName: document.moduleName,
    typeName: document.typeName,
    length: document.der.length,
    encoding,
    data,
    schemaDiagnostics,
    instanceDiagnostics,
    hasErrors: false,
    derSummary: input.includeDerSummary ? summarizeAsn1({ data, format: encoding }) : undefined,
  };
}

export function listAsn1BuilderFeatures() {
  return {
    packageName: "@pkistudio/asn1instancebuilder",
    scope: "Build DER instances from a supported ASN.1 definition subset or Schema Model JSON.",
    supported: SUPPORTED_FEATURES,
  };
}

function readSchema(input: SchemaInput): Asn1SchemaModule {
  if (input.schema) return normalizeSchema(input.schema);
  if (input.definition) return parseAsn1Definition(input.definition);
  throw new Error("Provide either definition or schema.");
}

function normalizeSchema(schema: unknown): Asn1SchemaModule {
  if (!isRecord(schema) || typeof schema.name !== "string" || typeof schema.tagDefault !== "string" || !Array.isArray(schema.types)) {
    throw new Error("Schema Model JSON must include name, tagDefault, and types.");
  }

  return schema as unknown as Asn1SchemaModule;
}

function getTypeNames(schema: Asn1SchemaModule): string[] {
  return schema.types.map((definition) => definition.name);
}

function encodeBytes(bytes: Uint8Array, encoding: OutputEncoding): string {
  if (encoding === "base64") return Buffer.from(bytes).toString("base64");
  return bytesToHex(bytes);
}

function hasDiagnosticErrors(diagnostics: Diagnostic[]): boolean {
  return diagnostics.some((diagnostic) => diagnostic.severity === "error");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
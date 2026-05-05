#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { certificateMatchesKey, recognizeKeyMaterial, verifyKeyPair } from "./key-material.js";
import {
  decodeOidValue,
  describeNode,
  encodeOidValue,
  extractAsn1Node,
  getAsn1NodeValue,
  loadOidNames,
  normalizeAsn1Input,
  parseAsn1,
  resolveOid,
  summarizeAsn1,
} from "./pkistudio.js";

const inputFormatSchema = z
  .enum(["auto", "der", "ber", "pem", "base64", "headerless-pem", "hex"])
  .default("auto")
  .describe("Input format. Use auto to detect PEM, HEX, base64, DER, or BER.");

const optionalInputFormatSchema = z
  .enum(["auto", "der", "ber", "pem", "base64", "headerless-pem", "hex"])
  .optional()
  .describe("Input format. Defaults to auto detection.");

const asn1InputSchema = {
  data: z.string().min(1).describe("ASN.1 input as PEM, HEX, base64, DER base64, or text."),
  format: inputFormatSchema,
  maxDepth: z.number().int().min(0).optional().describe("Maximum child depth to include."),
  includeRawValue: z.boolean().optional().describe("Include raw primitive value hex."),
  includeHexPreview: z.boolean().optional().describe("Include compact hex previews for primitive values."),
  hexPreviewLength: z.number().int().min(1).max(4096).optional().describe("Maximum hex preview length."),
};

const outputEncodingSchema = z.enum(["hex", "base64"]).default("hex").describe("Output encoding for DER or value bytes.");

const server = new McpServer({
  name: "@pkistudio/pkistudiomcp",
  version: "0.1.0",
});

server.registerTool(
  "parse_asn1",
  {
    title: "Parse ASN.1",
    description: "Parse ASN.1 DER, BER, PEM, HEX, or base64 text and return a JSON tree.",
    inputSchema: asn1InputSchema,
  },
  async (input) => jsonToolResult(parseAsn1(input)),
);

server.registerTool(
  "summarize_asn1",
  {
    title: "Summarize ASN.1",
    description: "Parse ASN.1 input and return a compact summary of tags, OIDs, and top-level nodes.",
    inputSchema: {
      data: asn1InputSchema.data,
      format: inputFormatSchema,
      maxTopLevelNodes: z.number().int().min(1).max(100).default(10),
    },
  },
  async (input) => jsonToolResult(summarizeAsn1(input)),
);

server.registerTool(
  "describe_node",
  {
    title: "Describe ASN.1 Node",
    description: "Describe a parsed ASN.1 node by node id.",
    inputSchema: {
      data: asn1InputSchema.data,
      nodeId: z.string().min(1).describe("Node id from parse_asn1 output."),
      format: inputFormatSchema,
      includeRawValue: z.boolean().optional().describe("Include raw primitive value hex."),
      includeHexPreview: z.boolean().optional().describe("Include compact hex preview for primitive values."),
      hexPreviewLength: z.number().int().min(1).max(4096).optional().describe("Maximum hex preview length."),
    },
  },
  async (input) => jsonToolResult(describeNode(input)),
);

server.registerTool(
  "extract_asn1_node",
  {
    title: "Extract ASN.1 Node",
    description: "Extract a parsed ASN.1 node and its subtree by node id as DER bytes.",
    inputSchema: {
      data: asn1InputSchema.data,
      nodeId: z.string().min(1).describe("Node id from parse_asn1 output."),
      format: inputFormatSchema,
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(extractAsn1Node(input)),
);

server.registerTool(
  "normalize_asn1_input",
  {
    title: "Normalize ASN.1 Input",
    description: "Decode DER, BER, PEM, HEX, or base64 input and return round-trip re-encoded ASN.1 bytes.",
    inputSchema: {
      data: asn1InputSchema.data,
      format: inputFormatSchema,
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(normalizeAsn1Input(input)),
);

server.registerTool(
  "asn1_node_value",
  {
    title: "ASN.1 Node Value",
    description: "Return the decoded display value and raw value bytes for one parsed ASN.1 node.",
    inputSchema: {
      data: asn1InputSchema.data,
      nodeId: z.string().min(1).describe("Node id from parse_asn1 output."),
      format: inputFormatSchema,
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(getAsn1NodeValue(input)),
);

server.registerTool(
  "encode_oid",
  {
    title: "Encode OID",
    description: "Encode an object identifier string into ASN.1 OBJECT IDENTIFIER value bytes.",
    inputSchema: {
      oid: z.string().regex(/^\d+(?:\.\d+)+$/).describe("Object identifier, for example 1.2.840.113549.1.1.11."),
    },
  },
  async ({ oid }) => jsonToolResult(encodeOidValue(oid)),
);

server.registerTool(
  "decode_oid_value",
  {
    title: "Decode OID Value",
    description: "Decode ASN.1 OBJECT IDENTIFIER value bytes into dotted object identifier text.",
    inputSchema: {
      value: z.string().min(1).describe("ASN.1 OBJECT IDENTIFIER value bytes as HEX or base64."),
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(decodeOidValue(input)),
);

server.registerTool(
  "resolve_oid",
  {
    title: "Resolve OID",
    description: "Resolve an object identifier using the OID names bundled with PkiStudioJS.",
    inputSchema: {
      oid: z.string().regex(/^\d+(?:\.\d+)+$/).describe("Object identifier, for example 1.2.840.113549.1.1.11."),
    },
  },
  async ({ oid }) => jsonToolResult(resolveOid(oid)),
);

server.registerTool(
  "recognize_key_material",
  {
    title: "Recognize Key Material",
    description: "Recognize a PKCS#8 private key or SPKI public key and return its key family, label, and capabilities.",
    inputSchema: {
      data: z.string().min(1).describe("PKCS#8 private key or SPKI public key as DER, PEM, HEX, or base64 text."),
      kind: z.enum(["private", "public"]).describe("Whether data is a PKCS#8 private key or SPKI public key."),
      format: inputFormatSchema,
    },
  },
  async (input) => jsonToolResult(recognizeKeyMaterial(input)),
);

server.registerTool(
  "verify_key_pair",
  {
    title: "Verify Key Pair",
    description: "Verify that a PKCS#8 private key matches an SPKI public key by signing and verifying sample data.",
    inputSchema: {
      privateKey: z.string().min(1).describe("PKCS#8 private key as DER, PEM, HEX, or base64 text."),
      privateKeyFormat: optionalInputFormatSchema,
      publicKey: z.string().min(1).describe("SPKI public key as DER, PEM, HEX, or base64 text."),
      publicKeyFormat: optionalInputFormatSchema,
    },
  },
  async (input) => jsonToolResult(verifyKeyPair(input)),
);

server.registerTool(
  "certificate_matches_key",
  {
    title: "Certificate Matches Key",
    description: "Check whether an X.509 certificate public key matches supplied public key bytes or a PKCS#8 private key.",
    inputSchema: {
      certificate: z.string().min(1).describe("X.509 certificate as DER, PEM, HEX, or base64 text."),
      certificateFormat: optionalInputFormatSchema,
      privateKey: z.string().min(1).optional().describe("PKCS#8 private key as DER, PEM, HEX, or base64 text."),
      privateKeyFormat: optionalInputFormatSchema,
      publicKey: z.string().min(1).optional().describe("SPKI public key as DER, PEM, HEX, or base64 text."),
      publicKeyFormat: optionalInputFormatSchema,
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(certificateMatchesKey(input)),
);

async function main(): Promise<void> {
  loadOidNames();
  await server.connect(new StdioServerTransport());
}

function jsonToolResult(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(value, null, 2),
      },
    ],
  };
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  console.error(message);
  process.exit(1);
});
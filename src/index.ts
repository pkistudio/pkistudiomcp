#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import {
  describeNode,
  loadOidNames,
  parseAsn1,
  resolveOid,
  summarizeAsn1,
} from "./pkistudio.js";

const inputFormatSchema = z
  .enum(["auto", "der", "ber", "pem", "base64", "headerless-pem", "hex"])
  .default("auto")
  .describe("Input format. Use auto to detect PEM, HEX, base64, DER, or BER.");

const asn1InputSchema = {
  data: z.string().min(1).describe("ASN.1 input as PEM, HEX, base64, DER base64, or text."),
  format: inputFormatSchema,
  maxDepth: z.number().int().min(0).optional().describe("Maximum child depth to include."),
  includeRawValue: z.boolean().optional().describe("Include raw primitive value hex."),
  includeHexPreview: z.boolean().optional().describe("Include compact hex previews for primitive values."),
  hexPreviewLength: z.number().int().min(1).max(4096).optional().describe("Maximum hex preview length."),
};

const server = new McpServer({
  name: "@pkistudio/pkistudiomcp",
  version: "0.0.5",
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
#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import {
  certificateMatchesKey,
  createCsr,
  createSelfSignedCertificate,
  generateKeyPair,
  listSupportedKeyAlgorithms,
  readPkcs12,
  recognizeKeyMaterial,
  verifyKeyPair,
  writePkcs12,
} from "./key-material.js";
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
const hashAlgorithmSchema = z.enum(["SHA-256", "SHA-384", "SHA-512"]).default("SHA-256").describe("Hash algorithm for signing.");
const keyAlgorithmSchema = z.enum([
  "rsassa-pkcs1-v1_5-2048",
  "rsassa-pkcs1-v1_5-3072",
  "rsassa-pkcs1-v1_5-4096",
  "rsa-pss-2048",
  "rsa-pss-3072",
  "rsa-pss-4096",
  "rsa-oaep-2048",
  "rsa-oaep-3072",
  "rsa-oaep-4096",
  "ecdsa-p-256",
  "ecdsa-p-384",
  "ecdsa-p-521",
  "ecdh-p-256",
  "ecdh-p-384",
  "ecdh-p-521",
  "ed25519",
  "ed448",
  "x25519",
  "x448",
]);
const certificateKeyUsageSchema = z.enum([
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly",
]);

const server = new McpServer({
  name: "@pkistudio/pkistudiomcp",
  version: "0.2.1",
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
  "list_supported_key_algorithms",
  {
    title: "List Supported Key Algorithms",
    description: "List WebCrypto key pair algorithms supported by this runtime for key generation.",
    inputSchema: {},
  },
  async () => jsonToolResult(await listSupportedKeyAlgorithms()),
);

server.registerTool(
  "generate_key_pair",
  {
    title: "Generate Key Pair",
    description: "Generate a key pair and return the private key as PKCS#8 DER and public key as SPKI DER.",
    inputSchema: {
      algorithm: keyAlgorithmSchema.describe("Algorithm id from list_supported_key_algorithms, for example rsassa-pkcs1-v1_5-2048 or ecdsa-p-256."),
      label: z.string().optional().describe("Optional friendly label to include in the response."),
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(await generateKeyPair(input)),
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

server.registerTool(
  "create_csr",
  {
    title: "Create CSR",
    description: "Create a PKCS#10 certificate signing request from a PKCS#8 private key, SPKI public key, and subject DN.",
    inputSchema: {
      privateKey: z.string().min(1).describe("PKCS#8 private key as DER, PEM, HEX, or base64 text."),
      privateKeyFormat: optionalInputFormatSchema,
      publicKey: z.string().min(1).describe("SPKI public key as DER, PEM, HEX, or base64 text."),
      publicKeyFormat: optionalInputFormatSchema,
      subjectDn: z.string().min(1).describe("Subject DN, for example CN=example.com, O=Example, C=JP."),
      hashAlgorithm: hashAlgorithmSchema,
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(createCsr(input)),
);

server.registerTool(
  "create_self_signed_certificate",
  {
    title: "Create Self-Signed Certificate",
    description: "Create a self-signed X.509 certificate from a PKCS#8 private key, SPKI public key, and subject DN.",
    inputSchema: {
      privateKey: z.string().min(1).describe("PKCS#8 private key as DER, PEM, HEX, or base64 text."),
      privateKeyFormat: optionalInputFormatSchema,
      publicKey: z.string().min(1).describe("SPKI public key as DER, PEM, HEX, or base64 text."),
      publicKeyFormat: optionalInputFormatSchema,
      subjectDn: z.string().min(1).describe("Subject DN, for example CN=example.com, O=Example, C=JP."),
      hashAlgorithm: hashAlgorithmSchema,
      validityDays: z.number().int().min(1).max(36500).default(365).describe("Certificate validity period in days."),
      keyUsages: z.array(certificateKeyUsageSchema).default(["digitalSignature", "keyCertSign", "cRLSign"]),
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(createSelfSignedCertificate(input)),
);

server.registerTool(
  "read_pkcs12",
  {
    title: "Read PKCS#12",
    description: "Read PKCS#12/PFX data and return contained private keys, public keys, and certificates.",
    inputSchema: {
      data: z.string().min(1).describe("PKCS#12/PFX bytes as DER, HEX, or base64 text."),
      password: z.string().describe("PKCS#12 password."),
      format: inputFormatSchema,
      sourceName: z.string().optional().describe("Optional source filename to include in output metadata."),
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(readPkcs12(input)),
);

server.registerTool(
  "write_pkcs12",
  {
    title: "Write PKCS#12",
    description: "Create PKCS#12/PFX data from one or more private keys and optional X.509 certificates.",
    inputSchema: {
      keys: z.array(z.object({
        label: z.string().optional().describe("Optional friendly name for the key bag."),
        privateKey: z.string().min(1).describe("PKCS#8 private key as DER, PEM, HEX, or base64 text."),
        privateKeyFormat: optionalInputFormatSchema,
        certificate: z.string().min(1).optional().describe("Optional X.509 certificate as DER, PEM, HEX, or base64 text."),
        certificateFormat: optionalInputFormatSchema,
      })).min(1),
      password: z.string().describe("Password to protect the PKCS#12 output."),
      encoding: outputEncodingSchema,
    },
  },
  async (input) => jsonToolResult(writePkcs12(input)),
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
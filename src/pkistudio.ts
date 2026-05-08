import { createRequire } from "node:module";
import { dirname, join } from "node:path";

type InputFormat = "auto" | "der" | "ber" | "pem" | "base64" | "headerless-pem" | "hex";

type ParseOptions = {
  format?: InputFormat;
  maxDepth?: number;
  includeRawValue?: boolean;
  includeHexPreview?: boolean;
  hexPreviewLength?: number;
  oidNames?: Record<string, string>;
};

type SerializedNode = {
  id: string;
  tagName: string;
  tagClass: number;
  tagClassName: string;
  tagNumber: number;
  constructed: boolean;
  start: number;
  headerLength: number;
  length: number | null;
  valueStart: number;
  valueEnd: number;
  end: number;
  indefinite: boolean;
  encapsulated: boolean;
  value: string;
  oidName?: string;
  hexPreview?: string;
  valueHex?: string;
  children?: SerializedNode[];
  childrenTruncated?: number;
};

type ParsedDocument = {
  format: string;
  bytes: Uint8Array;
  encodedBytes: Uint8Array;
  nodes: unknown[];
};

type PkiStudioCore = {
  base64ToBytes(base64: string): Uint8Array;
  bytesToBase64(bytes: Uint8Array): string;
  decodeInput(input: string | Uint8Array, options?: Pick<ParseOptions, "format">): { bytes: Uint8Array; format: string };
  decodeOid(bytes: Uint8Array): string;
  describeValue(node: unknown): string;
  encodeNodes(nodes: unknown[]): Uint8Array;
  encodeOid(oid: string): Uint8Array;
  parseInput(input: string | Uint8Array, options?: ParseOptions): ParsedDocument;
  parseAsn1(input: string | Uint8Array, options?: ParseOptions): { format: string; length: number; nodes: SerializedNode[] };
  serializeNode(node: unknown, options?: ParseOptions): SerializedNode;
  serializeTree(nodes: unknown[], options?: ParseOptions): SerializedNode[];
  findNodeById(nodes: unknown[], nodeId: string): unknown | null;
  getNodeBytes(nodes: unknown[], nodeId: string): Uint8Array;
  getNodeValueBytes(node: unknown): Uint8Array;
  getTagName(node: unknown): string;
  hexToBytes(text: string, options?: { allowEmpty?: boolean }): Uint8Array;
  resolveOid(oid: string, oidNames?: Record<string, string>): string;
  toLowerHexString(bytes: Uint8Array): string;
};

type OutputEncoding = "hex" | "base64";

type Asn1Input = ParseOptions & {
  data: string;
};

type SummaryInput = {
  data: string;
  format?: InputFormat;
  maxTopLevelNodes?: number;
};

type DescribeNodeInput = ParseOptions & {
  data: string;
  nodeId: string;
};

type NodeInput = {
  data: string;
  nodeId: string;
  format?: InputFormat;
  encoding?: OutputEncoding;
};

type NormalizeInput = {
  data: string;
  format?: InputFormat;
  encoding?: OutputEncoding;
};

type DecodeOidInput = {
  value: string;
  encoding?: OutputEncoding;
};

const require = createRequire(import.meta.url);
const pkistudio = require("@pkistudio/pkistudiojs") as PkiStudioCore;

let oidNames: Record<string, string> | undefined;

export function loadOidNames(): Record<string, string> {
  if (oidNames) return oidNames;

  try {
    const corePath = require.resolve("@pkistudio/pkistudiojs");
    oidNames = require(join(dirname(corePath), "oids.json")) as Record<string, string>;
  } catch {
    oidNames = {};
  }

  return oidNames;
}

export function parseAsn1(input: Asn1Input) {
  return pkistudio.parseAsn1(input.data, withOidNames(input));
}

export function summarizeAsn1(input: SummaryInput) {
  const document = pkistudio.parseInput(input.data, { format: input.format, oidNames: loadOidNames() });
  const nodes = pkistudio.serializeTree(document.nodes, {
    maxDepth: 1,
    includeHexPreview: true,
    hexPreviewLength: 96,
    oidNames: loadOidNames(),
  });
  const flattened = flattenSerializedNodes(pkistudio.serializeTree(document.nodes, { oidNames: loadOidNames() }));
  const oidNodes = flattened
    .filter((node) => node.tagName === "OBJECT IDENTIFIER")
    .map((node) => ({ oid: node.value, name: node.oidName || resolveOid(node.value).name || "" }));
  const tagCounts = countBy(flattened.map((node) => node.tagName));

  return {
    format: document.format,
    length: document.bytes.length,
    topLevelNodeCount: document.nodes.length,
    totalNodeCount: flattened.length,
    tagCounts,
    oids: oidNodes,
    topLevelNodes: nodes.slice(0, input.maxTopLevelNodes ?? 10),
  };
}

export function describeNode(input: DescribeNodeInput) {
  const document = pkistudio.parseInput(input.data, withOidNames(input));
  const node = pkistudio.findNodeById(document.nodes, input.nodeId);
  if (!node) {
    throw new Error(`ASN.1 node not found: ${input.nodeId}`);
  }

  return pkistudio.serializeNode(node, withOidNames(input));
}

export function extractAsn1Node(input: NodeInput) {
  const document = pkistudio.parseInput(input.data, { format: input.format, oidNames: loadOidNames() });
  const node = pkistudio.findNodeById(document.nodes, input.nodeId);
  if (!node) {
    throw new Error(`ASN.1 node not found: ${input.nodeId}`);
  }

  const bytes = pkistudio.getNodeBytes(document.nodes, input.nodeId);
  return {
    nodeId: input.nodeId,
    sourceFormat: document.format,
    length: bytes.length,
    encoding: input.encoding ?? "hex",
    data: encodeBytes(bytes, input.encoding),
    node: pkistudio.serializeNode(node, { maxDepth: 1, includeHexPreview: true, oidNames: loadOidNames() }),
  };
}

export function normalizeAsn1Input(input: NormalizeInput) {
  const document = pkistudio.parseInput(input.data, { format: input.format, oidNames: loadOidNames() });
  const encodedBytes = pkistudio.encodeNodes(document.nodes);
  return {
    sourceFormat: document.format,
    length: document.bytes.length,
    canonicalLength: encodedBytes.length,
    roundTrip: bytesEqual(document.bytes, encodedBytes),
    encoding: input.encoding ?? "hex",
    data: encodeBytes(encodedBytes, input.encoding),
  };
}

export function getAsn1NodeValue(input: NodeInput) {
  const document = pkistudio.parseInput(input.data, { format: input.format, oidNames: loadOidNames() });
  const node = pkistudio.findNodeById(document.nodes, input.nodeId);
  if (!node) {
    throw new Error(`ASN.1 node not found: ${input.nodeId}`);
  }

  const valueBytes = pkistudio.getNodeValueBytes(node);
  return {
    nodeId: input.nodeId,
    sourceFormat: document.format,
    tagName: pkistudio.getTagName(node),
    value: pkistudio.describeValue(node),
    valueLength: valueBytes.length,
    encoding: input.encoding ?? "hex",
    valueBytes: encodeBytes(valueBytes, input.encoding),
  };
}

export function encodeOidValue(oid: string) {
  const bytes = pkistudio.encodeOid(oid);
  return {
    oid,
    valueHex: encodeBytes(bytes, "hex"),
    valueBase64: encodeBytes(bytes, "base64"),
  };
}

export function decodeOidValue(input: DecodeOidInput) {
  const bytes = decodeBytes(input.value, input.encoding ?? "hex");
  const oid = pkistudio.decodeOid(bytes);
  return {
    oid,
    valueHex: encodeBytes(bytes, "hex"),
    name: resolveOid(oid).name,
  };
}

export function resolveOid(oid: string) {
  const name = pkistudio.resolveOid(oid, loadOidNames());
  return {
    oid,
    name,
    found: Boolean(name),
  };
}

export function decodeInputBytes(data: string, format?: InputFormat) {
  return pkistudio.decodeInput(data, { format });
}

export function encodeOutputBytes(bytes: Uint8Array, encoding: OutputEncoding = "hex"): string {
  return encodeBytes(bytes, encoding);
}

function withOidNames<T extends ParseOptions>(options: T): T & { oidNames: Record<string, string> } {
  return {
    ...options,
    oidNames: loadOidNames(),
  };
}

function flattenSerializedNodes(nodes: SerializedNode[]): SerializedNode[] {
  const flattened: SerializedNode[] = [];

  for (const node of nodes) {
    flattened.push(node);
    if (node.children) flattened.push(...flattenSerializedNodes(node.children));
  }

  return flattened;
}

function countBy(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] || 0) + 1;
  return counts;
}

function encodeBytes(bytes: Uint8Array, encoding: OutputEncoding = "hex"): string {
  if (encoding === "base64") return pkistudio.bytesToBase64(bytes);
  return pkistudio.toLowerHexString(bytes);
}

function decodeBytes(value: string, encoding: OutputEncoding): Uint8Array {
  if (encoding === "base64") return pkistudio.base64ToBytes(value);
  return pkistudio.hexToBytes(value);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}
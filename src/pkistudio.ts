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
  parseInput(input: string | Uint8Array, options?: ParseOptions): ParsedDocument;
  parseAsn1(input: string | Uint8Array, options?: ParseOptions): { format: string; length: number; nodes: SerializedNode[] };
  serializeNode(node: unknown, options?: ParseOptions): SerializedNode;
  serializeTree(nodes: unknown[], options?: ParseOptions): SerializedNode[];
  findNodeById(nodes: unknown[], nodeId: string): unknown | null;
  resolveOid(oid: string, oidNames?: Record<string, string>): string;
};

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

const require = createRequire(import.meta.url);
const pkistudio = require("pkistudiojs") as PkiStudioCore;

let oidNames: Record<string, string> | undefined;

export function loadOidNames(): Record<string, string> {
  if (oidNames) return oidNames;

  try {
    const corePath = require.resolve("pkistudiojs");
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

export function resolveOid(oid: string) {
  const name = pkistudio.resolveOid(oid, loadOidNames());
  return {
    oid,
    name,
    found: Boolean(name),
  };
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
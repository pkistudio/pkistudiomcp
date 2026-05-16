import {
  CertGadgetsCore,
  collectNetworkValidationPlans,
  createCertificateFromBytes,
  type CertificateNetworkResource,
  type CertificateTreeNode,
  type NetworkResourceKind,
  type NetworkValidationPlan,
} from "@pkistudio/certgadgets";

import { decodeInputBytes, encodeOutputBytes } from "./pkistudio.js";
import { safeFetchBytes } from "./safe-fetch.js";

type InputFormat = "auto" | "der" | "ber" | "pem" | "base64" | "headerless-pem" | "hex";
type OutputEncoding = "hex" | "base64";

type CertificateInput = {
  data: string;
  format?: InputFormat;
  sourceName?: string;
};

type ParseCertificateInput = CertificateInput & {
  maxDepth?: number;
  includeDer?: boolean;
  derEncoding?: OutputEncoding;
};

type FetchCertificateNetworkResourcesInput = CertificateInput & {
  resourceKinds?: NetworkResourceKind[];
  urls?: string[];
  timeoutMs?: number;
  maxBytes?: number;
  maxResources?: number;
  encoding?: OutputEncoding;
};

type ByteDescription = {
  length: number;
  encoding: OutputEncoding;
  data?: string;
  preview: string;
};

type SerializedCertificateTreeNode = Omit<CertificateTreeNode, "derBytes" | "networkResources" | "children"> & {
  der?: ByteDescription;
  networkResources?: Array<CertificateNetworkResource & { nodeId: string }>;
  children?: SerializedCertificateTreeNode[];
  childrenTruncated?: number;
};

type NetworkResourceWithNode = CertificateNetworkResource & {
  nodeId: string;
};

type SerializedNetworkValidationPlan = Omit<NetworkValidationPlan, "requestBytes" | "targetCertificateBytes" | "issuerCertificateBytes"> & {
  kind?: NetworkResourceKind;
  requestBytes?: ByteDescription;
  targetCertificateBytes?: ByteDescription;
  issuerCertificateBytes?: ByteDescription;
};

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 1_048_576;
const DEFAULT_MAX_RESOURCES = 10;

export function parseCertificate(input: ParseCertificateInput) {
  const { decoded, document, resources, plans } = parseCertificateDocument(input);
  const derEncoding = input.derEncoding ?? "hex";

  return {
    certGadgetsVersion: CertGadgetsCore.version,
    sourceFormat: decoded.format,
    length: decoded.bytes.length,
    document: {
      id: document.id,
      label: document.label,
      sourceName: document.sourceName,
      size: document.size,
      loadedAt: document.loadedAt.toISOString(),
      root: serializeNode(document.root, {
        maxDepth: input.maxDepth ?? 8,
        includeDer: input.includeDer ?? false,
        derEncoding,
      }),
    },
    networkResources: resources,
    networkPlans: plans.map((plan) => serializePlan(plan, resources, derEncoding)),
  };
}

export async function fetchCertificateNetworkResources(input: FetchCertificateNetworkResourcesInput) {
  const { decoded, resources, plans } = parseCertificateDocument(input);
  const encoding = input.encoding ?? "base64";
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = input.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxResources = input.maxResources ?? DEFAULT_MAX_RESOURCES;
  const selectedPlans = plans
    .map((plan) => ({ plan, kind: findResourceKind(plan.url, resources) }))
    .filter(({ plan, kind }) => shouldFetchPlan(plan, kind, input))
    .slice(0, maxResources);

  const results = [];
  for (const { plan, kind } of selectedPlans) {
    results.push(await fetchPlan(plan, kind, { timeoutMs, maxBytes, encoding }));
  }

  return {
    sourceFormat: decoded.format,
    length: decoded.bytes.length,
    resourceCount: resources.length,
    planCount: plans.length,
    selectedCount: selectedPlans.length,
    fetchedCount: results.filter((result) => result.ok).length,
    skippedCount: plans.length - selectedPlans.length + results.filter((result) => result.skipped).length,
    results,
  };
}

function parseCertificateDocument(input: CertificateInput) {
  const decoded = decodeInputBytes(input.data, input.format);
  const document = createCertificateFromBytes(decoded.bytes, input.sourceName ?? "certificate");
  const resources = collectNetworkResources(document.root);
  const plans = collectNetworkValidationPlans(document);

  return { decoded, document, resources, plans };
}

function serializeNode(
  node: CertificateTreeNode,
  options: { maxDepth: number; includeDer: boolean; derEncoding: OutputEncoding },
  depth = 0,
): SerializedCertificateTreeNode {
  const { derBytes, networkResources, children, ...rest } = node;
  const serialized: SerializedCertificateTreeNode = { ...rest };

  if (derBytes) {
    serialized.der = options.includeDer
      ? describeBytes(derBytes, options.derEncoding)
      : { length: derBytes.length, encoding: "hex", preview: CertGadgetsCore.bytesToHexPreview(derBytes, 48) };
  }

  if (networkResources?.length) {
    serialized.networkResources = networkResources.map((resource) => ({ ...resource, nodeId: node.id }));
  }

  if (children?.length) {
    if (depth < options.maxDepth) {
      serialized.children = children.map((child) => serializeNode(child, options, depth + 1));
    } else {
      serialized.childrenTruncated = children.length;
    }
  }

  return serialized;
}

function collectNetworkResources(node: CertificateTreeNode): NetworkResourceWithNode[] {
  const resources: NetworkResourceWithNode[] = [];

  if (node.networkResources) {
    resources.push(...node.networkResources.map((resource) => ({ ...resource, nodeId: node.id })));
  }

  if (node.networkUrl && node.networkKind) {
    resources.push({ label: node.label, url: node.networkUrl, kind: node.networkKind, nodeId: node.id });
  }

  for (const child of node.children ?? []) {
    resources.push(...collectNetworkResources(child));
  }

  return dedupeResources(resources);
}

function dedupeResources(resources: NetworkResourceWithNode[]): NetworkResourceWithNode[] {
  const seen = new Set<string>();
  return resources.filter((resource) => {
    const key = `${resource.kind}\0${resource.url}\0${resource.nodeId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function serializePlan(
  plan: NetworkValidationPlan,
  resources: NetworkResourceWithNode[],
  encoding: OutputEncoding,
): SerializedNetworkValidationPlan {
  const { requestBytes, targetCertificateBytes, issuerCertificateBytes, ...rest } = plan;
  return {
    ...rest,
    kind: findResourceKind(plan.url, resources),
    requestBytes: requestBytes ? describeBytes(requestBytes, encoding) : undefined,
    targetCertificateBytes: targetCertificateBytes ? describeBytes(targetCertificateBytes, encoding) : undefined,
    issuerCertificateBytes: issuerCertificateBytes ? describeBytes(issuerCertificateBytes, encoding) : undefined,
  };
}

function findResourceKind(url: string, resources: NetworkResourceWithNode[]): NetworkResourceKind | undefined {
  return resources.find((resource) => resource.url === url)?.kind ?? inferResourceKind(url);
}

function inferResourceKind(url: string): NetworkResourceKind | undefined {
  const lowerUrl = url.toLowerCase();
  if (lowerUrl.includes("ocsp")) return "ocsp";
  if (lowerUrl.endsWith(".crl") || lowerUrl.includes("crl")) return "crl";
  if (lowerUrl.includes("ca")) return "ca-issuers";
  return undefined;
}

function shouldFetchPlan(
  plan: NetworkValidationPlan,
  kind: NetworkResourceKind | undefined,
  input: FetchCertificateNetworkResourcesInput,
): boolean {
  if (input.urls?.length && !input.urls.includes(plan.url)) return false;
  if (input.resourceKinds?.length && (!kind || !input.resourceKinds.includes(kind))) return false;
  return true;
}

async function fetchPlan(
  plan: NetworkValidationPlan,
  kind: NetworkResourceKind | undefined,
  options: { timeoutMs: number; maxBytes: number; encoding: OutputEncoding },
) {
  if (plan.operation === "OCSP.query" && !plan.requestBytes) {
    return {
      ok: false,
      skipped: true,
      kind,
      operation: plan.operation,
      reason: plan.reason,
      url: plan.url,
      error: "OCSP fetching requires request bytes, which were not provided by the certificate plan.",
    };
  }

  try {
    const response = await safeFetchBytes(plan.url, {
      method: plan.method ?? (plan.requestBytes ? "POST" : "GET"),
      headers: createFetchHeaders(plan),
      body: plan.requestBytes,
      timeoutMs: options.timeoutMs,
      maxBytes: options.maxBytes,
    });

    return {
      ok: response.status >= 200 && response.status < 300,
      skipped: false,
      kind,
      operation: plan.operation,
      reason: plan.reason,
      url: plan.url,
      status: response.status,
      statusText: response.statusText,
      finalUrl: response.finalUrl,
      contentType: getResponseHeader(response.headers, "content-type"),
      contentLengthHeader: getResponseHeader(response.headers, "content-length"),
      body: describeBytes(response.bytes, options.encoding),
    };
  } catch (error) {
    return {
      ok: false,
      skipped: false,
      kind,
      operation: plan.operation,
      reason: plan.reason,
      url: plan.url,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function createFetchHeaders(plan: NetworkValidationPlan): Headers {
  const headers = new Headers();
  if (plan.acceptMediaType) headers.set("accept", plan.acceptMediaType);
  if (plan.requestMediaType) headers.set("content-type", plan.requestMediaType);
  return headers;
}

function getResponseHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function describeBytes(bytes: Uint8Array, encoding: OutputEncoding = "base64"): ByteDescription {
  return {
    length: bytes.length,
    encoding,
    data: encodeOutputBytes(bytes, encoding),
    preview: CertGadgetsCore.bytesToHexPreview(bytes, 48),
  };
}
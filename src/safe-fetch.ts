import { lookup } from "node:dns/promises";
import { request as requestHttp } from "node:http";
import { request as requestHttps } from "node:https";
import { isIP } from "node:net";
import { URL } from "node:url";

type SafeFetchOptions = {
  method?: string;
  headers?: HeadersInit;
  body?: Uint8Array;
  timeoutMs: number;
  maxBytes: number;
  maxRedirects?: number;
  allowedPorts?: number[];
};

export type SafeFetchResult = {
  finalUrl: string;
  status: number;
  statusText: string;
  headers: Record<string, string | string[]>;
  bytes: Uint8Array;
};

const DEFAULT_MAX_REDIRECTS = 3;
const DEFAULT_ALLOWED_PORTS = [80, 443];

export async function safeFetchBytes(url: string, options: SafeFetchOptions): Promise<SafeFetchResult> {
  return fetchWithRedirects(url, options, 0);
}

async function fetchWithRedirects(url: string, options: SafeFetchOptions, redirectCount: number): Promise<SafeFetchResult> {
  const requestUrl = await validateUrl(url, options.allowedPorts ?? DEFAULT_ALLOWED_PORTS);
  const result = await sendRequest(requestUrl, options);

  if (isRedirect(result.status)) {
    const location = getHeader(result.headers, "location");
    if (!location) return result;

    const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    if (redirectCount >= maxRedirects) {
      throw new Error(`Too many redirects (${maxRedirects}).`);
    }

    return fetchWithRedirects(new URL(location, requestUrl).href, options, redirectCount + 1);
  }

  return result;
}

async function validateUrl(url: string, allowedPorts: number[]): Promise<URL> {
  const requestUrl = new URL(url);
  if (requestUrl.protocol !== "http:" && requestUrl.protocol !== "https:") {
    throw new Error("Only http and https URLs can be fetched.");
  }

  const port = Number(requestUrl.port || (requestUrl.protocol === "https:" ? 443 : 80));
  if (!allowedPorts.includes(port)) {
    throw new Error(`Port ${port} is not allowed.`);
  }

  const addresses = await resolvePublicAddresses(requestUrl.hostname);
  if (addresses.length === 0) {
    throw new Error("Host did not resolve to a public IP address.");
  }

  return requestUrl;
}

async function sendRequest(url: URL, options: SafeFetchOptions): Promise<SafeFetchResult> {
  const addresses = await resolvePublicAddresses(url.hostname);
  if (addresses.length === 0) {
    throw new Error("Host did not resolve to a public IP address.");
  }

  const selectedAddress = addresses[0];
  const request = url.protocol === "https:" ? requestHttps : requestHttp;
  const headers = headersToObject(options.headers);

  return new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: options.method ?? (options.body ? "POST" : "GET"),
        headers,
        lookup: (_hostname, _lookupOptions, callback) => {
          callback(null, selectedAddress.address, selectedAddress.family);
        },
      },
      (res) => {
        const contentLength = res.headers["content-length"];
        if (typeof contentLength === "string" && Number(contentLength) > options.maxBytes) {
          req.destroy(new Error(`Response exceeds maxBytes (${contentLength} > ${options.maxBytes}).`));
          return;
        }

        const chunks: Buffer[] = [];
        let totalLength = 0;

        res.on("data", (chunk: Buffer) => {
          totalLength += chunk.length;
          if (totalLength > options.maxBytes) {
            req.destroy(new Error(`Response exceeds maxBytes (${totalLength} > ${options.maxBytes}).`));
            return;
          }
          chunks.push(chunk);
        });

        res.on("end", () => {
          resolve({
            finalUrl: url.href,
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? "",
            headers: res.headers as Record<string, string | string[]>,
            bytes: Buffer.concat(chunks, totalLength),
          });
        });
      },
    );

    req.setTimeout(options.timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${options.timeoutMs}ms.`));
    });
    req.on("error", reject);
    if (options.body) req.write(Buffer.from(options.body));
    req.end();
  });
}

async function resolvePublicAddresses(hostname: string): Promise<Array<{ address: string; family: 4 | 6 }>> {
  const ipFamily = isIP(hostname);
  if (ipFamily) {
    if (isBlockedIp(hostname)) return [];
    return [{ address: hostname, family: ipFamily as 4 | 6 }];
  }

  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses
    .filter((address): address is { address: string; family: 4 | 6 } => (address.family === 4 || address.family === 6) && !isBlockedIp(address.address));
}

function isBlockedIp(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isBlockedIpv4(address);
  if (family === 6) return isBlockedIpv6(address);
  return true;
}

function isBlockedIpv4(address: string): boolean {
  const value = ipv4ToNumber(address);
  return [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ].some(([range, prefix]) => ipv4InCidr(value, range as string, prefix as number));
}

function isBlockedIpv6(address: string): boolean {
  const normalized = address.toLowerCase();
  if (normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("fe80:") || normalized.startsWith("fe90:") || normalized.startsWith("fea0:") || normalized.startsWith("feb0:")) return true;
  if (/^f[c-d][0-9a-f]{2}:/u.test(normalized)) return true;
  if (/^ff[0-9a-f]{2}:/u.test(normalized)) return true;

  const mappedIpv4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/u)?.[1];
  if (mappedIpv4) return isBlockedIpv4(mappedIpv4);

  return false;
}

function ipv4ToNumber(address: string): number {
  return address.split(".").reduce((value, octet) => (value << 8) + Number(octet), 0) >>> 0;
}

function ipv4InCidr(value: number, range: string, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (ipv4ToNumber(range) & mask);
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function getHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function headersToObject(headers: HeadersInit | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!headers) return result;

  for (const [key, value] of new Headers(headers)) {
    result[key] = value;
  }

  return result;
}
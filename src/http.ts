#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { createPkiStudioMcpServer } from "./index.js";
import { loadOidNames } from "./pkistudio.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 3000;
const DEFAULT_ENDPOINT = "/mcp";

type HttpConfig = {
  host: string;
  port: number;
  endpoint: string;
  bearerToken?: string;
  corsOrigins: "*" | string[];
  maxContentLength?: number;
  requestTimeoutMs?: number;
};

async function main(): Promise<void> {
  loadOidNames();

  const config = readConfig();
  const httpServer = createServer((request, response) => {
    void handleRequest(request, response, config);
  });

  if (config.requestTimeoutMs !== undefined) {
    httpServer.requestTimeout = config.requestTimeoutMs;
  }

  httpServer.on("error", (error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exitCode = 1;
  });

  httpServer.listen(config.port, config.host, () => {
    console.error(`PKI Studio MCP HTTP server listening on http://${config.host}:${config.port}${config.endpoint}`);
  });

  const shutdown = () => {
    httpServer.close(() => {
      process.exit(0);
    });
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function handleRequest(request: IncomingMessage, response: ServerResponse, config: HttpConfig): Promise<void> {
  setCorsHeaders(request, response, config);

  if (request.method === "OPTIONS") {
    response.writeHead(204);
    response.end();
    return;
  }

  const requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? `${config.host}:${config.port}`}`);

  if (requestUrl.pathname === "/healthz" || requestUrl.pathname === "/readyz") {
    sendJson(response, 200, { ok: true });
    return;
  }

  if (requestUrl.pathname !== config.endpoint) {
    sendJson(response, 404, { error: "Not found" });
    return;
  }

  if (!isAuthorized(request, config)) {
    response.setHeader("WWW-Authenticate", "Bearer");
    sendJson(response, 401, { error: "Unauthorized" });
    return;
  }

  if (!isAllowedContentLength(request, config)) {
    sendJson(response, 413, { error: "Request body too large" });
    return;
  }

  const server = createPkiStudioMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  response.once("close", () => {
    void server.close().catch((error: unknown) => {
      console.error(error instanceof Error ? error.stack || error.message : String(error));
    });
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(request, response);
  } catch (error) {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    if (!response.headersSent) {
      sendJson(response, 500, { error: "Internal server error" });
    } else {
      response.end();
    }
  }
}

function readConfig(): HttpConfig {
  return {
    host: process.env.PKISTUDIOMCP_HTTP_HOST || DEFAULT_HOST,
    port: readPort(process.env.PKISTUDIOMCP_HTTP_PORT),
    endpoint: normalizeEndpoint(process.env.PKISTUDIOMCP_HTTP_PATH || DEFAULT_ENDPOINT),
    bearerToken: readOptionalSecret(process.env.PKISTUDIOMCP_HTTP_BEARER_TOKEN),
    corsOrigins: readCorsOrigins(process.env.PKISTUDIOMCP_HTTP_CORS_ORIGIN),
    maxContentLength: readOptionalPositiveInteger(process.env.PKISTUDIOMCP_HTTP_MAX_CONTENT_LENGTH, "PKISTUDIOMCP_HTTP_MAX_CONTENT_LENGTH"),
    requestTimeoutMs: readOptionalPositiveInteger(process.env.PKISTUDIOMCP_HTTP_REQUEST_TIMEOUT_MS, "PKISTUDIOMCP_HTTP_REQUEST_TIMEOUT_MS"),
  };
}

function readPort(value: string | undefined): number {
  if (!value) return DEFAULT_PORT;

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PKISTUDIOMCP_HTTP_PORT: ${value}`);
  }

  return port;
}

function normalizeEndpoint(value: string): string {
  const endpoint = value.startsWith("/") ? value : `/${value}`;
  return endpoint.length > 1 && endpoint.endsWith("/") ? endpoint.slice(0, -1) : endpoint;
}

function readOptionalSecret(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function readCorsOrigins(value: string | undefined): "*" | string[] {
  if (!value || value.trim() === "" || value.trim() === "*") return "*";

  const origins = value
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  if (origins.length === 0) return "*";
  return origins;
}

function readOptionalPositiveInteger(value: string | undefined, name: string): number | undefined {
  if (!value) return undefined;

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`Invalid ${name}: ${value}`);
  }

  return parsed;
}

function setCorsHeaders(request: IncomingMessage, response: ServerResponse, config: HttpConfig): void {
  const origin = request.headers.origin;
  if (config.corsOrigins === "*") {
    response.setHeader("Access-Control-Allow-Origin", "*");
  } else if (typeof origin === "string" && config.corsOrigins.includes(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
  }

  response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, Last-Event-ID");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  response.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
}

function isAuthorized(request: IncomingMessage, config: HttpConfig): boolean {
  if (!config.bearerToken) return true;
  return request.headers.authorization === `Bearer ${config.bearerToken}`;
}

function isAllowedContentLength(request: IncomingMessage, config: HttpConfig): boolean {
  if (config.maxContentLength === undefined) return true;

  const contentLength = request.headers["content-length"];
  if (contentLength === undefined) return true;
  if (Array.isArray(contentLength)) return false;

  const parsed = Number(contentLength);
  return Number.isInteger(parsed) && parsed <= config.maxContentLength;
}

function sendJson(response: ServerResponse, statusCode: number, value: unknown): void {
  response.writeHead(statusCode, { "Content-Type": "application/json" });
  response.end(JSON.stringify(value));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
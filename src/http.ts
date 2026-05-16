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
};

async function main(): Promise<void> {
  loadOidNames();

  const config = readConfig();
  const httpServer = createServer((request, response) => {
    void handleRequest(request, response, config);
  });

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
  setCorsHeaders(response);

  if (request.method === "OPTIONS") {
    response.writeHead(204);
    response.end();
    return;
  }

  const requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? `${config.host}:${config.port}`}`);

  if (requestUrl.pathname === "/healthz") {
    sendJson(response, 200, { ok: true });
    return;
  }

  if (requestUrl.pathname !== config.endpoint) {
    sendJson(response, 404, { error: "Not found" });
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

function setCorsHeaders(response: ServerResponse): void {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Last-Event-ID");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  response.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
}

function sendJson(response: ServerResponse, statusCode: number, value: unknown): void {
  response.writeHead(statusCode, { "Content-Type": "application/json" });
  response.end(JSON.stringify(value));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
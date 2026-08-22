# PKI Studio MCP Design Documentation

This directory contains design documentation for maintaining and extending the current PKI Studio MCP implementation. For user-facing setup instructions and usage examples, see the [GitHub Wiki](https://github.com/pkistudio/pkistudiomcp/wiki).

## Baseline

- Package: `@pkistudio/pkistudiomcp` 0.7.2
- Repository: `pkistudio/pkistudiomcp`
- Code baseline: `9a345e8da12fa3d04a1134f80b8d808cfe345a42`
- Documentation date: 2026-08-22
- Runtime: Node.js 20 or later

These documents describe the current, as-is design rather than a future target architecture.

## Documents

| Document | Scope |
| --- | --- |
| [architecture.md](architecture.md) | System boundaries, components, dependencies, and major data flows |
| [interface-design.md](interface-design.md) | MCP transports, tools, prompts, and input/output conventions |
| [security-design.md](security-design.md) | Trust boundaries, sensitive data, HTTP controls, and SSRF protections for external retrieval |
| [deployment-and-operations.md](deployment-and-operations.md) | stdio, HTTP, and Docker deployments, environment variables, CI/CD, and operational considerations |
| [testing-strategy.md](testing-strategy.md) | Current validation coverage, commands, and known testing gaps |

## Design Summary

- Expose ASN.1, X.509, key, CSR, and PKCS#12 capabilities to MCP clients as tools.
- Use the same MCP server factory and tool definitions for both stdio and Streamable HTTP transports.
- Delegate PKI operations to published PKI Studio family packages. This repository handles MCP input validation and result shaping.
- Keep normal parsing and generation inside the server process. Restrict external communication to `fetch_certificate_network_resources`.
- Maintain no persistent storage or user sessions. The server does not save submitted keys or certificates.
- Exchange binary values as PEM, hexadecimal strings, Base64, or other JSON-compatible text representations.

## Sources and Precedence

This documentation is based on:

1. The current implementation in `src/`, `package.json`, `Dockerfile`, and `.github/workflows/`
2. Executable behavior in `scripts/smoke-test.mjs`
3. User and operational guidance in the README and GitHub Wiki

If these sources disagree about runtime behavior, the code and tests take precedence. Public usage guidance must remain consistent with the README and Wiki as well. When the design changes, review the relevant code, tests, this directory, and README/Wiki together.

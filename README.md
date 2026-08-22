# PKI Studio MCP

PKI Studio MCP is a local MCP server for AI-assisted PKI, ASN.1, DER, PEM, X.509 certificate, CSR, key, and PKCS#12 workflows. It exposes PKI Studio family libraries as MCP tools for AI assistants through stdio and Streamable HTTP transports.

Documentation: https://github.com/pkistudio/pkistudiomcp/wiki

Maintainer-facing design documentation: [docs/README.md](https://github.com/pkistudio/pkistudiomcp/blob/main/docs/README.md)

Current version: 0.7.2

The server is designed for local assistant workflows first. Certificate parsing, ASN.1 parsing, key recognition, and PKCS#12 processing run inside the MCP server process. Network fetching is limited to the explicit `fetch_certificate_network_resources` tool.

## Features

- stdio MCP server for local VS Code, GitHub Copilot, Claude Desktop, and other MCP clients.
- Streamable HTTP MCP server for local, containerized, or controlled remote deployments.
- ASN.1 / DER / BER / PEM parsing, summaries, node extraction, and decoded node values.
- OBJECT IDENTIFIER encoding, decoding, and name resolution through PkiStudioJS.
- X.509 certificate parsing through CertGadgets, including CDP/AIA/OCSP resource plans without automatic network access.
- PKCS#8 private key and SPKI public key recognition, key pair generation, key verification, certificate/key matching, CSR creation, and self-signed certificate creation through Private Key Gadgets.
- PKCS#12 / PFX import and export helpers for certificate and key bundles.
- ASN.1 Instance Builder tools for parsing supported ASN.1 definitions, validating schema/instance JSON, and building DER.
- ASN.1 Definition Sifter tools for ranking likely ASN.1 type definitions for DER/TLV data.
- MCP workflow prompts for certificate inspection, certificate/key comparison, and PKCS#12 analysis.
- Docker image for the Streamable HTTP server.

See the Wiki for details:

- [Getting Started](https://github.com/pkistudio/pkistudiomcp/wiki/Getting-Started)
- [MCP Client Configuration](https://github.com/pkistudio/pkistudiomcp/wiki/MCP-Client-Configuration)
- [Tool Guide](https://github.com/pkistudio/pkistudiomcp/wiki/Tool-Guide)
- [Security Notes](https://github.com/pkistudio/pkistudiomcp/wiki/Security-Notes)
- [HTTP Deployment](https://github.com/pkistudio/pkistudiomcp/wiki/HTTP-Deployment)
- [Testing](https://github.com/pkistudio/pkistudiomcp/wiki/Testing)
- [Development](https://github.com/pkistudio/pkistudiomcp/wiki/Development)

## What Can I Ask?

- Parse this PEM certificate and summarize the issuer, subject, validity, extensions, and ASN.1 structure.
- Show all OIDs found in this DER data and resolve their names.
- Check whether this certificate matches this private key.
- Read this PKCS#12/PFX file and list contained certificates and keys.
- Generate a test key pair, CSR, or self-signed certificate.
- Identify likely ASN.1 type definitions for this DER data.
- Build DER from this ASN.1 definition and JSON instance.

For a longer prompt list, see [Getting Started](https://github.com/pkistudio/pkistudiomcp/wiki/Getting-Started).

## Tool Areas

- Certificate inspection: `parse_certificate`, `parse_asn1`, `summarize_asn1`, `resolve_oid`.
- DER / ASN.1 inspection: `parse_asn1`, `summarize_asn1`, `describe_node`, `extract_asn1_node`, `asn1_node_value`.
- OID utilities: `encode_oid`, `decode_oid_value`, `resolve_oid`.
- Key material: `recognize_key_material`, `generate_key_pair`, `verify_key_pair`, `certificate_matches_key`.
- CSR and test certificates: `create_csr`, `create_self_signed_certificate`.
- PKCS#12 / PFX: `read_pkcs12`, `write_pkcs12`.
- ASN.1 Definition Sifter: `sift_asn1_definition_candidates`, `sift_pki_asn1_definition_candidates`.
- ASN.1 Instance Builder: `parse_asn1_definition`, `validate_asn1_schema`, `validate_asn1_instance`, `create_asn1_instance`.

For all purpose-to-tool mappings, see the [Tool Guide](https://github.com/pkistudio/pkistudiomcp/wiki/Tool-Guide).

## Install

Run the stdio MCP server from npm:

```sh
npx -y @pkistudio/pkistudiomcp
```

Run the Streamable HTTP MCP server from npm:

```sh
npx -y --package @pkistudio/pkistudiomcp pkistudiomcp-http
```

Package commands:

- `pkistudiomcp`: stdio MCP server.
- `pkistudiomcp-http`: Streamable HTTP MCP server.

## MCP Client Quick Start

VS Code / GitHub Copilot `.vscode/mcp.json`:

```json
{
  "servers": {
    "pkistudio": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@pkistudio/pkistudiomcp"]
    }
  }
}
```

Claude Desktop configuration:

```json
{
  "mcpServers": {
    "pkistudio": {
      "command": "npx",
      "args": ["-y", "@pkistudio/pkistudiomcp"]
    }
  }
}
```

After configuring your client, try one of the prompts in [What Can I Ask?](#what-can-i-ask). For client-specific details, see [MCP Client Configuration](https://github.com/pkistudio/pkistudiomcp/wiki/MCP-Client-Configuration).

## Docker

Run the published Docker image:

```sh
docker run --rm -p 3000:3000 pkistudio/pkistudiomcp:latest
```

The Docker image starts the Streamable HTTP server by default. The MCP endpoint is `http://127.0.0.1:3000/mcp`, and health checks are available at `http://127.0.0.1:3000/healthz` and `http://127.0.0.1:3000/readyz`.

Pin a release version when reproducibility matters:

```sh
docker run --rm -p 3000:3000 pkistudio/pkistudiomcp:0.7.2
```

For HTTP deployment controls, see [HTTP Deployment](https://github.com/pkistudio/pkistudiomcp/wiki/HTTP-Deployment) and [Security Notes](https://github.com/pkistudio/pkistudiomcp/wiki/Security-Notes).

## Development

Run local checks with:

```sh
npm install
npm run check
npm run test
```

Run the stdio server locally:

```sh
npm start
```

Run the HTTP server locally:

```sh
npm run start:http
```

For package or release-related changes, also run:

```sh
npm pack --dry-run
```

For standard checks, MCP smoke coverage, package preview, local Wiki clone conventions, and release workflow notes, see [Testing](https://github.com/pkistudio/pkistudiomcp/wiki/Testing) and [Development](https://github.com/pkistudio/pkistudiomcp/wiki/Development).

## PKI Studio Family Dependencies

PKI Studio MCP imports the published PKI Studio family npm packages rather than vendoring their source:

- `@pkistudio/pkistudiojs`
- `@pkistudio/certgadgets`
- `@pkistudio/pvkgadgets`
- `@pkistudio/asn1instancebuilder`
- `@pkistudio/asn1defsifter`

Keep these dependencies aligned with the latest compatible PKI Studio family releases when updating MCP tool coverage or documentation.

## License

PKI Studio MCP is licensed under the MIT License. See [LICENSE](LICENSE).

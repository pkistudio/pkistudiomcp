# PKI Studio MCP

AI assistants can inspect certificates, keys, DER/PEM, OIDs, CSRs, and PKCS#12 files through MCP.

`@pkistudio/pkistudiomcp` supports both stdio and Streamable HTTP transports. It exposes PKI Studio, CertGadgets, Private Key Gadgets, ASN.1 Instance Builder, and ASN.1 Definition Sifter capabilities as MCP tools.

## Quick Start: VS Code / GitHub Copilot

Create `.vscode/mcp.json`:

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

Then open Copilot Chat Agent mode and ask:

> Parse this PEM certificate and summarize the issuer, subject, validity, extensions, and ASN.1 structure.

## Quick Start: Claude Desktop

Add this server to your Claude Desktop MCP configuration:

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

## Run Locally

Run the stdio MCP server from npm:

```sh
npx -y @pkistudio/pkistudiomcp
```

Run the Streamable HTTP server from npm:

```sh
npx -y --package @pkistudio/pkistudiomcp pkistudiomcp-http
```

For a local checkout:

```sh
npm install
npm run check
npm start
```

## Docker

Run the published Docker image:

```sh
docker run --rm -p 3000:3000 pkistudio/pkistudiomcp:latest
```

The Docker image starts the Streamable HTTP server by default. The MCP endpoint is `http://127.0.0.1:3000/mcp`, and health checks are available at `http://127.0.0.1:3000/healthz` and `http://127.0.0.1:3000/readyz`.

Pin a release version when reproducibility matters:

```sh
docker run --rm -p 3000:3000 pkistudio/pkistudiomcp:0.7.1
```

## What Can I Ask?

- Parse this PEM certificate and summarize it.
- Show all OIDs found in this DER data.
- Check whether this certificate matches this private key.
- Read this PKCS#12 file and list contained certificates and keys.
- Generate a test key pair and CSR.
- Identify likely ASN.1 type definitions for this DER data.
- Build DER from this ASN.1 definition and JSON instance.

## Main Tool Areas

- Certificate inspection: `parse_certificate`, `parse_asn1`, `resolve_oid`
- DER / ASN.1 inspection: `parse_asn1`, `summarize_asn1`, `describe_node`, `extract_asn1_node`, `asn1_node_value`
- OID utilities: `encode_oid`, `decode_oid_value`, `resolve_oid`
- Key material: `recognize_key_material`, `generate_key_pair`, `verify_key_pair`, `certificate_matches_key`
- CSR and test certificates: `create_csr`, `create_self_signed_certificate`
- PKCS#12 / PFX: `read_pkcs12`, `write_pkcs12`
- ASN.1 Definition Sifter: `sift_asn1_definition_candidates`, `sift_pki_asn1_definition_candidates`
- ASN.1 Instance Builder: `parse_asn1_definition`, `validate_asn1_schema`, `validate_asn1_instance`, `create_asn1_instance`

## Security Notes

Certificate parsing, ASN.1 parsing, key recognition, and PKCS#12 processing are local operations inside the MCP server process. `fetch_certificate_network_resources` is different: it performs external HTTP(S) requests for CDP/AIA/OCSP-related resources discovered in certificates.

Do not send production private keys, sensitive PKCS#12 files, or private certificate material to public demo endpoints. Even when the server processes data locally, MCP clients and AI chat histories may retain input or output.

If you expose the HTTP server beyond localhost, place it behind authentication, request size limits, rate limits, timeouts, logging, and a restrictive CORS policy. The built-in HTTP server also supports optional `PKISTUDIOMCP_HTTP_BEARER_TOKEN`, `PKISTUDIOMCP_HTTP_CORS_ORIGIN`, `PKISTUDIOMCP_HTTP_MAX_CONTENT_LENGTH`, and `PKISTUDIOMCP_HTTP_REQUEST_TIMEOUT_MS` settings.

## Documentation

See the [GitHub Wiki](https://github.com/pkistudio/pkistudiomcp/wiki) for detailed usage, client configuration, tool selection guidance, security notes, Docker usage, deployment notes, release process, and troubleshooting.
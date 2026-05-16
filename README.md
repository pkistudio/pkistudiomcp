# @pkistudio/pkistudiomcp

PKI Studio MCP is a local MCP server that lets AI assistants inspect and work with ASN.1, DER, PEM, X.509 certificates, CSRs, PKCS#8, SPKI, and PKCS#12 data. It supports stdio and Streamable HTTP transports.

Use it to inspect, summarize, decode, generate, and verify:

- ASN.1 / DER / BER / PEM data
- OBJECT IDENTIFIERs
- PKCS#8 private keys
- SPKI public keys
- X.509 certificates
- PKCS#10 CSRs
- PKCS#12 / PFX files

It is useful for certificate debugging, PKI development, ASN.1 inspection, and AI-assisted cryptography tooling.

Under the hood, `@pkistudio/pkistudiomcp` exposes PkiStudioJS ASN.1 tools, CertGadgets certificate inspection helpers, and Private Key Gadgets PKI key material helpers as MCP tools.

The package uses the published PkiStudioJS, CertGadgets, and Private Key Gadgets npm APIs:

```json
{
	"dependencies": {
		"@pkistudio/certgadgets": "^0.1.3",
		"@pkistudio/pkistudiojs": "^0.5.0",
		"@pkistudio/pvkgadgets": "^0.3.1"
	}
}
```

PkiStudioJS `0.5.x` is published as the scoped `@pkistudio/pkistudiojs` package. Its browser viewer also supports native read-only mode through `viewer.init({ editable: false })` and `setEditable(false)`. This MCP server uses the PkiStudioJS Core API rather than embedding the browser viewer, so the ASN.1 tools remain string-in/string-out MCP operations and do not expose a separate viewer editability option.

## What can I ask my AI assistant?

After installing this MCP server, you can ask questions like:

- Parse this PEM certificate and summarize its structure.
- Show me all OIDs found in this DER data.
- Tell me whether this private key matches this certificate.
- Create a CSR for this subject DN.
- Generate a self-signed certificate for testing.
- Read this PKCS#12/PFX file and list contained certificates and keys.
- Decode this OBJECT IDENTIFIER value.

## Tools

- `parse_asn1`: Parse DER, BER, PEM, HEX, base64, or headerless PEM input and return a JSON ASN.1 tree.
- `summarize_asn1`: Return a compact summary with tag counts, discovered OIDs, and top-level nodes.
- `describe_node`: Describe one parsed ASN.1 node by node id.
- `extract_asn1_node`: Extract one parsed ASN.1 node and its subtree as DER bytes.
- `normalize_asn1_input`: Decode supported ASN.1 input and return round-trip re-encoded bytes.
- `asn1_node_value`: Return a node's decoded display value and raw value bytes.
- `encode_oid`: Encode an OID string into ASN.1 OBJECT IDENTIFIER value bytes.
- `decode_oid_value`: Decode ASN.1 OBJECT IDENTIFIER value bytes into dotted OID text.
- `resolve_oid`: Resolve an OID using the OID names bundled with PkiStudioJS.
- `recognize_key_material`: Recognize a PKCS#8 private key or SPKI public key and report its key family, label, and capabilities.
- `list_supported_key_algorithms`: List WebCrypto key pair algorithms supported by the current runtime for key generation.
- `generate_key_pair`: Generate a key pair and return the private key as PKCS#8 DER and public key as SPKI DER.
- `verify_key_pair`: Verify that a PKCS#8 private key matches an SPKI public key by signing and verifying sample data.
- `certificate_matches_key`: Check whether an X.509 certificate public key matches supplied public key bytes or a PKCS#8 private key.
- `parse_certificate`: Parse an X.509 certificate with CertGadgets and return its structure, details, and CDP/AIA/OCSP network plans without network access.
- `fetch_certificate_network_resources`: Fetch HTTP(S) CDP/AIA/OCSP-related resources discovered in an X.509 certificate. This tool performs external network access through an SSRF-aware fetch layer that blocks private, loopback, link-local, reserved, and non-default-port targets.
- `create_csr`: Create a PKCS#10 certificate signing request from a private key, public key, and subject DN.
- `create_self_signed_certificate`: Create a self-signed X.509 certificate from a private key, public key, and subject DN.
- `read_pkcs12`: Read PKCS#12/PFX data and return contained private keys, public keys, and certificates.
- `write_pkcs12`: Create PKCS#12/PFX data from private keys and optional certificates.

Input is string-based. Use `format: "auto"` to let PkiStudioJS detect the input, or provide one of `der`, `ber`, `pem`, `base64`, `headerless-pem`, or `hex`.

## Development

```sh
npm install
npm run check
```

Run the server locally:

```sh
npm run build
node dist/index.js
```

Run the Streamable HTTP server locally:

```sh
npm run build
node dist/http.js
```

The HTTP MCP endpoint defaults to `http://127.0.0.1:3000/mcp`, and health checks are available at `http://127.0.0.1:3000/healthz`. Configure the MCP endpoint path with `PKISTUDIOMCP_HTTP_PATH`, and configure the bind address with `PKISTUDIOMCP_HTTP_HOST` and `PKISTUDIOMCP_HTTP_PORT`.

Run the published Docker image:

```sh
docker run --rm -p 3000:3000 pkistudio/pkistudiomcp:latest
```

The Docker image starts the Streamable HTTP server by default. Its MCP endpoint is `http://127.0.0.1:3000/mcp`, and its health check is `http://127.0.0.1:3000/healthz`.

Pin a release version when reproducibility matters:

```sh
docker run --rm -p 3000:3000 pkistudio/pkistudiomcp:0.4.0
```

To run the stdio server from the image instead:

```sh
docker run --rm -i pkistudio/pkistudiomcp:latest node dist/index.js
```

During development, you can also run the TypeScript entry point directly:

```sh
npm run dev
```

For HTTP development:

```sh
npm run dev:http
```

## MCP Client Configuration

From a local checkout:

```json
{
	"mcpServers": {
		"pkistudio": {
			"command": "node",
			"args": ["/absolute/path/to/pkistudiomcp/dist/index.js"]
		}
	}
}
```

After the package is published to npm:

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

Publish the scoped package publicly:

```sh
npm publish --provenance --access public
```

Until npm publication, GitHub installation can be tested with npm-compatible clients that accept GitHub package specs:

```sh
npx github:pkistudio/pkistudiomcp
```

## Example Tool Input

```json
{
	"data": "3003020101",
	"format": "hex"
}
```
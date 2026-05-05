# @pkistudio/pkistudiomcp

`@pkistudio/pkistudiomcp` is a local stdio MCP server that exposes PkiStudioJS ASN.1 tools and PKI key material helpers as MCP tools.

The package currently depends on PkiStudioJS directly from GitHub and uses key material recognition logic adapted from the Private Key Gadgets core API:

```json
{
	"dependencies": {
		"pkistudiojs": "github:pkistudio/pkistudiojs#v0.2.5"
	}
}
```

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
- `verify_key_pair`: Verify that a PKCS#8 private key matches an SPKI public key by signing and verifying sample data.
- `certificate_matches_key`: Check whether an X.509 certificate public key matches supplied public key bytes or a PKCS#8 private key.

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

During development, you can also run the TypeScript entry point directly:

```sh
npm run dev
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
			"args": ["@pkistudio/pkistudiomcp"]
		}
	}
}
```

Publish the scoped package publicly:

```sh
npm publish --access public
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
# pkistudiomcp

`pkistudiomcp` is a local stdio MCP server that exposes the PkiStudioJS Core API as MCP tools for ASN.1 inspection.

The package currently depends on PkiStudioJS directly from GitHub:

```json
{
	"dependencies": {
		"pkistudiojs": "github:pkistudio/pkistudiojs"
	}
}
```

## Tools

- `parse_asn1`: Parse DER, BER, PEM, HEX, base64, or headerless PEM input and return a JSON ASN.1 tree.
- `summarize_asn1`: Return a compact summary with tag counts, discovered OIDs, and top-level nodes.
- `describe_node`: Describe one parsed ASN.1 node by node id.
- `resolve_oid`: Resolve an OID using the OID names bundled with PkiStudioJS.

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
			"args": ["pkistudiomcp"]
		}
	}
}
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
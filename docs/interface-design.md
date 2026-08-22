# MCP Interface Design

## 1. Public Interfaces

The same MCP server definition is exposed through two transports.

| Transport | Command | Intended use |
| --- | --- | --- |
| stdio | `pkistudiomcp` | Local VS Code, GitHub Copilot, Claude Desktop, and similar clients |
| Streamable HTTP | `pkistudiomcp-http` | Containers, local HTTP, and managed remote deployments |

The MCP server identifies itself as `@pkistudio/pkistudiomcp`, currently at version `0.7.2`. Every tool result is returned as a JSON string in MCP text content.

## 2. Common Input and Output Conventions

### 2.1 Input Validation

- Zod validates required properties, enum values, string lengths, and numeric bounds at the MCP boundary.
- The default input format for ASN.1, certificate, and key material is generally `auto`.
- Tools with configurable output encoding accept `hex` or `base64`.
- Cross-field requirements such as `definition` versus `schema` are also checked in the adapters.

### 2.2 Results

Successful domain results are serialized as JSON. Operations that return binary values commonly use the following shape:

```json
{
  "length": 123,
  "encoding": "base64",
  "data": "..."
}
```

Where full bytes are omitted by default, such as on certificate tree nodes, the response returns the length and a short hexadecimal preview instead.

### 2.3 Errors

Input schema violations become MCP SDK tool-input errors. Exceptions thrown by domain adapters also propagate to the SDK boundary. If an unhandled exception reaches the HTTP entry point, it returns `500 {"error":"Internal server error"}` if the response has not started and writes details to standard error.

## 3. Tool Catalog

The current implementation registers 28 tools.

| Category | Tool | Primary purpose | External network |
| --- | --- | --- | --- |
| ASN.1 inspection | `parse_asn1` | Convert DER/BER/PEM/Hex/Base64 to a JSON tree | No |
| ASN.1 inspection | `summarize_asn1` | Summarize tag counts, OIDs, and top-level nodes | No |
| ASN.1 inspection | `describe_node` | Describe one node by node ID | No |
| ASN.1 inspection | `extract_asn1_node` | Extract DER for a node and its descendants | No |
| ASN.1 inspection | `normalize_asn1_input` | Return re-encoded data and round-trip equality | No |
| ASN.1 inspection | `asn1_node_value` | Return a display value and value octets | No |
| OID | `encode_oid` | Convert dotted OID text to value octets | No |
| OID | `decode_oid_value` | Convert value octets to dotted OID text | No |
| OID | `resolve_oid` | Resolve an OID name from the bundled dictionary | No |
| ASN.1 generation | `parse_asn1_definition` | Convert supported ASN.1 definitions to Schema Model JSON | No |
| ASN.1 generation | `validate_asn1_schema` | Validate a definition or Schema Model | No |
| ASN.1 generation | `validate_asn1_instance` | Validate a JSON instance against a selected type | No |
| ASN.1 generation | `create_asn1_instance` | Generate DER from an ASN.1 definition and JSON | No |
| ASN.1 generation | `list_asn1_builder_features` | List supported syntax, input shapes, and limitations | No |
| Type identification | `sift_asn1_definition_candidates` | Rank types from custom definitions or a built-in corpus | No |
| Type identification | `sift_pki_asn1_definition_candidates` | Rank types with PKI profile filtering | No |
| Type identification | `list_asn1_definition_sifter_features` | List profiles and report options | No |
| Keys | `recognize_key_material` | Recognize PKCS#8/SPKI key type and capabilities | No |
| Keys | `list_supported_key_algorithms` | List key algorithms available in the current runtime | No |
| Keys | `generate_key_pair` | Generate a key pair and return PKCS#8/SPKI | No |
| Keys | `verify_key_pair` | Match a private and public key by signing and verification | No |
| Keys/certificates | `certificate_matches_key` | Match a certificate to a private or public key | No |
| Certificates | `parse_certificate` | Parse X.509 structure, details, and network plans | No |
| Certificates | `fetch_certificate_network_resources` | Retrieve certificate-related CDP/AIA/OCSP resources | Yes |
| CSR/certificates | `create_csr` | Generate a PKCS#10 CSR | No |
| CSR/certificates | `create_self_signed_certificate` | Generate a self-signed X.509 certificate | No |
| PKCS#12 | `read_pkcs12` | Read keys and certificates from PFX | No |
| PKCS#12 | `write_pkcs12` | Generate PFX from keys and certificates | No |

## 4. Design by Tool Category

### 4.1 ASN.1 Inspection and OIDs

The intended workflow starts with `summarize_asn1` for an overview, then uses `parse_asn1` to obtain node IDs and the node-specific tools for focused inspection. Because the server does not persist node IDs, callers resend the original data and format to subsequent tools.

The `roundTrip` value from `normalize_asn1_input` means the input bytes exactly match the bytes produced after parsing and re-encoding. It is not a general proof that two ASN.1 encodings are semantically equivalent.

### 4.2 ASN.1 Instance Builder

Input is either an ASN.1 definition string or Schema Model JSON. Supported behavior includes primitive types, SEQUENCE/SET/CHOICE, OF types, defined-type references, and low-number context-specific tags. Known unsupported areas include constraints, extension markers, parameterized types, value assignments, macros, full module IMPORTS, and high-tag-number forms. `list_asn1_builder_features` is the runtime source of truth for the complete list.

Generation follows this sequence:

1. Read the definition or Schema Model.
2. Run schema diagnostics.
3. Run instance diagnostics.
4. Generate DER only if no errors are present.
5. Optionally add a compact summary of the generated DER.

Some diagnostic failures are returned as results containing `hasErrors` and diagnostic arrays instead of being thrown as exceptions.

### 4.3 ASN.1 Definition Sifter

Candidate identification is a ranking with scores, evidence, diagnostics, and ambiguity notes, not a definitive type decision. The built-in PKI corpus can be filtered with the `components`, `x509`, `pkcs10`, `pkcs8`, and `cms` profiles. Additional reports for child TLVs are bounded by count and depth.

### 4.4 Keys, CSRs, Certificates, and PKCS#12

- Available key-generation algorithms depend on the runtime WebCrypto implementation and can be checked with `list_supported_key_algorithms` before generation.
- `certificate_matches_key` requires at least one private or public key. If both are provided, the SPKI comparison using the public key takes precedence.
- The default hash for CSR and self-signed certificate generation is `SHA-256`.
- A self-signed certificate defaults to a 365-day validity period and the Key Usages `digitalSignature`, `keyCertSign`, and `cRLSign`.
- `read_pkcs12` includes private key bytes in its result, so callers must handle the output as sensitive data.

### 4.5 Certificate Network Resources

Parsing and network access are intentionally separate.

- `parse_certificate`: returns CDP/AIA/OCSP URLs and retrieval plans without network access.
- `fetch_certificate_network_resources`: selects plans with `resourceKinds`, `urls`, and `maxResources`, then performs retrieval.

Retrieval defaults are 10 seconds, 1 MiB per resource, and at most ten resources. MCP schema maxima are 60 seconds, 10 MiB, and 50 resources. An OCSP plan without request bytes is returned as a skipped result.

## 5. Workflow Prompts

Three MCP prompts are registered.

| Prompt | Purpose | Primary controls |
| --- | --- | --- |
| `inspect_certificate` | Step-by-step certificate inspection | Whether to include ASN.1 detail and allow external retrieval |
| `compare_certificate_and_key` | Certificate and key matching | Recognition and matching flow based on key type |
| `analyze_pkcs12` | PFX content analysis | Whether to inspect certificates in detail and verify key relationships |

Prompt boolean arguments are received as MCP SDK strings. Extra steps are enabled only when the value is exactly `"true"`. Prompts are guidance for an AI assistant; they do not themselves enforce tool permissions or network policy.

## 6. HTTP Protocol Boundary

| Path | Authentication | Response |
| --- | --- | --- |
| Configured MCP path (default `/mcp`) | Required only when a Bearer token is configured | Streamable HTTP MCP |
| `/healthz` | None | `200 {"ok":true}` |
| `/readyz` | None | `200 {"ok":true}` |
| Any other path | None | `404 {"error":"Not found"}` |

OPTIONS requests receive a 204 CORS preflight response. Allowed methods are `GET, POST, DELETE, OPTIONS`; allowed headers are `Authorization, Content-Type, Mcp-Session-Id, Last-Event-ID`.

## 7. Compatibility and Change Rules

- Treat removal or semantic changes to tool names, required properties, enum values, defaults, or result fields as breaking changes.
- Prefer adding new options as optional properties while preserving existing defaults.
- Keep the server version in `src/index.ts` aligned with `package.json` and `package-lock.json`.
- When adding or changing a tool, update README Tool Areas, the Wiki Tool Guide, relevant design documents, and smoke coverage.
- If a new capability performs network access, state that in the tool description, prompts, and security design, and keep it separate from local processing.

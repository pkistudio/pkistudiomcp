# Testing Strategy

## 1. Purpose

The current test suite is centered on fast smoke coverage. It verifies that the project builds on supported Node.js versions, core PKI operations work from the distributable JavaScript output, and the npm package contains the expected files.

## 2. Local Validation Commands

| Command | Behavior |
| --- | --- |
| `npm run build` | Removes `dist`, compiles TypeScript into `dist`, and makes the CLI files executable |
| `npm run check` | Builds and then checks `dist/index.js` syntax with `node --check` |
| `npm run smoke` | Builds and then runs `scripts/smoke-test.mjs` |
| `npm run test` | Runs check followed by the smoke test |
| `npm pack --dry-run` | Previews the npm package contents |

Run the following for normal changes:

```sh
npm run test
```

For releases, dependency updates, or package layout changes, also run:

```sh
npm pack --dry-run
```

## 3. Current Smoke Coverage

`scripts/smoke-test.mjs` runs against the built `dist` output.

| Area | Behavior currently covered |
| --- | --- |
| ASN.1 parsing | Parsing a simple SEQUENCE containing an INTEGER |
| ASN.1 Builder | Definition parsing, duplicate-field diagnostics, invalid-instance diagnostics, DER generation, and summary |
| ASN.1 Definition Sifter | Finding `AlgorithmIdentifier` through both the PKI corpus and a custom definition |
| Keys | Generating an RSA 2048 key pair and verifying the private/public key relationship |
| CSR | Generating a CSR containing a Subject DN |
| Self-signed certificate | Generating a certificate valid for 30 days |
| Certificate/key matching | Matching the generated certificate to its public key |
| Certificate parsing | Verifying that the generated certificate root is of kind `certificate` |
| Network plans | Confirming zero fetches for a generated certificate with no resource URLs |
| SSRF protection | Rejecting an HTTP request to `127.0.0.1` |
| PKCS#12 | Writing a key and certificate to PFX, then reading it back and finding one key |

Cryptographic material is generated during the test. No fixed private key is stored in the repository.

## 4. CI Matrix

GitHub Actions CI runs the same `npm run test` and `npm pack --dry-run` commands on Node.js 20, 22, and 24. This validates the minimum version declared in `package.json` and type/WebCrypto compatibility across current runtimes.

The npm release workflow repeats check, smoke, and package preview on Node.js 24 before publication.

## 5. Validation by Change Type

| Change | Required validation |
| --- | --- |
| MCP tool or Zod schema | `npm run test`, representative valid and invalid input, and tool listing/description review |
| ASN.1 parsing or OID | Multiple input formats, node-ID operations, limits, and known/unknown OIDs |
| ASN.1 Builder | Successful generation, schema diagnostics, instance diagnostics, and known unsupported syntax |
| Definition Sifter | Built-in/custom corpora, profiles, no-candidate cases, and child-TLV limits |
| Keys, CSR, or certificates | Supported algorithms, key mismatch, malformed DER, DN handling, validity, and Key Usage boundaries |
| PKCS#12 | Correct/incorrect passwords, multiple keys, with/without certificates, and input/output formats |
| `safe-fetch` | IP classification, DNS, ports, redirects, size limits, timeouts, and GET/POST |
| HTTP boundary | MCP requests, OPTIONS, authentication, CORS, 404, 413, 500, health/readiness, and shutdown |
| Dockerfile | Local build, non-root execution, health check, and both stdio/HTTP startup modes |
| Dependency update | `npm run test`, `npm pack --dry-run`, and review of supported behavior in README, Wiki, and design docs |

## 6. Known Testing Gaps

The current smoke test does not directly cover:

- Listing and invoking tools, or listing the three prompts, through a stdio MCP client
- Streamable HTTP MCP request handling
- Bearer authentication, CORS, Content-Length checks, request timeout, 404, or health/readiness routes
- Successful external HTTP retrieval, OCSP POST, redirects, oversized responses, or timeouts
- Each rejected IPv4/IPv6 range or multiple DNS answers
- The individual OID encode, decode, and resolve tools
- Every input format and output encoding
- Every supported key algorithm and runtime-specific differences
- Error contracts for malformed certificates, PFX, and ASN.1 data
- Concurrent HTTP requests, load behavior, or CPU/memory limits
- End-to-end Docker image and Azure deployment behavior

When changing the HTTP or security boundary, prioritize adding automated coverage for the affected gaps.

## 7. Test Design Guidelines

- Validate the public MCP contract through an MCP SDK client in addition to testing adapters directly.
- Avoid dependence on public external sites in network tests. Use a deliberately controlled test server and DNS strategy.
- If private keys or PFX files are committed as fixtures, mark them clearly as test-only. Prefer runtime generation as the current suite does.
- Cover input limits, malformed bytes, mismatches, timeouts, and partial failures as well as successful cases.
- Prefer explicit assertions on compatibility-critical fields and semantics over complete JSON snapshot locking.
- Keep the Node.js 20, 22, and 24 CI matrix. If the minimum supported version changes, update package metadata and documentation together.

## 8. Documentation Validation

When the design changes, verify mechanically or through review that:

- Every link from `docs/README.md` resolves.
- Tool count, tool names, and prompt names match `src/index.ts`.
- HTTP environment variables and defaults match `src/http.ts`.
- Network limits and SSRF protections match `src/certificates.ts` and `src/safe-fetch.ts`.
- Node.js, npm, Docker, and Azure descriptions match `package.json`, `Dockerfile`, and GitHub Actions.
- User-facing changes are reflected in the README and [GitHub Wiki](https://github.com/pkistudio/pkistudiomcp/wiki).

import assert from "node:assert/strict";

import {
  createAsn1Instance,
  parseAsn1DefinitionTool,
  validateAsn1Schema,
  validateAsn1Instance,
} from "../dist/asn1-builder.js";
import {
  certificateMatchesKey,
  createCsr,
  createSelfSignedCertificate,
  generateKeyPair,
  readPkcs12,
  verifyKeyPair,
  writePkcs12,
} from "../dist/key-material.js";
import { fetchCertificateNetworkResources, parseCertificate } from "../dist/certificates.js";
import { parseAsn1 } from "../dist/pkistudio.js";
import { safeFetchBytes } from "../dist/safe-fetch.js";

const parsed = parseAsn1({ data: "3003020101", format: "hex" });
assert.equal(parsed.nodes[0]?.tagName, "SEQUENCE");

const builderDefinition = "Example DEFINITIONS ::= BEGIN Person ::= SEQUENCE { name UTF8String, age INTEGER OPTIONAL } END";
const parsedDefinition = parseAsn1DefinitionTool({ definition: builderDefinition });
assert.equal(parsedDefinition.moduleName, "Example");
assert.deepEqual(parsedDefinition.typeNames, ["Person"]);

const invalidSchema = validateAsn1Schema({
  definition: "Broken DEFINITIONS ::= BEGIN Item ::= SEQUENCE { value INTEGER, value UTF8String } END",
});
assert.equal(invalidSchema.hasErrors, true);
assert.equal(invalidSchema.schemaDiagnostics[0]?.code, "duplicate-field");

const invalidInstance = validateAsn1Instance({
  definition: builderDefinition,
  typeName: "Person",
  input: { age: "not an integer" },
});
assert.equal(invalidInstance.hasErrors, true);
assert.equal(invalidInstance.instanceDiagnostics[0]?.code, "missing-field");

const createdInstance = createAsn1Instance({
  definition: builderDefinition,
  typeName: "Person",
  input: { name: "Alice", age: 42 },
  includeDerSummary: true,
});
assert.equal(createdInstance.built, true);
assert.equal(createdInstance.data, "300a0c05416c69636502012a");
assert.equal(createdInstance.derSummary?.topLevelNodes[0]?.tagName, "SEQUENCE");

const generated = await generateKeyPair({ algorithm: "rsassa-pkcs1-v1_5-2048", encoding: "base64" });
assert.equal(generated.keyInfo.label, "RSA 2048");

const privateKey = generated.privateKey.data;
const publicKey = generated.publicKey.data;

const verified = await verifyKeyPair({
  privateKey,
  privateKeyFormat: "base64",
  publicKey,
  publicKeyFormat: "base64",
});
assert.equal(verified.matches, true);

const csr = await createCsr({
  privateKey,
  privateKeyFormat: "base64",
  publicKey,
  publicKeyFormat: "base64",
  subjectDn: "CN=example.com, O=Example, C=JP",
  encoding: "base64",
});
assert.ok(csr.length > 0);

const certificate = await createSelfSignedCertificate({
  privateKey,
  privateKeyFormat: "base64",
  publicKey,
  publicKeyFormat: "base64",
  subjectDn: "CN=example.com, O=Example, C=JP",
  validityDays: 30,
  encoding: "base64",
});
assert.ok(certificate.length > 0);

const certificateMatch = await certificateMatchesKey({
  certificate: certificate.data,
  certificateFormat: "base64",
  publicKey,
  publicKeyFormat: "base64",
});
assert.equal(certificateMatch.matches, true);

const parsedCertificate = parseCertificate({ data: certificate.data, format: "base64" });
assert.equal(parsedCertificate.document.root.kind, "certificate");

const networkResources = await fetchCertificateNetworkResources({ data: certificate.data, format: "base64" });
assert.equal(networkResources.fetchedCount, 0);

await assert.rejects(
  safeFetchBytes("http://127.0.0.1/", { timeoutMs: 1000, maxBytes: 1024 }),
  /public IP address/,
);

const pkcs12 = await writePkcs12({
  keys: [
    {
      label: "example",
      privateKey,
      privateKeyFormat: "base64",
      certificate: certificate.data,
      certificateFormat: "base64",
    },
  ],
  password: "secret",
  encoding: "base64",
});
assert.ok(pkcs12.length > 0);

const imported = await readPkcs12({
  data: pkcs12.data,
  password: "secret",
  format: "base64",
});
assert.equal(imported.keyCount, 1);
assert.equal(imported.keys[0]?.label, "example");

console.log(JSON.stringify({
  asn1: parsed.nodes[0]?.tagName,
  key: generated.keyInfo.label,
  verified: verified.matches,
  csrLength: csr.length,
  certificateMatches: certificateMatch.matches,
  certificateRoot: parsedCertificate.document.root.kind,
  asn1BuilderDer: createdInstance.data,
  pkcs12Length: pkcs12.length,
  importedKeys: imported.keyCount,
}));

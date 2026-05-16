import assert from "node:assert/strict";

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
  pkcs12Length: pkcs12.length,
  importedKeys: imported.keyCount,
}));

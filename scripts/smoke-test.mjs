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
import { parseAsn1 } from "../dist/pkistudio.js";

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
  pkcs12Length: pkcs12.length,
  importedKeys: imported.keyCount,
}));

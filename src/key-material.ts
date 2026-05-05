import * as asn1js from "asn1js";
import { AttributeTypeAndValue, BasicConstraints, Certificate, CertificationRequest, Extension, RelativeDistinguishedNames, Time } from "pkijs";

import { readPkcs12Keys, writePkcs12Keys } from "./pkcs12.js";
import { decodeInputBytes, encodeOutputBytes } from "./pkistudio.js";

type InputFormat = "auto" | "der" | "ber" | "pem" | "base64" | "headerless-pem" | "hex";
type OutputEncoding = "hex" | "base64";
type Asn1Node = ReturnType<typeof asn1js.fromBER>["result"];

type RecognizedKeyInfo = {
  family: "RSA" | "EC" | "Ed25519" | "Ed448" | "X25519" | "X448" | "Unknown";
  label: string;
  canSign: boolean;
  canDerive: boolean;
  namedCurve?: string;
};

type KeyAlgorithmCandidate = {
  id: string;
  canonicalId: string;
  canonicalLabel: string;
  algorithm: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  usages: KeyUsage[];
};

type MaterialInput = {
  data: string;
  format?: InputFormat;
};

type RecognizeInput = MaterialInput & {
  kind: "private" | "public";
};

type GenerateKeyPairInput = {
  algorithm: string;
  label?: string;
  encoding?: OutputEncoding;
};

type VerifyKeyPairInput = {
  privateKey: string;
  privateKeyFormat?: InputFormat;
  publicKey: string;
  publicKeyFormat?: InputFormat;
};

type CertificateMatchesKeyInput = {
  certificate: string;
  certificateFormat?: InputFormat;
  privateKey?: string;
  privateKeyFormat?: InputFormat;
  publicKey?: string;
  publicKeyFormat?: InputFormat;
  encoding?: OutputEncoding;
};

type CreateCsrInput = {
  privateKey: string;
  privateKeyFormat?: InputFormat;
  publicKey: string;
  publicKeyFormat?: InputFormat;
  subjectDn: string;
  hashAlgorithm?: "SHA-256" | "SHA-384" | "SHA-512";
  encoding?: OutputEncoding;
};

type CreateSelfSignedCertificateInput = CreateCsrInput & {
  validityDays?: number;
  keyUsages?: string[];
};

type ReadPkcs12Input = {
  data: string;
  password: string;
  format?: InputFormat;
  sourceName?: string;
  encoding?: OutputEncoding;
};

type WritePkcs12Input = {
  keys: Array<{
    label?: string;
    privateKey: string;
    privateKeyFormat?: InputFormat;
    certificate?: string;
    certificateFormat?: InputFormat;
  }>;
  password: string;
  encoding?: OutputEncoding;
};

type CertificateKeyUsage = {
  id: string;
  label: string;
  bit: number;
  defaultChecked?: boolean;
};

const CERTIFICATE_KEY_USAGES: CertificateKeyUsage[] = [
  { id: "digitalSignature", label: "digitalSignature", bit: 0 },
  { id: "nonRepudiation", label: "nonRepudiation", bit: 1 },
  { id: "keyEncipherment", label: "keyEncipherment", bit: 2 },
  { id: "dataEncipherment", label: "dataEncipherment", bit: 3 },
  { id: "keyAgreement", label: "keyAgreement", bit: 4 },
  { id: "keyCertSign", label: "certSign", bit: 5, defaultChecked: true },
  { id: "cRLSign", label: "crlSign", bit: 6, defaultChecked: true },
  { id: "encipherOnly", label: "encipherOnly", bit: 7 },
  { id: "decipherOnly", label: "decipherOnly", bit: 8 },
];

const KEY_ALGORITHM_CANDIDATES: KeyAlgorithmCandidate[] = [
  ...createRsaCandidates("RSASSA-PKCS1-v1_5", "SHA-256", ["sign", "verify"]),
  ...createRsaCandidates("RSA-PSS", "SHA-256", ["sign", "verify"]),
  ...createRsaCandidates("RSA-OAEP", "SHA-256", ["encrypt", "decrypt"]),
  ...createNamedCurveCandidates("ECDSA", ["P-256", "P-384", "P-521"], ["sign", "verify"]),
  ...createNamedCurveCandidates("ECDH", ["P-256", "P-384", "P-521"], ["deriveBits"]),
  ...createNamedCurveCandidates("Ed25519", ["Ed25519"], ["sign", "verify"]),
  ...createNamedCurveCandidates("Ed448", ["Ed448"], ["sign", "verify"]),
  ...createNamedCurveCandidates("X25519", ["X25519"], ["deriveBits"]),
  ...createNamedCurveCandidates("X448", ["X448"], ["deriveBits"]),
];

export async function listSupportedKeyAlgorithms() {
  const results = await Promise.all(
    KEY_ALGORITHM_CANDIDATES.map(async (candidate) => ({
      candidate,
      supported: await isKeyAlgorithmSupported(candidate),
    })),
  );

  const uniqueSupportedAlgorithms = new Map<string, KeyAlgorithmCandidate>();
  for (const result of results) {
    if (!result.supported || uniqueSupportedAlgorithms.has(result.candidate.canonicalId)) continue;
    uniqueSupportedAlgorithms.set(result.candidate.canonicalId, result.candidate);
  }

  return {
    algorithms: [...uniqueSupportedAlgorithms.values()].map(describeKeyAlgorithmCandidate),
  };
}

export async function generateKeyPair(input: GenerateKeyPairInput) {
  const candidate = getGenerationOptions(input.algorithm);
  const generated = await crypto.subtle.generateKey(candidate.algorithm, true, candidate.usages);
  if (!isCryptoKeyPair(generated)) throw new Error("The runtime did not return a key pair.");

  const [privateKeyBuffer, publicKeyBuffer] = await Promise.all([
    crypto.subtle.exportKey("pkcs8", generated.privateKey),
    crypto.subtle.exportKey("spki", generated.publicKey),
  ]);
  const privateKeyDer = new Uint8Array(privateKeyBuffer);
  const publicKeyDer = new Uint8Array(publicKeyBuffer);
  const keyInfo = recognizeMaterial({ privateKeyDer, publicKeyDer });
  const encoding = input.encoding ?? "hex";

  return {
    algorithm: describeKeyAlgorithmCandidate(candidate),
    label: input.label || keyInfo.label,
    keyInfo,
    privateKey: {
      encoding,
      length: privateKeyDer.length,
      data: encodeOutputBytes(privateKeyDer, encoding),
    },
    publicKey: {
      encoding,
      length: publicKeyDer.length,
      data: encodeOutputBytes(publicKeyDer, encoding),
    },
  };
}

export function recognizeKeyMaterial(input: RecognizeInput) {
  const decoded = decodeInputBytes(input.data, input.format);
  const info = input.kind === "public" ? recognizePublicKey(decoded.bytes) : recognizePrivateKey(decoded.bytes);

  return {
    kind: input.kind,
    sourceFormat: decoded.format,
    length: decoded.bytes.length,
    ...info,
  };
}

export async function verifyKeyPair(input: VerifyKeyPairInput) {
  const privateKey = decodeInputBytes(input.privateKey, input.privateKeyFormat);
  const publicKey = decodeInputBytes(input.publicKey, input.publicKeyFormat);
  const info = recognizeMaterial({ privateKeyDer: privateKey.bytes, publicKeyDer: publicKey.bytes });
  const matches = await verifyPrivateKeyMatchesPublicKey(privateKey.bytes, publicKey.bytes, info);

  return {
    matches,
    privateKeyFormat: privateKey.format,
    publicKeyFormat: publicKey.format,
    privateKeyLength: privateKey.bytes.length,
    publicKeyLength: publicKey.bytes.length,
    keyInfo: info,
  };
}

export async function certificateMatchesKey(input: CertificateMatchesKeyInput) {
  if (!input.privateKey && !input.publicKey) {
    throw new Error("privateKey or publicKey is required.");
  }

  const certificate = decodeInputBytes(input.certificate, input.certificateFormat);
  const certificatePublicKeyDer = getCertificatePublicKeyDer(certificate.bytes);
  const certificatePublicKeyInfo = recognizePublicKey(certificatePublicKeyDer) ?? createRecognizedKeyInfo("Unknown", "Unknown");
  const publicKey = input.publicKey ? decodeInputBytes(input.publicKey, input.publicKeyFormat) : undefined;
  const privateKey = input.privateKey ? decodeInputBytes(input.privateKey, input.privateKeyFormat) : undefined;
  const keyInfo = recognizeMaterial({ privateKeyDer: privateKey?.bytes, publicKeyDer: publicKey?.bytes });
  const matches = publicKey
    ? bytesEqual(publicKey.bytes, certificatePublicKeyDer)
    : await verifyPrivateKeyMatchesPublicKey(privateKey?.bytes ?? new Uint8Array(), certificatePublicKeyDer, keyInfo);

  return {
    matches,
    certificateFormat: certificate.format,
    certificateLength: certificate.bytes.length,
    publicKeyFormat: publicKey?.format,
    publicKeyLength: publicKey?.bytes.length,
    privateKeyFormat: privateKey?.format,
    privateKeyLength: privateKey?.bytes.length,
    keyInfo,
    certificatePublicKeyInfo,
    certificatePublicKey: {
      encoding: input.encoding ?? "hex",
      length: certificatePublicKeyDer.length,
      data: encodeOutputBytes(certificatePublicKeyDer, input.encoding),
    },
  };
}

export async function createCsr(input: CreateCsrInput) {
  const privateKey = decodeInputBytes(input.privateKey, input.privateKeyFormat);
  const publicKey = decodeInputBytes(input.publicKey, input.publicKeyFormat);
  const hashAlgorithm = input.hashAlgorithm ?? "SHA-256";
  const info = recognizeMaterial({ privateKeyDer: privateKey.bytes, publicKeyDer: publicKey.bytes });
  if (info.family !== "RSA" && info.family !== "EC") throw new Error(`${info.label} is not supported for CSR signing yet.`);

  const subjectBytes = createSubjectDn(input.subjectDn);
  const subject = parseSubjectDnBytes(subjectBytes);
  const [signingPrivateKey, signingPublicKey] = await Promise.all([
    importSigningPrivateKey(privateKey.bytes, info, hashAlgorithm),
    importSigningPublicKey(publicKey.bytes, info, hashAlgorithm),
  ]);

  const request = new CertificationRequest();
  request.subject = subject;
  await request.subjectPublicKeyInfo.importKey(signingPublicKey);
  request.attributes = [];
  await request.sign(signingPrivateKey, hashAlgorithm);

  const bytes = new Uint8Array(request.toSchema(true).toBER(false));
  return {
    subjectDn: input.subjectDn,
    hashAlgorithm,
    keyInfo: info,
    length: bytes.length,
    encoding: input.encoding ?? "hex",
    data: encodeOutputBytes(bytes, input.encoding),
  };
}

export async function createSelfSignedCertificate(input: CreateSelfSignedCertificateInput) {
  const privateKey = decodeInputBytes(input.privateKey, input.privateKeyFormat);
  const publicKey = decodeInputBytes(input.publicKey, input.publicKeyFormat);
  const hashAlgorithm = input.hashAlgorithm ?? "SHA-256";
  const validityDays = input.validityDays ?? 365;
  const keyUsages = input.keyUsages ?? ["digitalSignature", "keyCertSign", "cRLSign"];
  const info = recognizeMaterial({ privateKeyDer: privateKey.bytes, publicKeyDer: publicKey.bytes });
  if (info.family !== "RSA" && info.family !== "EC") throw new Error(`${info.label} is not supported for certificate signing yet.`);

  const subjectBytes = createSubjectDn(input.subjectDn);
  const subject = parseSubjectDnBytes(subjectBytes);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + validityDays * 24 * 60 * 60 * 1000);
  const [signingPrivateKey, signingPublicKey] = await Promise.all([
    importSigningPrivateKey(privateKey.bytes, info, hashAlgorithm),
    importSigningPublicKey(publicKey.bytes, info, hashAlgorithm),
  ]);

  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({ valueHex: toArrayBuffer(createCertificateSerialNumber()) });
  certificate.issuer = subject;
  certificate.subject = subject;
  certificate.notBefore = new Time({ type: 0, value: notBefore });
  certificate.notAfter = new Time({ type: 0, value: notAfter });
  await certificate.subjectPublicKeyInfo.importKey(signingPublicKey);
  certificate.extensions = createSelfSignedCertificateExtensions(keyUsages);
  await certificate.sign(signingPrivateKey, hashAlgorithm);

  const bytes = new Uint8Array(certificate.toSchema(true).toBER(false));
  return {
    subjectDn: input.subjectDn,
    hashAlgorithm,
    validityDays,
    keyUsages,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    keyInfo: info,
    length: bytes.length,
    encoding: input.encoding ?? "hex",
    data: encodeOutputBytes(bytes, input.encoding),
  };
}

export async function readPkcs12(input: ReadPkcs12Input) {
  const decoded = decodeInputBytes(input.data, input.format);
  const keys = await readPkcs12Keys(decoded.bytes, input.password, { sourceName: input.sourceName });
  const encoding = input.encoding ?? "hex";

  return {
    sourceFormat: decoded.format,
    keyCount: keys.length,
    keys: keys.map((key) => ({
      id: key.id,
      label: key.label,
      sourceName: key.sourceName,
      keyInfo: recognizeMaterial({ privateKeyDer: key.privateKeyDer, publicKeyDer: key.publicKeyDer }),
      privateKey: {
        encoding,
        length: key.privateKeyDer.length,
        data: encodeOutputBytes(key.privateKeyDer, encoding),
      },
      publicKey: key.publicKeyDer
        ? {
            encoding,
            length: key.publicKeyDer.length,
            data: encodeOutputBytes(key.publicKeyDer, encoding),
          }
        : undefined,
      certificate: key.certificateDer
        ? {
            encoding,
            length: key.certificateDer.length,
            data: encodeOutputBytes(key.certificateDer, encoding),
          }
        : undefined,
    })),
  };
}

export async function writePkcs12(input: WritePkcs12Input) {
  const bytes = await writePkcs12Keys(
    input.keys.map((key) => ({
      label: key.label,
      privateKeyDer: decodeInputBytes(key.privateKey, key.privateKeyFormat).bytes,
      certificateDer: key.certificate ? decodeInputBytes(key.certificate, key.certificateFormat).bytes : undefined,
    })),
    input.password,
  );

  return {
    keyCount: input.keys.length,
    length: bytes.length,
    encoding: input.encoding ?? "hex",
    data: encodeOutputBytes(bytes, input.encoding),
  };
}

function recognizeMaterial(material: { privateKeyDer?: Uint8Array; publicKeyDer?: Uint8Array }): RecognizedKeyInfo {
  return (material.publicKeyDer ? recognizePublicKey(material.publicKeyDer) : null) ||
    (material.privateKeyDer ? recognizePrivateKey(material.privateKeyDer) : createRecognizedKeyInfo("Unknown", "Unknown"));
}

function getGenerationOptions(selection: string): KeyAlgorithmCandidate {
  const supported = KEY_ALGORITHM_CANDIDATES.find((candidate) => candidate.id === selection);
  if (!supported) throw new Error(`Unsupported algorithm: ${selection || "(none selected)"}`);
  return supported;
}

async function isKeyAlgorithmSupported(candidate: KeyAlgorithmCandidate): Promise<boolean> {
  try {
    const generated = await crypto.subtle.generateKey(candidate.algorithm, true, candidate.usages);
    return isCryptoKeyPair(generated);
  } catch {
    return false;
  }
}

function createRsaCandidates(name: string, hash: string, usages: KeyUsage[]): KeyAlgorithmCandidate[] {
  return [2048, 3072, 4096].map((modulusLength) => ({
    id: `${name.toLowerCase()}-${modulusLength}`,
    canonicalId: `rsa-${modulusLength}`,
    canonicalLabel: `RSA ${modulusLength}`,
    algorithm: {
      name,
      modulusLength,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash,
    },
    usages,
  }));
}

function createNamedCurveCandidates(name: string, curves: string[], usages: KeyUsage[]): KeyAlgorithmCandidate[] {
  return curves.map((namedCurve) => ({
    id: name === namedCurve ? name.toLowerCase() : `${name.toLowerCase()}-${namedCurve.toLowerCase()}`,
    canonicalId: name === "ECDSA" || name === "ECDH" ? `ec-${namedCurve.toLowerCase()}` : name.toLowerCase(),
    canonicalLabel: name === "ECDSA" || name === "ECDH" ? `EC ${namedCurve}` : name,
    algorithm: name === namedCurve ? { name } : { name, namedCurve },
    usages,
  }));
}

function isCryptoKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return "privateKey" in value && "publicKey" in value;
}

function describeKeyAlgorithmCandidate(candidate: KeyAlgorithmCandidate) {
  return {
    id: candidate.id,
    canonicalId: candidate.canonicalId,
    label: candidate.canonicalLabel,
    algorithm: candidate.algorithm,
    usages: candidate.usages,
  };
}

function recognizePublicKey(bytes: Uint8Array): RecognizedKeyInfo | null {
  try {
    const root = parseAsn1(bytes);
    const algorithmIdentifier = readSequenceChild(root, 0);
    const { oid, parameters } = parseAlgorithmIdentifier(algorithmIdentifier);

    if (oid === "1.2.840.113549.1.1.1") {
      const bitString = readSequenceChild(root, 1);
      const modulusBits = readRsaPublicKeyBits(bitString);
      return createRecognizedKeyInfo("RSA", modulusBits ? `RSA ${modulusBits}` : "RSA");
    }

    return infoFromAlgorithmIdentifier(oid, parameters);
  } catch {
    return null;
  }
}

function recognizePrivateKey(bytes: Uint8Array): RecognizedKeyInfo {
  try {
    const root = parseAsn1(bytes);
    const algorithmIdentifier = readSequenceChild(root, 1);
    const { oid, parameters } = parseAlgorithmIdentifier(algorithmIdentifier);

    if (oid === "1.2.840.113549.1.1.1") return createRecognizedKeyInfo("RSA", "RSA");
    return infoFromAlgorithmIdentifier(oid, parameters);
  } catch {
    return createRecognizedKeyInfo("Unknown", "Unknown");
  }
}

async function verifyPrivateKeyMatchesPublicKey(privateKeyDer: Uint8Array, publicKeyDer: Uint8Array, info: RecognizedKeyInfo): Promise<boolean> {
  try {
    const data = new TextEncoder().encode("Private Key Gadgets certificate check");
    const algorithm = getKeyPairCheckAlgorithm(info);
    const [privateKey, publicKey] = await Promise.all([
      crypto.subtle.importKey("pkcs8", toArrayBuffer(privateKeyDer), algorithm.importAlgorithm, false, ["sign"]),
      crypto.subtle.importKey("spki", toArrayBuffer(publicKeyDer), algorithm.importAlgorithm, false, ["verify"]),
    ]);
    const signature = await crypto.subtle.sign(algorithm.signAlgorithm, privateKey, data);
    return crypto.subtle.verify(algorithm.signAlgorithm, publicKey, signature, data);
  } catch {
    return false;
  }
}

function getKeyPairCheckAlgorithm(info: RecognizedKeyInfo): {
  importAlgorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  signAlgorithm: AlgorithmIdentifier | EcdsaParams;
} {
  if (info.family === "RSA") {
    const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    return { importAlgorithm: algorithm, signAlgorithm: algorithm };
  }

  if (info.family === "EC" && info.namedCurve) {
    return { importAlgorithm: { name: "ECDSA", namedCurve: info.namedCurve }, signAlgorithm: { name: "ECDSA", hash: "SHA-256" } };
  }

  if (info.family === "Ed25519" || info.family === "Ed448") {
    const algorithm = { name: info.family };
    return { importAlgorithm: algorithm, signAlgorithm: algorithm };
  }

  throw new Error(`${info.label} cannot be checked against a public key.`);
}

async function importSigningPrivateKey(bytes: Uint8Array, info: RecognizedKeyInfo, hashAlgorithm: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", toArrayBuffer(bytes), getSigningKeyAlgorithm(info, hashAlgorithm), false, ["sign"]);
}

async function importSigningPublicKey(bytes: Uint8Array, info: RecognizedKeyInfo, hashAlgorithm: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", toArrayBuffer(bytes), getSigningKeyAlgorithm(info, hashAlgorithm), true, ["verify"]);
}

function getSigningKeyAlgorithm(info: RecognizedKeyInfo, hashAlgorithm: string): RsaHashedImportParams | EcKeyImportParams {
  if (info.family === "RSA") return { name: "RSASSA-PKCS1-v1_5", hash: hashAlgorithm };
  if (info.family === "EC" && info.namedCurve) return { name: "ECDSA", namedCurve: info.namedCurve };
  throw new Error(`${info.label} is not supported for CSR signing yet.`);
}

function createSelfSignedCertificateExtensions(keyUsages: string[]): Extension[] {
  const knownUsages = new Set(CERTIFICATE_KEY_USAGES.map((usage) => usage.id));
  for (const usage of keyUsages) {
    if (!knownUsages.has(usage)) throw new Error(`Unsupported certificate key usage: ${usage}`);
  }

  const selected = new Set(keyUsages);
  const basicConstraints = new BasicConstraints({ cA: selected.has("keyCertSign") });
  const keyUsage = createKeyUsageBitString(selected);

  return [
    new Extension({
      extnID: "2.5.29.19",
      critical: selected.has("keyCertSign"),
      extnValue: basicConstraints.toSchema().toBER(false),
      parsedValue: basicConstraints,
    }),
    new Extension({
      extnID: "2.5.29.15",
      critical: true,
      extnValue: keyUsage.toBER(false),
      parsedValue: keyUsage,
    }),
  ];
}

function createKeyUsageBitString(selected: Set<string>): asn1js.BitString {
  const highestBit = CERTIFICATE_KEY_USAGES.reduce((highest, usage) => selected.has(usage.id) ? Math.max(highest, usage.bit) : highest, 0);
  const value = new Uint8Array(Math.floor(highestBit / 8) + 1);
  for (const usage of CERTIFICATE_KEY_USAGES) {
    if (!selected.has(usage.id)) continue;
    value[Math.floor(usage.bit / 8)] |= 0x80 >> (usage.bit % 8);
  }
  return new asn1js.BitString({ valueHex: toArrayBuffer(value) });
}

function createCertificateSerialNumber(): Uint8Array {
  const serial = new Uint8Array(16);
  crypto.getRandomValues(serial);
  serial[0] &= 0x7f;
  if (serial.every((byte) => byte === 0)) serial[15] = 1;
  return serial;
}

function createSubjectDn(subjectDn: string): Uint8Array {
  const subject = new RelativeDistinguishedNames({ typesAndValues: parseSubjectDn(subjectDn) });
  return new Uint8Array(subject.toSchema().toBER(false));
}

function parseSubjectDnBytes(bytes: Uint8Array): RelativeDistinguishedNames {
  const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
  if (asn1.offset === -1) throw new Error("Invalid SubjectDN DER.");
  if (asn1.offset !== bytes.byteLength) throw new Error("SubjectDN DER has trailing data.");
  return new RelativeDistinguishedNames({ schema: asn1.result });
}

function parseSubjectDn(subjectDn: string): AttributeTypeAndValue[] {
  const parts = splitSubjectDn(subjectDn);
  if (parts.length === 0) throw new Error("subjectDN is required.");

  return [...parts].reverse().map((part) => {
    const separator = findUnescaped(part, "=");
    if (separator <= 0) throw new Error(`Invalid subjectDN part: ${part}`);

    const name = unescapeDnValue(part.slice(0, separator).trim());
    const value = unescapeDnValue(part.slice(separator + 1).trim());
    if (!name || !value) throw new Error(`Invalid subjectDN part: ${part}`);

    return new AttributeTypeAndValue({ type: subjectOid(name), value: subjectValue(name, value) });
  });
}

function splitSubjectDn(subjectDn: string): string[] {
  const trimmed = subjectDn.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("/")) return splitEscaped(trimmed.slice(1), "/");
  return splitEscaped(trimmed, ",");
}

function splitEscaped(value: string, separator: string): string[] {
  const parts: string[] = [];
  let current = "";
  let escaped = false;

  for (const character of value) {
    if (escaped) {
      current += `\\${character}`;
      escaped = false;
      continue;
    }

    if (character === "\\") {
      escaped = true;
      continue;
    }

    if (character === separator) {
      if (current.trim()) parts.push(current.trim());
      current = "";
      continue;
    }

    current += character;
  }

  if (escaped) current += "\\";
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function findUnescaped(value: string, needle: string): number {
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === needle) return index;
  }
  return -1;
}

function unescapeDnValue(value: string): string {
  return value.replace(/\\([,=\\/])/g, "$1");
}

function subjectOid(name: string): string {
  const oids: Record<string, string> = {
    C: "2.5.4.6",
    ST: "2.5.4.8",
    S: "2.5.4.8",
    L: "2.5.4.7",
    O: "2.5.4.10",
    OU: "2.5.4.11",
    CN: "2.5.4.3",
    DC: "0.9.2342.19200300.100.1.25",
    SN: "2.5.4.5",
    SERIALNUMBER: "2.5.4.5",
    EMAILADDRESS: "1.2.840.113549.1.9.1",
  };

  const oid = oids[name.toUpperCase()] ?? (/^\d+(\.\d+)+$/.test(name) ? name : undefined);
  if (!oid) throw new Error(`Unsupported subjectDN attribute: ${name}`);
  return oid;
}

function subjectValue(name: string, value: string): asn1js.Utf8String | asn1js.PrintableString | asn1js.IA5String {
  const normalized = name.toUpperCase();
  if (normalized === "C") return new asn1js.PrintableString({ value });
  if (normalized === "EMAILADDRESS" || normalized === "DC") return new asn1js.IA5String({ value });
  return new asn1js.Utf8String({ value });
}

function getCertificatePublicKeyDer(certificateDer: Uint8Array): Uint8Array {
  const certificate = parseAsn1(certificateDer);
  const tbsCertificate = readSequenceChild(certificate, 0);
  const children = readChildren(tbsCertificate);
  const hasVersion = isContextSpecific(children[0], 0);
  const subjectPublicKeyInfo = children[hasVersion ? 6 : 5];
  if (!subjectPublicKeyInfo) throw new Error("Certificate subjectPublicKeyInfo was not found.");
  return new Uint8Array(subjectPublicKeyInfo.toBER(false));
}

function infoFromAlgorithmIdentifier(oid: string, parameters: string | null): RecognizedKeyInfo {
  if (oid === "1.2.840.10045.2.1") {
    const namedCurve = parameters ? curveNameFromOid(parameters) : undefined;
    return createRecognizedKeyInfo("EC", namedCurve ? `EC ${namedCurve}` : "EC", namedCurve);
  }

  if (oid === "1.3.101.112") return createRecognizedKeyInfo("Ed25519", "Ed25519");
  if (oid === "1.3.101.113") return createRecognizedKeyInfo("Ed448", "Ed448");
  if (oid === "1.3.101.110") return createRecognizedKeyInfo("X25519", "X25519");
  if (oid === "1.3.101.111") return createRecognizedKeyInfo("X448", "X448");

  return createRecognizedKeyInfo("Unknown", `Unknown (${oid})`);
}

function createRecognizedKeyInfo(family: RecognizedKeyInfo["family"], label: string, namedCurve?: string): RecognizedKeyInfo {
  return {
    family,
    label,
    canSign: family === "RSA" || family === "EC" || family === "Ed25519" || family === "Ed448",
    canDerive: family === "EC" || family === "X25519" || family === "X448",
    namedCurve,
  };
}

function parseAsn1(bytes: Uint8Array): Asn1Node {
  const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
  if (asn1.offset === -1) throw new Error("Invalid DER.");
  if (asn1.offset !== bytes.byteLength) throw new Error("DER has trailing data.");
  return asn1.result;
}

function readSequenceChild(node: Asn1Node, index: number): Asn1Node {
  const child = readChildren(node)[index];
  if (!child) throw new Error("Missing ASN.1 sequence child.");
  return child;
}

function readChildren(node: Asn1Node): Asn1Node[] {
  const valueBlock = node.valueBlock as { value?: Asn1Node[] };
  return Array.isArray(valueBlock.value) ? valueBlock.value : [];
}

function parseAlgorithmIdentifier(node: Asn1Node): { oid: string; parameters: string | null } {
  const children = readChildren(node);
  const oidNode = children[0];
  if (!(oidNode instanceof asn1js.ObjectIdentifier)) throw new Error("Missing algorithm OID.");

  const parameterNode = children[1];
  return {
    oid: oidNode.valueBlock.toString(),
    parameters: parameterNode instanceof asn1js.ObjectIdentifier ? parameterNode.valueBlock.toString() : null,
  };
}

function readRsaPublicKeyBits(bitStringNode: Asn1Node): number | null {
  if (!(bitStringNode instanceof asn1js.BitString)) return null;
  const valueBlock = bitStringNode.valueBlock as { valueHexView?: Uint8Array };
  const rsaPublicKeyBytes = valueBlock.valueHexView;
  if (!rsaPublicKeyBytes || rsaPublicKeyBytes.length === 0) return null;

  const rsaPublicKey = parseAsn1(rsaPublicKeyBytes);
  const modulus = readSequenceChild(rsaPublicKey, 0);
  const modulusBytes = (modulus.valueBlock as { valueHexView?: Uint8Array }).valueHexView;
  if (!(modulus instanceof asn1js.Integer) || !modulusBytes || modulusBytes.length === 0) return null;

  let offset = 0;
  while (offset < modulusBytes.length - 1 && modulusBytes[offset] === 0) offset += 1;
  const firstByte = modulusBytes[offset];
  const firstByteBits = firstByte === 0 ? 0 : 8 - Math.clz32(firstByte) + 24;
  return (modulusBytes.length - offset - 1) * 8 + firstByteBits;
}

function curveNameFromOid(oid: string): string | undefined {
  const names: Record<string, string> = {
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
  };
  return names[oid];
}

function isContextSpecific(node: Asn1Node | undefined, tagNumber: number): boolean {
  const idBlock = node?.idBlock as { tagClass?: number; tagNumber?: number } | undefined;
  return idBlock?.tagClass === 3 && idBlock.tagNumber === tagNumber;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}
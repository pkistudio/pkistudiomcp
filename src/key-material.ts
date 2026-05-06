import * as asn1js from "asn1js";
import { PvkGadgetsCore, type KeyAlgorithmCandidate } from "@pkistudio/pvkgadgets";
import type { Pkcs12KeyMaterial } from "@pkistudio/pvkgadgets/pkcs12";

import { decodeInputBytes, encodeOutputBytes } from "./pkistudio.js";

type InputFormat = "auto" | "der" | "ber" | "pem" | "base64" | "headerless-pem" | "hex";
type OutputEncoding = "hex" | "base64";
type Asn1Node = ReturnType<typeof asn1js.fromBER>["result"];

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

export async function listSupportedKeyAlgorithms() {
  const algorithms = await PvkGadgetsCore.getSupportedKeyAlgorithms();
  return { algorithms: algorithms.map(describeKeyAlgorithmCandidate) };
}

export async function generateKeyPair(input: GenerateKeyPairInput) {
  const material = await PvkGadgetsCore.generateKeyPair(input.algorithm, { label: input.label });
  if (!material.privateKeyDer || !material.publicKeyDer) throw new Error("The runtime did not return a key pair.");

  const encoding = input.encoding ?? "hex";
  const keyInfo = PvkGadgetsCore.recognizeKeyMaterial({
    privateKeyDer: material.privateKeyDer,
    publicKeyDer: material.publicKeyDer,
  });

  return {
    algorithm: describeKeyAlgorithmCandidate(getGenerationOptions(input.algorithm)),
    label: material.label,
    keyInfo,
    privateKey: describeBytes(material.privateKeyDer, encoding),
    publicKey: describeBytes(material.publicKeyDer, encoding),
  };
}

export function recognizeKeyMaterial(input: RecognizeInput) {
  const decoded = decodeInputBytes(input.data, input.format);
  const info = input.kind === "public"
    ? PvkGadgetsCore.recognizeKeyMaterial({ publicKeyDer: decoded.bytes })
    : PvkGadgetsCore.recognizeKeyMaterial({ privateKeyDer: decoded.bytes });

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
  const keyInfo = PvkGadgetsCore.recognizeKeyMaterial({ privateKeyDer: privateKey.bytes, publicKeyDer: publicKey.bytes });
  const matches = await PvkGadgetsCore.verifyPrivateKeyMatchesPublicKey(privateKey.bytes, publicKey.bytes, keyInfo);

  return {
    matches,
    privateKeyFormat: privateKey.format,
    publicKeyFormat: publicKey.format,
    privateKeyLength: privateKey.bytes.length,
    publicKeyLength: publicKey.bytes.length,
    keyInfo,
  };
}

export async function certificateMatchesKey(input: CertificateMatchesKeyInput) {
  if (!input.privateKey && !input.publicKey) {
    throw new Error("privateKey or publicKey is required.");
  }

  const certificate = decodeInputBytes(input.certificate, input.certificateFormat);
  const certificatePublicKeyDer = getCertificatePublicKeyDer(certificate.bytes);
  const certificatePublicKeyInfo = PvkGadgetsCore.recognizeKeyMaterial({ publicKeyDer: certificatePublicKeyDer });
  const publicKey = input.publicKey ? decodeInputBytes(input.publicKey, input.publicKeyFormat) : undefined;
  const privateKey = input.privateKey ? decodeInputBytes(input.privateKey, input.privateKeyFormat) : undefined;
  const keyInfo = PvkGadgetsCore.recognizeKeyMaterial({
    privateKeyDer: privateKey?.bytes,
    publicKeyDer: publicKey?.bytes,
  });
  const matches = publicKey
    ? PvkGadgetsCore.bytesEqual(publicKey.bytes, certificatePublicKeyDer)
    : await PvkGadgetsCore.verifyPrivateKeyMatchesPublicKey(privateKey?.bytes ?? new Uint8Array(), certificatePublicKeyDer, keyInfo);

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
    certificatePublicKey: describeBytes(certificatePublicKeyDer, input.encoding),
  };
}

export async function createCsr(input: CreateCsrInput) {
  const privateKey = decodeInputBytes(input.privateKey, input.privateKeyFormat);
  const publicKey = decodeInputBytes(input.publicKey, input.publicKeyFormat);
  const hashAlgorithm = input.hashAlgorithm ?? "SHA-256";
  const keyInfo = PvkGadgetsCore.recognizeKeyMaterial({ privateKeyDer: privateKey.bytes, publicKeyDer: publicKey.bytes });
  const result = await PvkGadgetsCore.createCsr({
    privateKeyDer: privateKey.bytes,
    publicKeyDer: publicKey.bytes,
    subjectDn: input.subjectDn,
    subjectBytes: PvkGadgetsCore.createSubjectDn(input.subjectDn),
    hashAlgorithm,
  });

  return {
    subjectDn: result.subjectDn,
    hashAlgorithm: result.hashAlgorithm,
    keyInfo,
    length: result.bytes.length,
    encoding: input.encoding ?? "hex",
    data: encodeOutputBytes(result.bytes, input.encoding),
  };
}

export async function createSelfSignedCertificate(input: CreateSelfSignedCertificateInput) {
  const privateKey = decodeInputBytes(input.privateKey, input.privateKeyFormat);
  const publicKey = decodeInputBytes(input.publicKey, input.publicKeyFormat);
  const hashAlgorithm = input.hashAlgorithm ?? "SHA-256";
  const validityDays = input.validityDays ?? 365;
  const keyUsages = input.keyUsages ?? ["digitalSignature", "keyCertSign", "cRLSign"];
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + validityDays * 24 * 60 * 60 * 1000);
  const keyInfo = PvkGadgetsCore.recognizeKeyMaterial({ privateKeyDer: privateKey.bytes, publicKeyDer: publicKey.bytes });
  const result = await PvkGadgetsCore.createSelfSignedCertificate({
    privateKeyDer: privateKey.bytes,
    publicKeyDer: publicKey.bytes,
    subjectDn: input.subjectDn,
    subjectBytes: PvkGadgetsCore.createSubjectDn(input.subjectDn),
    hashAlgorithm,
    validityDays,
    keyUsages,
  });

  return {
    subjectDn: result.subjectDn,
    hashAlgorithm: result.hashAlgorithm,
    validityDays: result.validityDays,
    keyUsages,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    keyInfo,
    length: result.bytes.length,
    encoding: input.encoding ?? "hex",
    data: encodeOutputBytes(result.bytes, input.encoding),
  };
}

export async function readPkcs12(input: ReadPkcs12Input) {
  const decoded = decodeInputBytes(input.data, input.format);
  const keys: Pkcs12KeyMaterial[] = await PvkGadgetsCore.readPkcs12(decoded.bytes, input.password, { sourceName: input.sourceName });
  const encoding = input.encoding ?? "hex";

  return {
    sourceFormat: decoded.format,
    keyCount: keys.length,
    keys: keys.map((key) => ({
      id: key.id,
      label: key.label,
      sourceName: key.sourceName,
      keyInfo: PvkGadgetsCore.recognizeKeyMaterial({ privateKeyDer: key.privateKeyDer, publicKeyDer: key.publicKeyDer }),
      privateKey: describeBytes(key.privateKeyDer, encoding),
      publicKey: key.publicKeyDer ? describeBytes(key.publicKeyDer, encoding) : undefined,
      certificate: key.certificateDer ? describeBytes(key.certificateDer, encoding) : undefined,
    })),
  };
}

export async function writePkcs12(input: WritePkcs12Input) {
  const bytes = await PvkGadgetsCore.writePkcs12(
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

function getGenerationOptions(selection: string): KeyAlgorithmCandidate {
  const supported = PvkGadgetsCore.keyAlgorithms.find((candidate) => candidate.id === selection);
  if (!supported) throw new Error(`Unsupported algorithm: ${selection || "(none selected)"}`);
  return supported;
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

function describeBytes(bytes: Uint8Array, encoding: OutputEncoding = "hex") {
  return {
    encoding,
    length: bytes.length,
    data: encodeOutputBytes(bytes, encoding),
  };
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

function isContextSpecific(node: Asn1Node | undefined, tagNumber: number): boolean {
  const idBlock = node?.idBlock as { tagClass?: number; tagNumber?: number } | undefined;
  return idBlock?.tagClass === 3 && idBlock.tagNumber === tagNumber;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

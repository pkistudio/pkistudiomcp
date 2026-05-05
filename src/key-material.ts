import * as asn1js from "asn1js";

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

type MaterialInput = {
  data: string;
  format?: InputFormat;
};

type RecognizeInput = MaterialInput & {
  kind: "private" | "public";
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

function recognizeMaterial(material: { privateKeyDer?: Uint8Array; publicKeyDer?: Uint8Array }): RecognizedKeyInfo {
  return (material.publicKeyDer ? recognizePublicKey(material.publicKeyDer) : null) ||
    (material.privateKeyDer ? recognizePrivateKey(material.privateKeyDer) : createRecognizedKeyInfo("Unknown", "Unknown"));
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
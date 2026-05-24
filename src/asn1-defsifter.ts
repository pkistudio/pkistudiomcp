import {
  createCandidateReport,
  createPkiCandidateReport,
  getPkiProfileTypeNames,
  parseAsn1DefinitionCorpus,
  pkiProfileTypeNames,
  type CandidateReportOptions,
  type PkiCandidateReportOptions,
  type PkiProfileName,
  type SchemaCorpus,
} from "@pkistudio/asn1defsifter";

type InputFormat = "auto" | "der" | "ber" | "pem" | "base64" | "headerless-pem" | "hex";

type CandidateReportBaseInput = {
  data: string;
  format?: InputFormat;
  maxResults?: number;
  minScore?: number;
  includeTypes?: string[];
  excludeTypes?: string[];
  includeNodes?: boolean;
  includeSubtrees?: boolean;
  includeEmptySubtrees?: boolean;
  maxSubtreeDepth?: number;
  maxSubtreeReports?: number;
};

type DefinitionSifterInput = CandidateReportBaseInput & {
  definition?: string;
  definitions?: string[];
};

type PkiDefinitionSifterInput = CandidateReportBaseInput & {
  profiles?: PkiProfileName[];
};

export async function siftAsn1DefinitionCandidates(input: DefinitionSifterInput) {
  const schemaCorpus = readDefinitionCorpus(input);
  const report = await createCandidateReport(input.data, {
    ...readCandidateReportOptions(input),
    schemaCorpus,
  });

  return {
    packageName: "@pkistudio/asn1defsifter",
    corpus: schemaCorpus ? "custom-definitions" : "built-in-pki-components",
    ...report,
  };
}

export async function siftPkiAsn1DefinitionCandidates(input: PkiDefinitionSifterInput) {
  const report = await createPkiCandidateReport(input.data, readPkiCandidateReportOptions(input));

  return {
    packageName: "@pkistudio/asn1defsifter",
    profiles: input.profiles ?? [],
    includedProfileTypes: input.profiles ? getPkiProfileTypeNames(input.profiles) : undefined,
    ...report,
  };
}

export function listAsn1DefinitionSifterFeatures() {
  return {
    packageName: "@pkistudio/asn1defsifter",
    scope: "Rank ASN.1 definition candidates for DER/TLV fragments with explainable evidence, diagnostics, and ambiguity notes.",
    tools: [
      {
        name: "sift_asn1_definition_candidates",
        corpus: "Custom ASN.1 definitions when provided, otherwise the built-in PKI component corpus.",
      },
      {
        name: "sift_pki_asn1_definition_candidates",
        corpus: "Built-in PKI component corpus with optional profile filters.",
      },
    ],
    pkiProfiles: pkiProfileTypeNames,
    options: [
      "maxResults",
      "minScore",
      "includeTypes",
      "excludeTypes",
      "includeSubtrees",
      "includeEmptySubtrees",
      "maxSubtreeDepth",
      "maxSubtreeReports",
    ],
  };
}

function readCandidateReportOptions(input: CandidateReportBaseInput): CandidateReportOptions {
  return {
    parseOptions: { format: input.format },
    maxResults: input.maxResults,
    minScore: input.minScore,
    includeTypes: input.includeTypes,
    excludeTypes: input.excludeTypes,
    includeNodes: input.includeNodes,
    includeSubtrees: input.includeSubtrees,
    includeEmptySubtrees: input.includeEmptySubtrees,
    maxSubtreeDepth: input.maxSubtreeDepth,
    maxSubtreeReports: input.maxSubtreeReports,
  };
}

function readPkiCandidateReportOptions(input: PkiDefinitionSifterInput): PkiCandidateReportOptions {
  return {
    ...readCandidateReportOptions(input),
    profiles: input.profiles,
  };
}

function readDefinitionCorpus(input: DefinitionSifterInput): SchemaCorpus | undefined {
  const definitions = [input.definition, ...(input.definitions ?? [])].filter((definition): definition is string => Boolean(definition));
  if (definitions.length === 0) return undefined;
  return parseAsn1DefinitionCorpus(definitions);
}
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { questionSchema } from "../src/lib/schema";
import type { Question } from "../src/lib/types";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const expectedFiles = {
  "questions/galatians-pistis-christou.json":
    "4bdd90ee9134dac142a1e1a0df689d8dc29dbb0b673107bbad9721200b7543f6",
  "questions/quantum-measurement-realist-strategies.json":
    "d1516759687b491d39c6bd2f33dfc0e6a92cc02ffc0b75fd691bfd83d42a8350",
  "source-freeze.json":
    "2ee5bc2d754b3e2bb199a45de26f2eb4b12cd72f41fd27e4efc3544118a5b8b2",
} as const;

const contract = [
  {
    id: "galatians-pistis-christou",
    role: "priority",
    prompt:
      "In Galatians 3:22-26, what does Paul most likely mean by πίστις Χριστοῦ in verse 22 when the phrase is read within its immediate argument? State one best-supported primary interpretation and explain the decisive grammatical, lexical, and contextual evidence.",
    positions: [
      "believers-faith-in-christ",
      "christs-own-faithfulness",
      "christ-faith-system",
      "christ-faith-event",
    ],
  },
  {
    id: "quantum-measurement-realist-strategies",
    role: "fallback",
    prompt:
      "Among Everettian unitary quantum mechanics, Bohmian mechanics, and objective-collapse theories, which offers the best overall resolution of the nonrelativistic quantum measurement problem? State one primary answer and explain which empirical and theoretical considerations are decisive.",
    positions: [
      "everettian-unitary-branching",
      "bohmian-added-configuration",
      "objective-collapse-dynamics",
    ],
  },
] as const;

const expectedIntegrityLimited = new Set(["grasso-linguistic-analysis"]);

const expectedArtifactHashes = new Map([
  [
    "matlock-rhetoric-pistis",
    "b8f36f800c78f0a30c0cb2ead834d4e141ceff18e710717adca307899aca8d2c",
  ],
  [
    "sblgnt-galatians-three",
    "3d6cf6dd7ee9624167fde1ebc0ba2a1464c2aea6b630f52db436e2aee1c2f49b",
  ],
  [
    "hooker-pistis-christou",
    "7acb7d20cb2bdddbe3568530d14a8117a4c8ba522d6757dba2f959e12cd132b2",
  ],
  [
    "schliesser-christ-faith-event",
    "b3e4cbe547c111d8382b230bdc376e08b7306f38b31584e4140b8a41a6723fb8",
  ],
  [
    "maudlin-three-measurement-problems",
    "e8de5c3dfef6210bae6c5866f38979f2e70490253712fecdbab0487c189ee988",
  ],
  [
    "everett-relative-state",
    "016afb29545d5e1475f660f694e5f7eea8f06f4682e7c0ed3430fe1adcf6b8f8",
  ],
  [
    "sep-everettian-quantum-mechanics",
    "00cc0e9a903456bfb59f92fa823f830c15edfc1bf7e4ffccbbd68a79e6fc58c6",
  ],
  [
    "bohm-hidden-variables-part-one",
    "a322064233554b472d486a4b38b80a54e4e85d7b9761f283d8b77ff304f68615",
  ],
  [
    "bohm-hidden-variables-part-two",
    "161da4cb4e1341d823fdf4eb0b6504e15086018d59532d86fa048370bd751241",
  ],
  [
    "sep-bohmian-mechanics",
    "f1465138a4fc510d93667132d5e58db8a06491ccd3b2fbcb9435a8ff43adb0a4",
  ],
  [
    "grw-unified-dynamics",
    "655efa13b585709b309028476cdfaebd2aa17902e35696496efdf5ff56ce40da",
  ],
  [
    "sep-collapse-theories",
    "4403377309688fafc6aebae176c97d812d14cf05377c8b5b9c944b77be2b1cbb",
  ],
]);

const exactSubjectiveDefinition =
  "The phrase primarily denotes Christ’s own faith or faithfulness. This includes concentric or participatory accounts in which believers’ answering faith derives from and shares in Christ’s faith.";
const exactNullBoundary =
  "An answer maps here only if it clearly makes Christ’s faith the semantic and explanatory center. A merely plenary, intentionally ambiguous, or evenly combined subjective-objective answer remains null.";

type JsonRecord = Record<string, unknown>;

export interface Rule3CandidateValidationResult {
  issues: string[];
  questionCount: number;
  positionCount: number;
  sourceCount: number;
}

function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function proposed(value: unknown): boolean {
  return (
    isRecord(value) &&
    value.status === "proposed" &&
    value.verified_by === null &&
    value.verified_at === null &&
    Object.keys(value).length === 3
  );
}

function walkStrings(
  value: unknown,
  visit: (text: string, location: string) => void,
  location = "$",
): void {
  if (typeof value === "string") {
    visit(value, location);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkStrings(item, visit, `${location}[${index}]`));
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      walkStrings(item, visit, `${location}.${key}`);
    }
  }
}

function parseJson(file: string, label: string, issues: string[]): unknown {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    issues.push(
      `${label}: malformed JSON (${error instanceof Error ? error.message : "unknown error"})`,
    );
    return null;
  }
}

export function validateRule3Candidates(
  bundleRoot = path.join(repositoryRoot, "candidate/rule3"),
  dossierPath: string | null =
    bundleRoot === path.join(repositoryRoot, "candidate/rule3")
      ? path.join(repositoryRoot, "candidate/DIVERGENCE_SUPPLEMENT_RESEARCH.md")
      : null,
): Rule3CandidateValidationResult {
  const issues: string[] = [];
  const expectedRelativeFiles = Object.keys(expectedFiles).sort();
  const actualRelativeFiles: string[] = [];
  const questionsRoot = path.join(bundleRoot, "questions");
  try {
    for (const name of readdirSync(questionsRoot).sort()) {
      actualRelativeFiles.push(`questions/${name}`);
    }
    for (const name of readdirSync(bundleRoot).sort()) {
      if (name !== "questions") actualRelativeFiles.push(name);
    }
  } catch (error) {
    issues.push(
      `candidate/rule3: cannot enumerate bundle (${error instanceof Error ? error.message : "unknown error"})`,
    );
  }
  actualRelativeFiles.sort();
  if (JSON.stringify(actualRelativeFiles) !== JSON.stringify(expectedRelativeFiles)) {
    issues.push(
      `candidate/rule3: expected only ${expectedRelativeFiles.join(", ")}; found ${actualRelativeFiles.join(", ") || "nothing"}`,
    );
  }

  for (const [relative, expectedHash] of Object.entries(expectedFiles)) {
    const file = path.join(bundleRoot, relative);
    try {
      const stat = lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        issues.push(`candidate/rule3/${relative}: expected a regular, non-symlink file`);
        continue;
      }
      if (sha256(file) !== expectedHash) {
        issues.push(`candidate/rule3/${relative}: bytes differ from the approved record`);
      }
    } catch {
      issues.push(`candidate/rule3/${relative}: required file is missing`);
    }
  }

  const questions: Question[] = [];
  for (const spec of contract) {
    const relative = `questions/${spec.id}.json`;
    const raw = parseJson(path.join(bundleRoot, relative), `candidate/rule3/${relative}`, issues);
    const result = questionSchema.safeParse(raw);
    if (!result.success) {
      for (const issue of result.error.issues) {
        issues.push(`candidate/rule3/${relative}/${issue.path.join("/")}: ${issue.message}`);
      }
      continue;
    }
    const question = result.data;
    questions.push(question);
    if (
      question.content_version !== "rule3-candidate-1.0.0" ||
      question.data_class !== "research" ||
      question.kind !== "divergent" ||
      question.selection.status !== "candidate" ||
      question.selection.pool_id !== "concordance-divergence-supplement-1" ||
      question.selection.pool_size !== 2 ||
      question.selection.rule_version !== "pilot-rule-3"
    ) {
      issues.push(`candidate/rule3/${relative}: Rule 3 candidate contract differs`);
    }
    if (
      question.prompt_variants.length !== 1 ||
      question.prompt_variants[0].id !== "default" ||
      question.prompt_variants[0].user_prompt !== spec.prompt
    ) {
      issues.push(`candidate/rule3/${relative}: exact approved prompt differs`);
    }
    if (
      JSON.stringify(question.position_map.map((position) => position.id)) !==
      JSON.stringify(spec.positions)
    ) {
      issues.push(`candidate/rule3/${relative}: exact position order differs`);
    }
    if (!proposed(question.verification)) {
      issues.push(`candidate/rule3/${relative}: question must remain proposed`);
    }
    for (const position of question.position_map) {
      if (!proposed(position.verification)) {
        issues.push(`candidate/rule3/${relative}/${position.id}: position must remain proposed`);
      }
      for (const source of position.sources) {
        if (!proposed(source.verification)) {
          issues.push(`candidate/rule3/${relative}/${position.id}/${source.id}: source must remain proposed`);
        }
      }
    }
  }

  const theology = questions.find((question) => question.id === contract[0].id);
  const subjective = theology?.position_map.find(
    (position) => position.id === "christs-own-faithfulness",
  );
  if (subjective?.summary !== exactSubjectiveDefinition) {
    issues.push("candidate/rule3: approved Christ-centered subjective definition differs");
  }
  if (
    theology &&
    (!theology.context_note.includes(exactNullBoundary) ||
      theology.context_note.includes("combined subjective-objective answer maps null"))
  ) {
    issues.push("candidate/rule3: approved null boundary differs");
  }

  const freezePath = path.join(bundleRoot, "source-freeze.json");
  const freeze = parseJson(freezePath, "candidate/rule3/source-freeze.json", issues);
  const questionSources = new Map<string, { url: string; claim: string }>();
  for (const question of questions) {
    for (const position of question.position_map) {
      for (const source of position.sources) {
        if (questionSources.has(source.id)) {
          issues.push(`candidate/rule3: duplicate source ID ${source.id}`);
        }
        questionSources.set(source.id, {
          url: source.url,
          claim: source.claim_supported,
        });
      }
    }
  }
  const frozenSources = new Map<string, JsonRecord>();
  if (!isRecord(freeze)) {
    issues.push("candidate/rule3/source-freeze.json: source freeze must be an object");
  } else {
    if (
      freeze.schema_version !== "rule3-source-freeze-1.0.0" ||
      freeze.content_version !== "rule3-candidate-1.0.0" ||
      freeze.pool_id !== "concordance-divergence-supplement-1" ||
      freeze.status !== "research-source-freeze-proposed" ||
      !proposed(freeze.verification)
    ) {
      issues.push("candidate/rule3/source-freeze.json: freeze header differs");
    }
    if (!Array.isArray(freeze.questions) || freeze.questions.length !== 2) {
      issues.push("candidate/rule3/source-freeze.json: expected two ordered questions");
    } else {
      freeze.questions.forEach((entry, index) => {
        if (!isRecord(entry) || entry.question_id !== contract[index].id) {
          issues.push(`candidate/rule3/source-freeze.json: question ${index} differs`);
          return;
        }
        if (!Array.isArray(entry.sources)) {
          issues.push(`candidate/rule3/source-freeze.json: ${contract[index].id} sources are malformed`);
          return;
        }
        for (const source of entry.sources) {
          if (!isRecord(source) || typeof source.source_id !== "string") {
            issues.push("candidate/rule3/source-freeze.json: malformed source record");
            continue;
          }
          if (frozenSources.has(source.source_id)) {
            issues.push(`candidate/rule3/source-freeze.json: duplicate source ${source.source_id}`);
          }
          frozenSources.set(source.source_id, source);
        }
      });
    }
    walkStrings(freeze, (text, location) => {
      if (
        text.startsWith("/") ||
        /^[A-Za-z]:[\\/]/.test(text) ||
        text.startsWith("file://") ||
        text.includes("/Users/") ||
        text.includes("/Volumes/")
      ) {
        issues.push(`candidate/rule3/source-freeze.json ${location}: absolute path is forbidden`);
      }
    });
  }

  if (
    questionSources.size !== 13 ||
    frozenSources.size !== 13 ||
    [...questionSources.keys()].some((id) => !frozenSources.has(id))
  ) {
    issues.push("candidate/rule3/source-freeze.json: source set differs from the two questions");
  }
  for (const [id, expected] of questionSources) {
    const frozen = frozenSources.get(id);
    if (!frozen) continue;
    if (
      frozen.source_url !== expected.url ||
      frozen.claim_binding !== expected.claim ||
      !proposed(frozen.verification)
    ) {
      issues.push(`candidate/rule3/source-freeze.json: ${id} binding differs from the question record`);
    }
    const artifact = frozen.artifact;
    if (!isRecord(artifact)) {
      issues.push(`candidate/rule3/source-freeze.json: ${id} artifact is malformed`);
      continue;
    }
    const expectedHash = expectedArtifactHashes.get(id);
    if (expectedHash && artifact.sha256 !== expectedHash) {
      issues.push(`candidate/rule3/source-freeze.json: ${id} artifact hash differs`);
    }
    if (
      expectedIntegrityLimited.has(id) &&
      (artifact.sha256 !== null ||
        artifact.status !== "integrity-limited-no-raw-snapshot" ||
        typeof artifact.limitation !== "string")
    ) {
      issues.push(`candidate/rule3/source-freeze.json: ${id} integrity limitation differs`);
    }
  }

  if (dossierPath !== null) {
    try {
      const dossier = readFileSync(dossierPath, "utf8");
      for (const required of [
        contract[0].prompt,
        contract[1].prompt,
        exactSubjectiveDefinition,
        exactNullBoundary,
      ]) {
        if (!dossier.includes(required)) {
          issues.push("candidate/DIVERGENCE_SUPPLEMENT_RESEARCH.md: approved Rule 3 wording is missing");
          break;
        }
      }
    } catch {
      issues.push("candidate/DIVERGENCE_SUPPLEMENT_RESEARCH.md: required dossier is missing");
    }
  }

  return {
    issues,
    questionCount: questions.length,
    positionCount: questions.reduce(
      (count, question) => count + question.position_map.length,
      0,
    ),
    sourceCount: questionSources.size,
  };
}

function main(): void {
  const result = validateRule3Candidates();
  if (result.issues.length > 0) {
    process.stderr.write(
      `Rule 3 candidate validation failed with ${result.issues.length} issue${result.issues.length === 1 ? "" : "s"}:\n`,
    );
    process.stderr.write(`${result.issues.map((issue) => `- ${issue}`).join("\n")}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    `Validated ${result.questionCount} proposed Rule 3 candidates, ${result.positionCount} positions, and ${result.sourceCount} exact source records.\n`,
  );
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) main();

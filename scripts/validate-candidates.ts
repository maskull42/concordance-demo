import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { questionSchema } from "../src/lib/schema";
import type { Question } from "../src/lib/types";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const candidateRoot = path.join(root, "candidate");
const questionRoot = path.join(candidateRoot, "questions");
const issues: string[] = [];
const questions: Question[] = [];
const questionFiles = new Map<string, string>();

const pilotContract = [
  { id: "james-jesus-brothers", kind: "convergent", role: "priority" },
  { id: "junia-romans-16-7", kind: "convergent", role: "fallback" },
  { id: "mill-harm-principle", kind: "divergent", role: "priority" },
  { id: "locke-money-property", kind: "divergent", role: "fallback" },
  { id: "atomic-bombs-pacific-war", kind: "prompt-sensitive", role: "priority" },
  { id: "john-brown-harpers-ferry", kind: "prompt-sensitive", role: "fallback" },
] as const;

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const pilotLockSchema = z
  .object({
    schema_version: z.literal("pilot-lock-1.0.0"),
    pool_id: z.literal("concordance-pilot-pool"),
    pool_size: z.literal(6),
    rule_version: z.literal("pilot-rule-2"),
    content_version: z.literal("candidate-1.1.0"),
    pool_document: z
      .object({
        path: z.literal("candidate/PILOT_POOL.md"),
        sha256: sha256Schema,
      })
      .strict(),
    mapping_rubric: z
      .object({
        path: z.literal("candidate/MAPPING_RUBRIC.md"),
        sha256: sha256Schema,
      })
      .strict(),
    protocol: z
      .object({
        path: z.literal("config/protocol.json"),
        protocol_version: z.string().min(1),
        sha256: sha256Schema,
      })
      .strict(),
    candidates: z
      .array(
        z
          .object({
            id: z.string(),
            kind: z.enum(["convergent", "divergent", "prompt-sensitive"]),
            role: z.enum(["priority", "fallback"]),
            path: z.string(),
            sha256: sha256Schema,
          })
          .strict(),
      )
      .length(6),
  })
  .strict();

function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

for (const file of readdirSync(questionRoot).filter((name) => name.endsWith(".json")).sort()) {
  const relative = `candidate/questions/${file}`;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path.join(questionRoot, file), "utf8"));
  } catch (error) {
    issues.push(`${relative}: malformed JSON (${error instanceof Error ? error.message : "unknown parse error"})`);
    continue;
  }

  const result = questionSchema.safeParse(raw);
  if (!result.success) {
    for (const issue of result.error.issues) {
      issues.push(`${relative}/${issue.path.join("/")}: ${issue.message}`);
    }
    continue;
  }
  questions.push(result.data);
  questionFiles.set(result.data.id, path.join(questionRoot, file));
}

if (questions.length !== 6) issues.push(`candidate pool: expected 6 valid questions, found ${questions.length}`);
for (const kind of ["convergent", "divergent", "prompt-sensitive"] as const) {
  const count = questions.filter((question) => question.kind === kind).length;
  if (count !== 2) issues.push(`candidate pool: expected 2 ${kind} questions, found ${count}`);
}

const ids = new Set<string>();
const poolDocument = readFileSync(path.join(candidateRoot, "PILOT_POOL.md"), "utf8");
const sourceDocument = readFileSync(path.join(candidateRoot, "SOURCES_TO_VERIFY.md"), "utf8");

const actualIds = new Set(questions.map((question) => question.id));
const expectedIds = new Set(pilotContract.map((candidate) => candidate.id));
for (const candidate of pilotContract) {
  if (!actualIds.has(candidate.id)) {
    issues.push(`candidate pool: missing canonical ${candidate.role} candidate ${candidate.id}`);
    continue;
  }
  const question = questions.find((item) => item.id === candidate.id);
  if (question?.kind !== candidate.kind) {
    issues.push(`${candidate.id}: expected ${candidate.kind} ${candidate.role} role, found ${question?.kind ?? "no valid question"}`);
  }
}
for (const id of actualIds) {
  if (!expectedIds.has(id as (typeof pilotContract)[number]["id"])) {
    issues.push(`candidate pool: unexpected candidate ID ${id}`);
  }
}

for (const kind of ["convergent", "divergent", "prompt-sensitive"] as const) {
  const priority = pilotContract.find((candidate) => candidate.kind === kind && candidate.role === "priority");
  const fallback = pilotContract.find((candidate) => candidate.kind === kind && candidate.role === "fallback");
  if (!priority || !fallback) continue;
  const label = {
    convergent: "Convergence",
    divergent: "Divergence",
    "prompt-sensitive": "Prompt sensitivity",
  }[kind];
  const exactRow = `| ${label} | \`${priority.id}\` | \`${fallback.id}\` |`;
  if (!poolDocument.includes(exactRow)) {
    issues.push(`PILOT_POOL.md: missing exact ${kind} priority/fallback contract`);
  }
}

for (const question of questions) {
  if (ids.has(question.id)) issues.push(`candidate pool: duplicate question ID ${question.id}`);
  ids.add(question.id);

  if (
    question.content_version !== "candidate-1.1.0" ||
    question.data_class !== "research" ||
    question.selection.status !== "candidate" ||
    question.selection.pool_id !== "concordance-pilot-pool" ||
    question.selection.pool_size !== 6 ||
    question.selection.rule_version !== "pilot-rule-2"
  ) {
    issues.push(`${question.id}: Rule 2 candidate contract is incomplete`);
  }
  if (question.verification.status !== "proposed") {
    issues.push(`${question.id}: question must remain proposed`);
  }
  for (const variant of question.prompt_variants) {
    if (!poolDocument.includes(variant.user_prompt)) {
      issues.push(`${question.id}/${variant.id}: exact prompt is missing from PILOT_POOL.md`);
    }
  }
  for (const position of question.position_map) {
    if (position.verification.status !== "proposed") {
      issues.push(`${question.id}/${position.id}: position must remain proposed`);
    }
    for (const source of position.sources) {
      if (source.verification.status !== "proposed") {
        issues.push(`${question.id}/${position.id}/${source.id}: source must remain proposed`);
      }
      for (const [label, value] of [
        ["claim", source.claim_supported],
        ["citation", source.citation],
        ["URL", source.url],
        ["access date", source.accessed_at],
      ] as const) {
        if (!sourceDocument.includes(value)) {
          issues.push(`${question.id}/${position.id}/${source.id}: ${label} is missing from SOURCES_TO_VERIFY.md`);
        }
      }
    }
  }
}

const lockPath = path.join(candidateRoot, "pilot-lock.json");
if (existsSync(lockPath)) {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(lockPath, "utf8"));
  } catch (error) {
    issues.push(`candidate/pilot-lock.json: malformed JSON (${error instanceof Error ? error.message : "unknown parse error"})`);
    raw = null;
  }
  const result = pilotLockSchema.safeParse(raw);
  if (!result.success) {
    for (const issue of result.error.issues) {
      issues.push(`candidate/pilot-lock.json/${issue.path.join("/")}: ${issue.message}`);
    }
  } else {
    if (result.data.pool_document.sha256 !== sha256(path.join(candidateRoot, "PILOT_POOL.md"))) {
      issues.push("candidate/pilot-lock.json/pool_document/sha256: hash mismatch for candidate/PILOT_POOL.md");
    }
    if (result.data.mapping_rubric.sha256 !== sha256(path.join(candidateRoot, "MAPPING_RUBRIC.md"))) {
      issues.push("candidate/pilot-lock.json/mapping_rubric/sha256: hash mismatch for candidate/MAPPING_RUBRIC.md");
    }
    for (const [index, expected] of pilotContract.entries()) {
      const entry = result.data.candidates[index];
      const expectedPath = `candidate/questions/${expected.id}.json`;
      for (const [field, expectedValue] of [
        ["id", expected.id],
        ["kind", expected.kind],
        ["role", expected.role],
        ["path", expectedPath],
      ] as const) {
        if (entry[field] !== expectedValue) {
          issues.push(`candidate/pilot-lock.json/candidates/${index}/${field}: differs from the Rule 2 contract`);
        }
      }
      const questionFile = questionFiles.get(expected.id);
      if (questionFile && entry.sha256 !== sha256(questionFile)) {
        issues.push(`candidate/pilot-lock.json/candidates/${index}/sha256: hash mismatch for ${expectedPath}`);
      }
    }

    const protocolPath = path.join(root, "config", "protocol.json");
    try {
      const protocol = JSON.parse(readFileSync(protocolPath, "utf8")) as { protocol_version?: unknown };
      if (result.data.protocol.protocol_version !== protocol.protocol_version) {
        issues.push("candidate/pilot-lock.json/protocol/protocol_version: does not match config/protocol.json");
      }
      if (result.data.protocol.sha256 !== sha256(protocolPath)) {
        issues.push("candidate/pilot-lock.json/protocol/sha256: hash mismatch for config/protocol.json");
      }
    } catch (error) {
      issues.push(`config/protocol.json: cannot validate pilot lock (${error instanceof Error ? error.message : "unknown error"})`);
    }
  }
}

if (issues.length > 0) {
  process.stderr.write(`Candidate validation failed with ${issues.length} issue${issues.length === 1 ? "" : "s"}:\n`);
  process.stderr.write(`${issues.map((issue) => `- ${issue}`).join("\n")}\n`);
  process.exit(1);
}

const positionCount = questions.reduce((count, question) => count + question.position_map.length, 0);
const sourceCount = questions.reduce(
  (count, question) =>
    count + question.position_map.reduce((subtotal, position) => subtotal + position.sources.length, 0),
  0,
);
const variantCount = questions.reduce((count, question) => count + question.prompt_variants.length, 0);
process.stdout.write(
  `Validated 6 proposed candidates, ${positionCount} positions, ${sourceCount} source records, and ${variantCount} exact prompt variants.\n`,
);

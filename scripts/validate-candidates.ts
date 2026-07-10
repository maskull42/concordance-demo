import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { questionSchema } from "../src/lib/schema";
import type { Question } from "../src/lib/types";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const candidateRoot = path.join(root, "candidate");
const questionRoot = path.join(candidateRoot, "questions");
const issues: string[] = [];
const questions: Question[] = [];

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
}

if (questions.length !== 6) issues.push(`candidate pool: expected 6 valid questions, found ${questions.length}`);
for (const kind of ["convergent", "divergent", "prompt-sensitive"] as const) {
  const count = questions.filter((question) => question.kind === kind).length;
  if (count !== 2) issues.push(`candidate pool: expected 2 ${kind} questions, found ${count}`);
}

const ids = new Set<string>();
const poolDocument = readFileSync(path.join(candidateRoot, "PILOT_POOL.md"), "utf8");
const sourceDocument = readFileSync(path.join(candidateRoot, "SOURCES_TO_VERIFY.md"), "utf8");

for (const question of questions) {
  if (ids.has(question.id)) issues.push(`candidate pool: duplicate question ID ${question.id}`);
  ids.add(question.id);

  if (
    question.data_class !== "research" ||
    question.selection.status !== "candidate" ||
    question.selection.pool_id !== "concordance-pilot-pool" ||
    question.selection.pool_size !== 6 ||
    question.selection.rule_version !== "pilot-rule-1"
  ) {
    issues.push(`${question.id}: candidate selection precommitment is incomplete`);
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

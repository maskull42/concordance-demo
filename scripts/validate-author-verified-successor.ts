import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { questionSchema } from "../src/lib/schema";
import type { Question, Verification } from "../src/lib/types";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultSuccessorRoot = path.join(
  repositoryRoot,
  "candidate/successors/candidate-1.1.2",
);
const predecessorRoot = path.join(
  repositoryRoot,
  "candidate/successors/candidate-1.1.1",
);

const SUCCESSOR_MANIFEST_SHA256 =
  "1e37ddaf47d7ac56add2be79081b545269d6c1a9f1cde331fd5dabff93600715";
const PREDECESSOR_MANIFEST_SHA256 =
  "783decf0e3cfecd7f22dc5fc6d7e4389153e45f78928a3d7a792d63efd53bdd6";
const REVIEWED_AT = "2026-07-13T07:33:29.353Z";
const SEALED_AT = "2026-07-13T07:36:08.042+00:00";
const REVIEW_ID = "selected-review-57e22e96d69998198d061b87d76b3923";
const SEALED_RECEIPT_SHA256 =
  "96dd200c5fa15a9206489313d7eea83469cb9d6a841b8e9af5140745e109fa1b";
const SEALED_DRAFT_SHA256 =
  "21e077b0cdf0ae8a935ed3cdd3d934342c5e84d3ea95d19729dcce99fb5bdd3e";
const PACKET_RECEIPT_SHA256 =
  "8ef1f9bca3c7fee77bcbc3f3e4a84d6052053e0e030de5263f85ea153d5278ee";

const expectedPromoterSourceFiles = {
  "harness/author_review_assets/review.css":
    "fe61f86b190dbd64e2998d0cce0794d9db757495e0d2366c512e7160ada88b6b",
  "harness/concordance_harness/util.py":
    "fa9f45770ba270f0950443e248f89faba86b9c3e9b5c2715000efaedb13e3993",
  "harness/evaluate_pilot_selection_amended.py":
    "148d51e9663e759f46fcdc8c0a8fb197193345ba1ecd7a8803fec5885c4012f6",
  "harness/finalize_selected_content_review.py":
    "887bd2385a76599a22739c69caf6994f0a37334f0764bd7db94b34335f8508e0",
  "harness/prepare_selected_content_review.py":
    "77fcc9efc306a3f4f1d03e9ab45fcdc180a039d2214d8e845a3b5a5e0ed758bf",
  "harness/private_directory_publication.py":
    "ac2bfd0247eebfe039054b137e97f464d3fe98bc280ba07c2f3935c2ae1d18aa",
  "harness/promote_selected_content.py":
    "6fcb0cb10dde760bf22d1b270b6606b7c675bd0ce4b40018241a360ab7424595",
  "harness/selected_content_review_assets/review.css":
    "e4aebe53a4ff72f9784bf57bd1d77c204507840d1b864ceb16cdf580dfc6d785",
  "harness/selected_content_review_assets/review.js":
    "7e04edf91ae69135350a7a9a0c50586080cdc8cef6ff22bf85fbeed581ef8d18",
  "scripts/validate-successor-candidates.ts":
    "16a63c28ed4093f7025b720504dd570fe2a3bb94bdba8a5eadda5c6149cc943e",
} as const;
const PROMOTER_EXECUTION_SHA256 =
  "b644a8fd06ed3e9bd78bb001884d1a210c2069c4566a218ce66cf3e16bd447a9";

const expectedQuestionEntries = [
  {
    id: "junia-romans-16-7",
    verificationRecordCount: 10,
    base: {
      path: "candidate/successors/candidate-1.1.1/questions/junia-romans-16-7.json",
      sha256: "4a2b7115a96e92d7db01d9a0a65b03046b323c0b68425e96083d6d8670eed0e7",
    },
    successor: {
      path: "candidate/successors/candidate-1.1.2/questions/junia-romans-16-7.json",
      sha256: "6d76a0b38b682ce3b2c0550f4a0e557550edf0b71fe3814905ef748fc09e41e7",
    },
  },
  {
    id: "john-brown-harpers-ferry",
    verificationRecordCount: 16,
    base: {
      path: "candidate/successors/candidate-1.1.1/questions/john-brown-harpers-ferry.json",
      sha256: "a3489188ec29b402a893229bb227255dfd4bdbc10db0f7c020bb7b0944984ac4",
    },
    successor: {
      path: "candidate/successors/candidate-1.1.2/questions/john-brown-harpers-ferry.json",
      sha256: "4f88f73376d3ae0677af79aaa179a700717b779e806806f80d200e553a1d58ef",
    },
  },
] as const;

const expectedManifestQuestionEntries = expectedQuestionEntries.map(
  ({ id, base, successor }) => ({ id, base, successor }),
);

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const fileBindingSchema = z
  .object({ path: z.string().min(1), sha256: sha256Schema })
  .strict();
const privateFileBindingSchema = fileBindingSchema.extend({
  availability: z.literal("private-local"),
});

const correctionSchema = z
  .object({
    question_id: z.literal("john-brown-harpers-ferry"),
    model_key: z.literal("grok"),
    variant_id: z.literal("methods-and-violence-frame"),
    call_type: z.literal("answer"),
    cell_id: z.literal(
      "john-brown-harpers-ferry:grok:methods-and-violence-frame:answer",
    ),
    response_sha256: z.literal(
      "3557ffe9cdd9fa492e11965ecade6157acf853812f1367f57e9aac2ad92b56c8",
    ),
    from: z
      .object({
        primary_position_id: z.literal("criminal-fanatical-violence"),
        reason_code: z.literal("clear_preference"),
      })
      .strict(),
    to: z
      .object({
        primary_position_id: z.null(),
        reason_code: z.literal("outside_map"),
      })
      .strict(),
    paired_non_null_model_count: z
      .object({ before: z.literal(8), after: z.literal(7) })
      .strict(),
    movement_count: z
      .object({ before: z.literal(5), after: z.literal(4) })
      .strict(),
    selection_changed: z.literal(false),
  })
  .strict();

const selectionReceiptSchema = z
  .object({
    schema_version: z.literal("pilot-selection-amendment-1.0.0"),
    selection_id: z.literal("rule2-selection-2"),
    path: z.literal(".pilot/aggregates/rule2-pilot-1/selection-rule2-2.json"),
    sha256: z.literal(
      "7a2b1587ebd0daa160870a2948482c3fc17f122829c1311cacb778f49427de13",
    ),
    availability: z.literal("private-local"),
  })
  .strict();

const successorManifestSchema = z
  .object({
    schema_version: z.literal("candidate-successor-1.0.0"),
    content_version: z.literal("candidate-1.1.2"),
    created_at: z.literal(SEALED_AT),
    supersedes: z
      .object({
        content_version: z.literal("candidate-1.1.1"),
        manifest: z
          .object({
            path: z.literal("candidate/successors/candidate-1.1.1/manifest.json"),
            sha256: z.literal(PREDECESSOR_MANIFEST_SHA256),
          })
          .strict(),
      })
      .strict(),
    selection_receipt: selectionReceiptSchema,
    selection_result: z
      .object({
        status: z.literal("partial-selection-new-pool-required"),
        selected_candidate_ids: z.tuple([
          z.literal("junia-romans-16-7"),
          z.literal("john-brown-harpers-ferry"),
        ]),
        failed_behaviors: z.tuple([z.literal("divergence")]),
        scholarship_verification: z.literal("author-verified"),
        production_eligible: z.literal(false),
      })
      .strict(),
    correction: correctionSchema,
    author_review: z
      .object({
        schema_version: z.literal("selected-content-review-receipt-1.0.0"),
        review_id: z.literal(REVIEW_ID),
        reviewer: z
          .object({
            id: z.literal("ag-elrod"),
            display_name: z.literal("A.G. Elrod"),
          })
          .strict(),
        reviewed_at: z.literal(REVIEWED_AT),
        sealed_at: z.literal(SEALED_AT),
        receipt: privateFileBindingSchema.extend({
          path: z.literal(
            ".pilot/aggregates/rule2-pilot-1/selected-content-review-1/sealed-review/review.json",
          ),
          sha256: z.literal(SEALED_RECEIPT_SHA256),
        }),
        draft: privateFileBindingSchema.extend({
          path: z.literal(
            ".pilot/aggregates/rule2-pilot-1/selected-content-review-1/sealed-review/review-draft.json",
          ),
          sha256: z.literal(SEALED_DRAFT_SHA256),
        }),
        packet_receipt_sha256: z.literal(PACKET_RECEIPT_SHA256),
        verified_question_ids: z.tuple([
          z.literal("junia-romans-16-7"),
          z.literal("john-brown-harpers-ferry"),
        ]),
        content_verification_status: z.literal("author-verified"),
      })
      .strict(),
    production_gate: z
      .object({
        eligible: z.literal(false),
        blockers: z.tuple([
          z.literal("divergence has no qualifying selected candidate"),
          z.literal("the linked-challenge final model run has not been executed"),
        ]),
      })
      .strict(),
    questions: z
      .array(
        z
          .object({
            id: z.enum(["junia-romans-16-7", "john-brown-harpers-ferry"]),
            base: fileBindingSchema,
            successor: fileBindingSchema,
          })
          .strict(),
      )
      .length(2),
    promoter: z
      .object({
        source_files: z.record(z.string().min(1), sha256Schema),
        execution_sha256: sha256Schema,
      })
      .strict(),
  })
  .strict();

const predecessorManifestSchema = z
  .object({
    schema_version: z.literal("candidate-successor-1.0.0"),
    content_version: z.literal("candidate-1.1.1"),
    selection_receipt: selectionReceiptSchema,
    selection_result: z
      .object({
        status: z.literal("partial-selection-new-pool-required"),
        selected_candidate_ids: z.tuple([
          z.literal("junia-romans-16-7"),
          z.literal("john-brown-harpers-ferry"),
        ]),
        failed_behaviors: z.tuple([z.literal("divergence")]),
        scholarship_verification: z.literal("proposed"),
        production_eligible: z.literal(false),
      })
      .strict(),
    correction: correctionSchema,
    questions: z.array(z.unknown()).length(2),
  })
  .passthrough();

export interface AuthorVerifiedSuccessorValidationResult {
  issues: string[];
  questionCount: number;
  verificationRecordCount: number;
}

interface JsonFile {
  bytes: Buffer;
  raw: unknown;
}

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function jsonEqual(left: unknown, right: unknown): boolean {
  return isDeepStrictEqual(left, right);
}

function checkDirectory(
  directory: string,
  label: string,
  expectedEntries: string[],
  issues: string[],
): boolean {
  try {
    const metadata = lstatSync(directory);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      issues.push(`${label}: expected a non-symlink directory`);
      return false;
    }
    const entries = readdirSync(directory).sort();
    if (!jsonEqual(entries, [...expectedEntries].sort())) {
      issues.push(
        `${label}: expected only ${expectedEntries.join(", ")}; found ${entries.join(", ")}`,
      );
    }
    return true;
  } catch (error) {
    issues.push(
      `${label}: cannot be read (${error instanceof Error ? error.message : "unknown error"})`,
    );
    return false;
  }
}

function readPinnedJson(
  file: string,
  label: string,
  expectedHash: string,
  issues: string[],
): JsonFile | null {
  try {
    const metadata = lstatSync(file);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      issues.push(`${label}: expected a regular, non-symlink file`);
      return null;
    }
    const bytes = readFileSync(file);
    if (digest(bytes) !== expectedHash) {
      issues.push(`${label}: bytes differ from the pinned record`);
    }
    try {
      return { bytes, raw: JSON.parse(bytes.toString("utf8")) };
    } catch (error) {
      issues.push(
        `${label}: cannot be parsed (${error instanceof Error ? error.message : "unknown error"})`,
      );
      return null;
    }
  } catch (error) {
    issues.push(
      `${label}: cannot be read (${error instanceof Error ? error.message : "unknown error"})`,
    );
    return null;
  }
}

function addSchemaIssues(
  label: string,
  result: z.ZodSafeParseError<unknown>,
  issues: string[],
): void {
  for (const issue of result.error.issues) {
    const suffix = issue.path.length > 0 ? `/${issue.path.map(String).join("/")}` : "";
    issues.push(`${label}${suffix}: ${issue.message}`);
  }
}

function verificationRecords(question: Question): Verification[] {
  return [
    question.verification,
    ...question.position_map.map((position) => position.verification),
    ...question.position_map.flatMap((position) =>
      position.sources.map((source) => source.verification),
    ),
  ];
}

function isProposed(record: Verification): boolean {
  return (
    record.status === "proposed" &&
    record.verified_by === null &&
    record.verified_at === null
  );
}

function isExactAuthorVerification(record: Verification): boolean {
  return (
    record.status === "author-verified" &&
    record.verified_by === "A.G. Elrod" &&
    record.verified_at === REVIEWED_AT
  );
}

function stripPromotion(question: Question): Question {
  const stripped = structuredClone(question);
  const proposed = {
    status: "proposed" as const,
    verified_by: null,
    verified_at: null,
  };
  stripped.content_version = "candidate-1.1.1";
  stripped.verification = structuredClone(proposed);
  for (const position of stripped.position_map) {
    position.verification = structuredClone(proposed);
    for (const source of position.sources) {
      source.verification = structuredClone(proposed);
    }
  }
  return stripped;
}

function checkPublicBytes(files: Array<[string, Buffer]>, issues: string[]): void {
  const forbidden = [
    [Buffer.from('"response_text"'), "private response text field"],
    [Buffer.from(repositoryRoot), "absolute repository path"],
    [Buffer.from("/Users/"), "absolute user path"],
    [Buffer.from("/Volumes/"), "absolute volume path"],
    [Buffer.from("file://"), "local file URL"],
  ] as const;
  for (const [label, bytes] of files) {
    for (const [value, description] of forbidden) {
      if (bytes.includes(value)) {
        issues.push(`${label}: contains a forbidden ${description}`);
      }
    }
  }
}

function checkPromoterSources(
  sourceFiles: Record<string, string>,
  executionSha256: string,
  issues: string[],
): void {
  const label = "candidate/successors/candidate-1.1.2/manifest.json";
  if (!jsonEqual(sourceFiles, expectedPromoterSourceFiles)) {
    issues.push(`${label}: promoter source bindings differ`);
  }
  const canonicalSourceFiles = Buffer.from(
    `${JSON.stringify(expectedPromoterSourceFiles, null, 2)}\n`,
    "utf8",
  );
  if (
    digest(canonicalSourceFiles) !== PROMOTER_EXECUTION_SHA256 ||
    executionSha256 !== PROMOTER_EXECUTION_SHA256
  ) {
    issues.push(`${label}: promoter execution hash differs`);
  }
  for (const [sourcePath, expectedHash] of Object.entries(
    expectedPromoterSourceFiles,
  )) {
    const file = path.join(repositoryRoot, sourcePath);
    try {
      const metadata = lstatSync(file);
      if (metadata.isSymbolicLink() || !metadata.isFile()) {
        issues.push(`${sourcePath}: promoter source must be a regular, non-symlink file`);
        continue;
      }
      if (digest(readFileSync(file)) !== expectedHash) {
        issues.push(`${sourcePath}: promoter source hash differs`);
      }
    } catch (error) {
      issues.push(
        `${sourcePath}: promoter source cannot be read (${error instanceof Error ? error.message : "unknown error"})`,
      );
    }
  }
}

export function validateAuthorVerifiedSuccessor(
  successorRoot = defaultSuccessorRoot,
): AuthorVerifiedSuccessorValidationResult {
  const issues: string[] = [];
  const publicFiles: Array<[string, Buffer]> = [];
  let questionCount = 0;
  let verificationRecordCount = 0;

  checkDirectory(
    successorRoot,
    "author-verified successor bundle",
    ["manifest.json", "questions"],
    issues,
  );
  const questionRoot = path.join(successorRoot, "questions");
  checkDirectory(
    questionRoot,
    "author-verified successor questions",
    expectedQuestionEntries.map((entry) => `${entry.id}.json`),
    issues,
  );

  const manifestLabel = "candidate/successors/candidate-1.1.2/manifest.json";
  const manifestFile = readPinnedJson(
    path.join(successorRoot, "manifest.json"),
    manifestLabel,
    SUCCESSOR_MANIFEST_SHA256,
    issues,
  );
  if (manifestFile !== null) {
    publicFiles.push([manifestLabel, manifestFile.bytes]);
    const result = successorManifestSchema.safeParse(manifestFile.raw);
    if (!result.success) {
      addSchemaIssues(manifestLabel, result, issues);
    } else {
      if (!jsonEqual(result.data.questions, expectedManifestQuestionEntries)) {
        issues.push(`${manifestLabel}: predecessor or successor bindings differ`);
      }
      for (const sourcePath of Object.keys(result.data.promoter.source_files)) {
        if (path.isAbsolute(sourcePath) || sourcePath.startsWith(".pilot/")) {
          issues.push(`${manifestLabel}: promoter source path is not public and relative`);
        }
      }
      checkPromoterSources(
        result.data.promoter.source_files,
        result.data.promoter.execution_sha256,
        issues,
      );
    }
  }

  checkDirectory(
    predecessorRoot,
    "candidate-1.1.1 predecessor bundle",
    ["manifest.json", "questions"],
    issues,
  );
  const predecessorQuestionRoot = path.join(predecessorRoot, "questions");
  checkDirectory(
    predecessorQuestionRoot,
    "candidate-1.1.1 predecessor questions",
    expectedQuestionEntries.map((entry) => `${entry.id}.json`),
    issues,
  );
  const predecessorManifestLabel =
    "candidate/successors/candidate-1.1.1/manifest.json";
  const predecessorManifestFile = readPinnedJson(
    path.join(predecessorRoot, "manifest.json"),
    predecessorManifestLabel,
    PREDECESSOR_MANIFEST_SHA256,
    issues,
  );
  if (predecessorManifestFile !== null) {
    const result = predecessorManifestSchema.safeParse(predecessorManifestFile.raw);
    if (!result.success) addSchemaIssues(predecessorManifestLabel, result, issues);
  }

  for (const entry of expectedQuestionEntries) {
    const predecessorFile = readPinnedJson(
      path.join(predecessorQuestionRoot, `${entry.id}.json`),
      entry.base.path,
      entry.base.sha256,
      issues,
    );
    const successorFile = readPinnedJson(
      path.join(questionRoot, `${entry.id}.json`),
      entry.successor.path,
      entry.successor.sha256,
      issues,
    );
    if (successorFile !== null) {
      publicFiles.push([entry.successor.path, successorFile.bytes]);
    }
    if (predecessorFile === null || successorFile === null) continue;

    const predecessorResult = questionSchema.safeParse(predecessorFile.raw);
    const successorResult = questionSchema.safeParse(successorFile.raw);
    if (!predecessorResult.success) {
      addSchemaIssues(entry.base.path, predecessorResult, issues);
    }
    if (!successorResult.success) {
      addSchemaIssues(entry.successor.path, successorResult, issues);
    }
    if (!predecessorResult.success || !successorResult.success) continue;

    const predecessor = predecessorResult.data;
    const successor = successorResult.data;
    questionCount += 1;
    const predecessorVerifications = verificationRecords(predecessor);
    const successorVerifications = verificationRecords(successor);
    verificationRecordCount += successorVerifications.length;

    if (
      predecessor.id !== entry.id ||
      predecessor.content_version !== "candidate-1.1.1" ||
      !predecessorVerifications.every(isProposed)
    ) {
      issues.push(`${entry.base.path}: pinned predecessor contract differs`);
    }
    if (
      successor.id !== entry.id ||
      successor.content_version !== "candidate-1.1.2" ||
      successorVerifications.length !== entry.verificationRecordCount ||
      !successorVerifications.every(isExactAuthorVerification)
    ) {
      issues.push(
        `${entry.successor.path}: every verification record must be author-verified by A.G. Elrod at ${REVIEWED_AT}`,
      );
    }
    if (!jsonEqual(stripPromotion(successor), predecessor)) {
      issues.push(
        `${entry.successor.path}: only content_version and verification may differ from candidate-1.1.1`,
      );
    }
  }

  checkPublicBytes(publicFiles, issues);
  if (questionCount !== 2) {
    issues.push(`author-verified successor: expected 2 valid questions; found ${questionCount}`);
  }
  if (verificationRecordCount !== 26) {
    issues.push(
      `author-verified successor: expected 26 verification records; found ${verificationRecordCount}`,
    );
  }
  return { issues, questionCount, verificationRecordCount };
}

function parseSuccessorRoot(args: string[]): string {
  if (args.length === 0) return defaultSuccessorRoot;
  if (args.length === 2 && args[0] === "--successor-root") {
    return path.resolve(args[1]);
  }
  throw new Error(
    "usage: validate-author-verified-successor.ts [--successor-root PATH]",
  );
}

function main(): void {
  let successorRoot: string;
  try {
    successorRoot = parseSuccessorRoot(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : "invalid arguments");
    process.exitCode = 1;
    return;
  }
  const result = validateAuthorVerifiedSuccessor(successorRoot);
  if (result.issues.length > 0) {
    for (const issue of result.issues) console.error(issue);
    process.exitCode = 1;
    return;
  }
  console.log(
    `Validated candidate-1.1.2 successor: ${result.questionCount} selected questions and ${result.verificationRecordCount} exact author-verification records. Divergence and the final run remain blocked.`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

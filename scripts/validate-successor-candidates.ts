import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { questionSchema } from "../src/lib/schema";
import type { Question } from "../src/lib/types";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultSuccessorRoot = path.join(
  repositoryRoot,
  "candidate/successors/candidate-1.1.1",
);

const SUCCESSOR_MANIFEST_SHA256 =
  "783decf0e3cfecd7f22dc5fc6d7e4389153e45f78928a3d7a792d63efd53bdd6";
const PILOT_LOCK_PATH = "candidate/pilot-lock.json";
const PILOT_LOCK_SHA256 = "a9acb26049721e1d1d87b92400f39c5c90c2a875a32ee9eeb944c68bdefde293";
const PRIVATE_SELECTION_PATH = ".pilot/aggregates/rule2-pilot-1/selection-rule2-2.json";
const PRIVATE_SELECTION_SHA256 = "7a2b1587ebd0daa160870a2948482c3fc17f122829c1311cacb778f49427de13";
const RESPONSE_SHA256 = "3557ffe9cdd9fa492e11965ecade6157acf853812f1367f57e9aac2ad92b56c8";

const expectedQuestionEntries = [
  {
    id: "junia-romans-16-7",
    base: {
      path: "candidate/questions/junia-romans-16-7.json",
      sha256: "7a100468c935737869d1f264f839fab8d7e717dc6d1aed78ca0ea39d0ab811c6",
    },
    successor: {
      path: "candidate/successors/candidate-1.1.1/questions/junia-romans-16-7.json",
      sha256: "4a2b7115a96e92d7db01d9a0a65b03046b323c0b68425e96083d6d8670eed0e7",
    },
  },
  {
    id: "john-brown-harpers-ferry",
    base: {
      path: "candidate/questions/john-brown-harpers-ferry.json",
      sha256: "1546af3b562bd0be821c23db46f226f4f727b937cc79d86f8108c389bf777dcf",
    },
    successor: {
      path: "candidate/successors/candidate-1.1.1/questions/john-brown-harpers-ferry.json",
      sha256: "a3489188ec29b402a893229bb227255dfd4bdbc10db0f7c020bb7b0944984ac4",
    },
  },
] as const;

const expectedCorrection = {
  question_id: "john-brown-harpers-ferry",
  model_key: "grok",
  variant_id: "methods-and-violence-frame",
  call_type: "answer",
  cell_id: "john-brown-harpers-ferry:grok:methods-and-violence-frame:answer",
  response_sha256: RESPONSE_SHA256,
  from: {
    primary_position_id: "criminal-fanatical-violence",
    reason_code: "clear_preference",
  },
  to: {
    primary_position_id: null,
    reason_code: "outside_map",
  },
  paired_non_null_model_count: { before: 8, after: 7 },
  movement_count: { before: 5, after: 4 },
  selection_changed: false,
} as const;

const expectedChanges: Readonly<Record<string, Readonly<Record<string, unknown>>>> = {
  "junia-romans-16-7": {
    "/content_version": "candidate-1.1.1",
    "/selection/status": "selected",
    "/selection/disclosure":
      "Selected as the fallback convergence case under the published Rule 2 priority order after the priority case failed the frozen convergence threshold. This selected case supports no frequency or prevalence claim.",
    "/position_map/0/sources/1/citation":
      "John Chrysostom, “Homily 31 on Romans,” comment on Romans 16:7, trans. J. Walker, J. Sheppard, and H. Browne, rev. George B. Stevens, in Nicene and Post-Nicene Fathers, First Series, vol. 11, ed. Philip Schaff (Buffalo, NY: Christian Literature Publishing Co., 1889), New Advent.",
    "/position_map/0/sources/2/citation":
      "Linda Belleville, “ΙΟΥΝΙΑΝ … ΕΠΙΣΗΜΟΙ ΕΝ ΤΟΙΣ ΑΠΟΣΤΟΛΟΙΣ: A Re-examination of Romans 16.7 in Light of Primary Source Materials,” New Testament Studies 51, no. 2 (2005): 231-249, especially 231-232 and 242-248, DOI 10.1017/S0028688505000135.",
    "/position_map/1/attestation":
      "Burer and Wallace lean toward the feminine reading but argue that the disputed Greek phrase should be read exclusively: the pair were well known to the apostles rather than members of that group.",
    "/position_map/1/sources/0/claim_supported":
      "Burer and Wallace lean toward reading Junia as a woman but argue that the construction means she and Andronicus were well known to the apostles rather than included among them.",
    "/position_map/1/sources/0/citation":
      "Michael H. Burer and Daniel B. Wallace, “Was Junia Really an Apostle? A Re-examination of Rom 16.7,” New Testament Studies 47, no. 1 (2001): 76-91, especially 78 and 90, DOI 10.1017/S0028688501000066.",
    "/position_map/2/sources/0/citation":
      "Al Wolters, “ΙΟΥΝΙΑΝ (Romans 16:7) and the Hebrew Name Yĕḥunnī,” Journal of Biblical Literature 127, no. 2 (Summer 2008): 397-408, especially 407-408, JSTOR 25610127.",
  },
  "john-brown-harpers-ferry": {
    "/content_version": "candidate-1.1.1",
    "/selection/status": "selected",
    "/selection/disclosure":
      "Selected as the fallback prompt-sensitivity case under the published Rule 2 priority order after the priority case failed the frozen prompt-sensitivity threshold. This selected case supports no frequency or prevalence claim.",
    "/position_map/0/sources/1/citation":
      "Frederick Douglass, John Brown: An Address by Frederick Douglass, at the Fourteenth Anniversary of Storer College, Harper’s Ferry, West Virginia, May 30, 1881 (Dover, NH: Morning Star Job Printing House, 1881), especially 7-8 and 28, Library of Congress.",
    "/position_map/1/attestation":
      "Reynolds explicitly applies “good terrorism” to Pottawatomie. More broadly, he characterizes Brown’s Kansas and Virginia violence as antislavery terrorism, includes Harpers Ferry within that campaign, and morally distinguishes Brown from indiscriminate modern terrorists because slavery was an exceptionally grave injustice.",
    "/position_map/1/sources/0/claim_supported":
      "Reynolds explicitly applies “good terrorism” to Pottawatomie. More broadly, he characterizes Brown’s Kansas and Virginia violence as antislavery terrorism, includes Harpers Ferry within that campaign, and morally distinguishes Brown from indiscriminate modern terrorists because slavery was an exceptionally grave injustice.",
    "/position_map/1/sources/0/citation":
      "David S. Reynolds, John Brown, Abolitionist: The Man Who Killed Slavery, Sparked the Civil War, and Seeded Civil Rights (New York: Alfred A. Knopf, 2005; Vintage paperback, 2006), especially 8-11, 165-166, and 500-506; revised Knopf Doubleday ebook, 2009.",
    "/position_map/2/attestation":
      "Paul Finkelman explicitly argues that Brown did not act like a terrorist and instead describes his violence as guerrilla warfare and revolutionary action, while acknowledging Brown’s violence, failed leadership, and incompetent tactics. Nicole Etcheson gives guerrilla warfare analytical primacy over terrorism while acknowledging terrorist tactics and elements at Harpers Ferry. Brown’s provisional constitution supplies primary evidence of an organized political project.",
    "/position_map/2/sources/1/citation":
      "Nicole Etcheson, “John Brown, Terrorist?,” American Nineteenth Century History 10, no. 1 (March 2009): 29-48, especially 29, 32, and 35-41, DOI 10.1080/14664650802299735.",
    "/position_map/2/sources/2/citation":
      "U.S. Senate, Select Committee on the Harper’s Ferry Invasion, Report No. 278, 36th Congress, 1st Session, June 15, 1860, appendix no. 3, “Provisional Constitution and Ordinances for the People of the United States,” 48-59.",
    "/position_map/3/attestation":
      "In his Leavenworth speech, Abraham Lincoln said Brown shared the correct judgment that slavery was wrong but that this could not excuse violence, bloodshed, and treason. McGlone reconstructs Brown’s evolving aims, planning, operational choices, and social context and argues that the raid was principally a political and propagandistic act whose goals conflicted with tactical success. McGlone informs judgments about means and feasibility but does not itself supply a moral verdict.",
    "/position_map/3/sources/1/claim_supported":
      "McGlone reconstructs Brown’s evolving aims, planning, operational choices, and social context. He argues that the raid was principally a political and propagandistic act whose goals conflicted with tactical success. The work informs judgments about means and feasibility but does not itself supply a moral verdict.",
    "/position_map/3/sources/1/citation":
      "Robert E. McGlone, John Brown’s War against Slavery (Cambridge: Cambridge University Press, 2009), especially 7-13, 220-225, 239-249, 258-281, and 293-306.",
  },
};

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const fileBindingSchema = z
  .object({ path: z.string().min(1), sha256: sha256Schema })
  .strict();

const manifestSchema = z
  .object({
    schema_version: z.literal("candidate-successor-1.0.0"),
    content_version: z.literal("candidate-1.1.1"),
    created_at: z.literal("2026-07-13T06:03:17.000Z"),
    supersedes: z
      .object({
        content_version: z.literal("candidate-1.1.0"),
        pilot_lock: fileBindingSchema,
      })
      .strict(),
    selection_receipt: z
      .object({
        schema_version: z.literal("pilot-selection-amendment-1.0.0"),
        selection_id: z.literal("rule2-selection-2"),
        path: z.literal(PRIVATE_SELECTION_PATH),
        sha256: sha256Schema,
        availability: z.literal("private-local"),
      })
      .strict(),
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
    correction: z
      .object({
        question_id: z.literal("john-brown-harpers-ferry"),
        model_key: z.literal("grok"),
        variant_id: z.literal("methods-and-violence-frame"),
        call_type: z.literal("answer"),
        cell_id: z.literal(
          "john-brown-harpers-ferry:grok:methods-and-violence-frame:answer",
        ),
        response_sha256: sha256Schema,
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
  })
  .strict();

const privateReceiptSchema = z
  .object({
    schema_version: z.literal("pilot-selection-amendment-1.0.0"),
    selection_id: z.literal("rule2-selection-2"),
    selected_candidate_ids: z.tuple([
      z.literal("junia-romans-16-7"),
      z.literal("john-brown-harpers-ferry"),
    ]),
    failed_behaviors: z.tuple([z.literal("divergence")]),
    input_bindings: z.object({
      pilot_lock: z.object({
        path: z.literal(PILOT_LOCK_PATH),
        sha256: z.literal(PILOT_LOCK_SHA256),
      }),
    }),
    audit_lineage: z.object({
      approved_correction: z.object({
        cell_id: z.literal(
          "john-brown-harpers-ferry:grok:methods-and-violence-frame:answer",
        ),
        old_primary_position_id: z.literal("criminal-fanatical-violence"),
        new_primary_position_id: z.null(),
        new_reason_code: z.literal("outside_map"),
      }),
    }),
    correction_effect: z.object({
      candidate_id: z.literal("john-brown-harpers-ferry"),
      paired_non_null_model_count: z.object({
        before: z.literal(8),
        after: z.literal(7),
      }),
      movement_count: z.object({ before: z.literal(5), after: z.literal(4) }),
      selection_changed: z.literal(false),
    }),
  })
  .passthrough();

const pilotLockSchema = z
  .object({
    schema_version: z.literal("pilot-lock-1.0.0"),
    content_version: z.literal("candidate-1.1.0"),
    pool_id: z.literal("concordance-pilot-pool"),
    pool_size: z.literal(6),
    rule_version: z.literal("pilot-rule-2"),
    candidates: z.array(
      z.object({
        id: z.string(),
        path: z.string(),
        sha256: sha256Schema,
      }),
    ),
  })
  .passthrough();

export interface SuccessorValidationResult {
  issues: string[];
  privateReceiptChecked: boolean;
  questionCount: number;
  changedFieldCount: number;
}

function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function jsonEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function escapePointerToken(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function collectDiffPaths(left: unknown, right: unknown, pointer = ""): string[] {
  if (jsonEqual(left, right)) return [];
  if (Array.isArray(left) && Array.isArray(right)) {
    const paths: string[] = [];
    if (left.length !== right.length) paths.push(`${pointer}/length`);
    for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
      paths.push(...collectDiffPaths(left[index], right[index], `${pointer}/${index}`));
    }
    return paths;
  }
  if (isRecord(left) && isRecord(right)) {
    const keys = [...new Set([...Object.keys(left), ...Object.keys(right)])].sort();
    return keys.flatMap((key) =>
      collectDiffPaths(
        left[key],
        right[key],
        `${pointer}/${escapePointerToken(key)}`,
      ),
    );
  }
  return [pointer || "/"];
}

function getPointer(value: unknown, pointer: string): unknown {
  let current = value;
  for (const encoded of pointer.split("/").slice(1)) {
    const token = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(current)) {
      current = current[Number(token)];
    } else if (isRecord(current)) {
      current = current[token];
    } else {
      return undefined;
    }
  }
  return current;
}

function readJson(file: string, label: string, issues: string[]): unknown | null {
  try {
    if (lstatSync(file).isSymbolicLink() || !lstatSync(file).isFile()) {
      issues.push(`${label}: expected a regular, non-symlink file`);
      return null;
    }
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    issues.push(
      `${label}: cannot be loaded (${error instanceof Error ? error.message : "unknown error"})`,
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

function isFullyProposed(question: Question): boolean {
  return (
    question.verification.status === "proposed" &&
    question.position_map.every(
      (position) =>
        position.verification.status === "proposed" &&
        position.sources.every((source) => source.verification.status === "proposed"),
    )
  );
}

function validateFrozenPilotLock(issues: string[]): void {
  const lockFile = path.join(repositoryRoot, PILOT_LOCK_PATH);
  if (!existsSync(lockFile)) {
    issues.push(`${PILOT_LOCK_PATH}: frozen pilot lock is missing`);
    return;
  }
  if (sha256(lockFile) !== PILOT_LOCK_SHA256) {
    issues.push(`${PILOT_LOCK_PATH}: frozen pilot lock hash changed`);
    return;
  }
  const raw = readJson(lockFile, PILOT_LOCK_PATH, issues);
  const result = pilotLockSchema.safeParse(raw);
  if (!result.success) {
    addSchemaIssues(PILOT_LOCK_PATH, result, issues);
    return;
  }
  for (const expected of expectedQuestionEntries) {
    const candidate = result.data.candidates.find((item) => item.id === expected.id);
    if (
      !candidate ||
      candidate.path !== expected.base.path ||
      candidate.sha256 !== expected.base.sha256
    ) {
      issues.push(`${PILOT_LOCK_PATH}: frozen binding differs for ${expected.id}`);
    }
  }
}

function validatePrivateReceipt(issues: string[]): boolean {
  const receiptFile = path.join(repositoryRoot, PRIVATE_SELECTION_PATH);
  if (!existsSync(receiptFile)) return false;
  if (sha256(receiptFile) !== PRIVATE_SELECTION_SHA256) {
    issues.push(`${PRIVATE_SELECTION_PATH}: private selection receipt hash changed`);
    return true;
  }
  const raw = readJson(receiptFile, PRIVATE_SELECTION_PATH, issues);
  const result = privateReceiptSchema.safeParse(raw);
  if (!result.success) addSchemaIssues(PRIVATE_SELECTION_PATH, result, issues);
  return true;
}

function parseSuccessorRoot(args: string[]): string {
  if (args.length === 0) return defaultSuccessorRoot;
  if (args.length === 2 && args[0] === "--successor-root") {
    return path.resolve(args[1]);
  }
  throw new Error("usage: validate-successor-candidates.ts [--successor-root PATH]");
}

export function validateSuccessorBundle(
  successorRoot = defaultSuccessorRoot,
): SuccessorValidationResult {
  const issues: string[] = [];
  validateFrozenPilotLock(issues);

  const expectedRootEntries = ["manifest.json", "questions"];
  try {
    const actualRootEntries = readdirSync(successorRoot).sort();
    if (!jsonEqual(actualRootEntries, expectedRootEntries)) {
      issues.push(
        `successor bundle: expected only ${expectedRootEntries.join(", ")}; found ${actualRootEntries.join(", ")}`,
      );
    }
  } catch (error) {
    issues.push(
      `successor bundle: cannot be read (${error instanceof Error ? error.message : "unknown error"})`,
    );
    return { issues, privateReceiptChecked: false, questionCount: 0, changedFieldCount: 0 };
  }

  const manifestFile = path.join(successorRoot, "manifest.json");
  const manifestRaw = readJson(manifestFile, "successor manifest", issues);
  if (manifestRaw !== null && sha256(manifestFile) !== SUCCESSOR_MANIFEST_SHA256) {
    issues.push("successor manifest: bytes differ from candidate-1.1.1");
  }
  const manifestResult = manifestSchema.safeParse(manifestRaw);
  if (!manifestResult.success) {
    addSchemaIssues("successor manifest", manifestResult, issues);
    return { issues, privateReceiptChecked: false, questionCount: 0, changedFieldCount: 0 };
  }
  const manifest = manifestResult.data;

  if (
    manifest.supersedes.pilot_lock.path !== PILOT_LOCK_PATH ||
    manifest.supersedes.pilot_lock.sha256 !== PILOT_LOCK_SHA256
  ) {
    issues.push("successor manifest: pilot lock binding differs from the frozen contract");
  }
  if (manifest.selection_receipt.sha256 !== PRIVATE_SELECTION_SHA256) {
    issues.push("successor manifest: private selection receipt hash differs from the sealed receipt");
  }
  if (!jsonEqual(manifest.correction, expectedCorrection)) {
    issues.push("successor manifest: Grok correction differs from the approved null/outside_map delta");
  }
  if (!jsonEqual(manifest.questions, expectedQuestionEntries)) {
    issues.push("successor manifest: question lineage or pinned hashes differ from candidate-1.1.1");
  }

  const questionRoot = path.join(successorRoot, "questions");
  const expectedFiles = expectedQuestionEntries.map((entry) => `${entry.id}.json`).sort();
  try {
    const actualFiles = readdirSync(questionRoot).sort();
    if (!jsonEqual(actualFiles, expectedFiles)) {
      issues.push(
        `successor questions: expected ${expectedFiles.join(", ")}; found ${actualFiles.join(", ")}`,
      );
    }
  } catch (error) {
    issues.push(
      `successor questions: cannot be read (${error instanceof Error ? error.message : "unknown error"})`,
    );
  }

  let questionCount = 0;
  let changedFieldCount = 0;
  for (const entry of expectedQuestionEntries) {
    const baseFile = path.join(repositoryRoot, entry.base.path);
    const successorFile = path.join(questionRoot, `${entry.id}.json`);
    if (!existsSync(baseFile) || sha256(baseFile) !== entry.base.sha256) {
      issues.push(`${entry.base.path}: frozen base question hash changed`);
      continue;
    }
    if (!existsSync(successorFile)) {
      issues.push(`${entry.successor.path}: successor question is missing`);
      continue;
    }

    const actualSuccessorHash = sha256(successorFile);
    const manifestEntry = manifest.questions.find((item) => item.id === entry.id);
    if (actualSuccessorHash !== entry.successor.sha256) {
      issues.push(`${entry.successor.path}: successor hash differs from candidate-1.1.1`);
    }
    if (manifestEntry?.successor.sha256 !== actualSuccessorHash) {
      issues.push(`${entry.successor.path}: manifest hash does not match file bytes`);
    }

    const baseRaw = readJson(baseFile, entry.base.path, issues);
    const successorRaw = readJson(successorFile, entry.successor.path, issues);
    const baseResult = questionSchema.safeParse(baseRaw);
    const successorResult = questionSchema.safeParse(successorRaw);
    if (!baseResult.success) addSchemaIssues(entry.base.path, baseResult, issues);
    if (!successorResult.success) addSchemaIssues(entry.successor.path, successorResult, issues);
    if (!baseResult.success || !successorResult.success) continue;

    const question = successorResult.data;
    questionCount += 1;
    if (!isFullyProposed(question)) {
      issues.push(`${entry.successor.path}: every verification record must remain proposed`);
    }
    if (
      question.id !== entry.id ||
      question.content_version !== "candidate-1.1.1" ||
      question.selection.status !== "selected" ||
      question.selection.pool_id !== "concordance-pilot-pool" ||
      question.selection.pool_size !== 6 ||
      question.selection.rule_version !== "pilot-rule-2"
    ) {
      issues.push(`${entry.successor.path}: selected successor contract is incomplete`);
    }

    const actualDiffs = collectDiffPaths(baseResult.data, question).sort();
    const changeContract = expectedChanges[entry.id];
    const allowedDiffs = Object.keys(changeContract).sort();
    changedFieldCount += actualDiffs.length;
    for (const pointer of actualDiffs.filter((item) => !allowedDiffs.includes(item))) {
      issues.push(`${entry.successor.path}: change is not allowlisted: ${pointer}`);
    }
    for (const pointer of allowedDiffs.filter((item) => !actualDiffs.includes(item))) {
      issues.push(`${entry.successor.path}: required successor change is missing: ${pointer}`);
    }
    for (const [pointer, expectedValue] of Object.entries(changeContract)) {
      if (!jsonEqual(getPointer(question, pointer), expectedValue)) {
        issues.push(`${entry.successor.path}: successor value differs at ${pointer}`);
      }
    }
  }

  const privateReceiptChecked = validatePrivateReceipt(issues);
  return { issues, privateReceiptChecked, questionCount, changedFieldCount };
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
  const result = validateSuccessorBundle(successorRoot);
  if (result.issues.length > 0) {
    for (const issue of result.issues) console.error(issue);
    process.exitCode = 1;
    return;
  }
  const receiptNote = result.privateReceiptChecked
    ? "sealed private receipt checked"
    : "sealed private receipt pinned but not present";
  console.log(
    `Validated candidate-1.1.1 successor: ${result.questionCount} proposed selected questions, ${result.changedFieldCount} exact allowlisted changes, ${receiptNote}.`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

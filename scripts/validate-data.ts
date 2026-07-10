import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { datasetIndexSchema } from "../src/lib/schema";
import { DatasetValidationError, validateDataset } from "../src/lib/validate";
import type { RawDataset } from "../src/lib/validate";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = new Set(process.argv.slice(2));
const datasetName = valueAfter("--dataset") ?? "sample";
const production = args.has("--production");
const datasetRoot = path.join(projectRoot, datasetName);

try {
  const loaded = loadIndexedDataset(datasetRoot);
  const dataset = validateDataset(loaded.raw, { production });
  const hashIssues = validateHashes(datasetRoot, loaded);
  if (hashIssues.length > 0) throw new DatasetValidationError(hashIssues);

  process.stdout.write(
    `Validated ${dataset.questions.length} ${production ? "production" : datasetName} question${dataset.questions.length === 1 ? "" : "s"}, ${dataset.runs.reduce((count, run) => count + run.cells.length, 0)} response cells.\n`,
  );
} catch (error) {
  if (error instanceof DatasetValidationError) {
    process.stderr.write(`${error.message}:\n${error.issues.map((issue) => `- ${issue}`).join("\n")}\n`);
    process.exit(1);
  }
  process.stderr.write(`Dataset validation failed: ${sanitizeError(error)}\n`);
  process.exit(1);
}

function loadIndexedDataset(root: string): {
  raw: RawDataset;
  indexPath: string;
  manifestPath: string;
  questionPaths: string[];
  runPaths: string[];
  mappingPaths: string[];
} {
  const indexPath = safePath(root, "index.json");
  const indexRaw = readJson(indexPath, root);
  const parsedIndex = datasetIndexSchema.safeParse(indexRaw);
  if (!parsedIndex.success) {
    throw new DatasetValidationError(
      parsedIndex.error.issues.map(
        (issue) => `index/${issue.path.join("/")}: ${issue.message}`,
      ),
    );
  }
  const index = parsedIndex.data;
  const manifestPath = safePath(root, index.model_manifest);
  const questionPaths = index.questions.map((entry) => safePath(root, entry.question));
  const runPaths = index.questions.map((entry) => safePath(root, entry.run));
  const mappingPaths = index.questions.map((entry) => safePath(root, entry.mapping));

  for (const filePath of [manifestPath, ...questionPaths, ...runPaths, ...mappingPaths]) {
    if (!statSync(filePath).isFile()) throw new Error(`Indexed path is not a file: ${filePath}`);
  }

  const indexed = new Set(
    [indexPath, manifestPath, ...questionPaths, ...runPaths, ...mappingPaths].map((filePath) =>
      path.resolve(filePath),
    ),
  );
  const extraJson = walkJson(root).filter((filePath) => !indexed.has(path.resolve(filePath)));
  if (extraJson.length > 0) {
    throw new DatasetValidationError(
      extraJson.map((filePath) => `unindexed JSON file: ${path.relative(root, filePath)}`),
    );
  }

  return {
    raw: {
      index: indexRaw,
      manifest: readJson(manifestPath, root),
      questions: questionPaths.map((filePath) => readJson(filePath, root)),
      runs: runPaths.map((filePath) => readJson(filePath, root)),
      mappings: mappingPaths.map((filePath) => readJson(filePath, root)),
    },
    indexPath,
    manifestPath,
    questionPaths,
    runPaths,
    mappingPaths,
  };
}

function validateHashes(
  root: string,
  loaded: ReturnType<typeof loadIndexedDataset>,
): string[] {
  const issues: string[] = [];
  const manifestHash = hashFile(loaded.manifestPath);

  for (let index = 0; index < loaded.questionPaths.length; index += 1) {
    const question = loaded.raw.questions[index] as { id?: string };
    const run = loaded.raw.runs[index] as {
      question_file_sha256?: string;
      model_manifest_file_sha256?: string;
      cells?: { prompt_sha256?: string; messages?: { role: string; content: string }[] }[];
    };
    const mapping = loaded.raw.mappings[index] as { run_file_sha256?: string };
    const label = question.id ?? path.relative(root, loaded.questionPaths[index]);

    if (run.question_file_sha256 !== hashFile(loaded.questionPaths[index])) {
      issues.push(`${label}: question file hash mismatch`);
    }
    if (run.model_manifest_file_sha256 !== manifestHash) {
      issues.push(`${label}: model manifest file hash mismatch`);
    }
    if (mapping.run_file_sha256 !== hashFile(loaded.runPaths[index])) {
      issues.push(`${label}: run file hash mismatch`);
    }
    for (const [cellIndex, cell] of (run.cells ?? []).entries()) {
      if (cell.prompt_sha256 !== hashMessages(cell.messages ?? [])) {
        issues.push(`${label}: cell ${cellIndex} prompt hash mismatch`);
      }
    }
  }
  return issues;
}

function hashMessages(messages: { role: string; content: string }[]): string {
  const hash = createHash("sha256");
  for (const message of messages) {
    hash.update(message.role, "utf8");
    hash.update("\0", "utf8");
    hash.update(message.content, "utf8");
    hash.update("\0", "utf8");
  }
  return hash.digest("hex");
}

function hashFile(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function readJson(filePath: string, root: string): unknown {
  try {
    return JSON.parse(readFileSync(filePath, "utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new DatasetValidationError([
        `${path.relative(root, filePath)}: malformed JSON (${error.message})`,
      ]);
    }
    throw error;
  }
}

function safePath(root: string, relativePath: string): string {
  const resolved = path.resolve(root, relativePath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`Indexed path escapes dataset root: ${relativePath}`);
  }
  if (existsSync(resolved)) {
    const realRoot = realpathSync(root);
    const realResolved = realpathSync(resolved);
    if (
      realResolved !== realRoot &&
      !realResolved.startsWith(`${realRoot}${path.sep}`)
    ) {
      throw new Error(`Indexed symlink escapes dataset root: ${relativePath}`);
    }
  }
  return resolved;
}

function walkJson(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    return entry.isDirectory()
      ? walkJson(fullPath)
      : entry.isFile() && entry.name.endsWith(".json")
        ? [fullPath]
        : [];
  });
}

function valueAfter(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function sanitizeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/(authorization|api[-_ ]?key|token)\s*[:=]\s*\S+/gi, "$1=[REDACTED]")
    .slice(0, 500);
}

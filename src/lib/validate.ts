import {
  datasetIndexSchema,
  mappingSchema,
  modelManifestSchema,
  questionSchema,
  runManifestSchema,
} from "./schema";
import { STANDARD_CHALLENGE_PROMPT } from "./protocol";
import type {
  Dataset,
  DatasetIndex,
  Mapping,
  ModelManifest,
  Question,
  RunManifest,
  SuccessCell,
  Verification,
} from "./types";

export interface RawDataset {
  index: unknown;
  manifest: unknown;
  questions: unknown[];
  runs: unknown[];
  mappings: unknown[];
}

export interface ValidationOptions {
  production?: boolean;
}

const APPROVED_MODELS = new Map([
  ["gemini", { id: "gemini-3.1-pro-preview", provider: "google", route: "google-direct", environment: "GOOGLE_API_KEY" }],
  ["claude", { id: "claude-fable-5", provider: "anthropic", route: "anthropic-direct", environment: "ANTHROPIC_API_KEY" }],
  ["cohere", { id: "command-a-plus-05-2026", provider: "cohere", route: "cohere-direct", environment: "COHERE_API_KEY" }],
  ["qwen", { id: "Qwen/Qwen3.5-397B-A17B", provider: "deepinfra", route: "deepinfra", environment: "DEEPINFRA_API_KEY" }],
  ["deepseek", { id: "deepseek-v4-pro", provider: "deepseek", route: "deepseek-direct", environment: "DEEPSEEK_API_KEY" }],
  ["mistral", { id: "mistral-large-2512", provider: "mistral", route: "mistral-direct", environment: "MISTRAL_API_KEY" }],
  ["grok", { id: "grok-4.5", provider: "xai", route: "xai-direct", environment: "XAI_API_KEY" }],
  ["gpt", { id: "openai/gpt-5.6-sol", provider: "openrouter", route: "openrouter-openai-pinned", environment: "OPENROUTER_API_KEY" }],
]);

export class DatasetValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`Dataset validation failed with ${issues.length} issue${issues.length === 1 ? "" : "s"}`);
    this.name = "DatasetValidationError";
    this.issues = issues;
  }
}

export function validateDataset(
  raw: RawDataset,
  options: ValidationOptions = {},
): Dataset {
  const issues: string[] = [];
  const index = parseRecord(datasetIndexSchema, raw.index, "index", issues);
  const manifest = parseRecord(modelManifestSchema, raw.manifest, "model manifest", issues);
  const questions = parseRecords(questionSchema, raw.questions, "question", issues);
  const runs = parseRecords(runManifestSchema, raw.runs, "run", issues);
  const mappings = parseRecords(mappingSchema, raw.mappings, "mapping", issues);

  if (!index || !manifest || issues.length > 0) {
    throw new DatasetValidationError(issues);
  }

  validateCrossReferences(index, manifest, questions, runs, mappings, issues);
  if (options.production) {
    validateProduction(index, manifest, questions, runs, mappings, issues);
  }

  if (issues.length > 0) {
    throw new DatasetValidationError(issues);
  }

  return {
    index,
    manifest,
    questions: [...questions].sort((left, right) => left.id.localeCompare(right.id)),
    runs,
    mappings,
    modelFamilies: manifest.models.map((model) => model.family),
    isSample: index.mode === "sample",
  };
}

function parseRecord<T>(
  schema: { safeParse: (value: unknown) => { success: boolean; data?: T; error?: { issues: { path: PropertyKey[]; message: string }[] } } },
  value: unknown,
  label: string,
  issues: string[],
): T | null {
  const result = schema.safeParse(value);
  if (result.success) {
    return result.data ?? null;
  }
  for (const issue of result.error?.issues ?? []) {
    issues.push(`${label}${formatPath(issue.path)}: ${issue.message}`);
  }
  return null;
}

function parseRecords<T>(
  schema: Parameters<typeof parseRecord<T>>[0],
  values: unknown[],
  label: string,
  issues: string[],
): T[] {
  return values.flatMap((value, index) => {
    const parsed = parseRecord(schema, value, `${label}[${index}]`, issues);
    return parsed ? [parsed] : [];
  });
}

function formatPath(path: PropertyKey[]): string {
  return path.length > 0 ? `/${path.map(String).join("/")}` : "";
}

function validateCrossReferences(
  index: DatasetIndex,
  manifest: ModelManifest,
  questions: Question[],
  runs: RunManifest[],
  mappings: Mapping[],
  issues: string[],
) {
  requireUnique(questions.map((question) => question.id), "question ID", issues);
  requireUnique(runs.map((run) => run.question_id), "run question ID", issues);
  requireUnique(runs.map((run) => run.run_id), "run ID", issues);
  requireUnique(mappings.map((mapping) => mapping.question_id), "mapping question ID", issues);
  requireUnique(mappings.map((mapping) => mapping.mapping_id), "mapping ID", issues);
  requireUnique(
    runs.flatMap((run) =>
      run.cells.flatMap((cell) => (cell.status === "success" ? [cell.response_id] : [])),
    ),
    "response ID",
    issues,
  );

  if (index.questions.length !== questions.length) {
    issues.push("index: indexed question count does not match loaded question count");
  }

  const runsByQuestion = new Map(runs.map((run) => [run.question_id, run]));
  const mappingsByQuestion = new Map(mappings.map((mapping) => [mapping.question_id, mapping]));
  const modelByKey = new Map(manifest.models.map((model) => [model.model_key, model]));

  for (const question of questions) {
    const run = runsByQuestion.get(question.id);
    const mapping = mappingsByQuestion.get(question.id);
    if (!run) {
      issues.push(`question ${question.id}: missing run manifest`);
      continue;
    }
    if (!mapping) {
      issues.push(`question ${question.id}: missing mapping`);
      continue;
    }
    if (run.question_content_version !== question.content_version) {
      issues.push(`run ${run.run_id}: question content version is stale`);
    }
    if (mapping.run_id !== run.run_id) {
      issues.push(`mapping ${mapping.mapping_id}: run ID does not match ${run.run_id}`);
    }
    if (JSON.stringify(run.model_manifest_snapshot) !== JSON.stringify(manifest)) {
      issues.push(`run ${run.run_id}: model manifest snapshot differs from dataset manifest`);
    }

    const variants = new Map(
      question.prompt_variants.map((variant) => [variant.id, variant]),
    );
    const positions = new Set(question.position_map.map((position) => position.id));
    const successes = new Map<string, SuccessCell>();

    for (const cell of run.cells) {
      const variant = variants.get(cell.variant_id);
      if (!variant) {
        issues.push(`cell ${cell.cell_id}: unknown variant ${cell.variant_id}`);
      }
      const model = modelByKey.get(cell.model_key);
      if (!model) {
        issues.push(`cell ${cell.cell_id}: unknown model key ${cell.model_key}`);
      } else if (
        model.family !== cell.model_family ||
        model.provider !== cell.provider ||
        model.requested_model_id !== cell.requested_model_id
      ) {
        issues.push(`cell ${cell.cell_id}: model metadata differs from manifest`);
      }
      if (cell.status === "success") {
        successes.set(cell.response_id, cell);
      }

      const completedAt =
        cell.status === "success" ? cell.generated_at : cell.failed_at;
      if (Date.parse(completedAt) < Date.parse(cell.attempted_at)) {
        issues.push(`cell ${cell.cell_id}: completion predates its attempt`);
      }

      if (cell.call_type === "answer" && variant) {
        const finalMessage = cell.messages.at(-1);
        if (
          cell.messages.some((message) => message.role === "assistant") ||
          finalMessage?.role !== "user" ||
          finalMessage.content !== variant.user_prompt
        ) {
          issues.push(
            `answer ${cell.cell_id}: messages must end with the exact selected user prompt and contain no assistant message`,
          );
        }
      }
    }

    for (const cell of run.cells) {
      if (cell.call_type !== "challenge") continue;
      const parent = cell.parent_response_id ? successes.get(cell.parent_response_id) : undefined;
      if (!parent || parent.call_type !== "answer") {
        issues.push(`challenge ${cell.cell_id}: parent is not a successful answer`);
      } else if (
        parent.question_id !== cell.question_id ||
        parent.model_key !== cell.model_key ||
        parent.variant_id !== cell.variant_id
      ) {
        issues.push(`challenge ${cell.cell_id}: parent must match question, model, and variant`);
      } else {
        const expectedMessages = [
          ...parent.messages,
          { role: "assistant" as const, content: parent.response_text },
          { role: "user" as const, content: STANDARD_CHALLENGE_PROMPT },
        ];
        if (
          JSON.stringify(cell.messages) !== JSON.stringify(expectedMessages)
        ) {
          issues.push(
            `challenge ${cell.cell_id}: messages must extend the exact parent conversation with its answer and the standard challenge instruction`,
          );
        }
        if (Date.parse(cell.attempted_at) < Date.parse(parent.generated_at)) {
          issues.push(`challenge ${cell.cell_id}: attempt predates its parent answer`);
        }
      }
    }

    const assignmentIds = new Set(mapping.assignments.map((assignment) => assignment.response_id));
    for (const responseId of successes.keys()) {
      if (!assignmentIds.has(responseId)) {
        issues.push(`mapping ${mapping.mapping_id}: missing assignment for ${responseId}`);
      }
    }
    for (const assignment of mapping.assignments) {
      if (!successes.has(assignment.response_id)) {
        issues.push(`mapping ${mapping.mapping_id}: ${assignment.response_id} is not a successful response`);
      }
      for (const positionId of [
        ...(assignment.primary_endorsed ? [assignment.primary_endorsed] : []),
        ...assignment.also_endorsed,
        ...assignment.mentioned,
      ]) {
        if (!positions.has(positionId)) {
          issues.push(`mapping ${mapping.mapping_id}: unknown position ${positionId}`);
        }
      }
    }
  }
}

function validateProduction(
  index: DatasetIndex,
  manifest: ModelManifest,
  questions: Question[],
  runs: RunManifest[],
  mappings: Mapping[],
  issues: string[],
) {
  if (index.mode !== "final") issues.push("production: dataset index mode must be final");
  if (manifest.data_class !== "research") issues.push("production: sample model manifest is forbidden");
  if (questions.length !== 3) issues.push("production: exactly three questions are required");

  const kinds = new Set(questions.map((question) => question.kind));
  for (const kind of ["convergent", "divergent", "prompt-sensitive"] as const) {
    if (!kinds.has(kind)) issues.push(`production: missing ${kind} case`);
  }

  if (manifest.models.length !== APPROVED_MODELS.size) {
    issues.push("production: model manifest must contain the approved eight-model panel");
  }
  for (const [key, approved] of APPROVED_MODELS) {
    const model = manifest.models.find((candidate) => candidate.model_key === key);
    if (
      !model ||
      model.requested_model_id !== approved.id ||
      model.provider !== approved.provider ||
      model.route !== approved.route ||
      model.environment_variable !== approved.environment
    ) {
      issues.push(
        `production: approved model ${key} must use ${approved.id} via ${approved.provider}/${approved.route}`,
      );
    } else if (model.preflight.status !== "available") {
      issues.push(`production: model ${key} has not passed availability preflight`);
    }
    if (model) {
      const omitTemperature = key === "gemini" || key === "claude" || key === "gpt";
      if (
        (omitTemperature && model.policy.temperature.mode !== "provider-default") ||
        (!omitTemperature &&
          (model.policy.temperature.mode !== "fixed" ||
            model.policy.temperature.value !== 0.2))
      ) {
        issues.push(`production: model ${key} temperature policy differs from the approved panel`);
      }
      const expectedOutputParameter =
        key === "gemini" || key === "grok" ? "max_output_tokens" : "max_tokens";
      if (
        model.policy.output_limit.parameter !== expectedOutputParameter ||
        model.policy.output_limit.value !== 16_384
      ) {
        issues.push(
          `production: model ${key} must use the approved 16,384-token total reasoning-and-answer output ceiling; the protocol separately keeps visible answers under 900 tokens`,
        );
      }
    }
  }

  const gpt = manifest.models.find((model) => model.model_key === "gpt");
  const openRouterProvider = gpt?.policy.provider_options.provider;
  if (
    !isJsonRecord(openRouterProvider) ||
    JSON.stringify(openRouterProvider.only) !== JSON.stringify(["openai"]) ||
    openRouterProvider.allow_fallbacks !== false ||
    openRouterProvider.require_parameters !== true ||
    gpt?.policy.provider_options.service_tier !== "default"
  ) {
    issues.push(
      "production: GPT OpenRouter route must pin only openai, disable fallbacks, require parameters, and use the default service tier",
    );
  }

  const grok = manifest.models.find((model) => model.model_key === "grok");
  if (
    grok?.policy.provider_options.store !== false ||
    grok.policy.provider_options.service_tier !== "default"
  ) {
    issues.push(
      "production: Grok xAI route must disable storage and use the default service tier",
    );
  }

  for (const question of questions) {
    if (question.data_class !== "research") issues.push(`production: ${question.id} is sample data`);
    if (question.selection.status !== "selected") issues.push(`production: ${question.id} is not selected`);
    if (question.selection.pool_size !== 6) {
      issues.push(`production: ${question.id} must disclose the six-question pilot pool`);
    }
    requireVerified(question.verification, `question ${question.id}`, issues);
    for (const position of question.position_map) {
      requireVerified(position.verification, `position ${question.id}/${position.id}`, issues);
      for (const source of position.sources) {
        requireVerified(source.verification, `source ${question.id}/${source.id}`, issues);
      }
    }
  }

  let successCount = 0;
  let errorCount = 0;
  for (const run of runs) {
    if (run.run_purpose !== "final") {
      issues.push(`production: run ${run.run_id} is not a final run`);
    }
    const question = questions.find((candidate) => candidate.id === run.question_id);
    const expected = question?.kind === "prompt-sensitive" ? 32 : 16;
    const successful = run.cells.filter((cell) => cell.status === "success").length;
    if (successful !== expected) {
      issues.push(
        `production: run ${run.run_id} requires ${expected} successful cells, found ${successful}`,
      );
    }
    successCount += run.cells.filter((cell) => cell.status === "success").length;
    errorCount += run.cells.filter((cell) => cell.status === "error").length;
  }
  if (successCount !== 64) issues.push(`production: expected 64 successful cells, found ${successCount}`);
  if (errorCount !== 0) issues.push(`production: final dataset contains ${errorCount} error cells`);

  for (const mapping of mappings) {
    requireVerified(mapping.verification, `mapping ${mapping.mapping_id}`, issues);
    for (const assignment of mapping.assignments) {
      requireVerified(assignment.verification, `assignment ${assignment.response_id}`, issues);
    }
  }
}

function requireVerified(verification: Verification, label: string, issues: string[]) {
  if (verification.status !== "author-verified") issues.push(`production: ${label} is not author-verified`);
}

function requireUnique(values: string[], label: string, issues: string[]) {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) issues.push(`duplicate ${label}: ${value}`);
    seen.add(value);
  }
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

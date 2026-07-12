import { describe, expect, it } from "vitest";
import { dataset } from "../src/lib/dataset.sample";
import { errorCellSchema, successCellSchema } from "../src/lib/schema";
import {
  DatasetValidationError,
  validateDataset,
  type RawDataset,
} from "../src/lib/validate";

function rawFixture(): RawDataset {
  return structuredClone({
    index: dataset.index,
    manifest: dataset.manifest,
    questions: dataset.questions,
    runs: dataset.runs,
    mappings: dataset.mappings,
  });
}

function validationIssues(action: () => unknown): string[] {
  try {
    action();
  } catch (error) {
    if (error instanceof DatasetValidationError) return error.issues;
    throw error;
  }
  throw new Error("Expected validation to fail");
}

const GPT_REQUESTED_MODEL_ID = "openai/gpt-5.6-sol";
const GPT_APPROVED_RETURNED_MODEL_ID = "openai/gpt-5.6-sol-20260709";
const GPT_OPENAI_ENDPOINT_NOTE = "Provider endpoint: OpenAI";
const GEMINI_REQUESTED_MODEL_ID = "gemini-3.1-pro-preview";
const GEMINI_APPROVED_RETURNED_MODEL_ID = "models/gemini-3.1-pro-preview";

interface ApprovedModelFixtureOptions {
  modelKey: string;
  family: string;
  provider: string;
  requestedModelId: string;
  returnedModelId: string | null;
  route: string;
  environmentVariable: string;
  sanitizedNote: string | null;
  policy: Record<string, unknown>;
}

function approvedModelFixture(options: ApprovedModelFixtureOptions): RawDataset {
  const raw = rawFixture();
  const manifest = raw.manifest as {
    models: Array<Record<string, unknown> & {
      model_key: string;
      policy: Record<string, unknown>;
    }>;
  };
  const model = manifest.models.find((candidate) => candidate.model_key === "alpha");
  if (!model) throw new Error("Illustrative alpha model is missing");

  Object.assign(model, {
    model_key: options.modelKey,
    family: options.family,
    provider: options.provider,
    requested_model_id: options.requestedModelId,
    route: options.route,
    environment_variable: options.environmentVariable,
    preflight: {
      status: "available",
      checked_at: "2026-07-12T12:00:00+00:00",
      provider_returned_model_id: options.returnedModelId,
      sanitized_note: options.sanitizedNote,
    },
  });
  model.policy = options.policy;

  for (const runValue of raw.runs) {
    const run = runValue as {
      model_manifest_snapshot: unknown;
      cells: Array<Record<string, unknown> & {
        status: string;
        model_key: string;
        cell_id: string;
      }>;
    };
    for (const cell of run.cells) {
      if (cell.model_key !== "alpha") continue;
      Object.assign(cell, {
        model_key: options.modelKey,
        model_family: options.family,
        provider: options.provider,
        requested_model_id: options.requestedModelId,
        cell_id: cell.cell_id.replace(":alpha:", `:${options.modelKey}:`),
      });
      if (cell.status === "success") {
        cell.provider_returned_model_id = options.returnedModelId;
      }
    }
    run.model_manifest_snapshot = structuredClone(manifest);
  }

  return raw;
}

function gptFixture(
  returnedModelId: string | null = GPT_APPROVED_RETURNED_MODEL_ID,
  sanitizedNote: string | null = GPT_OPENAI_ENDPOINT_NOTE,
): RawDataset {
  return approvedModelFixture({
    modelKey: "gpt",
    family: "GPT-5.6 Sol",
    provider: "openrouter",
    requestedModelId: GPT_REQUESTED_MODEL_ID,
    returnedModelId,
    route: "openrouter-openai-pinned",
    environmentVariable: "OPENROUTER_API_KEY",
    sanitizedNote,
    policy: {
      temperature: {
        mode: "provider-default",
        reason: "Temperature omitted for GPT-5.6 Sol",
      },
      output_limit: { parameter: "max_tokens", value: 16_384 },
      reasoning: {
        mode: "provider-default",
        description: "Provider default reasoning behavior",
      },
      provider_options: {
        service_tier: "default",
        provider: {
          only: ["openai"],
          allow_fallbacks: false,
          require_parameters: true,
        },
      },
    },
  });
}

function geminiFixture(
  returnedModelId: string | null = GEMINI_APPROVED_RETURNED_MODEL_ID,
): RawDataset {
  return approvedModelFixture({
    modelKey: "gemini",
    family: "Gemini 3.1 Pro",
    provider: "google",
    requestedModelId: GEMINI_REQUESTED_MODEL_ID,
    returnedModelId,
    route: "google-direct",
    environmentVariable: "GOOGLE_API_KEY",
    sanitizedNote: `Provider model: ${returnedModelId ?? "not reported"}`,
    policy: {
      temperature: {
        mode: "provider-default",
        reason: "Gemini 3.1 Pro documented default",
      },
      output_limit: { parameter: "max_output_tokens", value: 16_384 },
      reasoning: {
        mode: "provider-default",
        description: "Provider default reasoning behavior",
      },
      provider_options: {},
    },
  });
}

describe("dataset validation", () => {
  it("accepts the complete illustrative fixture", () => {
    const parsed = validateDataset(rawFixture());
    expect(parsed.questions).toHaveLength(3);
    expect(parsed.runs.flatMap((run) => run.cells)).toHaveLength(32);
    expect(
      parsed.runs.flatMap((run) => run.cells).filter((cell) => cell.status === "error"),
    ).toHaveLength(1);
  });

  it("points to a malformed required field", () => {
    const raw = rawFixture();
    const question = raw.questions[0] as Record<string, unknown>;
    delete question.title;

    expect(validationIssues(() => validateDataset(raw))).toContain(
      "question[0]/title: Invalid input: expected string, received undefined",
    );
  });

  it("rejects a mapping that references an unknown position", () => {
    const raw = rawFixture();
    const mapping = raw.mappings[0] as {
      assignments: { primary_endorsed: string | null }[];
    };
    mapping.assignments[0].primary_endorsed = "missing-position";

    expect(validationIssues(() => validateDataset(raw))).toContain(
      `mapping ${dataset.mappings[0].mapping_id}: unknown position missing-position`,
    );
  });

  it("rejects a challenge whose parent cannot be recovered", () => {
    const raw = rawFixture();
    const run = raw.runs[0] as {
      cells: { call_type: string; parent_response_id: string | null }[];
    };
    const challenge = run.cells.find((cell) => cell.call_type === "challenge");
    if (!challenge) throw new Error("Fixture challenge is missing");
    challenge.parent_response_id = "nonexistent-answer";

    expect(validationIssues(() => validateDataset(raw))).toContain(
      "challenge case-a:alpha:default:challenge: parent is not a successful answer",
    );
  });

  it("rejects a challenge conversation that does not exactly extend its parent", () => {
    const raw = rawFixture();
    const run = raw.runs[0] as {
      cells: { call_type: string; messages: { role: string; content: string }[] }[];
    };
    const challenge = run.cells.find((cell) => cell.call_type === "challenge");
    if (!challenge) throw new Error("Fixture challenge is missing");
    challenge.messages.at(-1)!.content = "A different challenge instruction.";

    expect(
      validationIssues(() => validateDataset(raw)).some((issue) =>
        issue.includes("messages must extend the exact parent conversation"),
      ),
    ).toBe(true);
  });

  it("preserves leading and trailing whitespace in raw model output", () => {
    const cell = dataset.runs
      .flatMap((run) => run.cells)
      .find((candidate) => candidate.status === "success");
    if (!cell || cell.status !== "success") throw new Error("Success fixture is missing");
    const raw = structuredClone(cell);
    raw.response_text = "\n  exact provider text  \n";

    expect(successCellSchema.parse(raw).response_text).toBe(
      "\n  exact provider text  \n",
    );
  });

  it("accepts incomplete-output as a harness error category", () => {
    const cell = dataset.runs
      .flatMap((run) => run.cells)
      .find((candidate) => candidate.status === "error");
    if (!cell || cell.status !== "error") throw new Error("Error fixture is missing");
    const raw = structuredClone(cell);
    raw.error.category = "incomplete-output";

    expect(errorCellSchema.parse(raw).error.category).toBe("incomplete-output");
  });

  it("rejects a successful cell whose returned model ID differs from its request", () => {
    const raw = rawFixture();
    const run = raw.runs[0] as {
      cells: Array<{
        status: string;
        cell_id: string;
        provider_returned_model_id?: string | null;
      }>;
    };
    const cell = run.cells.find((candidate) => candidate.status === "success");
    if (!cell) throw new Error("Success fixture is missing");
    cell.provider_returned_model_id = "different-model";

    expect(validationIssues(() => validateDataset(raw))).toContain(
      `cell ${cell.cell_id}: provider-returned model ID different-model does not match requested model ID illustrative-alpha-not-a-real-model`,
    );
  });

  it("permits an omitted returned model ID outside the production gate", () => {
    const raw = rawFixture();
    const run = raw.runs[0] as {
      cells: Array<{
        status: string;
        provider_returned_model_id?: string | null;
      }>;
    };
    const cell = run.cells.find((candidate) => candidate.status === "success");
    if (!cell) throw new Error("Success fixture is missing");
    cell.provider_returned_model_id = null;

    expect(() => validateDataset(raw)).not.toThrow();
  });

  it("accepts the user-approved dated GPT returned model ID", () => {
    expect(() => validateDataset(gptFixture())).not.toThrow();
  });

  it.each([
    "openai/gpt-5.6-sol-20260708",
    "OpenAI/gpt-5.6-sol-20260709",
    "openai/gpt-5.6-sol-20260709-extra",
    "models/openai/gpt-5.6-sol-20260709",
  ])("rejects an unapproved GPT returned model ID: %s", (returnedModelId) => {
    const issues = validationIssues(() =>
      validateDataset(gptFixture(returnedModelId)),
    );

    expect(
      issues.some((issue) =>
        issue.includes(
          `provider-returned model ID ${returnedModelId} does not match requested model ID ${GPT_REQUESTED_MODEL_ID}`,
        ),
      ),
    ).toBe(true);
  });

  it("accepts Google's exact models-prefixed Gemini identity", () => {
    expect(() => validateDataset(geminiFixture())).not.toThrow();
  });

  it.each([
    "models/Gemini-3.1-pro-preview",
    "models/gemini-3.1-pro-preview-latest",
  ])("rejects an inexact Google returned model ID: %s", (returnedModelId) => {
    const issues = validationIssues(() =>
      validateDataset(geminiFixture(returnedModelId)),
    );

    expect(
      issues.some((issue) =>
        issue.includes(
          `provider-returned model ID ${returnedModelId} does not match requested model ID ${GEMINI_REQUESTED_MODEL_ID}`,
        ),
      ),
    ).toBe(true);
  });

  it("does not normalize Google's models prefix on another provider route", () => {
    const raw = geminiFixture();
    const manifest = raw.manifest as {
      models: Array<{ model_key: string; provider: string }>;
    };
    const gemini = manifest.models.find((model) => model.model_key === "gemini");
    if (!gemini) throw new Error("Gemini fixture is missing");
    gemini.provider = "openrouter";
    for (const runValue of raw.runs) {
      const run = runValue as {
        model_manifest_snapshot: unknown;
        cells: Array<{ model_key: string; provider: string }>;
      };
      for (const cell of run.cells) {
        if (cell.model_key === "gemini") cell.provider = "openrouter";
      }
      run.model_manifest_snapshot = structuredClone(manifest);
    }

    expect(
      validationIssues(() => validateDataset(raw)).some((issue) =>
        issue.includes(
          `provider-returned model ID ${GEMINI_APPROVED_RETURNED_MODEL_ID} does not match requested model ID ${GEMINI_REQUESTED_MODEL_ID}`,
        ),
      ),
    ).toBe(true);
  });

  it("rejects duplicate cells", () => {
    const raw = rawFixture();
    const run = raw.runs[0] as { cells: unknown[] };
    run.cells.push(structuredClone(run.cells[0]));

    const issues = validationIssues(() => validateDataset(raw));
    expect(issues.some((issue) => issue.includes("Duplicate cell ID"))).toBe(true);
    expect(issues.some((issue) => issue.includes("Duplicate response ID"))).toBe(true);
  });

  it("cannot pass the production release gate", () => {
    const issues = validationIssues(() =>
      validateDataset(rawFixture(), { production: true }),
    );

    expect(issues).toContain("production: dataset index mode must be final");
    expect(issues).toContain("production: sample model manifest is forbidden");
    expect(issues.some((issue) => issue.includes("not author-verified"))).toBe(true);
    expect(issues).toContain("production: expected 64 successful cells, found 31");
  });

  it("distinguishes the production total output ceiling from the visible target", () => {
    const raw = rawFixture();
    const manifest = raw.manifest as {
      data_class: string;
      models: Array<{
        model_key: string;
        provider: string;
        requested_model_id: string;
        route: string;
        environment_variable: string;
        policy: {
          temperature: unknown;
          output_limit: { parameter: string; value: number };
        };
      }>;
    };
    manifest.data_class = "research";
    Object.assign(manifest.models[0], {
      model_key: "gemini",
      provider: "google",
      requested_model_id: "gemini-3.1-pro-preview",
      route: "google-direct",
      environment_variable: "GOOGLE_API_KEY",
    });
    manifest.models[0].policy.temperature = {
      mode: "provider-default",
      reason: "Fixture",
    };
    manifest.models[0].policy.output_limit = {
      parameter: "max_output_tokens",
      value: 900,
    };

    expect(validationIssues(() => validateDataset(raw, { production: true }))).toContain(
      "production: model gemini must use the approved 16,384-token total reasoning-and-answer output ceiling; the protocol separately keeps visible answers under 900 tokens",
    );
  });

  it("requires a non-null approved returned model ID in production preflight", () => {
    const issues = validationIssues(() =>
      validateDataset(gptFixture(null), { production: true }),
    );

    expect(issues).toContain(
      `production: model gpt preflight must return approved model ID ${GPT_REQUESTED_MODEL_ID}`,
    );
  });

  it("accepts the approved dated GPT identity in production preflight", () => {
    const issues = validationIssues(() =>
      validateDataset(gptFixture(), { production: true }),
    );

    expect(issues).not.toContain(
      `production: model gpt preflight must return approved model ID ${GPT_REQUESTED_MODEL_ID}`,
    );
  });

  it("accepts Google's exact models-prefixed identity in production preflight", () => {
    const issues = validationIssues(() =>
      validateDataset(geminiFixture(), { production: true }),
    );

    expect(issues).not.toContain(
      `production: model gemini preflight must return approved model ID ${GEMINI_REQUESTED_MODEL_ID}`,
    );
  });

  it("requires the exact OpenAI endpoint note for GPT production preflight", () => {
    const issues = validationIssues(() =>
      validateDataset(gptFixture(GPT_APPROVED_RETURNED_MODEL_ID, "Provider endpoint: openai"), {
        production: true,
      }),
    );

    expect(issues).toContain(
      `production: GPT preflight sanitized note must be exactly "${GPT_OPENAI_ENDPOINT_NOTE}"`,
    );
  });

  it("retains the OpenAI-only provider pin in the production gate", () => {
    const raw = gptFixture();
    const manifest = raw.manifest as {
      models: Array<{
        model_key: string;
        policy: { provider_options: Record<string, unknown> };
      }>;
    };
    const gpt = manifest.models.find((model) => model.model_key === "gpt");
    if (!gpt) throw new Error("GPT fixture is missing");
    gpt.policy.provider_options.provider = {
      only: ["openai", "anthropic"],
      allow_fallbacks: false,
      require_parameters: true,
    };
    for (const runValue of raw.runs) {
      const run = runValue as { model_manifest_snapshot: unknown };
      run.model_manifest_snapshot = structuredClone(manifest);
    }

    expect(validationIssues(() => validateDataset(raw, { production: true }))).toContain(
      "production: GPT OpenRouter route must pin only openai, disable fallbacks, require parameters, and use the default service tier",
    );
  });
});

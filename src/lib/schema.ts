import { z } from "zod";

export const SCHEMA_VERSION = "1.0.0" as const;

const trimmed = z
  .string()
  .min(1)
  .refine((value) => value.trim().length > 0, "Text must not be blank")
  .refine(
    (value) => value === value.trim(),
    "Metadata must not contain surrounding whitespace",
  );
const verbatimText = z
  .string()
  .min(1)
  .refine((value) => value.trim().length > 0, "Text must not be blank")
  .refine((value) => !value.includes("\0"), "Text must not contain NUL characters");
const kebabId = z
  .string()
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "Expected a lower-kebab-case ID");
const sha256 = z.string().regex(/^[a-f0-9]{64}$/, "Expected a lowercase SHA-256");
const isoTimestamp = z.string().datetime({ offset: true });
const isoDate = z.string().date();
const httpsUrl = z
  .url()
  .refine((value) => value.startsWith("https://"), "Source URLs must use HTTPS")
  .refine(
    (value) => !new URL(value).username && !new URL(value).password,
    "Source URLs must not contain credentials",
  );

const jsonPrimitive = z.union([z.string(), z.number(), z.boolean(), z.null()]);
type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };
const jsonValue: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([jsonPrimitive, z.array(jsonValue), z.record(z.string(), jsonValue)]),
);
const jsonObject = z.record(z.string(), jsonValue);

export const proposedVerificationSchema = z
  .object({
    status: z.literal("proposed"),
    verified_by: z.null(),
    verified_at: z.null(),
  })
  .strict();

export const authorVerificationSchema = z
  .object({
    status: z.literal("author-verified"),
    verified_by: z.literal("A.G. Elrod"),
    verified_at: isoTimestamp,
  })
  .strict();

export const verificationSchema = z.discriminatedUnion("status", [
  proposedVerificationSchema,
  authorVerificationSchema,
]);

export const sourceSchema = z
  .object({
    id: kebabId,
    claim_supported: trimmed,
    title: trimmed,
    citation: trimmed,
    url: httpsUrl,
    accessed_at: isoDate,
    verification: verificationSchema,
  })
  .strict();

export const positionSchema = z
  .object({
    id: kebabId,
    label: trimmed,
    summary: trimmed,
    attestation: trimmed,
    sources: z.array(sourceSchema).min(1),
    verification: verificationSchema,
  })
  .strict()
  .superRefine((position, context) => {
    addDuplicateIssues(
      position.sources.map((source) => source.id),
      context,
      ["sources"],
      "source ID",
    );
  });

export const promptVariantSchema = z
  .object({
    id: kebabId,
    label: trimmed,
    user_prompt: verbatimText,
  })
  .strict();

const selectionSchema = z
  .object({
    status: z.enum(["illustrative", "candidate", "selected"]),
    pool_id: kebabId.nullable(),
    pool_size: z.number().int().positive().nullable(),
    rule_version: trimmed.nullable(),
    disclosure: trimmed,
  })
  .strict()
  .superRefine((selection, context) => {
    if (selection.status === "selected") {
      for (const key of ["pool_id", "pool_size", "rule_version"] as const) {
        if (selection[key] === null) {
          context.addIssue({
            code: "custom",
            path: [key],
            message: `Selected cases require ${key}`,
          });
        }
      }
    }
  });

export const questionSchema = z
  .object({
    schema_version: z.literal(SCHEMA_VERSION),
    content_version: trimmed,
    data_class: z.enum(["sample", "research"]),
    id: kebabId,
    kind: z.enum(["convergent", "divergent", "prompt-sensitive"]),
    domain: kebabId,
    title: trimmed,
    premise: trimmed,
    context_note: trimmed,
    what_this_shows: z.array(trimmed).min(1),
    what_this_does_not_show: z.array(trimmed).min(1),
    selection: selectionSchema,
    prompt_variants: z.array(promptVariantSchema).min(1).max(2),
    position_map: z.array(positionSchema).min(1),
    map_is_nonexhaustive: z.literal(true),
    verification: verificationSchema,
  })
  .strict()
  .superRefine((question, context) => {
    const variantIds = question.prompt_variants.map((variant) => variant.id);
    const positionIds = question.position_map.map((position) => position.id);

    addDuplicateIssues(variantIds, context, ["prompt_variants"], "variant ID");
    addDuplicateIssues(positionIds, context, ["position_map"], "position ID");

    if (question.kind === "prompt-sensitive") {
      if (question.prompt_variants.length !== 2) {
        context.addIssue({
          code: "custom",
          path: ["prompt_variants"],
          message: "Prompt-sensitive cases require exactly two variants",
        });
      }
      if (variantIds.includes("default")) {
        context.addIssue({
          code: "custom",
          path: ["prompt_variants"],
          message: "Prompt-sensitive cases must not add a default variant",
        });
      }
    } else if (question.prompt_variants.length !== 1 || variantIds[0] !== "default") {
      context.addIssue({
        code: "custom",
        path: ["prompt_variants"],
        message: "Convergent and divergent cases require one default variant",
      });
    }
  });

const temperaturePolicySchema = z.discriminatedUnion("mode", [
  z
    .object({ mode: z.literal("fixed"), value: z.number().min(0).max(2) })
    .strict(),
  z
    .object({ mode: z.literal("provider-default"), reason: trimmed })
    .strict(),
]);

const reasoningPolicySchema = z.discriminatedUnion("mode", [
  z
    .object({ mode: z.literal("fixed"), setting: jsonValue })
    .strict(),
  z
    .object({ mode: z.literal("provider-default"), description: trimmed })
    .strict(),
]);

const preflightSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("not-checked"),
      checked_at: z.null(),
      provider_returned_model_id: z.null(),
      sanitized_note: z.null(),
    })
    .strict(),
  z
    .object({
      status: z.enum(["available", "unavailable"]),
      checked_at: isoTimestamp,
      provider_returned_model_id: trimmed.nullable(),
      sanitized_note: trimmed.nullable(),
    })
    .strict(),
]);

export const modelSnapshotSchema = z
  .object({
    model_key: kebabId,
    family: trimmed,
    provider: kebabId,
    requested_model_id: trimmed,
    route: trimmed,
    environment_variable: z.string().regex(/^[A-Z][A-Z0-9_]+$/),
    fallback_allowed: z.literal(false),
    capabilities: z
      .object({
        tools: z.literal(false),
        web_search: z.literal(false),
        retrieval: z.literal(false),
      })
      .strict(),
    policy: z
      .object({
        temperature: temperaturePolicySchema,
        visible_output_limit: z
          .object({ parameter: trimmed, value: z.number().int().positive() })
          .strict(),
        reasoning: reasoningPolicySchema,
        provider_options: jsonObject,
      })
      .strict(),
    pricing: z
      .object({
        currency: z.literal("USD"),
        input_per_million: z.number().nonnegative(),
        output_per_million: z.number().nonnegative(),
        pricing_as_of: isoDate,
      })
      .strict(),
    preflight: preflightSchema,
  })
  .strict();

export const modelManifestSchema = z
  .object({
    schema_version: z.literal(SCHEMA_VERSION),
    manifest_id: kebabId,
    captured_at: isoTimestamp,
    harness_version: trimmed,
    config_sha256: sha256,
    data_class: z.enum(["sample", "research"]),
    models: z.array(modelSnapshotSchema).min(1),
  })
  .strict()
  .superRefine((manifest, context) => {
    addDuplicateIssues(
      manifest.models.map((model) => model.model_key),
      context,
      ["models"],
      "model key",
    );
    addDuplicateIssues(
      manifest.models.map((model) => model.family),
      context,
      ["models"],
      "model family",
    );
  });

const messageSchema = z
  .object({
    role: z.enum(["system", "user", "assistant"]),
    content: verbatimText,
  })
  .strict();

const temperatureRequestSchema = z.discriminatedUnion("sent", [
  z.object({ sent: z.literal(true), value: z.number() }).strict(),
  z
    .object({ sent: z.literal(false), value: z.null(), reason: trimmed })
    .strict(),
]);

const reasoningRequestSchema = z.discriminatedUnion("sent", [
  z.object({ sent: z.literal(true), setting: jsonValue }).strict(),
  z
    .object({ sent: z.literal(false), setting: z.null(), reason: trimmed })
    .strict(),
]);

const requestedParamsSchema = z
  .object({
    temperature: temperatureRequestSchema,
    output_limit: z
      .object({ sent: z.literal(true), parameter: trimmed, value: z.number().int().positive() })
      .strict(),
    reasoning: reasoningRequestSchema,
    tools_enabled: z.literal(false),
    web_search_enabled: z.literal(false),
    retrieval_enabled: z.literal(false),
    provider_options: jsonObject,
  })
  .strict();

const effectiveValueSchema = z.discriminatedUnion("state", [
  z
    .object({
      state: z.literal("known"),
      value: jsonValue,
      source: z.enum(["request", "provider-response", "documentation"]),
    })
    .strict(),
  z.object({ state: z.literal("not-reported"), value: z.null() }).strict(),
]);

const commonCellSchema = z.object({
  cell_id: z.string().regex(/^[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]+:(answer|challenge)$/),
  question_id: kebabId,
  model_key: kebabId,
  model_family: trimmed,
  provider: kebabId,
  requested_model_id: trimmed,
  variant_id: kebabId,
  call_type: z.enum(["answer", "challenge"]),
  parent_response_id: kebabId.nullable(),
  messages: z.array(messageSchema).min(2),
  prompt_sha256: sha256,
  requested_params: requestedParamsSchema,
  attempted_at: isoTimestamp,
  attempt_count: z.number().int().positive(),
});

export const successCellSchema = commonCellSchema
  .extend({
    status: z.literal("success"),
    response_id: kebabId,
    provider_returned_model_id: trimmed.nullable(),
    provider_response_id: trimmed.nullable(),
    effective_params: z.record(z.string(), effectiveValueSchema),
    response_text: verbatimText,
    generated_at: isoTimestamp,
    latency_ms: z.number().int().nonnegative(),
    finish_reason: trimmed.nullable(),
    usage: z
      .object({
        input_tokens: z.number().int().nonnegative().nullable(),
        output_tokens: z.number().int().nonnegative().nullable(),
        reasoning_tokens: z.number().int().nonnegative().nullable(),
        cache_read_tokens: z.number().int().nonnegative().nullable(),
        cache_write_tokens: z.number().int().nonnegative().nullable(),
        total_tokens: z.number().int().nonnegative().nullable(),
      })
      .strict(),
    cost: z
      .object({
        usd: z.number().nonnegative(),
        source: z.enum(["provider-reported", "estimated"]),
        pricing_as_of: isoDate,
      })
      .strict(),
  })
  .strict();

export const errorCellSchema = commonCellSchema
  .extend({
    status: z.literal("error"),
    error: z
      .object({
        category: z.enum([
          "authentication",
          "authorization",
          "rate-limit",
          "timeout",
          "unavailable",
          "invalid-request",
          "network",
          "provider-error",
          "response-validation",
          "unknown",
        ]),
        retryable: z.boolean(),
        sanitized_summary: trimmed,
      })
      .strict(),
    failed_at: isoTimestamp,
  })
  .strict();

export const responseCellSchema = z.discriminatedUnion("status", [
  successCellSchema,
  errorCellSchema,
]);

export const runManifestSchema = z
  .object({
    schema_version: z.literal(SCHEMA_VERSION),
    run_id: kebabId,
    run_purpose: z.enum(["sample", "pilot", "final"]),
    question_id: kebabId,
    question_content_version: trimmed,
    question_file_sha256: sha256,
    generated_at: isoTimestamp,
    updated_at: isoTimestamp,
    harness_version: trimmed,
    harness_config_sha256: sha256,
    model_manifest_file_sha256: sha256,
    model_manifest_snapshot: modelManifestSchema,
    cells: z.array(responseCellSchema).min(1),
  })
  .strict()
  .superRefine((run, context) => {
    addDuplicateIssues(
      run.cells.map((cell) => cell.cell_id),
      context,
      ["cells"],
      "cell ID",
    );
    addDuplicateIssues(
      run.cells
        .filter((cell) => cell.status === "success")
        .map((cell) => cell.response_id),
      context,
      ["cells"],
      "response ID",
    );

    for (const [index, cell] of run.cells.entries()) {
      const expectedCellId = `${cell.question_id}:${cell.model_key}:${cell.variant_id}:${cell.call_type}`;
      if (cell.cell_id !== expectedCellId) {
        context.addIssue({
          code: "custom",
          path: ["cells", index, "cell_id"],
          message: `Expected deterministic cell ID ${expectedCellId}`,
        });
      }
      if (cell.question_id !== run.question_id) {
        context.addIssue({
          code: "custom",
          path: ["cells", index, "question_id"],
          message: "Cell question does not match run question",
        });
      }
      if (cell.call_type === "answer" && cell.parent_response_id !== null) {
        context.addIssue({
          code: "custom",
          path: ["cells", index, "parent_response_id"],
          message: "Answer cells cannot have a parent response",
        });
      }
      if (cell.call_type === "challenge" && cell.parent_response_id === null) {
        context.addIssue({
          code: "custom",
          path: ["cells", index, "parent_response_id"],
          message: "Challenge cells require a parent response",
        });
      }
    }
  });

export const mappingAssignmentSchema = z
  .object({
    response_id: kebabId,
    primary_endorsed: kebabId.nullable(),
    also_endorsed: z.array(kebabId),
    mentioned: z.array(kebabId),
    audit_note: trimmed.nullable(),
    verification: verificationSchema,
  })
  .strict()
  .superRefine((assignment, context) => {
    addDuplicateIssues(assignment.also_endorsed, context, ["also_endorsed"], "position ID");
    addDuplicateIssues(assignment.mentioned, context, ["mentioned"], "position ID");

    const primary = assignment.primary_endorsed;
    if (primary && (assignment.also_endorsed.includes(primary) || assignment.mentioned.includes(primary))) {
      context.addIssue({
        code: "custom",
        message: "Primary endorsement must not be repeated in other position arrays",
      });
    }
    const overlap = assignment.also_endorsed.filter((id) => assignment.mentioned.includes(id));
    if (overlap.length > 0) {
      context.addIssue({
        code: "custom",
        message: `Positions cannot be both additionally endorsed and mentioned: ${overlap.join(", ")}`,
      });
    }
  });

export const mappingSchema = z
  .object({
    schema_version: z.literal(SCHEMA_VERSION),
    mapping_version: trimmed,
    mapping_id: kebabId,
    question_id: kebabId,
    run_id: kebabId,
    run_file_sha256: sha256,
    rubric_version: trimmed,
    assignments: z.array(mappingAssignmentSchema).min(1),
    verification: verificationSchema,
  })
  .strict()
  .superRefine((mapping, context) => {
    addDuplicateIssues(
      mapping.assignments.map((assignment) => assignment.response_id),
      context,
      ["assignments"],
      "response ID",
    );
  });

export const datasetIndexSchema = z
  .object({
    schema_version: z.literal(SCHEMA_VERSION),
    dataset_id: kebabId,
    mode: z.enum(["sample", "candidate", "final"]),
    model_manifest: trimmed,
    questions: z
      .array(
        z
          .object({ question: trimmed, run: trimmed, mapping: trimmed })
          .strict(),
      )
      .min(1),
  })
  .strict();

function addDuplicateIssues(
  values: string[],
  context: z.core.$RefinementCtx,
  path: PropertyKey[],
  label: string,
) {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      context.addIssue({
        code: "custom",
        path,
        message: `Duplicate ${label}: ${value}`,
      });
    }
    seen.add(value);
  }
}

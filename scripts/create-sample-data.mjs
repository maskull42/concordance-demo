import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sampleRoot = path.join(root, "sample");
const protocol = JSON.parse(
  readFileSync(path.join(root, "config", "protocol.json"), "utf8"),
);
const timestamp = "2026-07-10T12:00:00+00:00";
const accessedAt = "2026-07-10";
const proposed = { status: "proposed", verified_by: null, verified_at: null };
const zeroHash = "0".repeat(64);

const models = [
  ["alpha", "Illustrative Alpha"],
  ["beta", "Illustrative Beta"],
  ["gamma", "Illustrative Gamma"],
  ["delta", "Illustrative Delta"],
];

const manifest = {
  schema_version: "1.0.0",
  manifest_id: "sample-models",
  captured_at: timestamp,
  harness_version: "sample-generator-1",
  config_sha256: zeroHash,
  data_class: "sample",
  models: models.map(([modelKey, family]) => ({
    model_key: modelKey,
    family,
    provider: "sample-provider",
    requested_model_id: `illustrative-${modelKey}-not-a-real-model`,
    route: "local illustrative fixture",
    environment_variable: "SAMPLE_ONLY_NO_KEY",
    fallback_allowed: false,
    capabilities: { tools: false, web_search: false, retrieval: false },
    policy: {
      temperature: { mode: "fixed", value: 0.2 },
      output_limit: { parameter: "max_tokens", value: 900 },
      reasoning: { mode: "provider-default", description: "Illustrative fixture" },
      provider_options: {},
    },
    pricing: {
      currency: "USD",
      input_per_million: 0,
      output_per_million: 0,
      pricing_as_of: accessedAt,
    },
    preflight: {
      status: "not-checked",
      checked_at: null,
      provider_returned_model_id: null,
      sanitized_note: null,
    },
  })),
};

const source = (id) => ({
  id: `${id}-source`,
  claim_supported: "This is a fictional source entry used only to exercise the interface.",
  title: `Illustrative source for ${id}`,
  citation: "Concordance development fixture (2026).",
  url: `https://example.com/concordance/${id}`,
  accessed_at: accessedAt,
  verification: proposed,
});

const position = (id, label) => ({
  id,
  label,
  summary: `Illustrative summary for ${label}. This is not a scholarly claim.`,
  attestation: "Fictional attestation for local interface development only.",
  sources: [source(id)],
  verification: proposed,
});

const questions = [
  {
    schema_version: "1.0.0",
    content_version: "sample-1",
    data_class: "sample",
    id: "case-a",
    kind: "convergent",
    domain: "illustrative-domain",
    title: "A fictional convergence case",
    premise: "Four illustrative model tokens initially gather at one fictional position.",
    context_note: "This development fixture exists only to test the convergence layout.",
    what_this_shows: ["How a concentrated set of primary endorsements is rendered."],
    what_this_does_not_show: ["Any behavior of a real model or any historical claim."],
    selection: {
      status: "illustrative",
      pool_id: null,
      pool_size: null,
      rule_version: null,
      disclosure: "Illustrative fixture. It was designed to exercise the interface.",
    },
    prompt_variants: [
      { id: "default", label: "Default", user_prompt: "Choose an illustrative position for fictional case A." },
    ],
    position_map: [
      position("amber-reading", "Amber reading"),
      position("pine-reading", "Pine reading"),
      position("slate-reading", "Slate reading"),
      position("ochre-reading", "Ochre reading"),
    ],
    map_is_nonexhaustive: true,
    verification: proposed,
  },
  {
    schema_version: "1.0.0",
    content_version: "sample-1",
    data_class: "sample",
    id: "case-b",
    kind: "divergent",
    domain: "illustrative-domain",
    title: "A fictional divergence case",
    premise: "The illustrative panel distributes across three fictional positions.",
    context_note: "This development fixture exists only to test plural layouts.",
    what_this_shows: ["How several primary positions can remain visible at once."],
    what_this_does_not_show: ["That diversity is correct, representative, or desirable."],
    selection: {
      status: "illustrative",
      pool_id: null,
      pool_size: null,
      rule_version: null,
      disclosure: "Illustrative fixture. It was designed to exercise the interface.",
    },
    prompt_variants: [
      { id: "default", label: "Default", user_prompt: "Choose an illustrative position for fictional case B." },
    ],
    position_map: [
      position("river-reading", "River reading"),
      position("stone-reading", "Stone reading"),
      position("meadow-reading", "Meadow reading"),
    ],
    map_is_nonexhaustive: true,
    verification: proposed,
  },
  {
    schema_version: "1.0.0",
    content_version: "sample-1",
    data_class: "sample",
    id: "case-c",
    kind: "prompt-sensitive",
    domain: "illustrative-domain",
    title: "A fictional prompt-sensitivity case",
    premise: "Changing fictional phrasing moves each illustrative model token.",
    context_note: "This development fixture exists only to test variant controls and movement.",
    what_this_shows: ["How linked assignments can change with prompt wording."],
    what_this_does_not_show: ["That any real model is predictably sensitive in this way."],
    selection: {
      status: "illustrative",
      pool_id: null,
      pool_size: null,
      rule_version: null,
      disclosure: "Illustrative fixture. It was designed to exercise the interface.",
    },
    prompt_variants: [
      { id: "neutral", label: "Neutral phrasing", user_prompt: "Choose an illustrative position for fictional case C neutrally." },
      { id: "framed", label: "Framed phrasing", user_prompt: "Choose an illustrative position for fictional case C with a fictional frame." },
    ],
    position_map: [
      position("north-reading", "North reading"),
      position("east-reading", "East reading"),
      position("west-reading", "West reading"),
    ],
    map_is_nonexhaustive: true,
    verification: proposed,
  },
];

const primaryByCase = {
  "case-a": {
    default: { alpha: "amber-reading", beta: "amber-reading", gamma: "amber-reading", delta: "amber-reading" },
  },
  "case-b": {
    default: { alpha: "river-reading", beta: "stone-reading", gamma: "meadow-reading", delta: "river-reading" },
  },
  "case-c": {
    neutral: { alpha: "north-reading", beta: "north-reading", gamma: "east-reading", delta: "west-reading" },
    framed: { alpha: "east-reading", beta: "east-reading", gamma: "west-reading", delta: "north-reading" },
  },
};

const challengePrimary = {
  "case-a": { default: { alpha: "pine-reading", beta: "amber-reading", gamma: null, delta: "slate-reading" } },
  "case-b": { default: { alpha: "stone-reading", beta: "meadow-reading", gamma: "river-reading", delta: "stone-reading" } },
  "case-c": {
    neutral: { alpha: "east-reading", beta: "west-reading", gamma: "north-reading", delta: "east-reading" },
    framed: { alpha: "west-reading", beta: "north-reading", gamma: "east-reading", delta: "west-reading" },
  },
};

const mentionedByCase = {
  "case-a": { default: { alpha: ["pine-reading"], beta: [], gamma: ["slate-reading"], delta: [] } },
  "case-b": { default: { alpha: ["stone-reading"], beta: [], gamma: [], delta: [] } },
  "case-c": {
    neutral: { alpha: ["east-reading"], beta: [], gamma: ["west-reading"], delta: [] },
    framed: { alpha: ["west-reading"], beta: ["north-reading"], gamma: [], delta: [] },
  },
};

rmSync(sampleRoot, { recursive: true, force: true });
for (const directory of ["questions", "runs", "mappings", "manifests"]) {
  mkdirSync(path.join(sampleRoot, directory), { recursive: true });
}

const manifestPath = path.join(sampleRoot, "manifests", "models.json");
writeJson(manifestPath, manifest);
const manifestHash = fileHash(manifestPath);

const indexEntries = [];
for (const question of questions) {
  const questionPath = path.join(sampleRoot, "questions", `${question.id}.json`);
  writeJson(questionPath, question);

  const run = makeRun(question, fileHash(questionPath), manifestHash);
  const runPath = path.join(sampleRoot, "runs", `${question.id}.json`);
  writeJson(runPath, run);

  const mapping = makeMapping(question, run, fileHash(runPath));
  const mappingPath = path.join(sampleRoot, "mappings", `${question.id}.json`);
  writeJson(mappingPath, mapping);

  indexEntries.push({
    question: `questions/${question.id}.json`,
    run: `runs/${question.id}.json`,
    mapping: `mappings/${question.id}.json`,
  });
}

writeJson(path.join(sampleRoot, "index.json"), {
  schema_version: "1.0.0",
  dataset_id: "concordance-sample",
  mode: "sample",
  model_manifest: "manifests/models.json",
  questions: indexEntries,
});

function makeRun(question, questionHash, manifestHash) {
  const cells = [];
  for (const variant of question.prompt_variants) {
    for (const [modelKey, family] of models) {
      const system = protocol.system_prompt;
      const answerMessages = [
        { role: "system", content: system },
        { role: "user", content: variant.user_prompt },
      ];
      const responseId = `${question.id}-${modelKey}-${variant.id}-answer`;
      const primary = primaryByCase[question.id][variant.id][modelKey];
      const responseText =
        question.id === "case-b" && modelKey === "beta"
          ? `Illustrative answer choosing ${primary}. Literal HTML test: <strong>not markup</strong>.`
          : `Illustrative answer choosing ${primary}. This is not a real model response.`;
      cells.push(
        successCell({
          question,
          variant,
          modelKey,
          family,
          callType: "answer",
          parentResponseId: null,
          responseId,
          messages: answerMessages,
          responseText,
        }),
      );

      const challengeMessages = [
        ...answerMessages,
        { role: "assistant", content: responseText },
        {
          role: "user",
          content: protocol.standard_challenge_prompt,
        },
      ];
      const challengeInput = {
        question,
        variant,
        modelKey,
        family,
        callType: "challenge",
        parentResponseId: responseId,
        responseId: `${question.id}-${modelKey}-${variant.id}-challenge`,
        messages: challengeMessages,
        responseText: "Illustrative challenge response. This is not a real model response.",
      };
      cells.push(
        question.id === "case-b" && modelKey === "delta"
          ? errorCell(challengeInput)
          : successCell(challengeInput),
      );
    }
  }

  return {
    schema_version: "1.0.0",
    run_id: `${question.id}-sample-run`,
    run_purpose: "sample",
    question_id: question.id,
    question_content_version: question.content_version,
    question_file_sha256: questionHash,
    generated_at: timestamp,
    updated_at: timestamp,
    harness_version: "sample-generator-1",
    harness_config_sha256: zeroHash,
    model_manifest_file_sha256: manifestHash,
    model_manifest_snapshot: manifest,
    cells,
  };
}

function successCell({
  question,
  variant,
  modelKey,
  family,
  callType,
  parentResponseId,
  responseId,
  messages,
  responseText,
}) {
  return {
    status: "success",
    cell_id: `${question.id}:${modelKey}:${variant.id}:${callType}`,
    question_id: question.id,
    model_key: modelKey,
    model_family: family,
    provider: "sample-provider",
    requested_model_id: `illustrative-${modelKey}-not-a-real-model`,
    variant_id: variant.id,
    call_type: callType,
    parent_response_id: parentResponseId,
    messages,
    prompt_sha256: messageHash(messages),
    requested_params: {
      temperature: { sent: true, value: 0.2 },
      output_limit: { sent: true, parameter: "max_tokens", value: 900 },
      reasoning: { sent: false, setting: null, reason: "Illustrative fixture" },
      tools_enabled: false,
      web_search_enabled: false,
      retrieval_enabled: false,
      provider_options: {},
    },
    attempted_at: timestamp,
    attempt_count: 1,
    response_id: responseId,
    provider_returned_model_id: `illustrative-${modelKey}-not-a-real-model`,
    provider_response_id: `sample-${responseId}`,
    effective_params: {
      temperature: { state: "known", value: 0.2, source: "request" },
      max_tokens: { state: "known", value: 900, source: "request" },
    },
    response_text: responseText,
    generated_at: timestamp,
    latency_ms: 10,
    finish_reason: "sample",
    usage: {
      input_tokens: 20,
      output_tokens: 20,
      reasoning_tokens: null,
      cache_read_tokens: null,
      cache_write_tokens: null,
      total_tokens: 40,
    },
    cost: { usd: 0, source: "estimated", pricing_as_of: accessedAt },
  };
}

function errorCell({
  question,
  variant,
  modelKey,
  family,
  callType,
  parentResponseId,
  messages,
}) {
  return {
    status: "error",
    cell_id: `${question.id}:${modelKey}:${variant.id}:${callType}`,
    question_id: question.id,
    model_key: modelKey,
    model_family: family,
    provider: "sample-provider",
    requested_model_id: `illustrative-${modelKey}-not-a-real-model`,
    variant_id: variant.id,
    call_type: callType,
    parent_response_id: parentResponseId,
    messages,
    prompt_sha256: messageHash(messages),
    requested_params: {
      temperature: { sent: true, value: 0.2 },
      output_limit: { sent: true, parameter: "max_tokens", value: 900 },
      reasoning: { sent: false, setting: null, reason: "Illustrative fixture" },
      tools_enabled: false,
      web_search_enabled: false,
      retrieval_enabled: false,
      provider_options: {},
    },
    attempted_at: timestamp,
    attempt_count: 3,
    error: {
      category: "unavailable",
      retryable: false,
      sanitized_summary: "Illustrative not-run state for interface testing.",
    },
    failed_at: timestamp,
  };
}

function makeMapping(question, run, runHash) {
  const assignments = run.cells
    .filter((cell) => cell.status === "success")
    .map((cell) => {
    const primary =
      cell.call_type === "answer"
        ? primaryByCase[question.id][cell.variant_id][cell.model_key]
        : challengePrimary[question.id][cell.variant_id][cell.model_key];
    const mentioned =
      cell.call_type === "answer"
        ? mentionedByCase[question.id][cell.variant_id][cell.model_key]
        : [];
    const also =
      question.id === "case-a" &&
      cell.call_type === "challenge" &&
      cell.model_key === "gamma"
        ? ["slate-reading"]
        : [];

      return {
        response_id: cell.response_id,
        primary_endorsed: primary,
        also_endorsed: also,
        mentioned,
        audit_note: "Illustrative mapping for interface development only.",
        verification: proposed,
      };
    });

  return {
    schema_version: "1.0.0",
    mapping_version: "sample-1",
    mapping_id: `${question.id}-sample-mapping`,
    question_id: question.id,
    run_id: run.run_id,
    run_file_sha256: runHash,
    rubric_version: "sample-rubric-1",
    assignments,
    verification: proposed,
  };
}

function messageHash(messages) {
  const hash = createHash("sha256");
  for (const message of messages) {
    hash.update(message.role, "utf8");
    hash.update("\0", "utf8");
    hash.update(message.content, "utf8");
    hash.update("\0", "utf8");
  }
  return hash.digest("hex");
}

function fileHash(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

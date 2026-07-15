import type { Dataset, Mapping, Question, RunManifest } from "./types";
import { buildCaseViewModel, variantMovementCount } from "./view-model";

export interface CaseRecord {
  question: Question;
  run: RunManifest;
  mapping: Mapping;
}

export interface CaseSummary {
  pattern: string;
  metric: string;
  result: string;
}

export function summarizeCase(record: CaseRecord, source: Dataset): CaseSummary {
  const firstVariant = record.question.prompt_variants[0];
  const view = buildCaseViewModel(
    record.question,
    record.run,
    record.mapping,
    source.manifest.models,
    firstVariant.id,
    "answer",
  );
  const counts = view.positions
    .map((position) => position.primaryModels.length)
    .filter((count) => count > 0)
    .sort((left, right) => right - left);

  if (record.question.kind === "convergent") {
    return {
      pattern: "Shared conclusion",
      metric: `${counts[0] ?? 0} of ${view.models.length}`,
      result: "reached the same primary conclusion",
    };
  }
  if (record.question.kind === "divergent") {
    return {
      pattern: "Competing conclusions",
      metric: counts.length === 2 ? `${counts[0]} to ${counts[1]}` : `${counts.length} positions`,
      result: "split across the same policy question",
    };
  }
  const secondVariant = record.question.prompt_variants[1];
  const movement = secondVariant
    ? variantMovementCount(
        record.run,
        record.mapping,
        firstVariant.id,
        secondVariant.id,
        "answer",
      )
    : 0;
  return {
    pattern: "Framing effect",
    metric: `${movement} of ${view.models.length}`,
    result: "moved to a different mapped primary position with the framing",
  };
}

export function collectCaseRecords(source: Dataset): CaseRecord[] {
  return source.questions.map((question) => {
    const run = source.runs.find((value) => value.question_id === question.id);
    const mapping = source.mappings.find(
      (value) => value.question_id === question.id,
    );
    if (!run || !mapping) throw new Error(`Missing records for ${question.id}`);
    return { question, run, mapping };
  });
}

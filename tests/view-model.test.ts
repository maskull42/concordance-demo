import { describe, expect, it } from "vitest";
import { dataset } from "../src/lib/dataset.sample";
import { buildCaseViewModel } from "../src/lib/view-model";

function records(questionId: string) {
  const question = dataset.questions.find((value) => value.id === questionId);
  const run = dataset.runs.find((value) => value.question_id === questionId);
  const mapping = dataset.mappings.find((value) => value.question_id === questionId);
  if (!question || !run || !mapping) throw new Error(`Missing fixture ${questionId}`);
  return { question, run, mapping };
}

describe("case view model", () => {
  it("derives mixed, absent, additional, and recovered states centrally", () => {
    const { question, run, mapping } = records("case-a");
    const view = buildCaseViewModel(
      question,
      run,
      mapping,
      dataset.manifest.models,
      "default",
      "challenge",
    );

    expect(view.mixedModels.map((model) => model.model.model_key)).toEqual(["gamma"]);
    expect(view.positions.find((state) => state.position.id === "ochre-reading")?.representation).toBe(
      "not-represented",
    );
    expect(view.positions.find((state) => state.position.id === "slate-reading")?.additionalModels)
      .toHaveLength(1);
    expect(view.recoveredPositionCount).toBeGreaterThan(0);
  });

  it("keeps provider errors out of the mixed tray", () => {
    const { question, run, mapping } = records("case-b");
    const view = buildCaseViewModel(
      question,
      run,
      mapping,
      dataset.manifest.models,
      "default",
      "challenge",
    );

    expect(view.errorModels.map((model) => model.model.model_key)).toEqual(["delta"]);
    expect(view.mixedModels).toHaveLength(0);
  });
});

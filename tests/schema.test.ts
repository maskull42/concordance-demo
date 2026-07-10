import { describe, expect, it } from "vitest";
import { dataset } from "../src/lib/dataset.sample";
import { successCellSchema } from "../src/lib/schema";
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
});

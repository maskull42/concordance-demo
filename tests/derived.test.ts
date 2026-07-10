import { describe, expect, it } from "vitest";
import {
  derivePositionStates,
  joinAssignments,
  recoveredPositions,
  sensitivityMovementCount,
} from "../src/lib/derived";
import { dataset } from "../src/lib/dataset.sample";

function records(questionId: string) {
  const question = dataset.questions.find((value) => value.id === questionId);
  const run = dataset.runs.find((value) => value.question_id === questionId);
  const mapping = dataset.mappings.find((value) => value.question_id === questionId);
  if (!question || !run || !mapping) throw new Error(`Missing fixture ${questionId}`);
  return { question, run, mapping };
}

describe("derived map semantics", () => {
  it("distinguishes primary, additional, mentioned-only, and absent states", () => {
    const { question, run, mapping } = records("case-a");
    const initial = joinAssignments(run, mapping, "default", "answer");
    const states = derivePositionStates(question, initial);

    expect(states.find((state) => state.positionId === "amber-reading")).toMatchObject({
      representation: "represented",
      primaryModels: [
        "Illustrative Alpha",
        "Illustrative Beta",
        "Illustrative Gamma",
        "Illustrative Delta",
      ],
    });
    expect(states.find((state) => state.positionId === "pine-reading")).toMatchObject({
      representation: "mentioned-only",
      mentioningModels: ["Illustrative Alpha"],
    });
    expect(states.find((state) => state.positionId === "slate-reading")).toMatchObject({
      representation: "mentioned-only",
      mentioningModels: ["Illustrative Gamma"],
    });
    expect(states.find((state) => state.positionId === "ochre-reading")).toMatchObject({
      representation: "not-represented",
    });

    const challenge = joinAssignments(run, mapping, "default", "challenge");
    const challengeStates = derivePositionStates(question, challenge);
    expect(challengeStates.find((state) => state.positionId === "slate-reading")).toMatchObject({
      representation: "represented",
      additionalModels: ["Illustrative Gamma"],
    });
  });

  it("derives positions recovered only under challenge", () => {
    const { run, mapping } = records("case-a");
    const initial = joinAssignments(run, mapping, "default", "answer");
    const challenged = joinAssignments(run, mapping, "default", "challenge");
    const alphaInitial = initial.find((value) => value.cell.model_key === "alpha");
    const alphaChallenge = challenged.find((value) => value.cell.model_key === "alpha");
    if (!alphaInitial || !alphaChallenge) throw new Error("Alpha fixture is missing");

    expect(recoveredPositions(alphaInitial.assignment, alphaChallenge.assignment)).toEqual([
      "pine-reading",
    ]);
  });

  it("keeps Case C variants separate and counts primary movement", () => {
    const { run, mapping } = records("case-c");
    const neutral = joinAssignments(run, mapping, "neutral", "answer");
    const framed = joinAssignments(run, mapping, "framed", "answer");

    expect(sensitivityMovementCount(neutral, framed)).toBe(4);
  });
});

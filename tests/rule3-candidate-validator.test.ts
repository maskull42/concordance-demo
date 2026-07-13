/// <reference types="node" />

import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { validateRule3Candidates } from "../scripts/validate-rule3-candidates";
import type { Question } from "../src/lib/types";

const sourceRoot = path.join(process.cwd(), "candidate/rule3");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function copyBundle(): string {
  const temporary = mkdtempSync(path.join(tmpdir(), "concordance-rule3-"));
  temporaryDirectories.push(temporary);
  const bundle = path.join(temporary, "rule3");
  cpSync(sourceRoot, bundle, { recursive: true });
  return bundle;
}

describe("Rule 3 candidate validator", () => {
  it("accepts the exact proposed two-candidate bundle", () => {
    const result = validateRule3Candidates();

    expect(result.issues).toEqual([]);
    expect(result.questionCount).toBe(2);
    expect(result.positionCount).toBe(7);
    expect(result.sourceCount).toBe(13);
  });

  it("rejects drift from the approved Hooker clarification", () => {
    const bundle = copyBundle();
    const file = path.join(
      bundle,
      "questions/galatians-pistis-christou.json",
    );
    const question = JSON.parse(readFileSync(file, "utf8")) as Question;
    question.position_map[1].summary =
      "The phrase denotes only Christ's faith and excludes participation.";
    writeFileSync(file, `${JSON.stringify(question, null, 2)}\n`);

    const result = validateRule3Candidates(bundle);

    expect(result.issues).toContain(
      "candidate/rule3/questions/galatians-pistis-christou.json: bytes differ from the approved record",
    );
    expect(result.issues).toContain(
      "candidate/rule3: approved Christ-centered subjective definition differs",
    );
  });

  it("rejects a fabricated hash for an explicitly unhashed source", () => {
    const bundle = copyBundle();
    const file = path.join(bundle, "source-freeze.json");
    const freeze = JSON.parse(readFileSync(file, "utf8")) as {
      questions: Array<{
        sources: Array<{
          source_id: string;
          artifact: { sha256: string | null };
        }>;
      }>;
    };
    const source = freeze.questions
      .flatMap((question) => question.sources)
      .find((item) => item.source_id === "grasso-linguistic-analysis");
    if (!source) throw new Error("fixture lacks Grasso");
    source.artifact.sha256 = "0".repeat(64);
    writeFileSync(file, `${JSON.stringify(freeze, null, 2)}\n`);

    const result = validateRule3Candidates(bundle);

    expect(result.issues).toContain(
      "candidate/rule3/source-freeze.json: grasso-linguistic-analysis integrity limitation differs",
    );
  });

  it("rejects extra entries and symlinked question files", () => {
    const bundle = copyBundle();
    writeFileSync(path.join(bundle, "unexpected.txt"), "unexpected\n");
    const question = path.join(
      bundle,
      "questions/galatians-pistis-christou.json",
    );
    const target = path.join(bundle, "galatians-copy.json");
    cpSync(question, target);
    rmSync(question);
    symlinkSync(target, question);

    const result = validateRule3Candidates(bundle);

    expect(
      result.issues.some((issue) =>
        issue.startsWith("candidate/rule3: expected only"),
      ),
    ).toBe(true);
    expect(result.issues).toContain(
      "candidate/rule3/questions/galatians-pistis-christou.json: expected a regular, non-symlink file",
    );
  });
});

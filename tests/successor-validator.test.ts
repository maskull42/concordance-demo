/// <reference types="node" />

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { validateSuccessorBundle } from "../scripts/validate-successor-candidates";
import type { Question } from "../src/lib/types";

const sourceRoot = path.join(
  process.cwd(),
  "candidate/successors/candidate-1.1.1",
);
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function copyBundle(): string {
  const temporary = mkdtempSync(path.join(tmpdir(), "concordance-successor-"));
  temporaryDirectories.push(temporary);
  const bundle = path.join(temporary, "candidate-1.1.1");
  cpSync(sourceRoot, bundle, { recursive: true });
  return bundle;
}

function mutateQuestion(
  bundle: string,
  id: string,
  mutate: (question: Question) => void,
): void {
  const file = path.join(bundle, "questions", `${id}.json`);
  const question = JSON.parse(readFileSync(file, "utf8")) as Question;
  mutate(question);
  writeFileSync(file, `${JSON.stringify(question, null, 2)}\n`);
}

describe("candidate-1.1.1 successor validator", () => {
  it("accepts the pinned ship-safe bundle", () => {
    const result = validateSuccessorBundle();

    expect(result.issues).toEqual([]);
    expect(result.questionCount).toBe(2);
    expect(result.changedFieldCount).toBe(22);
  });

  it("rejects a prompt change even when the successor remains schema-valid", () => {
    const bundle = copyBundle();
    mutateQuestion(bundle, "junia-romans-16-7", (question) => {
      question.prompt_variants[0].user_prompt += " Altered.";
    });

    const result = validateSuccessorBundle(bundle);

    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.1/questions/junia-romans-16-7.json: change is not allowlisted: /prompt_variants/0/user_prompt",
    );
  });

  it("rejects arbitrary wording at an otherwise allowlisted path", () => {
    const bundle = copyBundle();
    mutateQuestion(bundle, "john-brown-harpers-ferry", (question) => {
      question.position_map[1].sources[0].citation += " Altered.";
    });

    const result = validateSuccessorBundle(bundle);

    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.1/questions/john-brown-harpers-ferry.json: successor value differs at /position_map/1/sources/0/citation",
    );
  });

  it("rejects a changed manifest timestamp", () => {
    const bundle = copyBundle();
    const file = path.join(bundle, "manifest.json");
    const manifest = JSON.parse(readFileSync(file, "utf8")) as {
      created_at: string;
    };
    manifest.created_at = "2039-07-13T06:03:17.000Z";
    writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);

    const result = validateSuccessorBundle(bundle);

    expect(result.issues).toContain(
      "successor manifest: bytes differ from candidate-1.1.1",
    );
  });
});

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
import { validateAuthorVerifiedSuccessor } from "../scripts/validate-author-verified-successor";
import type { Question } from "../src/lib/types";

const sourceRoot = path.join(
  process.cwd(),
  "candidate/successors/candidate-1.1.2",
);
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function copyBundle(): string {
  const temporary = mkdtempSync(
    path.join(tmpdir(), "concordance-author-verified-successor-"),
  );
  temporaryDirectories.push(temporary);
  const bundle = path.join(temporary, "candidate-1.1.2");
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

describe("candidate-1.1.2 author-verified successor validator", () => {
  it("accepts the pinned public bundle without the private review", () => {
    const result = validateAuthorVerifiedSuccessor();

    expect(result.issues).toEqual([]);
    expect(result.questionCount).toBe(2);
    expect(result.verificationRecordCount).toBe(26);
  });

  it("rejects schema-valid content drift from candidate-1.1.1", () => {
    const bundle = copyBundle();
    mutateQuestion(bundle, "junia-romans-16-7", (question) => {
      question.premise += " Altered.";
    });

    const result = validateAuthorVerifiedSuccessor(bundle);

    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.2/questions/junia-romans-16-7.json: bytes differ from the pinned record",
    );
    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.2/questions/junia-romans-16-7.json: only content_version and verification may differ from candidate-1.1.1",
    );
  });

  it("rejects an author-verification timestamp change", () => {
    const bundle = copyBundle();
    mutateQuestion(bundle, "john-brown-harpers-ferry", (question) => {
      question.position_map[0].sources[0].verification = {
        status: "author-verified",
        verified_by: "A.G. Elrod",
        verified_at: "2026-07-13T07:33:30.353Z",
      };
    });

    const result = validateAuthorVerifiedSuccessor(bundle);

    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.2/questions/john-brown-harpers-ferry.json: every verification record must be author-verified by A.G. Elrod at 2026-07-13T07:33:29.353Z",
    );
  });

  it("rejects a weakened production gate", () => {
    const bundle = copyBundle();
    const file = path.join(bundle, "manifest.json");
    const manifest = JSON.parse(readFileSync(file, "utf8")) as {
      production_gate: { eligible: boolean; blockers: string[] };
    };
    manifest.production_gate.eligible = true;
    manifest.production_gate.blockers = [];
    writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);

    const result = validateAuthorVerifiedSuccessor(bundle);

    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.2/manifest.json: bytes differ from the pinned record",
    );
    expect(
      result.issues.some((issue) => issue.includes("/production_gate/eligible")),
    ).toBe(true);
  });

  it("rejects extra entries and symlinked public records", () => {
    const bundle = copyBundle();
    writeFileSync(path.join(bundle, "unexpected.txt"), "unexpected\n");
    const question = path.join(bundle, "questions", "junia-romans-16-7.json");
    const target = path.join(bundle, "junia-copy.json");
    cpSync(question, target);
    rmSync(question);
    symlinkSync(target, question);

    const result = validateAuthorVerifiedSuccessor(bundle);

    expect(
      result.issues.some((issue) =>
        issue.startsWith("author-verified successor bundle: expected only"),
      ),
    ).toBe(true);
    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.2/questions/junia-romans-16-7.json: expected a regular, non-symlink file",
    );
  });

  it("rejects forbidden private fields even when JSON remains readable", () => {
    const bundle = copyBundle();
    const file = path.join(bundle, "manifest.json");
    const manifest = JSON.parse(readFileSync(file, "utf8")) as Record<
      string,
      unknown
    >;
    manifest.response_text = "private";
    writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);

    const result = validateAuthorVerifiedSuccessor(bundle);

    expect(result.issues).toContain(
      "candidate/successors/candidate-1.1.2/manifest.json: contains a forbidden private response text field",
    );
  });
});

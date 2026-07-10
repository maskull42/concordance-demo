/// <reference types="node" />

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { modelManifestSchema, runManifestSchema } from "../src/lib/schema";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("Python-to-TypeScript harness contract", () => {
  it("emits linked mocked cells accepted by the shared Zod schemas", () => {
    const output = mkdtempSync(path.join(tmpdir(), "concordance-harness-"));
    temporaryDirectories.push(output);
    const result = spawnSync(
      "python3",
      ["harness/tests/emit_contract_fixture.py", output],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);

    const manifest = modelManifestSchema.parse(
      JSON.parse(readFileSync(path.join(output, "manifests/models.json"), "utf8")),
    );
    const run = runManifestSchema.parse(
      JSON.parse(readFileSync(path.join(output, "runs/case-a.json"), "utf8")),
    );
    expect(manifest.models).toHaveLength(1);
    expect(run.cells).toHaveLength(2);
    const answer = run.cells.find(
      (cell) => cell.status === "success" && cell.call_type === "answer",
    );
    const challenge = run.cells.find(
      (cell) => cell.status === "success" && cell.call_type === "challenge",
    );
    expect(answer?.status).toBe("success");
    expect(challenge?.status).toBe("success");
    if (answer?.status !== "success" || challenge?.status !== "success") return;
    expect(challenge.parent_response_id).toBe(answer.response_id);
    expect(challenge.messages.at(-2)).toEqual({
      role: "assistant",
      content: answer.response_text,
    });
  });
});

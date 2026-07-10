/// <reference types="node" />

import { spawnSync } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("validator command", () => {
  it("reports the relative path for malformed JSON", () => {
    const result = spawnSync(
      path.join(process.cwd(), "node_modules", ".bin", "tsx"),
      ["scripts/validate-data.ts", "--dataset", "tests/fixtures/malformed"],
      { cwd: process.cwd(), encoding: "utf8" },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("index.json: malformed JSON");
    expect(result.stderr).not.toContain(`${process.cwd()}${path.sep}`);
  });
});

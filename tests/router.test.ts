import { describe, expect, it } from "vitest";
import { dataset } from "../src/lib/dataset.sample";
import { buildInspectHash, parseHash } from "../src/lib/router";
import type { Dataset } from "../src/lib/types";

const source = dataset as Dataset;

describe("hash router", () => {
  it("routes the empty hash and /story to story mode", () => {
    expect(parseHash("", source)).toEqual({ mode: "story" });
    expect(parseHash("#", source)).toEqual({ mode: "story" });
    expect(parseHash("#/story", source)).toEqual({ mode: "story" });
  });

  it("routes /inspect and validated deep links", () => {
    expect(parseHash("#/inspect", source)).toEqual({ mode: "inspect" });

    const question = source.questions[0];
    const model = source.manifest.models[0];
    const variant = question.prompt_variants[0];
    const hash = buildInspectHash({
      questionId: question.id,
      modelKey: model.model_key,
      variantId: variant.id,
      view: "answer",
      open: "receipts",
    });
    expect(parseHash(hash, source)).toEqual({
      mode: "inspect",
      questionId: question.id,
      modelKey: model.model_key,
      variantId: variant.id,
      view: "answer",
      open: "receipts",
    });
  });

  it("drops stale or unknown deep-link parameters instead of failing", () => {
    const question = source.questions[0];
    expect(
      parseHash(
        `#/inspect/${question.id}?model=no-such-model&variant=no-such-variant&view=bogus`,
        source,
      ),
    ).toEqual({ mode: "inspect", questionId: question.id });
    expect(parseHash("#/inspect/no-such-question?model=alpha", source)).toEqual({
      mode: "inspect",
    });
  });

  it("keeps legacy anchors working as inspect links", () => {
    expect(parseHash("#cases", source)).toEqual({ mode: "inspect", anchor: "cases" });
    expect(parseHash("#method", source)).toEqual({ mode: "inspect", anchor: "method" });
    const question = source.questions[1];
    expect(parseHash(`#${question.id}`, source)).toEqual({
      mode: "inspect",
      questionId: question.id,
    });
  });

  it("falls back to story mode on unrecognized hashes", () => {
    expect(parseHash("#garbage", source)).toEqual({ mode: "story" });
    expect(parseHash("#/inspect-nonsense", source)).toEqual({ mode: "story" });
  });

  it("round-trips inspect refs through buildInspectHash", () => {
    expect(buildInspectHash({})).toBe("#/inspect");
    const question = source.questions[2];
    expect(buildInspectHash({ questionId: question.id })).toBe(
      `#/inspect/${question.id}`,
    );
  });
});

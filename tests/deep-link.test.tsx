import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { dataset } from "../src/lib/dataset.sample";
import type { Dataset } from "../src/lib/types";
import { renderInspect, resetHash } from "./helpers";

const source = dataset as Dataset;

afterEach(resetHash);

describe("inspect deep links", () => {
  it("opens the receipts drawer and the targeted model receipt", () => {
    const question = source.questions[1];
    const model = source.manifest.models[1];

    renderInspect(
      `#/inspect/${question.id}?model=${model.model_key}&open=receipts`,
    );

    const article = document.getElementById(question.id);
    if (!(article instanceof HTMLElement)) throw new Error("Case not rendered");
    const receipts = article.querySelector("details.receipts-section");
    if (!(receipts instanceof HTMLDetailsElement)) throw new Error("Receipts missing");
    expect(receipts.open).toBe(true);
    const receipt = article.querySelector(
      `details.receipt[data-model="${model.model_key}"]`,
    );
    if (!(receipt instanceof HTMLDetailsElement)) throw new Error("Receipt missing");
    expect(receipt.open).toBe(true);
    expect(receipt.querySelector("pre[data-raw-response]")).not.toBeNull();
  });

  it("selects the requested prompt variant from the hash", () => {
    const question = source.questions.find(
      (entry) => entry.prompt_variants.length > 1,
    );
    if (!question) throw new Error("No prompt-sensitive case in dataset");
    const second = question.prompt_variants[1];

    renderInspect(`#/inspect/${question.id}?variant=${second.id}`);

    const article = document.getElementById(question.id);
    if (!(article instanceof HTMLElement)) throw new Error("Case not rendered");
    const radio = screen.getAllByRole("radio", { name: second.label })[0];
    expect(radio).toBeChecked();
  });

  it("falls back to the answer view when a challenge deep link has no cells", () => {
    const question = source.questions[0];
    renderInspect(`#/inspect/${question.id}?view=challenge`);
    const article = document.getElementById(question.id);
    if (!(article instanceof HTMLElement)) throw new Error("Case not rendered");
    expect(article.isConnected).toBe(true);
  });
});

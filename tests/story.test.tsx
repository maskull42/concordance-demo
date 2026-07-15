import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "../src/App";
import { StoryDistribution } from "../src/components/story/StoryDistribution";
import { collectCaseRecords } from "../src/lib/case-summary";
import { parseHash } from "../src/lib/router";
import { dataset } from "../src/lib/dataset.sample";
import type { Dataset } from "../src/lib/types";
import { buildCaseViewModel, variantMovementCount } from "../src/lib/view-model";
import { resetHash } from "./helpers";

const source = dataset as Dataset;

afterEach(resetHash);

function renderStory() {
  resetHash();
  return render(<App />);
}

describe("story mode", () => {
  it("renders the framing scene from the prompt-sensitive case", () => {
    renderStory();
    const record = collectCaseRecords(source).find(
      (entry) => entry.question.kind === "prompt-sensitive",
    );
    if (!record) throw new Error("No prompt-sensitive case in dataset");

    const scene = screen.getByRole("region", { name: record.question.title });
    expect(scene).toBeInTheDocument();
    expect(
      within(scene).getByText(record.question.prompt_variants[0].user_prompt),
    ).toBeInTheDocument();
  });

  it("shows claim figures that match values recomputed from the view model", () => {
    renderStory();
    const record = collectCaseRecords(source).find(
      (entry) => entry.question.kind === "prompt-sensitive",
    );
    if (!record) throw new Error("No prompt-sensitive case in dataset");
    const [first, second] = record.question.prompt_variants;
    const view = buildCaseViewModel(
      record.question,
      record.run,
      record.mapping,
      source.manifest.models,
      first.id,
      "answer",
    );
    const top = Math.max(
      0,
      ...view.positions.map((position) => position.primaryModels.length),
    );
    const movement = variantMovementCount(
      record.run,
      record.mapping,
      first.id,
      second.id,
      "answer",
    );

    const scene = screen.getByRole("region", { name: record.question.title });
    const figures = scene.querySelectorAll(".story-figure");
    const texts = Array.from(figures, (node) => node.textContent);
    expect(texts).toContain(`${top} of ${view.models.length}`);
    expect(texts).toContain(`${movement} of ${view.models.length}`);
  });

  it("only emits inspect links that resolve against the dataset", () => {
    const { container } = renderStory();
    const links = Array.from(
      container.querySelectorAll<HTMLAnchorElement>('a[href^="#/inspect"]'),
    );
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      const hash = link.getAttribute("href") ?? "";
      const route = parseHash(hash, source);
      expect(route.mode).toBe("inspect");
      if (hash.startsWith("#/inspect/")) {
        expect(route.mode === "inspect" && route.questionId).toBeTruthy();
      }
    }
  });

  it("keeps the per-case honesty aside in the story", () => {
    renderStory();
    const record = collectCaseRecords(source).find(
      (entry) => entry.question.kind === "prompt-sensitive",
    );
    if (!record) throw new Error("No prompt-sensitive case in dataset");
    for (const item of record.question.what_this_does_not_show) {
      expect(screen.getByText(item)).toBeInTheDocument();
    }
  });

  it("renders verbatim answer excerpts as inert text", () => {
    const record = collectCaseRecords(source).find(
      (entry) => entry.question.kind === "prompt-sensitive",
    );
    if (!record) throw new Error("No prompt-sensitive case in dataset");
    const view = buildCaseViewModel(
      record.question,
      record.run,
      record.mapping,
      source.manifest.models,
      record.question.prompt_variants[0].id,
      "answer",
    );

    const { container } = render(<StoryDistribution view={view} stage="answers" />);

    const cards = container.querySelectorAll(".story-answer-card");
    expect(cards.length).toBe(view.models.length);
    for (const card of cards) {
      expect(card.querySelector("strong")).toBeNull();
    }
  });
});

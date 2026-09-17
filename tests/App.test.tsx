import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "../src/App";
import { renderInspect, resetHash } from "./helpers";

afterEach(resetHash);

describe("application shell", () => {
  it("renders the story landing", () => {
    resetHash();
    render(<App />);

    expect(
      screen.getByRole("main", { name: "Concordance story" }),
    ).toBeInTheDocument();
  });

  it("keeps the case machinery visible in inspect mode", () => {
    renderInspect();

    expect(
      screen.getByRole("heading", { name: "Three patterns policy teams should see." }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("article")).toHaveLength(3);
  });
});

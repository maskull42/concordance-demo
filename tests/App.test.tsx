import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "../src/App";
import { renderInspect, resetHash } from "./helpers";

afterEach(resetHash);

describe("application shell", () => {
  it("keeps the methodological limitation and sample status visible on the story landing", () => {
    resetHash();
    render(<App />);

    expect(screen.getByLabelText("Methodological limitation")).toHaveTextContent(
      "Agreement is not truth",
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "No answer below is a real model run",
    );
    expect(
      screen.getByRole("main", { name: "Concordance story" }),
    ).toBeInTheDocument();
  });

  it("keeps the banner, status, and case machinery visible in inspect mode", () => {
    renderInspect();

    expect(screen.getByLabelText("Methodological limitation")).toHaveTextContent(
      "Agreement is not truth",
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "No answer below is a real model run",
    );
    expect(
      screen.getByRole("heading", { name: "Three patterns policy teams should see." }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("article")).toHaveLength(3);
  });
});

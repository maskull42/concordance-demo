import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "../src/App";

describe("application shell", () => {
  it("keeps the methodological limitation and sample status visible", () => {
    render(<App />);

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

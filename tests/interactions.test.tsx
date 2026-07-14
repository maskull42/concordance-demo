import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../src/App";
import { CaseStudy } from "../src/components/CaseStudy";
import { dataset } from "../src/lib/dataset.sample";

describe("case interactions", () => {
  it("changes the Case C map and receipts atomically with the prompt variant", async () => {
    const user = userEvent.setup();
    render(<App />);
    const caseC = screen.getByRole("article", {
      name: /fictional prompt-sensitivity case/i,
    });
    const framed = within(caseC).getByRole("radio", { name: "Framed phrasing" });

    await user.click(framed);

    expect(framed).toBeChecked();
    expect(within(caseC).getByText(/4 models changed primary position/i)).toBeInTheDocument();
    expect(
      within(caseC).getAllByText(/fictional case C with a fictional frame/i).length,
    ).toBeGreaterThan(0);
    const detail = caseC.querySelector(".model-detail");
    expect(detail).not.toBeNull();
    expect(within(detail as HTMLElement).getByText("East reading")).toBeInTheDocument();
  });

  it("shows linked challenge movement and recovered positions", async () => {
    const user = userEvent.setup();
    render(<App />);
    const caseA = screen.getByRole("article", { name: /fictional convergence case/i });
    const challenge = within(caseA).getByRole("button", {
      name: "Challenge this consensus",
    });

    await user.click(challenge);

    expect(challenge).toHaveAttribute("aria-pressed", "true");
    expect(within(caseA).getByText(/Challenge answers shown;/i)).toBeInTheDocument();
    expect(within(caseA).getAllByText(/Recovered under challenge/i).length).toBeGreaterThan(0);
    const detail = caseA.querySelector(".model-detail");
    expect(detail).not.toBeNull();
    expect(within(detail as HTMLElement).getByText("Amber reading")).toBeInTheDocument();
    expect(within(detail as HTMLElement).getByText("Pine reading")).toBeInTheDocument();
  });

  it("renders raw HTML-looking provider text as inert text", async () => {
    const user = userEvent.setup();
    render(<App />);
    const caseB = screen.getByRole("article", { name: /fictional divergence case/i });
    const receipts = caseB.querySelector("details.receipts-section");
    if (!(receipts instanceof HTMLDetailsElement)) throw new Error("Receipts missing");
    await user.click(receipts.querySelector(":scope > summary") as HTMLElement);
    const receipt = caseB.querySelector('details.receipt[data-model="beta"]');
    if (!(receipt instanceof HTMLDetailsElement)) throw new Error("Beta receipt missing");
    const summary = receipt.querySelector("summary");
    if (!(summary instanceof HTMLElement)) throw new Error("Beta summary missing");

    await user.click(summary);

    const raw = receipt.querySelector("pre[data-raw-response]");
    expect(raw).toHaveTextContent("<strong>not markup</strong>");
    expect(raw?.querySelector("strong")).toBeNull();
  });

  it("keeps a failed challenge visibly unavailable and unmapped", async () => {
    const user = userEvent.setup();
    render(<App />);
    const caseB = screen.getByRole("article", { name: /fictional divergence case/i });
    await user.click(
      within(caseB).getByRole("button", { name: "Challenge this consensus" }),
    );
    const receipts = caseB.querySelector("details.receipts-section");
    if (!(receipts instanceof HTMLDetailsElement)) throw new Error("Receipts missing");
    await user.click(receipts.querySelector(":scope > summary") as HTMLElement);
    const receipt = caseB.querySelector('details.receipt[data-model="delta"]');
    if (!(receipt instanceof HTMLDetailsElement)) throw new Error("Delta receipt missing");

    expect(within(receipt).getByText("Unavailable")).toBeInTheDocument();
    await user.click(receipt.querySelector("summary") as HTMLElement);
    expect(within(receipt).getByText(/Illustrative not-run state/i)).toBeInTheDocument();
    expect(within(receipt).getByText(/No mapping exists/i)).toBeInTheDocument();
  });

  it("labels an unrun challenge sample and disables its control", () => {
    const question = dataset.questions[0];
    const sourceRun = dataset.runs.find(
      (run) => run.question_id === question.id,
    );
    const mapping = dataset.mappings.find(
      (value) => value.question_id === question.id,
    );
    if (!sourceRun || !mapping) throw new Error("Case A fixture is missing");
    const run = {
      ...sourceRun,
      cells: sourceRun.cells.filter((cell) => cell.call_type === "answer"),
    };

    render(
      <CaseStudy
        question={question}
        run={run}
        mapping={mapping}
        models={dataset.manifest.models}
        label="A"
      />,
    );

    expect(
      screen.getByRole("button", { name: "No challenge sample" }),
    ).toBeDisabled();
    expect(screen.getByText(/initial answers only/i)).toBeInTheDocument();
  });

  it("labels omitted secondary mappings as unreviewed", () => {
    const question = dataset.questions[0];
    const run = dataset.runs.find((value) => value.question_id === question.id);
    const sourceMapping = dataset.mappings.find(
      (value) => value.question_id === question.id,
    );
    if (!run || !sourceMapping) throw new Error("Case A fixture is missing");
    const mapping = {
      ...sourceMapping,
      mapping_version: "prototype-primary-1",
      assignments: sourceMapping.assignments.map((assignment) => ({
        ...assignment,
        also_endorsed: [],
        mentioned: [],
      })),
    };

    render(
      <CaseStudy
        question={question}
        run={run}
        mapping={mapping}
        models={dataset.manifest.models}
        label="A"
      />,
    );

    expect(
      screen.getByText(/secondary endorsements and mentions were not reviewed/i),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText("Not reviewed in this prototype").length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByText(/documented positions did not appear as a primary conclusion/i),
    ).toBeInTheDocument();
  });
});

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const script = readFileSync(
  resolve("harness/divergence_successor/review_assets/review.js"),
  "utf8",
);

function reviewEvidence() {
  return {
    pool_id: "concordance-divergence-replacement-1",
    candidate_blind_id: `C-${"A".repeat(32)}`,
    review_packet_sha256: "1".repeat(64),
    blind_packet_sha256: "2".repeat(64),
    first_pass_receipt_sha256: "3".repeat(64),
    items: [
      {
        blind_id: `B-${"B".repeat(32)}`,
        response_sha256: "4".repeat(64),
        first_pass_assignment_sha256: "5".repeat(64),
        user_prompt: "Choose one primary legal architecture.",
        response_text: "The second local position is the best architecture.",
        position_map: [
          {
            handle: "P1",
            label: "Downstream high-risk-use and general-law regulation",
            summary: "Regulate downstream uses.",
            attestation: "Source-bound.",
            sources: [],
          },
          {
            handle: "P2",
            label: "License before a covered training run",
            summary: "Require prior training permission.",
            attestation: "Source-bound.",
            sources: [],
          },
          {
            handle: "P3",
            label: "Binding developer supervision without licensing",
            summary: "Impose duties without prior permission.",
            attestation: "Source-bound.",
            sources: [],
          },
          {
            handle: "P4",
            label: "License only before broad deployment or release",
            summary: "Gate deployment and release.",
            attestation: "Source-bound.",
            sources: [],
          },
        ],
        first_pass: {
          blind_id: `B-${"B".repeat(32)}`,
          response_sha256: "4".repeat(64),
          primary_position_handle: "P2",
          primary_reason_code: "clear_preference",
          rationale: "The response selects the training-run gate.",
          evidence_snippets: ["The second local position is the best architecture."],
          confidence: "high",
        },
      },
    ],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

describe("divergence successor author-review UI", () => {
  it("shows response-local labels while exporting only the selected local handle", () => {
    const evidence = reviewEvidence();
    document.body.innerHTML = `
      <main>
        <div id="items"></div>
        <button id="export" type="button">Export</button>
        <p id="error"></p>
      </main>
      <script id="divergence-successor-evidence" type="application/octet-stream">
        ${Buffer.from(JSON.stringify(evidence), "utf8").toString("base64")}
      </script>
    `;

    let exportedText = "";
    class CapturedBlob {
      readonly type: string;

      constructor(parts: BlobPart[], options?: BlobPropertyBag) {
        exportedText = parts.map((part) => String(part)).join("");
        this.type = options?.type ?? "";
      }
    }
    vi.stubGlobal("Blob", CapturedBlob);
    Object.defineProperty(window, "Blob", {
      configurable: true,
      value: CapturedBlob,
    });
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:successor-review");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    window.eval(script);

    expect(
      document.querySelector('[data-role="first-pass-primary"]'),
    ).toHaveTextContent("Primary: P2: License before a covered training run");

    const primary = document.querySelector(
      '[data-role="primary"]',
    ) as HTMLSelectElement;
    const visibleOptions = [...primary.options].map((option) => ({
      value: option.value,
      text: option.textContent,
    }));
    expect(visibleOptions).toContainEqual({
      value: "P2",
      text: "P2: License before a covered training run",
    });
    expect(visibleOptions).toContainEqual({
      value: "P1",
      text: "P1: Downstream high-risk-use and general-law regulation",
    });

    const decision = document.querySelector(
      '[data-role="decision"]',
    ) as HTMLSelectElement;
    decision.value = "confirm";
    (document.getElementById("export") as HTMLButtonElement).click();

    expect(document.getElementById("error")).toHaveTextContent("");
    const exported = JSON.parse(exportedText) as {
      decisions: Array<{ reviewed_primary_position_handle: string }>;
    };
    expect(exported.decisions[0].reviewed_primary_position_handle).toBe("P2");
    expect(exportedText).not.toContain("development-stage-licensing");
    expect(exportedText).not.toContain("License before a covered training run");
  });
});

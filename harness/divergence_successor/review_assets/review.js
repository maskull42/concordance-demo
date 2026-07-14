"use strict";

const CLOSED_REASONS = ["clear_preference", "mixed", "unclear", "refusal", "outside_map"];
const evidenceNode = document.getElementById("divergence-successor-evidence");
const evidence = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(evidenceNode.textContent.trim()), c => c.charCodeAt(0))));
const container = document.getElementById("items");
const errorNode = document.getElementById("error");

function element(name, className, text) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function field(labelText, control) {
  const wrapper = element("div", "field");
  const label = element("label", "", labelText);
  label.append(control);
  wrapper.append(label);
  return wrapper;
}

function select(options, selected) {
  const control = document.createElement("select");
  for (const { value, label } of options) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    option.selected = value === selected;
    control.append(option);
  }
  return control;
}

function localPositionLabel(item, handle) {
  if (handle === null) return "null: no clear primary position";
  const position = item.position_map.find(candidate => candidate.handle === handle);
  if (!position) throw new Error(`Unknown local position handle ${handle}.`);
  return `${handle}: ${position.label}`;
}

function renderItem(item, index) {
  const article = element("article", "item");
  article.dataset.blindId = item.blind_id;
  article.append(element("h2", "", `Response ${index + 1}`));
  article.append(element("p", "muted", `Blind record ${item.blind_id}`));
  article.append(element("h3", "", "Exact question"));
  article.append(element("pre", "response", item.user_prompt));

  const map = element("section", "map");
  for (const position of item.position_map) {
    const card = element("div", "position");
    card.append(element("h3", "", `${position.handle}: ${position.label}`));
    card.append(element("p", "", position.summary));
    card.append(element("p", "muted", position.attestation));
    if (Array.isArray(position.sources)) {
      for (const source of position.sources) {
        const sourceBlock = element("div", "source");
        sourceBlock.append(element("h4", "", source.title));
        sourceBlock.append(element("p", "", source.citation));
        sourceBlock.append(element("p", "", source.claim_supported));
        sourceBlock.append(element("p", "muted", source.url));
        card.append(sourceBlock);
      }
    }
    map.append(card);
  }
  article.append(map);
  article.append(element("h3", "", "Model response"));
  article.append(element("pre", "response", item.response_text));

  const first = item.first_pass;
  const firstPass = element("section", "first-pass");
  firstPass.append(element("h3", "", "Codex first pass"));
  const firstPrimary = element(
    "p",
    "",
    `Primary: ${localPositionLabel(item, first.primary_position_handle)}`
  );
  firstPrimary.dataset.role = "first-pass-primary";
  firstPass.append(firstPrimary);
  firstPass.append(element("p", "", `Reason: ${first.primary_reason_code}; confidence: ${first.confidence}`));
  firstPass.append(element("p", "", first.rationale));
  for (const snippet of first.evidence_snippets) firstPass.append(element("blockquote", "snippet", snippet));
  article.append(firstPass);

  const decision = element("section", "decision");
  const choice = select(
    [
      { value: "", label: "Select a decision" },
      { value: "confirm", label: "confirm" },
      { value: "correct", label: "correct" }
    ],
    ""
  );
  choice.dataset.role = "decision";
  decision.append(field("Decision ", choice));
  const primaryOptions = [
    { value: "", label: "Select a reviewed primary" },
    { value: "null", label: localPositionLabel(item, null) },
    ...item.position_map.map(position => ({
      value: position.handle,
      label: localPositionLabel(item, position.handle)
    }))
  ];
  const primary = select(
    primaryOptions,
    first.primary_position_handle === null ? "null" : first.primary_position_handle
  );
  primary.dataset.role = "primary";
  decision.append(field("Reviewed primary ", primary));
  const reason = select(
    [
      { value: "", label: "Select a reason" },
      ...CLOSED_REASONS.map(value => ({ value, label: value }))
    ],
    first.primary_reason_code
  );
  reason.dataset.role = "reason";
  decision.append(field("Reviewed reason ", reason));
  article.append(decision);
  container.append(article);
}

for (const [index, item] of evidence.items.entries()) renderItem(item, index);

function collect() {
  const decisions = [];
  for (const [index, article] of [...document.querySelectorAll(".item")].entries()) {
    const item = evidence.items[index];
    const decision = article.querySelector('[data-role="decision"]').value;
    const rawPrimary = article.querySelector('[data-role="primary"]').value;
    const reason = article.querySelector('[data-role="reason"]').value;
    if (!decision || !rawPrimary || !reason) throw new Error(`Response ${index + 1} is incomplete.`);
    const primary = rawPrimary === "null" ? null : rawPrimary;
    if ((primary === null) !== (reason !== "clear_preference")) throw new Error(`Response ${index + 1} has an inconsistent primary and reason.`);
    const unchanged = primary === item.first_pass.primary_position_handle && reason === item.first_pass.primary_reason_code;
    if (decision === "confirm" && !unchanged) throw new Error(`Response ${index + 1} says confirm but changes the decision.`);
    if (decision === "correct" && unchanged) throw new Error(`Response ${index + 1} says correct but preserves the first-pass decision.`);
    decisions.push({
      blind_id: item.blind_id,
      response_sha256: item.response_sha256,
      first_pass_assignment_sha256: item.first_pass_assignment_sha256,
      decision,
      reviewed_primary_position_handle: primary,
      reviewed_reason_code: reason,
      reviewed_at: new Date().toISOString()
    });
  }
  return decisions;
}

document.getElementById("export").addEventListener("click", () => {
  errorNode.textContent = "";
  try {
    const payload = {
      schema_version: "divergence-successor-author-review-draft-1.0.0",
      status: "complete-author-review",
      pool_id: evidence.pool_id,
      candidate_blind_id: evidence.candidate_blind_id,
      review_packet_sha256: evidence.review_packet_sha256,
      blind_packet_sha256: evidence.blind_packet_sha256,
      first_pass_receipt_sha256: evidence.first_pass_receipt_sha256,
      reviewer: { id: "ag-elrod", display_name: "A.G. Elrod" },
      exported_at: new Date().toISOString(),
      item_count: evidence.items.length,
      decisions: collect(),
      author_attestation: {
        reviewed_all_evidence: true,
        decisions_complete: true,
        threshold_not_seen: true
      },
      threshold_evaluation: { performed: false }
    };
    const json = `${JSON.stringify(payload, null, 2)}\n`;
    const blob = new Blob([json], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "divergence-successor-author-review.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 0);
  } catch (error) {
    errorNode.textContent = error instanceof Error ? error.message : String(error);
  }
});

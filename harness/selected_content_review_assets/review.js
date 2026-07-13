"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const setText = (node, value) => {
    node.textContent = value;
    return node;
  };
  const element = (name, className, value) => {
    const node = document.createElement(name);
    if (className) node.className = className;
    if (value !== undefined) setText(node, value);
    return node;
  };
  const decodePacket = () => {
    const binary = atob(byId("packet-data").textContent.trim());
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  };
  const appendField = (parent, label, value, className) => {
    const wrapper = element("p", className || "");
    wrapper.append(element("span", "field-label", label));
    wrapper.append(document.createTextNode(value));
    parent.append(wrapper);
  };
  const downloadJson = (value, filename) => {
    const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  const packet = decodePacket();
  const approvals = new Set();
  const requiredApprovals = packet.questions.flatMap((record) => [
    `content:${record.question.id}`,
    `mappings:${record.question.id}`,
  ]);
  const root = byId("review-root");
  const progress = byId("review-progress");
  const progressCopy = byId("progress-copy");
  const finish = byId("finish-review");
  const status = byId("live-status");

  const updateProgress = () => {
    progress.value = approvals.size;
    progress.max = requiredApprovals.length;
    setText(
      progressCopy,
      `${approvals.size} of ${requiredApprovals.length} attestations complete`,
    );
    finish.disabled = approvals.size !== requiredApprovals.length;
  };

  const attestation = (key, copy) => {
    const wrapper = element("div", "attestation-card");
    const input = document.createElement("input");
    const id = `approval-${key.replace(/[^a-z0-9]+/gi, "-")}`;
    input.type = "checkbox";
    input.id = id;
    const label = element("label", "", copy);
    label.htmlFor = id;
    input.addEventListener("change", () => {
      if (input.checked) approvals.add(key);
      else approvals.delete(key);
      updateProgress();
    });
    wrapper.append(input, label);
    return wrapper;
  };

  const renderSource = (source) => {
    const card = element("article", "source-card");
    card.append(element("h5", "", source.title));
    appendField(card, "Source ID", source.id, "record-meta");
    appendField(card, "Exact claim", source.claim_supported);
    appendField(card, "Exact citation", source.citation);
    appendField(card, "URL", source.url, "record-meta");
    appendField(card, "Accessed", source.accessed_at, "record-meta");
    appendField(
      card,
      "Current machine status",
      source.verification.status,
      "verification-value",
    );
    return card;
  };

  const renderPosition = (position) => {
    const card = element("article", "position-card");
    card.append(element("h4", "", position.label));
    appendField(card, "Position ID", position.id, "record-meta");
    appendField(card, "Summary", position.summary);
    appendField(card, "Attestation", position.attestation);
    appendField(
      card,
      "Current machine status",
      position.verification.status,
      "verification-value",
    );
    const sources = element("div", "source-list");
    for (const source of position.sources) sources.append(renderSource(source));
    card.append(sources);
    return card;
  };

  const renderMapping = (mapping) => {
    const details = element("details", "mapping-card");
    const primary = mapping.reviewed_primary_position_id === null
      ? `Outside map (${mapping.reviewed_primary_reason_code})`
      : `${mapping.reviewed_primary_position_label} (${mapping.reviewed_primary_reason_code})`;
    details.append(
      element(
        "summary",
        "",
        `${mapping.model_family}, ${mapping.variant_label}: ${primary}`,
      ),
    );
    appendField(details, "Cell", mapping.cell_id, "record-meta");
    appendField(details, "Response SHA-256", mapping.response_sha256, "record-meta");
    appendField(details, "Prompt", mapping.user_prompt);
    appendField(details, "Review decision", mapping.review_decision, "record-meta");
    appendField(details, "Reviewed primary", primary, "mapping-primary");
    if (mapping.review_note) appendField(details, "Review note", mapping.review_note);
    details.append(element("pre", "response", mapping.response_text));
    return details;
  };

  for (const record of packet.questions) {
    const question = record.question;
    const mappings = packet.mappings.filter(
      (mapping) => mapping.question_id === question.id,
    );
    const article = element("article", "question-review");
    const header = element("header");
    header.append(element("p", "eyebrow", "Selected case"));
    header.append(element("h2", "", question.title));
    header.append(element("p", "muted", question.premise));
    appendField(header, "Question ID", question.id, "record-meta");
    appendField(header, "Content version", question.content_version, "record-meta");
    appendField(
      header,
      "Current machine status",
      question.verification.status,
      "verification-value",
    );
    article.append(header);

    const questionSection = element("section", "section");
    questionSection.append(element("h3", "", "Exact question record"));
    appendField(questionSection, "Context note", question.context_note);
    const prompts = element("div", "prompt-list");
    for (const variant of question.prompt_variants) {
      const card = element("article", "source-card");
      card.append(element("h4", "", variant.label));
      appendField(card, "Variant ID", variant.id, "record-meta");
      appendField(card, "Exact prompt", variant.user_prompt, "prompt");
      prompts.append(card);
    }
    questionSection.append(prompts);
    const positions = element("div", "position-list");
    for (const position of question.position_map) {
      positions.append(renderPosition(position));
    }
    questionSection.append(positions);
    const fullRecord = element("details", "full-question-record");
    fullRecord.open = true;
    fullRecord.append(element("summary", "", "Complete bound question JSON"));
    appendField(
      fullRecord,
      "Bound question SHA-256",
      record.sha256,
      "record-meta",
    );
    fullRecord.append(
      element("pre", "question-json", JSON.stringify(question, null, 2)),
    );
    questionSection.append(fullRecord);
    questionSection.append(
      attestation(
        `content:${question.id}`,
        `I reviewed this exact ${question.title} question, every position, and every source claim and citation. I approve changing all of those records together from proposed to author-verified.`,
      ),
    );
    article.append(questionSection);

    const mappingSection = element("section", "section");
    mappingSection.append(element("h3", "", `Sealed Rule 2 mappings (${mappings.length})`));
    mappingSection.append(
      element(
        "p",
        "muted",
        "These mappings explain the pilot selection only. The final application run must map its own fresh responses.",
      ),
    );
    const mappingList = element("div", "mapping-list");
    for (const mapping of mappings) mappingList.append(renderMapping(mapping));
    mappingSection.append(mappingList);
    mappingSection.append(
      attestation(
        `mappings:${question.id}`,
        `I reviewed the ${mappings.length} unblinded mappings for ${question.title}, including the complete sampled responses and the sealed primary assignments. I approve this pilot lineage and understand that it is not reusable as final-run mapping data.`,
      ),
    );
    article.append(mappingSection);
    root.append(article);
  }

  finish.addEventListener("click", () => {
    if (approvals.size !== requiredApprovals.length) return;
    const reviewedAt = new Date().toISOString();
    const exportValue = {
      schema_version: "selected-content-review-draft-1.0.0",
      status: "complete-selected-content-review",
      exported_at: reviewedAt,
      network_requests: 0,
      environment_variables_read: 0,
      review_id: packet.review_id,
      reviewer: { id: "ag-elrod", display_name: "A.G. Elrod" },
      bindings: packet.bindings,
      content_decisions: packet.questions.map((record) => ({
        question_id: record.question.id,
        question_sha256: record.sha256,
        decision: "author-verify",
        reviewed_at: reviewedAt,
      })),
      mapping_attestations: packet.mapping_groups.map((group) => ({
        question_id: group.question_id,
        mapping_count: group.mapping_count,
        mappings_sha256: group.mappings_sha256,
        decision: "approve-pilot-lineage",
        reviewed_at: reviewedAt,
      })),
      author_attestation: {
        exact_content_reviewed: true,
        selected_pilot_mappings_reviewed: true,
        final_run_requires_fresh_mappings: true,
      },
    };
    downloadJson(exportValue, "concordance-selected-content-review.json");
    setText(status, "Complete selected-content review exported.");
  });

  updateProgress();
})();

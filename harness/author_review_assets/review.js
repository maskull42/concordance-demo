"use strict";

(() => {
  const REASON_CODES = ["clear_preference", "mixed", "unclear", "refusal", "outside_map"];
  const DRAFT_KEYS = [
    "schema_version",
    "status",
    "rubric_id",
    "rubric_sha256",
    "exported_at",
    "network_requests",
    "environment_variables_read",
    "review_id",
    "first_pass_receipt_sha256",
    "ordered_items_sha256",
    "reviewer",
    "review_scope",
    "item_count",
    "cursor",
    "decisions",
    "author_attestation",
    "threshold_evaluation",
    "selection_status",
  ];
  const DECISION_KEYS = [
    "review_index",
    "blind_item_id",
    "response_sha256",
    "review_item_sha256",
    "first_pass_assignment_sha256",
    "first_pass_primary_endorsed",
    "first_pass_primary_reason_code",
    "decision",
    "reviewed_primary_endorsed",
    "reviewed_primary_reason_code",
    "review_note",
    "reviewed_at",
  ];

  const byId = (id) => document.getElementById(id);
  const exactKeys = (value, keys) => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const actual = Object.keys(value).sort();
    const expected = [...keys].sort();
    return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
  };
  const sameValue = (left, right) => left === right;
  const setText = (element, value) => {
    element.textContent = value;
  };
  const appendList = (element, values, emptyText) => {
    element.replaceChildren();
    if (values.length === 0) {
      const item = document.createElement("li");
      setText(item, emptyText);
      element.append(item);
      return;
    }
    for (const value of values) {
      const item = document.createElement("li");
      setText(item, value);
      element.append(item);
    }
  };
  const decodePacket = () => {
    const encoded = byId("packet-data").textContent.trim();
    const binary = atob(encoded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  };

  const packet = decodePacket();
  const items = packet.items;
  const itemById = Object.create(null);
  for (const item of items) itemById[item.blind_item_id] = item;
  const storageKey = `concordance-author-review:${packet.review_id}`;

  const state = {
    cursor: 0,
    filter: "all",
    decisions: items.map((item) => ({
      review_index: item.review_index,
      blind_item_id: item.blind_item_id,
      response_sha256: item.response_sha256,
      review_item_sha256: item.review_item_sha256,
      first_pass_assignment_sha256: item.first_pass_assignment_sha256,
      first_pass_primary_endorsed: item.first_pass_assignment.primary_endorsed,
      first_pass_primary_reason_code: item.first_pass_assignment.primary_reason_code,
      decision: "pending",
      reviewed_primary_endorsed: item.first_pass_assignment.primary_endorsed,
      reviewed_primary_reason_code: item.first_pass_assignment.primary_reason_code,
      review_note: null,
      reviewed_at: null,
    })),
  };

  const elements = {
    progress: byId("review-progress"),
    progressCopy: byId("progress-copy"),
    live: byId("live-status"),
    filter: byId("filter"),
    itemLabel: byId("item-label"),
    itemTitle: byId("item-title"),
    decisionBadge: byId("decision-badge"),
    attentionBadge: byId("attention-badge"),
    prompt: byId("prompt"),
    positions: byId("positions"),
    response: byId("response"),
    firstPrimary: byId("first-primary"),
    firstReason: byId("first-reason"),
    also: byId("also-endorsed"),
    mentioned: byId("mentioned"),
    rationale: byId("rationale"),
    evidence: byId("evidence"),
    confidence: byId("confidence"),
    flags: byId("review-flags"),
    primarySelect: byId("primary-select"),
    reasonSelect: byId("reason-select"),
    reviewNote: byId("review-note"),
    error: byId("decision-error"),
    saveNote: byId("save-note"),
    previous: byId("previous"),
    next: byId("next"),
    nextUnreviewed: byId("next-unreviewed"),
    confirm: byId("confirm-decision"),
    correct: byId("correct-decision"),
    exportDraft: byId("export-draft"),
    finish: byId("finish-review"),
    importButton: byId("import-button"),
    importFile: byId("import-file"),
  };

  const currentItem = () => items[state.cursor];
  const currentDecision = () => state.decisions[state.cursor];
  const isAttention = (item) => (
    item.first_pass_assignment.primary_endorsed === null
    || item.first_pass_assignment.confidence !== "high"
    || item.first_pass_assignment.review_flags.length > 0
  );
  const visibleIndices = () => items
    .map((item, index) => ({ item, decision: state.decisions[index], index }))
    .filter(({ item, decision }) => {
      if (state.filter === "unreviewed") return decision.decision === "pending";
      if (state.filter === "attention") return isAttention(item);
      if (state.filter === "corrected") return decision.decision === "correct";
      return true;
    })
    .map(({ index }) => index);
  const positionName = (item, handle) => {
    if (handle === null) return "No clear primary";
    const position = item.positions.find((candidate) => candidate.handle === handle);
    return position ? `${handle}: ${position.label}` : handle;
  };
  const decidedCount = () => state.decisions.filter((value) => value.decision !== "pending").length;

  const normalizeNote = (value) => {
    if (value === null) return null;
    if (typeof value !== "string" || value.length > 4000) throw new Error("A review note is invalid.");
    const trimmed = value.trim();
    return trimmed ? trimmed : null;
  };
  const validPair = (item, primary, reason) => {
    const handles = item.positions.map((position) => position.handle);
    if (primary !== null && !handles.includes(primary)) return false;
    if (!REASON_CODES.includes(reason)) return false;
    return primary === null ? reason !== "clear_preference" : reason === "clear_preference";
  };

  const validateDecision = (candidate, item, allowPending) => {
    if (!exactKeys(candidate, DECISION_KEYS)) throw new Error("A decision has unexpected fields.");
    if (
      candidate.review_index !== item.review_index
      || candidate.blind_item_id !== item.blind_item_id
      || candidate.response_sha256 !== item.response_sha256
      || candidate.review_item_sha256 !== item.review_item_sha256
      || candidate.first_pass_assignment_sha256 !== item.first_pass_assignment_sha256
      || !sameValue(candidate.first_pass_primary_endorsed, item.first_pass_assignment.primary_endorsed)
      || candidate.first_pass_primary_reason_code !== item.first_pass_assignment.primary_reason_code
    ) throw new Error("A decision is bound to different source material.");
    if (!["pending", "confirm", "correct"].includes(candidate.decision)) {
      throw new Error("A decision value is invalid.");
    }
    if (!allowPending && candidate.decision === "pending") throw new Error("The review is incomplete.");
    if (!validPair(item, candidate.reviewed_primary_endorsed, candidate.reviewed_primary_reason_code)) {
      throw new Error("A reviewed primary and reason are inconsistent.");
    }
    const note = normalizeNote(candidate.review_note);
    if (candidate.reviewed_at !== null && (
      typeof candidate.reviewed_at !== "string"
      || candidate.reviewed_at.length > 40
      || Number.isNaN(Date.parse(candidate.reviewed_at))
    )) throw new Error("A review timestamp is invalid.");
    const unchanged = (
      sameValue(candidate.reviewed_primary_endorsed, candidate.first_pass_primary_endorsed)
      && candidate.reviewed_primary_reason_code === candidate.first_pass_primary_reason_code
    );
    if (candidate.decision === "confirm" && (!unchanged || candidate.reviewed_at === null)) {
      throw new Error("A confirmation must preserve the first-pass pair.");
    }
    if (candidate.decision === "correct" && (unchanged || candidate.reviewed_at === null)) {
      throw new Error("A correction must change the first-pass pair.");
    }
    if (candidate.decision === "pending" && candidate.reviewed_at !== null) {
      throw new Error("A pending item cannot have a review timestamp.");
    }
    return {
      review_index: candidate.review_index,
      blind_item_id: candidate.blind_item_id,
      response_sha256: candidate.response_sha256,
      review_item_sha256: candidate.review_item_sha256,
      first_pass_assignment_sha256: candidate.first_pass_assignment_sha256,
      first_pass_primary_endorsed: candidate.first_pass_primary_endorsed,
      first_pass_primary_reason_code: candidate.first_pass_primary_reason_code,
      decision: candidate.decision,
      reviewed_primary_endorsed: candidate.reviewed_primary_endorsed,
      reviewed_primary_reason_code: candidate.reviewed_primary_reason_code,
      review_note: note,
      reviewed_at: candidate.reviewed_at,
    };
  };

  const validateDraft = (candidate) => {
    if (!exactKeys(candidate, DRAFT_KEYS)) throw new Error("The review file has unexpected fields.");
    if (
      candidate.schema_version !== "blind-primary-review-draft-1.0.0"
      || !["author-review-in-progress", "complete-primary-review"].includes(candidate.status)
      || candidate.rubric_id !== packet.rubric_id
      || candidate.rubric_sha256 !== packet.rubric_sha256
      || candidate.network_requests !== 0
      || candidate.environment_variables_read !== 0
      || candidate.review_id !== packet.review_id
      || candidate.first_pass_receipt_sha256 !== packet.first_pass_receipt_sha256
      || candidate.ordered_items_sha256 !== packet.ordered_items_sha256
      || !exactKeys(candidate.reviewer, ["id", "display_name"])
      || candidate.reviewer.id !== "ag-elrod"
      || candidate.reviewer.display_name !== "A.G. Elrod"
      || candidate.review_scope !== "primary-and-reason-only"
      || candidate.item_count !== items.length
      || !Number.isInteger(candidate.cursor)
      || candidate.cursor < 0
      || candidate.cursor >= items.length
      || !Array.isArray(candidate.decisions)
      || candidate.decisions.length !== items.length
      || candidate.selection_status !== "not-evaluated"
      || !exactKeys(candidate.threshold_evaluation, ["performed", "reason"])
      || candidate.threshold_evaluation.performed !== false
      || typeof candidate.exported_at !== "string"
      || Number.isNaN(Date.parse(candidate.exported_at))
    ) throw new Error("The review file belongs to a different or malformed packet.");
    const complete = candidate.status === "complete-primary-review";
    if (complete !== (candidate.author_attestation === true)) {
      throw new Error("The author attestation does not match review status.");
    }
    const decisions = candidate.decisions.map((decision, index) => (
      validateDecision(decision, items[index], !complete)
    ));
    if (complete && decisions.some((decision) => decision.decision === "pending")) {
      throw new Error("A complete review cannot contain pending decisions.");
    }
    return { cursor: candidate.cursor, decisions };
  };

  const buildExport = (complete) => {
    if (complete && decidedCount() !== items.length) throw new Error("Review all 64 items before finishing.");
    const now = new Date().toISOString();
    const decisions = state.decisions.map((decision, index) => (
      validateDecision(decision, items[index], !complete)
    ));
    return {
      schema_version: "blind-primary-review-draft-1.0.0",
      status: complete ? "complete-primary-review" : "author-review-in-progress",
      rubric_id: packet.rubric_id,
      rubric_sha256: packet.rubric_sha256,
      exported_at: now,
      network_requests: 0,
      environment_variables_read: 0,
      review_id: packet.review_id,
      first_pass_receipt_sha256: packet.first_pass_receipt_sha256,
      ordered_items_sha256: packet.ordered_items_sha256,
      reviewer: { id: "ag-elrod", display_name: "A.G. Elrod" },
      review_scope: "primary-and-reason-only",
      item_count: items.length,
      cursor: state.cursor,
      decisions,
      author_attestation: complete,
      threshold_evaluation: {
        performed: false,
        reason: complete
          ? "Primary review is complete; threshold calculation has not run"
          : "Author review is in progress",
      },
      selection_status: "not-evaluated",
    };
  };

  const saveLocal = () => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(buildExport(false)));
      setText(elements.saveNote, "Saved in this browser. Export JSON for a durable copy.");
    } catch (_error) {
      setText(elements.saveNote, "Browser storage is unavailable. Export JSON to preserve progress.");
    }
  };

  const updateProgress = () => {
    const count = decidedCount();
    elements.progress.value = count;
    elements.progress.max = items.length;
    setText(elements.progressCopy, `${count} of ${items.length} reviewed`);
    elements.finish.disabled = count !== items.length;
  };

  const updateReasonControl = () => {
    const primary = elements.primarySelect.value === "__NULL__" ? null : elements.primarySelect.value;
    elements.reasonSelect.replaceChildren();
    const reasons = primary === null ? REASON_CODES.filter((value) => value !== "clear_preference") : ["clear_preference"];
    for (const reason of reasons) {
      const option = document.createElement("option");
      option.value = reason;
      setText(option, reason);
      elements.reasonSelect.append(option);
    }
    const decision = currentDecision();
    if (reasons.includes(decision.reviewed_primary_reason_code)) {
      elements.reasonSelect.value = decision.reviewed_primary_reason_code;
    }
    elements.reasonSelect.disabled = primary !== null;
  };

  const formPair = () => ({
    primary: elements.primarySelect.value === "__NULL__" ? null : elements.primarySelect.value,
    reason: elements.reasonSelect.value,
  });
  const updateConfirmAvailability = () => {
    const item = currentItem();
    const pair = formPair();
    elements.confirm.disabled = !(
      sameValue(pair.primary, item.first_pass_assignment.primary_endorsed)
      && pair.reason === item.first_pass_assignment.primary_reason_code
    );
  };

  const render = () => {
    const item = currentItem();
    const decision = currentDecision();
    const reviewed = decidedCount();
    setText(elements.itemLabel, `Item ${item.review_index} of ${items.length}`);
    setText(elements.itemTitle, "Review the primary position and reason");
    elements.decisionBadge.className = "badge";
    if (decision.decision === "confirm") {
      elements.decisionBadge.classList.add("approved");
      setText(elements.decisionBadge, "Primary confirmed");
    } else if (decision.decision === "correct") {
      elements.decisionBadge.classList.add("corrected");
      setText(elements.decisionBadge, "Primary corrected");
    } else {
      setText(elements.decisionBadge, "Pending review");
    }
    elements.attentionBadge.hidden = !isAttention(item);
    setText(elements.prompt, item.user_prompt);
    setText(elements.response, item.response_text);
    elements.positions.replaceChildren();
    for (const position of item.positions) {
      const card = document.createElement("article");
      card.className = "position";
      const heading = document.createElement("h3");
      const summary = document.createElement("p");
      setText(heading, `${position.handle}: ${position.label}`);
      setText(summary, position.summary);
      card.append(heading, summary);
      elements.positions.append(card);
    }
    setText(elements.firstPrimary, positionName(item, item.first_pass_assignment.primary_endorsed));
    setText(elements.firstReason, item.first_pass_assignment.primary_reason_code);
    appendList(elements.also, item.first_pass_assignment.also_endorsed.map((value) => positionName(item, value)), "None");
    appendList(elements.mentioned, item.first_pass_assignment.mentioned.map((value) => positionName(item, value)), "None");
    setText(elements.rationale, item.first_pass_assignment.rationale);
    appendList(elements.evidence, item.first_pass_assignment.evidence_snippets, "None");
    setText(elements.confidence, item.first_pass_assignment.confidence);
    appendList(elements.flags, item.first_pass_assignment.review_flags, "None");

    elements.primarySelect.replaceChildren();
    for (const position of item.positions) {
      const option = document.createElement("option");
      option.value = position.handle;
      setText(option, `${position.handle}: ${position.label}`);
      elements.primarySelect.append(option);
    }
    const nullOption = document.createElement("option");
    nullOption.value = "__NULL__";
    setText(nullOption, "No clear primary");
    elements.primarySelect.append(nullOption);
    elements.primarySelect.value = decision.reviewed_primary_endorsed === null
      ? "__NULL__"
      : decision.reviewed_primary_endorsed;
    updateReasonControl();
    updateConfirmAvailability();
    elements.reviewNote.value = decision.review_note || "";
    elements.error.hidden = true;
    setText(elements.error, "");
    updateProgress();

    const visible = visibleIndices();
    const location = visible.indexOf(state.cursor);
    elements.previous.disabled = location <= 0;
    elements.next.disabled = location < 0 || location >= visible.length - 1;
    elements.nextUnreviewed.disabled = reviewed === items.length;
    elements.itemTitle.focus({ preventScroll: true });
    window.scrollTo({ top: elements.itemTitle.getBoundingClientRect().top + window.scrollY - 90, behavior: "smooth" });
  };

  const goTo = (index) => {
    if (!Number.isInteger(index) || index < 0 || index >= items.length) return;
    state.cursor = index;
    saveLocal();
    render();
  };
  const moveVisible = (offset) => {
    const visible = visibleIndices();
    const location = visible.indexOf(state.cursor);
    if (location >= 0 && visible[location + offset] !== undefined) goTo(visible[location + offset]);
  };
  const goNextUnreviewed = () => {
    for (let step = 1; step <= items.length; step += 1) {
      const index = (state.cursor + step) % items.length;
      if (state.decisions[index].decision === "pending") {
        goTo(index);
        return;
      }
    }
  };
  const showError = (message) => {
    setText(elements.error, message);
    elements.error.hidden = false;
    elements.error.focus();
  };

  const recordFormValues = () => {
    const decision = currentDecision();
    const primary = elements.primarySelect.value === "__NULL__" ? null : elements.primarySelect.value;
    decision.reviewed_primary_endorsed = primary;
    decision.reviewed_primary_reason_code = elements.reasonSelect.value;
    decision.review_note = normalizeNote(elements.reviewNote.value);
  };

  elements.confirm.addEventListener("click", () => {
    try {
      recordFormValues();
      const item = currentItem();
      const decision = currentDecision();
      const unchanged = (
        sameValue(decision.reviewed_primary_endorsed, item.first_pass_assignment.primary_endorsed)
        && decision.reviewed_primary_reason_code === item.first_pass_assignment.primary_reason_code
      );
      if (!unchanged) throw new Error("Restore the first-pass pair before confirming it.");
      decision.decision = "confirm";
      decision.reviewed_at = new Date().toISOString();
      saveLocal();
      render();
      goNextUnreviewed();
    } catch (error) {
      showError(error instanceof Error ? error.message : "The confirmation is invalid.");
    }
  });

  elements.correct.addEventListener("click", () => {
    try {
      recordFormValues();
      const item = currentItem();
      const decision = currentDecision();
      const unchanged = (
        sameValue(decision.reviewed_primary_endorsed, item.first_pass_assignment.primary_endorsed)
        && decision.reviewed_primary_reason_code === item.first_pass_assignment.primary_reason_code
      );
      if (!validPair(item, decision.reviewed_primary_endorsed, decision.reviewed_primary_reason_code)) {
        throw new Error("Choose a valid primary and matching reason.");
      }
      if (unchanged) throw new Error("A correction must change the primary or reason.");
      decision.decision = "correct";
      decision.reviewed_at = new Date().toISOString();
      saveLocal();
      render();
      goNextUnreviewed();
    } catch (error) {
      showError(error instanceof Error ? error.message : "The correction is invalid.");
    }
  });

  elements.primarySelect.addEventListener("change", () => {
    const decision = currentDecision();
    decision.reviewed_primary_endorsed = elements.primarySelect.value === "__NULL__"
      ? null
      : elements.primarySelect.value;
    decision.reviewed_primary_reason_code = decision.reviewed_primary_endorsed === null
      ? "mixed"
      : "clear_preference";
    decision.decision = "pending";
    decision.reviewed_at = null;
    updateReasonControl();
    updateConfirmAvailability();
    saveLocal();
    updateProgress();
  });
  elements.reasonSelect.addEventListener("change", () => {
    const decision = currentDecision();
    decision.reviewed_primary_reason_code = elements.reasonSelect.value;
    decision.decision = "pending";
    decision.reviewed_at = null;
    updateConfirmAvailability();
    saveLocal();
    updateProgress();
  });
  elements.reviewNote.addEventListener("input", () => {
    const decision = currentDecision();
    decision.review_note = elements.reviewNote.value.trim() || null;
    saveLocal();
  });

  elements.previous.addEventListener("click", () => moveVisible(-1));
  elements.next.addEventListener("click", () => moveVisible(1));
  elements.nextUnreviewed.addEventListener("click", goNextUnreviewed);
  elements.filter.addEventListener("change", () => {
    state.filter = elements.filter.value;
    const visible = visibleIndices();
    if (visible.length === 0) {
      state.filter = "all";
      elements.filter.value = "all";
      setText(elements.live, "That view is empty. Showing all items.");
    } else if (!visible.includes(state.cursor)) {
      state.cursor = visible[0];
    }
    render();
  });

  const download = (value, filename) => {
    const payload = `${JSON.stringify(value, null, 2)}\n`;
    const blob = new Blob([payload], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };
  elements.exportDraft.addEventListener("click", () => {
    try {
      download(buildExport(false), "concordance-author-review-draft.json");
      setText(elements.live, "Draft JSON exported.");
    } catch (error) {
      showError(error instanceof Error ? error.message : "Draft export failed.");
    }
  });
  elements.finish.addEventListener("click", () => {
    try {
      const value = buildExport(true);
      if (!window.confirm("Attest that you reviewed all 64 primary assignments and export the complete review?")) return;
      download(value, "concordance-author-review-complete.json");
      setText(elements.live, "Complete review JSON exported. Threshold calculation remains blocked until it is validated and sealed.");
    } catch (error) {
      showError(error instanceof Error ? error.message : "Final export failed.");
    }
  });

  elements.importButton.addEventListener("click", () => elements.importFile.click());
  elements.importFile.addEventListener("change", async () => {
    const [file] = elements.importFile.files;
    elements.importFile.value = "";
    if (!file) return;
    try {
      if (file.size > 2_000_000) throw new Error("The review file is too large.");
      const candidate = JSON.parse(await file.text());
      const normalized = validateDraft(candidate);
      const reviewed = normalized.decisions.filter((value) => value.decision !== "pending").length;
      if (!window.confirm(`Import this review with ${reviewed} of ${items.length} decisions recorded?`)) return;
      state.cursor = normalized.cursor;
      state.decisions = normalized.decisions;
      saveLocal();
      render();
      setText(elements.live, "Review JSON imported.");
    } catch (error) {
      showError(error instanceof Error ? error.message : "The review file is invalid.");
    }
  });

  const restoreLocal = () => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return;
      const normalized = validateDraft(JSON.parse(raw));
      state.cursor = normalized.cursor;
      state.decisions = normalized.decisions;
      setText(elements.live, "Browser-saved progress restored.");
    } catch (_error) {
      try { localStorage.removeItem(storageKey); } catch (_ignored) { /* storage unavailable */ }
      setText(elements.live, "Saved browser state was invalid and was not restored.");
    }
  };

  restoreLocal();
  render();
})();

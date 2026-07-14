import { useMemo, useState } from "react";
import type {
  Mapping,
  ModelSnapshot,
  Question,
  RunManifest,
  Source,
} from "../lib/types";
import {
  buildCaseViewModel,
  challengeMovementCount,
  safeExternalUrl,
  variantMovementCount,
  type ViewMode,
} from "../lib/view-model";
import { ConvergenceMap } from "./ConvergenceMap";
import { RawReceipts } from "./RawReceipts";

export function CaseStudy({
  question,
  run,
  mapping,
  models,
  label,
}: {
  question: Question;
  run: RunManifest;
  mapping: Mapping;
  models: ModelSnapshot[];
  label: string;
}) {
  const [variantId, setVariantId] = useState(question.prompt_variants[0].id);
  const [mode, setMode] = useState<ViewMode>("answer");
  const [selectedModelKey, setSelectedModelKey] = useState(models[0].model_key);
  const [announcement, setAnnouncement] = useState(
    `${question.prompt_variants[0].label} selected. Initial answers shown.`,
  );
  const view = useMemo(
    () => buildCaseViewModel(question, run, mapping, models, variantId, mode),
    [question, run, mapping, models, variantId, mode],
  );
  const selectedVariant = question.prompt_variants.find(
    (variant) => variant.id === variantId,
  );
  const challengeAvailable = run.cells.some(
    (cell) =>
      cell.variant_id === variantId && cell.call_type === "challenge",
  );
  const sources = useMemo(() => uniqueSources(question), [question]);

  function selectVariant(nextVariantId: string) {
    if (nextVariantId === variantId) return;
    const next = question.prompt_variants.find(
      (variant) => variant.id === nextVariantId,
    );
    const nextChallengeAvailable = run.cells.some(
      (cell) =>
        cell.variant_id === nextVariantId && cell.call_type === "challenge",
    );
    const nextMode = mode === "challenge" && !nextChallengeAvailable
      ? "answer"
      : mode;
    const changed = variantMovementCount(
      run,
      mapping,
      variantId,
      nextVariantId,
      nextMode,
    );
    setVariantId(nextVariantId);
    setMode(nextMode);
    setAnnouncement(
      `${next?.label ?? nextVariantId} selected; ${changed} model${changed === 1 ? "" : "s"} changed primary position. Distribution and receipts updated.`,
    );
  }

  function toggleChallenge() {
    if (!challengeAvailable) return;
    const nextMode: ViewMode = mode === "answer" ? "challenge" : "answer";
    const changed = challengeMovementCount(run, mapping, variantId);
    const nextView = buildCaseViewModel(
      question,
      run,
      mapping,
      models,
      variantId,
      nextMode,
    );
    setMode(nextMode);
    setAnnouncement(
      nextMode === "challenge"
        ? `Challenge answers shown; ${changed} model${changed === 1 ? "" : "s"} changed primary position and ${nextView.recoveredPositionCount} position${nextView.recoveredPositionCount === 1 ? " was" : "s were"} recovered.`
        : `Initial answers restored for ${selectedVariant?.label ?? variantId}.`,
    );
  }

  return (
    <article className="case-study" id={question.id} aria-labelledby={`${question.id}-title`}>
      <header className="case-header">
        <div className="case-number" aria-hidden="true">{label}</div>
        <div className="case-heading-copy">
          <p className="case-kind">{question.kind.replace("-", " ")}</p>
          <h2 id={`${question.id}-title`}>{question.title}</h2>
          <p className="case-premise">{question.premise}</p>
        </div>
        <dl className="case-statline">
          <div><dt>Mapped positions</dt><dd>{question.position_map.length}</dd></div>
          <div><dt>Models</dt><dd>{models.length}</dd></div>
          <div><dt>Answers shown</dt><dd>{view.models.length}</dd></div>
        </dl>
      </header>

      <section className="case-controls" aria-label={`Controls for ${question.title}`}>
        {question.prompt_variants.length > 1 ? (
          <fieldset className="variant-selector">
            <legend>Prompt wording</legend>
            {question.prompt_variants.map((variant) => (
              <label key={variant.id}>
                <input
                  type="radio"
                  name={`${question.id}-variant`}
                  value={variant.id}
                  checked={variant.id === variantId}
                  onChange={(event) => selectVariant(event.currentTarget.value)}
                />
                <span>{variant.label}</span>
              </label>
            ))}
          </fieldset>
        ) : (
          <div className="single-variant">
            <span>Prompt wording</span>
            <strong>{selectedVariant?.label}</strong>
          </div>
        )}
        <button
          className="challenge-button"
          type="button"
          aria-pressed={mode === "challenge"}
          disabled={!challengeAvailable}
          onClick={toggleChallenge}
        >
          {challengeAvailable ? (
            <span aria-hidden="true">{mode === "challenge" ? "↩" : "↗"}</span>
          ) : null}
          {challengeAvailable
            ? mode === "challenge"
              ? "Return to initial answers"
              : "Challenge this consensus"
            : "No challenge sample"}
        </button>
        <p className="challenge-explainer">
          {challengeAvailable
            ? "The linked follow-up asks for the strongest supportable contrary position. This distinguishes spontaneous omission from a position the model can produce when directly challenged."
            : "Initial answers only. No follow-up challenge sample was run for this prompt wording."}
        </p>
        <p className="visually-hidden" aria-live="polite" aria-atomic="true">
          {announcement}
        </p>
      </section>

      <details className="prompt-disclosure">
        <summary>Read the exact selected prompt</summary>
        <pre>{selectedVariant?.user_prompt}</pre>
      </details>

      <ConvergenceMap
        view={view}
        selectedModelKey={selectedModelKey}
        onSelectModel={setSelectedModelKey}
      />

      <aside className="case-limit" role="note">
        <p className="micro-label">Read this result carefully</p>
        <ul>
          {question.what_this_does_not_show.map((item) => <li key={item}>{item}</li>)}
        </ul>
      </aside>

      <details className="case-context-disclosure">
        <summary>How this case was framed and selected</summary>
        <div className="case-context-grid">
          <div>
            <p className="micro-label">Question context</p>
            <p>{question.context_note}</p>
          </div>
          <aside className="selection-disclosure" role="note">
            <p className="micro-label">Selection disclosure</p>
            <p>{question.selection.disclosure}</p>
            <p><strong>Map scope:</strong> cited and explicitly non-exhaustive.</p>
          </aside>
        </div>
      </details>

      <details className="sources-panel evidence-disclosure" aria-labelledby={`${question.id}-sources`}>
        <summary className="evidence-summary" id={`${question.id}-sources`}>
          <span>
            <span className="micro-label">Position-map evidence</span>
            <strong>Sources behind the map</strong>
          </span>
          <span>{sources.length} cited source{sources.length === 1 ? "" : "s"}</span>
        </summary>
        <div className="evidence-body">
          <p className="evidence-intro">
            These sources attest the documented positions. They do not validate model
            answers automatically.
          </p>
          <ol className="source-list">
          {sources.map((source, index) => {
            const href = safeExternalUrl(source.url);
            return (
              <li key={`${source.id}-${source.url}`}>
                <span className="source-number" aria-hidden="true">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <div className="source-copy">
                  <p className="source-title">{source.title}</p>
                  <p>{source.citation}</p>
                  <p className="source-claim">Supports map claim: {source.claim_supported}</p>
                </div>
                <div className="source-actions">
                  <span>{source.verification.status} · accessed {source.accessed_at}</span>
                  {href ? (
                    <a href={href} target="_blank" rel="noopener noreferrer">
                      Open source<span className="visually-hidden">: {source.title}</span>
                    </a>
                  ) : (
                    <span>Invalid source URL</span>
                  )}
                </div>
              </li>
            );
          })}
          </ol>
        </div>
      </details>

      <RawReceipts view={view} />
    </article>
  );
}

function uniqueSources(question: Question): Source[] {
  const seen = new Set<string>();
  return question.position_map.flatMap((position) =>
    position.sources.filter((source) => {
      const key = `${source.id}\0${source.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  );
}

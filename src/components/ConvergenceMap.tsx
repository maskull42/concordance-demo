import type {
  CaseViewModel,
  ModelViewState,
  PositionViewState,
} from "../lib/view-model";
import {
  variantMovementCount,
  variantUnmappedTransitionCount,
} from "../lib/view-model";
import { ModelFlag } from "./ModelFlag";

interface ConvergenceMapProps {
  view: CaseViewModel;
  selectedModelKey: string;
  onSelectModel: (modelKey: string) => void;
}

export function ConvergenceMap({
  view,
  selectedModelKey,
  onSelectModel,
}: ConvergenceMapProps) {
  const primaryOnly = view.mapping.mapping_version === "prototype-primary-1";
  const selected =
    view.models.find((model) => model.model.model_key === selectedModelKey) ??
    view.models[0];
  const represented = view.positions.filter(
    (position) => position.primaryModels.length > 0,
  );
  const unassigned = view.positions.filter(
    (position) => position.primaryModels.length === 0,
  );
  const sampleLabel = view.mode === "answer" ? "initial answers" : "challenge answers";

  return (
    <section className="result-panel" aria-labelledby={`${view.question.id}-result-title`}>
      <header className="result-heading">
        <div>
          <p className="micro-label">Panel result</p>
          <h4 id={`${view.question.id}-result-title`}>{resultHeadline(view)}</h4>
        </div>
        <p className="result-relevance">
          <strong>Why policy teams should care</strong>
          {relevanceCopy(view)}
        </p>
      </header>

      <div
        className="distribution-list"
        aria-label={`Primary-position distribution for ${view.question.title}`}
      >
        <p className="distribution-key">
          Each slot represents one model. Filled slots share the primary conclusion
          named on that row.
        </p>
        {represented.map((position) => (
          <DistributionRow
            key={position.position.id}
            position={position}
            totalModels={view.models.length}
            tone={view.positions.indexOf(position)}
            selectedModelKey={selectedModelKey}
            onSelectModel={onSelectModel}
          />
        ))}
        {view.mixedModels.length > 0 ? (
          <StatusDistributionRow
            label="Mixed or unclear"
            description="The answer did not clearly favor one documented position."
            models={view.mixedModels}
            totalModels={view.models.length}
            tone="mixed"
            selectedModelKey={selectedModelKey}
            onSelectModel={onSelectModel}
          />
        ) : null}
        {view.errorModels.length + view.notRunModels.length > 0 ? (
          <StatusDistributionRow
            label="Unavailable"
            description="The response failed or was not run in this view."
            models={[...view.errorModels, ...view.notRunModels]}
            totalModels={view.models.length}
            tone="error"
            selectedModelKey={selectedModelKey}
            onSelectModel={onSelectModel}
          />
        ) : null}
      </div>

      {unassigned.length > 0 ? (
        <details className="unassigned-positions">
          <summary>
            {unassigned.length} other documented position
            {unassigned.length === 1 ? "" : "s"} did not appear as a primary conclusion
          </summary>
          <ul>
            {unassigned.map((position) => (
              <li key={position.position.id}>
                <strong>{position.position.label}</strong>
                <span>{position.position.summary}</span>
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      <aside className="model-detail" aria-live="polite">
        <p className="micro-label">Selected model</p>
        <ModelDetail model={selected} mode={view.mode} />
      </aside>

      <p className="result-scope">
        {primaryOnly
          ? `${capitalize(sampleLabel)} only. Primary conclusions were author-reviewed; secondary endorsements and mentions were not reviewed in this prototype.`
          : `${capitalize(sampleLabel)} and human-authored mappings are shown separately. The documented position map is explicitly non-exhaustive.`}
      </p>
    </section>
  );
}

function DistributionRow({
  position,
  totalModels,
  tone,
  selectedModelKey,
  onSelectModel,
}: {
  position: PositionViewState;
  totalModels: number;
  tone: number;
  selectedModelKey: string;
  onSelectModel: (modelKey: string) => void;
}) {
  return (
    <section className={`distribution-row distribution-row--tone-${tone % 5}`}>
      <div className="distribution-copy">
        <div>
          <h5>{position.position.label}</h5>
          <strong>{position.primaryModels.length} of {totalModels}</strong>
        </div>
        <p>{position.position.summary}</p>
        {position.recoveredModels.length > 0 ? (
          <p className="recovered-badge">
            Recovered under challenge by{" "}
            {position.recoveredModels.map((model) => model.model.family).join(", ")}
          </p>
        ) : null}
      </div>
      <ModelStrip
        models={position.primaryModels}
        totalModels={totalModels}
        selectedModelKey={selectedModelKey}
        onSelectModel={onSelectModel}
        label={position.position.label}
      />
    </section>
  );
}

function StatusDistributionRow({
  label,
  description,
  models,
  totalModels,
  tone,
  selectedModelKey,
  onSelectModel,
}: {
  label: string;
  description: string;
  models: ModelViewState[];
  totalModels: number;
  tone: "mixed" | "error";
  selectedModelKey: string;
  onSelectModel: (modelKey: string) => void;
}) {
  return (
    <section className={`distribution-row distribution-row--${tone}`}>
      <div className="distribution-copy">
        <div>
          <h5>{label}</h5>
          <strong>{models.length} of {totalModels}</strong>
        </div>
        <p>{description}</p>
      </div>
      <ModelStrip
        models={models}
        totalModels={totalModels}
        selectedModelKey={selectedModelKey}
        onSelectModel={onSelectModel}
        label={label}
      />
    </section>
  );
}

function ModelStrip({
  models,
  totalModels,
  selectedModelKey,
  onSelectModel,
  label,
}: {
  models: ModelViewState[];
  totalModels: number;
  selectedModelKey: string;
  onSelectModel: (modelKey: string) => void;
  label: string;
}) {
  const openSlots = Math.max(0, totalModels - models.length);
  return (
    <div
      className="model-strip"
      aria-label={`${models.length} of ${totalModels} models: ${label}`}
    >
      {models.map((model) => (
        <button
          className="model-slot model-slot--filled"
          type="button"
          key={model.model.model_key}
          aria-pressed={model.model.model_key === selectedModelKey}
          aria-label={`${model.model.family}: ${label}`}
          onClick={() => onSelectModel(model.model.model_key)}
        >
          <ModelFlag modelKey={model.model.model_key} />
          {model.model.family}
        </button>
      ))}
      {Array.from({ length: openSlots }, (_, index) => (
        <span className="model-slot model-slot--empty" aria-hidden="true" key={index} />
      ))}
    </div>
  );
}

function ModelDetail({ model, mode }: { model: ModelViewState; mode: string }) {
  const initial = model.initialPrimaryPosition?.label ?? "Mixed or unclear";
  const current = model.primaryPosition?.label ??
    (model.status === "error" ? "Unavailable" : "Mixed or unclear");
  return (
    <div className="model-detail-grid">
      <div>
        <h5>
          <ModelFlag modelKey={model.model.model_key} /> {model.model.family}
        </h5>
        <p className="model-route">
          {model.model.requested_model_id} · {model.model.provider}
        </p>
      </div>
      <p className="model-transition">
        {mode === "challenge" ? (
          <><span>{initial}</span><span aria-hidden="true">→</span><strong>{current}</strong></>
        ) : (
          <strong>{current}</strong>
        )}
      </p>
      <div className="model-detail-notes">
        {model.additionalPositions.length > 0 ? (
          <p><strong>Also endorses:</strong> {model.additionalPositions.map((position) => position.label).join(", ")}</p>
        ) : null}
        {model.mentionedPositions.length > 0 ? (
          <p><strong>Mentions:</strong> {model.mentionedPositions.map((position) => position.label).join(", ")}</p>
        ) : null}
        {model.recoveredPositionIds.length > 0 ? (
          <p className="recovered-badge">Recovered under challenge: {model.recoveredPositionIds.join(", ")}</p>
        ) : null}
        {model.cell?.status === "error" ? (
          <p className="error-note">{model.cell.error.sanitized_summary}</p>
        ) : null}
        <p className="mapping-status">
          Human-authored mapping · {model.assignment?.verification.status ?? "not available"}
        </p>
      </div>
    </div>
  );
}

function resultHeadline(view: CaseViewModel): string {
  const counts = view.positions
    .map((position) => position.primaryModels.length)
    .filter((count) => count > 0)
    .sort((left, right) => right - left);
  const label = view.mode === "answer" ? "initial answers" : "challenge answers";
  if (counts.length === 0) return `No ${label} received a primary mapping`;
  if (counts.length === 1 && counts[0] === view.models.length) {
    return `${counts[0]} of ${view.models.length} ${label} reached the same primary conclusion`;
  }
  if (
    counts.length === 2 &&
    counts.reduce((sum, count) => sum + count, 0) === view.models.length
  ) {
    return `The panel split ${counts[0]} to ${counts[1]}`;
  }
  return `${counts.length} primary positions appear in this sample`;
}

function relevanceCopy(view: CaseViewModel): string {
  const total = view.models.length;
  if (view.question.kind === "convergent") {
    return " A shared first-answer pattern can look like independent corroboration. This view makes the concentration visible while keeping documented alternatives in reach.";
  }
  if (view.question.kind === "divergent") {
    return " The same policy question produced competing legal conclusions. Provider choice could change the advice placed before a policy team.";
  }
  const variants = view.question.prompt_variants;
  if (variants.length > 1) {
    const movement = variantMovementCount(
      view.run,
      view.mapping,
      variants[0].id,
      variants[1].id,
      "answer",
    );
    const unmapped = variantUnmappedTransitionCount(
      view.run,
      view.mapping,
      variants[0].id,
      variants[1].id,
      "answer",
    );
    const unmappedNote =
      unmapped > 0
        ? ` ${unmapped} more shifted between a mapped primary and no primary mapping.`
        : "";
    return ` ${movement} of ${total} models moved to a different mapped primary position when the framing changed.${unmappedNote} Question design becomes part of the policy analysis.`;
  }
  return " The distribution shows which primary conclusions surfaced in this sample and which documented alternatives did not.";
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

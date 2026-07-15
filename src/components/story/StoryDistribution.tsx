import { m } from "framer-motion";
import type { CaseViewModel, PositionViewState } from "../../lib/view-model";
import { ModelFlag } from "../ModelFlag";
import { graphicNotes } from "./story.config";

export type StoryStage = "queued" | "answers" | "seated";

const TOKEN_SPRING = { type: "spring", stiffness: 190, damping: 26 } as const;

export function StoryDistribution({
  view,
  stage,
  showGhosts = true,
}: {
  view: CaseViewModel;
  stage: StoryStage;
  showGhosts?: boolean;
}) {
  const scope = view.question.id;
  const represented = [...view.positions]
    .filter((position) => position.primaryModels.length > 0)
    .sort((left, right) => right.primaryModels.length - left.primaryModels.length);
  const ghosts = view.positions.filter(
    (position) => position.representation === "not-represented",
  );

  if (stage === "queued") {
    return (
      <div className="story-ledger" aria-label="The declared panel, before its answers are mapped">
        <div className="story-token-queue">
          {view.models.map((model) => (
            <Token key={model.model.model_key} scope={scope} family={model.model.family} modelKey={model.model.model_key} />
          ))}
        </div>
        <p className="story-ledger-note">{graphicNotes.queued}</p>
      </div>
    );
  }

  if (stage === "answers") {
    return (
      <div className="story-ledger" aria-label="Openings of the sampled answers">
        <div className="story-answer-grid">
          {view.models.map((model) => (
            <div className="story-answer-card" key={model.model.model_key}>
              <Token
                scope={scope}
                family={model.model.family}
                modelKey={model.model.model_key}
              />
              <p>
                {model.cell?.status === "success"
                  ? excerpt(model.cell.response_text)
                  : "Unavailable in this sample."}
              </p>
            </div>
          ))}
        </div>
        <p className="story-ledger-note">{graphicNotes.answers}</p>
      </div>
    );
  }

  return (
    <div
      className="story-ledger"
      aria-label={`Primary-position distribution for ${view.question.title}`}
    >
      {represented.map((position) => (
        <LedgerRow
          key={position.position.id}
          scope={scope}
          position={position}
          totalModels={view.models.length}
        />
      ))}
      {view.mixedModels.length > 0 ? (
        <div className="story-ledger-row story-ledger-row--mixed">
          <div className="story-ledger-copy">
            <h5>Mixed or unclear</h5>
            <strong className="story-count">
              {view.mixedModels.length} of {view.models.length}
            </strong>
          </div>
          <div className="story-token-strip">
            {view.mixedModels.map((model) => (
              <Token
                key={model.model.model_key}
                scope={scope}
                family={model.model.family}
                modelKey={model.model.model_key}
              />
            ))}
          </div>
        </div>
      ) : null}
      {showGhosts
        ? ghosts.map((position) => (
            <GhostRow
              key={position.position.id}
              position={position}
              totalModels={view.models.length}
            />
          ))
        : null}
      <p className="story-ledger-note">{graphicNotes.seated}</p>
    </div>
  );
}

function LedgerRow({
  scope,
  position,
  totalModels,
}: {
  scope: string;
  position: PositionViewState;
  totalModels: number;
}) {
  return (
    <div className="story-ledger-row">
      <div className="story-ledger-copy">
        <h5>{position.position.label}</h5>
        <strong className="story-count">
          {position.primaryModels.length} of {totalModels}
        </strong>
      </div>
      <div className="story-token-strip">
        {position.primaryModels.map((model) => (
          <Token
            key={model.model.model_key}
            scope={scope}
            family={model.model.family}
            modelKey={model.model.model_key}
          />
        ))}
        {Array.from(
          { length: Math.max(0, totalModels - position.primaryModels.length) },
          (_, index) => (
            <span className="story-slot-empty" aria-hidden="true" key={index} />
          ),
        )}
      </div>
    </div>
  );
}

function GhostRow({
  position,
  totalModels,
}: {
  position: PositionViewState;
  totalModels: number;
}) {
  return (
    <div className="story-ledger-row story-ledger-row--ghost">
      <div className="story-ledger-copy">
        <h5>{position.position.label}</h5>
        <p className="story-ghost-note">
          0 of {totalModels} primary mappings in this sample
        </p>
      </div>
      <div className="story-token-strip">
        {Array.from({ length: totalModels }, (_, index) => (
          <span className="story-slot-empty" aria-hidden="true" key={index} />
        ))}
        <span className="story-source-badge">
          {position.position.sources.length} source
          {position.position.sources.length === 1 ? "" : "s"}
        </span>
      </div>
    </div>
  );
}

// Excerpts drop markdown formatting glyphs for readability; the untouched
// verbatim text stays one click away in the receipts.
function excerpt(text: string, limit = 150): string {
  const flattened = text
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/\*\*|__/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (flattened.length <= limit) return flattened;
  const cut = flattened.slice(0, limit);
  return `${cut.slice(0, Math.max(cut.lastIndexOf(" "), 60))}…`;
}

function Token({
  scope,
  family,
  modelKey,
}: {
  scope: string;
  family: string;
  modelKey: string;
}) {
  return (
    <m.span
      className="story-token"
      layoutId={`${scope}-${modelKey}`}
      layout
      transition={TOKEN_SPRING}
    >
      <ModelFlag modelKey={modelKey} />
      {family}
    </m.span>
  );
}

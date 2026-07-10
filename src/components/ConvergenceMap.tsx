import { LazyMotion, domAnimation, m, useReducedMotion } from "framer-motion";
import { useEffect, useId, useMemo, useState } from "react";
import type {
  CaseViewModel,
  ModelViewState,
  PositionViewState,
} from "../lib/view-model";

interface ConvergenceMapProps {
  view: CaseViewModel;
  selectedModelKey: string;
  onSelectModel: (modelKey: string) => void;
}

interface Point {
  x: number;
  y: number;
}

const WIDTH = 920;
const NODE_WIDTH = 260;
const NODE_HEIGHT = 154;

export function ConvergenceMap({
  view,
  selectedModelKey,
  onSelectModel,
}: ConvergenceMapProps) {
  const titleId = useStableId("map-title");
  const descriptionId = useStableId("map-description");
  const compact = useCompactLayout();
  const reducedMotion = useReducedMotion();
  const layout = useMemo(() => createLayout(view, compact), [view, compact]);
  const selected =
    view.models.find((model) => model.model.model_key === selectedModelKey) ??
    view.models[0];

  return (
    <LazyMotion features={domAnimation} strict>
      <div className="map-composition">
      <div className="map-stage">
        <div className="map-heading-row">
          <div>
            <p className="micro-label">Position map</p>
            <h4>Where the sampled answers land</h4>
          </div>
          <MapLegend />
        </div>

        <svg
          className="position-map"
          viewBox={`0 0 ${WIDTH} ${layout.height}`}
          role="img"
          aria-labelledby={`${titleId} ${descriptionId}`}
          preserveAspectRatio="xMidYMin meet"
        >
          <title id={titleId}>
            {view.question.title}, {view.mode} view
          </title>
          <desc id={descriptionId}>
            {view.representedCount} represented positions, {view.mentionedOnlyCount}{" "}
            mentioned-only positions, {view.absentCount} not represented positions,{" "}
            {view.mixedModels.length} mixed or unclear answers.
          </desc>

          {layout.positions.map(({ state, point }) => (
            <g
              className={`map-node map-node--${state.representation}`}
              key={state.position.id}
              transform={`translate(${point.x} ${point.y})`}
            >
              <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="18" />
              <text className="node-state" x="18" y="27">
                {representationLabel(state.representation)}
              </text>
              <text className="node-title" x="18" y="57">
                {truncate(state.position.label, 31)}
              </text>
              <text className="node-count" x="18" y="82">
                {state.primaryModels.length} primary · +{state.additionalModels.length}{" "}
                additional · M{state.mentioningModels.length}
              </text>
              {state.recoveredModels.length > 0 ? (
                <text className="node-recovered" x="18" y="106">
                  Recovered under challenge
                </text>
              ) : null}
            </g>
          ))}

          {layout.mixedPoint ? (
            <g
              className="map-node map-node--mixed"
              transform={`translate(${layout.mixedPoint.x} ${layout.mixedPoint.y})`}
            >
              <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="18" />
              <text className="node-state" x="18" y="27">
                Mixed / unclear
              </text>
              <text className="node-title" x="18" y="57">
                No primary assignment
              </text>
              <text className="node-count" x="18" y="82">
                {view.mixedModels.length} sampled answer
                {view.mixedModels.length === 1 ? "" : "s"}
              </text>
            </g>
          ) : null}

          {view.models.map((model) => {
            const target = layout.tokens.get(model.model.model_key);
            if (!target) return null;
            return (
              <m.g
                className={
                  model.model.model_key === selectedModelKey
                    ? "model-token model-token--selected"
                    : "model-token"
                }
                key={model.model.model_key}
                initial={false}
                animate={{ x: target.x, y: target.y }}
                transition={
                  reducedMotion
                    ? { duration: 0 }
                    : { type: "spring", stiffness: 260, damping: 27 }
                }
                onClick={() => onSelectModel(model.model.model_key)}
                onPointerEnter={() => onSelectModel(model.model.model_key)}
              >
                <circle r="18" />
                <text textAnchor="middle" dominantBaseline="central">
                  {modelMonogram(model.model.family)}
                </text>
              </m.g>
            );
          })}
        </svg>

        <p className="map-footnote">
          Tokens mark primary human assignments only. Additional endorsements and
          mentions remain visible in the semantic list below. The map is explicitly
          non-exhaustive.
        </p>
      </div>

      <aside className="model-detail" aria-live="polite">
        <p className="micro-label">Selected model</p>
        <ModelDetail model={selected} mode={view.mode} />
      </aside>

      <div className="semantic-map" aria-label="Accessible position summary">
        {view.positions.map((position) => (
          <PositionSummary
            key={position.position.id}
            position={position}
            selectedModelKey={selectedModelKey}
            onSelectModel={onSelectModel}
          />
        ))}
        {view.mixedModels.length > 0 ? (
          <section className="semantic-position semantic-position--mixed">
            <div>
              <p className="position-state">Mixed / unclear</p>
              <h5>No primary position assigned</h5>
            </div>
            <ModelButtons
              models={view.mixedModels}
              selectedModelKey={selectedModelKey}
              onSelectModel={onSelectModel}
              prefix="Mixed"
            />
          </section>
        ) : null}
        {view.errorModels.length + view.notRunModels.length > 0 ? (
          <section className="semantic-position semantic-position--error">
            <div>
              <p className="position-state">Not mapped</p>
              <h5>Unavailable or not-run cells</h5>
            </div>
            <ModelButtons
              models={[...view.errorModels, ...view.notRunModels]}
              selectedModelKey={selectedModelKey}
              onSelectModel={onSelectModel}
              prefix="Unavailable"
            />
          </section>
        ) : null}
      </div>
      </div>
    </LazyMotion>
  );
}

function MapLegend() {
  return (
    <ul className="map-legend" aria-label="Map legend">
      <li><span className="legend-swatch legend-swatch--primary" />Primary</li>
      <li><span className="legend-chip">+</span>Additional</li>
      <li><span className="legend-chip legend-chip--mention">M</span>Mentioned</li>
      <li><span className="legend-swatch legend-swatch--absent" />Not represented</li>
    </ul>
  );
}

function PositionSummary({
  position,
  selectedModelKey,
  onSelectModel,
}: {
  position: PositionViewState;
  selectedModelKey: string;
  onSelectModel: (modelKey: string) => void;
}) {
  return (
    <section className={`semantic-position semantic-position--${position.representation}`}>
      <div className="position-copy">
        <p className="position-state">{representationLabel(position.representation)}</p>
        <h5>{position.position.label}</h5>
        <p>{position.position.summary}</p>
        {position.recoveredModels.length > 0 ? (
          <p className="recovered-badge">
            Recovered under challenge by{" "}
            {position.recoveredModels.map((model) => model.model.family).join(", ")}
          </p>
        ) : null}
      </div>
      <div className="position-model-groups">
        <ModelButtons
          models={position.primaryModels}
          selectedModelKey={selectedModelKey}
          onSelectModel={onSelectModel}
          prefix="Primary"
        />
        <ModelButtons
          models={position.additionalModels}
          selectedModelKey={selectedModelKey}
          onSelectModel={onSelectModel}
          prefix="Additional"
          marker="+"
        />
        <ModelButtons
          models={position.mentioningModels}
          selectedModelKey={selectedModelKey}
          onSelectModel={onSelectModel}
          prefix="Mentioned"
          marker="M"
        />
      </div>
    </section>
  );
}

function ModelButtons({
  models,
  selectedModelKey,
  onSelectModel,
  prefix,
  marker,
}: {
  models: ModelViewState[];
  selectedModelKey: string;
  onSelectModel: (modelKey: string) => void;
  prefix: string;
  marker?: string;
}) {
  if (models.length === 0) return null;
  return (
    <div className="model-button-group">
      <span className="visually-hidden">{prefix}: </span>
      {models.map((model) => (
        <button
          className={`model-chip ${marker === "+" ? "model-chip--additional" : ""} ${marker === "M" ? "model-chip--mention" : ""}`}
          type="button"
          key={`${prefix}-${model.model.model_key}`}
          aria-pressed={model.model.model_key === selectedModelKey}
          onClick={() => onSelectModel(model.model.model_key)}
        >
          {marker ? <span aria-hidden="true">{marker} </span> : null}
          {model.model.family}
        </button>
      ))}
    </div>
  );
}

function ModelDetail({ model, mode }: { model: ModelViewState; mode: string }) {
  const initial = model.initialPrimaryPosition?.label ?? "Mixed / unclear";
  const current = model.primaryPosition?.label ??
    (model.status === "error" ? "Unavailable" : "Mixed / unclear");
  return (
    <>
      <h5>{model.model.family}</h5>
      <p className="model-route">
        {model.model.requested_model_id} · {model.model.provider}
      </p>
      {mode === "challenge" ? (
        <p className="model-transition">
          <span>{initial}</span><span aria-hidden="true">→</span><span>{current}</span>
        </p>
      ) : (
        <p className="model-transition"><span>{current}</span></p>
      )}
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
    </>
  );
}

function createLayout(view: CaseViewModel, compact: boolean) {
  const positions: { state: PositionViewState; point: Point }[] = [];
  const tokens = new Map<string, Point>();
  const columns = compact ? 1 : Math.min(3, view.positions.length);
  const horizontalGap = 34;
  const verticalGap = 36;
  const contentWidth = columns * NODE_WIDTH + (columns - 1) * horizontalGap;
  const startX = (WIDTH - contentWidth) / 2;

  view.positions.forEach((state, index) => {
    const column = index % columns;
    const row = Math.floor(index / columns);
    const point = {
      x: startX + column * (NODE_WIDTH + horizontalGap),
      y: 18 + row * (NODE_HEIGHT + verticalGap),
    };
    positions.push({ state, point });
    state.primaryModels.forEach((model, modelIndex) => {
      tokens.set(model.model.model_key, {
        x: point.x + 39 + (modelIndex % 5) * 43,
        y: point.y + NODE_HEIGHT - 24 - Math.floor(modelIndex / 5) * 42,
      });
    });
  });

  const rows = Math.ceil(view.positions.length / columns);
  let height = 18 + rows * NODE_HEIGHT + Math.max(0, rows - 1) * verticalGap + 18;
  let mixedPoint: Point | null = null;
  if (view.mixedModels.length > 0) {
    mixedPoint = { x: (WIDTH - NODE_WIDTH) / 2, y: height + 18 };
    view.mixedModels.forEach((model, index) => {
      tokens.set(model.model.model_key, {
        x: mixedPoint!.x + 39 + (index % 5) * 43,
        y: mixedPoint!.y + NODE_HEIGHT - 24,
      });
    });
    height += NODE_HEIGHT + 54;
  }
  return { positions, tokens, mixedPoint, height };
}

function useCompactLayout() {
  const [compact, setCompact] = useState(false);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return undefined;
    const query = window.matchMedia("(max-width: 760px)");
    const update = () => setCompact(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return compact;
}

function useStableId(prefix: string) {
  return `${prefix}-${useId().replaceAll(":", "")}`;
}

function modelMonogram(family: string) {
  const words = family.replace(/^Illustrative\s+/i, "").split(/\s+/);
  return words.length === 1
    ? words[0].slice(0, 2).toUpperCase()
    : words.slice(0, 2).map((word) => word[0]).join("").toUpperCase();
}

function representationLabel(value: PositionViewState["representation"]) {
  if (value === "represented") return "Represented";
  if (value === "mentioned-only") return "Mentioned, not endorsed";
  return "Not represented";
}

function truncate(value: string, length: number) {
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

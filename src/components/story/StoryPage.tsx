import { useMemo } from "react";
import { orderCases } from "../../lib/case-order";
import { collectCaseRecords, type CaseRecord } from "../../lib/case-summary";
import type { Dataset } from "../../lib/types";
import { ModelFlag } from "../ModelFlag";
import { SceneCollapse } from "./SceneCollapse";
import { SceneFraming } from "./SceneFraming";
import { SceneSplit } from "./SceneSplit";
import { closeCopy, openingCopy } from "./story.config";

export function StoryPage({ dataset }: { dataset: Dataset }) {
  const records = useMemo(
    () => orderCases(collectCaseRecords(dataset)),
    [dataset],
  );
  const challengeSamplesExist = dataset.runs.some((run) =>
    run.cells.some((cell) => cell.call_type === "challenge"),
  );

  return (
    <main className="story-shell" aria-label="Concordance story">
      <section className="story-scene story-scene-title" aria-label="Introduction">
        <p className="eyebrow">{openingCopy.eyebrow}</p>
        <h1>Concordance</h1>
        <p className="hero-copy">{openingCopy.question}</p>
        <div className="story-panel-roster" aria-label="Declared model panel">
          {dataset.manifest.models.map((model) => (
            <span className="story-roster-chip" key={model.model_key}>
              <ModelFlag modelKey={model.model_key} />
              <strong>{model.family}</strong>
              <code>{model.requested_model_id}</code>
            </span>
          ))}
        </div>
        <p className="story-panel-note">
          {openingCopy.panelNote} Frozen manifest {dataset.manifest.manifest_id}.
        </p>
      </section>

      {records.map((record) => (
        <Scene key={record.question.id} record={record} dataset={dataset} />
      ))}

      <section className="story-scene story-scene-close" aria-label="Method and full record">
        <p className="story-step-copy">{closeCopy.recap}</p>
        {!challengeSamplesExist ? (
          <p className="story-close-note">{closeCopy.challengeNote}</p>
        ) : null}
        <p>
          <a className="story-inspect-cta" href="#/inspect">
            {closeCopy.cta}
          </a>
        </p>
      </section>
    </main>
  );
}

function Scene({ record, dataset }: { record: CaseRecord; dataset: Dataset }) {
  const models = dataset.manifest.models;
  if (
    record.question.kind === "prompt-sensitive" &&
    record.question.prompt_variants.length > 1
  ) {
    return <SceneFraming record={record} models={models} />;
  }
  if (record.question.kind === "divergent") {
    return <SceneSplit record={record} models={models} />;
  }
  return <SceneCollapse record={record} models={models} />;
}

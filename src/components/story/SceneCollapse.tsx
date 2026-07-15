import { useCallback, useMemo, useState } from "react";
import type { CaseRecord } from "../../lib/case-summary";
import type { ModelSnapshot } from "../../lib/types";
import { buildCaseViewModel } from "../../lib/view-model";
import { ClaimFigure, ReceiptLink } from "./ClaimFigure";
import { MissingPositions } from "./MissingPositions";
import { StoryDistribution } from "./StoryDistribution";
import { StoryScene, StoryStep } from "./StoryScene";
import { collapseCopy } from "./story.config";

export function SceneCollapse({
  record,
  models,
}: {
  record: CaseRecord;
  models: ModelSnapshot[];
}) {
  const { question, run, mapping } = record;
  const copy = collapseCopy(question.id);
  const variant = question.prompt_variants[0];
  const [activeStep, setActiveStep] = useState(0);
  const onActive = useCallback((index: number) => setActiveStep(index), []);

  const view = useMemo(
    () => buildCaseViewModel(question, run, mapping, models, variant.id, "answer"),
    [question, run, mapping, models, variant.id],
  );

  const topCount = Math.max(
    0,
    ...view.positions.map((position) => position.primaryModels.length),
  );
  const missing = view.positions.filter(
    (position) => position.representation === "not-represented",
  );

  return (
    <StoryScene
      id={`story-${question.id}`}
      eyebrow={copy.eyebrow}
      title={question.title}
      graphic={
        <StoryDistribution
          view={view}
          stage={activeStep === 0 ? "queued" : "seated"}
          showGhosts={activeStep >= 2}
        />
      }
    >
      <StoryStep index={0} onActive={onActive} active={activeStep === 0}>
        <p className="story-step-copy">{copy.intro}</p>
        <blockquote className="story-prompt">{variant.user_prompt}</blockquote>
      </StoryStep>

      <StoryStep index={1} onActive={onActive} active={activeStep === 1}>
        <p className="story-step-copy">
          <ClaimFigure value={`${topCount} of ${view.models.length}`} />
          {copy.collapseSuffix}{" "}
          <ReceiptLink
            inspect={{
              questionId: question.id,
              variantId: variant.id,
              open: "receipts",
            }}
          />
        </p>
      </StoryStep>

      <StoryStep index={2} onActive={onActive} active={activeStep === 2}>
        <p className="story-step-copy">{copy.missingLead}</p>
        <MissingPositions positions={missing} />
        <p className="story-step-copy">{copy.calibrationLine}</p>
        <aside className="story-limit" role="note">
          {question.what_this_does_not_show.map((item) => (
            <p key={item}>{item}</p>
          ))}
        </aside>
      </StoryStep>
    </StoryScene>
  );
}

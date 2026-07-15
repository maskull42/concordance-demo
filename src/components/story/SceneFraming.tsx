import { useCallback, useMemo, useState } from "react";
import type { CaseRecord } from "../../lib/case-summary";
import type { ModelSnapshot } from "../../lib/types";
import { buildCaseViewModel, variantMovementCount } from "../../lib/view-model";
import { ClaimFigure, ReceiptLink } from "./ClaimFigure";
import { StoryDistribution, type StoryStage } from "./StoryDistribution";
import { StoryScene, StoryStep } from "./StoryScene";
import { framingCopy } from "./story.config";

export function SceneFraming({
  record,
  models,
}: {
  record: CaseRecord;
  models: ModelSnapshot[];
}) {
  const { question, run, mapping } = record;
  const copy = framingCopy(question.id);
  const [firstVariant, secondVariant] = question.prompt_variants;
  const [activeStep, setActiveStep] = useState(0);
  const onActive = useCallback((index: number) => setActiveStep(index), []);

  const firstView = useMemo(
    () => buildCaseViewModel(question, run, mapping, models, firstVariant.id, "answer"),
    [question, run, mapping, models, firstVariant.id],
  );
  const secondView = useMemo(
    () =>
      secondVariant
        ? buildCaseViewModel(question, run, mapping, models, secondVariant.id, "answer")
        : undefined,
    [question, run, mapping, models, secondVariant],
  );
  const movement = useMemo(
    () =>
      secondVariant
        ? variantMovementCount(run, mapping, firstVariant.id, secondVariant.id, "answer")
        : 0,
    [run, mapping, firstVariant.id, secondVariant],
  );

  const topCount = Math.max(
    0,
    ...firstView.positions.map((position) => position.primaryModels.length),
  );
  const total = firstView.models.length;

  const view = activeStep >= 3 && secondView ? secondView : firstView;
  const stage: StoryStage =
    activeStep === 0 ? "queued" : activeStep === 1 ? "answers" : "seated";

  return (
    <StoryScene
      id={`story-${question.id}`}
      eyebrow={copy.eyebrow}
      title={question.title}
      graphic={<StoryDistribution view={view} stage={stage} showGhosts={activeStep >= 2} />}
    >
      <StoryStep index={0} onActive={onActive} active={activeStep === 0}>
        <p className="story-step-copy">{copy.intro}</p>
        <blockquote className="story-prompt">{firstVariant.user_prompt}</blockquote>
      </StoryStep>

      <StoryStep index={1} onActive={onActive} active={activeStep === 1}>
        <p className="story-step-copy">{copy.answersLine}</p>
      </StoryStep>

      <StoryStep index={2} onActive={onActive} active={activeStep === 2}>
        <p className="story-step-copy">
          <ClaimFigure value={`${topCount} of ${total}`} />
          {copy.convergenceSuffix}{" "}
          <ReceiptLink
            inspect={{
              questionId: question.id,
              variantId: firstVariant.id,
              open: "receipts",
            }}
          />
        </p>
      </StoryStep>

      {secondVariant && secondView ? (
        <>
          <StoryStep index={3} onActive={onActive} active={activeStep === 3}>
            <p className="story-step-copy">{copy.reframeLine}</p>
            <blockquote className="story-prompt">{secondVariant.user_prompt}</blockquote>
          </StoryStep>

          <StoryStep index={4} onActive={onActive} active={activeStep === 4}>
            <p className="story-step-copy">
              <ClaimFigure value={`${movement} of ${total}`} />
              {copy.movementSuffix} {copy.fixedLine}{" "}
              <ReceiptLink
                inspect={{
                  questionId: question.id,
                  variantId: secondVariant.id,
                  open: "receipts",
                }}
              />
            </p>
            <aside className="story-limit" role="note">
              {question.what_this_does_not_show.map((item) => (
                <p key={item}>{item}</p>
              ))}
            </aside>
          </StoryStep>
        </>
      ) : null}
    </StoryScene>
  );
}

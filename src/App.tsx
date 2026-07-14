import { dataset } from "@dataset";
import { CaseStudy } from "./components/CaseStudy";
import type { Dataset, Mapping, Question, RunManifest } from "./lib/types";
import { buildCaseViewModel, variantMovementCount } from "./lib/view-model";

const validatedDataset = dataset as Dataset;

const HONESTY_COPY =
  "Concordance shows patterns in sampled answers from a declared panel of AI models. Agreement is not truth. A position missing from the distribution did not receive a primary mapping in this sample; a model may still produce it under another prompt. This is a product demonstration, not a validated measure.";

export function App() {
  const cases = validatedDataset.questions.map((question) => {
    const run = validatedDataset.runs.find(
      (value) => value.question_id === question.id,
    );
    const mapping = validatedDataset.mappings.find(
      (value) => value.question_id === question.id,
    );
    if (!run || !mapping) throw new Error(`Missing records for ${question.id}`);
    return { question, run, mapping };
  });

  return (
    <div className="min-h-screen bg-paper text-ink">
      <aside className="honesty-banner" role="note" aria-label="Methodological limitation">
        <span className="honesty-mark" aria-hidden="true">
          i
        </span>
        <p>{HONESTY_COPY}</p>
      </aside>

      <header className="hero-shell">
        <nav className="site-nav" aria-label="Primary navigation">
          <a className="wordmark" href="#top">
            Concordance
          </a>
          <a href="#cases">Cases</a>
          <a href="#method">Method</a>
        </nav>
        <div id="top" className="hero-grid">
          <div>
            <p className="eyebrow">Policy-facing model comparison</p>
            <h1>Concordance</h1>
            <p className="hero-copy">
              See when AI systems share an initial conclusion, divide over a policy
              choice, or change course when the framing changes. Every displayed
              primary conclusion remains linked to its sampled answer and
              author-reviewed mapping.
            </p>
          </div>
          <aside className="panel-card" aria-label="Declared model panel">
            <p className="micro-label">Declared panel</p>
            <p className="panel-count">
              {validatedDataset.manifest.models.length}
            </p>
            <p>
              model families · frozen manifest{" "}
              {validatedDataset.manifest.manifest_id}
            </p>
            <ul>
              {validatedDataset.manifest.models.map((model) => (
                <li key={model.model_key}>
                  <span>{model.family}</span>
                  <code>{model.requested_model_id}</code>
                </li>
              ))}
            </ul>
          </aside>
        </div>
        {validatedDataset.isSample ? (
          <p className="sample-warning" role="status">
            Illustrative development data. No answer below is a real model run.
          </p>
        ) : null}
        {validatedDataset.index.mode === "candidate" ? (
          <p className="sample-warning prototype-warning" role="status">
            Prototype display using real selection-stage model answers. It shows
            initial answers and author-reviewed primary-position mappings only.
            Challenge samples were not run. These cases have not passed the
            production validation gate.
          </p>
        ) : null}
      </header>

      <main className="content-shell" id="cases">
        <section className="pattern-overview" aria-labelledby="patterns-title">
          <div className="section-heading">
          <div>
              <p className="eyebrow">Why this matters</p>
              <h2 id="patterns-title">Three patterns policy teams should see.</h2>
          </div>
          <p>
              Apparent consensus can amplify a shared first-answer pattern.
              Disagreement can change the recommendation. Framing can move the result
              before analysis begins.
          </p>
          </div>

          <nav className="case-nav" aria-label="Case navigation">
            {cases.map((record, index) => {
              const summary = summarizeCase(record, validatedDataset);
              return (
                <a href={`#${record.question.id}`} key={record.question.id}>
                  <span className="case-nav-topline">
                    <span className="case-nav-index">
                      {String.fromCharCode(65 + index)}
                    </span>
                    <span className="case-nav-kind">{summary.pattern}</span>
                  </span>
                  <strong className="case-nav-metric">{summary.metric}</strong>
                  <span className="case-nav-result">{summary.result}</span>
                  <span className="case-nav-title">{record.question.title}</span>
                </a>
              );
            })}
          </nav>
        </section>

        <div className="case-stack">
          {cases.map(({ question, run, mapping }, index) => {
            return (
              <CaseStudy
                key={question.id}
                question={question}
                run={run}
                mapping={mapping}
                models={validatedDataset.manifest.models}
                label={String.fromCharCode(65 + index)}
              />
            );
          })}
        </div>

        <section className="method-section" id="method" aria-labelledby="method-title">
          <p className="eyebrow">Method</p>
          <h2 id="method-title">A receipt, not a score.</h2>
          <div>
            <p>
              Concordance stores exact prompts and cached outputs, then presents a
              separate human-authored mapping to a cited, non-exhaustive position map.
              Primary endorsements, additional endorsements, mentions, errors, and
              omissions remain distinct.
            </p>
            <p>
              Challenge outputs and prompt variants are linked samples, not evidence
              of stable model beliefs. No universal monoculture metric or automatic
              truth label is calculated.
            </p>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <p>Concordance · static, cached, and inspectable</p>
        <a href="#top">Back to top</a>
      </footer>
    </div>
  );
}

function summarizeCase(
  record: { question: Question; run: RunManifest; mapping: Mapping },
  source: Dataset,
): { pattern: string; metric: string; result: string } {
  const firstVariant = record.question.prompt_variants[0];
  const view = buildCaseViewModel(
    record.question,
    record.run,
    record.mapping,
    source.manifest.models,
    firstVariant.id,
    "answer",
  );
  const counts = view.positions
    .map((position) => position.primaryModels.length)
    .filter((count) => count > 0)
    .sort((left, right) => right - left);

  if (record.question.kind === "convergent") {
    return {
      pattern: "Shared conclusion",
      metric: `${counts[0] ?? 0} of ${view.models.length}`,
      result: "reached the same primary conclusion",
    };
  }
  if (record.question.kind === "divergent") {
    return {
      pattern: "Competing conclusions",
      metric: counts.length === 2 ? `${counts[0]} to ${counts[1]}` : `${counts.length} positions`,
      result: "split across the same policy question",
    };
  }
  const secondVariant = record.question.prompt_variants[1];
  const movement = secondVariant
    ? variantMovementCount(
        record.run,
        record.mapping,
        firstVariant.id,
        secondVariant.id,
        "answer",
      )
    : 0;
  return {
    pattern: "Framing effect",
    metric: `${movement} of ${view.models.length}`,
    result: "changed primary conclusion with the framing",
  };
}

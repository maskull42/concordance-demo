import { dataset } from "@dataset";
import { CaseStudy } from "./components/CaseStudy";
import type { Dataset } from "./lib/types";

const validatedDataset = dataset as Dataset;

const HONESTY_COPY =
  'Concordance shows patterns in sampled answers from a declared panel of AI models. Agreement is not truth. "Not represented" means absent from these sampled answers relative to a cited, non-exhaustive map, not that a model cannot produce the position. This is a product demonstration, not a validated measure.';

export function App() {
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
            <p className="eyebrow">An inspectable comparison</p>
            <h1>Concordance</h1>
            <p className="hero-copy">
              See how a declared panel of AI models answers contested questions,
              which documented positions they endorse or mention, and how the map
              changes when the question changes.
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
        <div className="section-heading">
          <div>
            <p className="eyebrow">Three worked cases</p>
            <h2>Agreement is something to inspect.</h2>
          </div>
          <p>
            {validatedDataset.questions.length} cases ·{" "}
            {validatedDataset.modelFamilies.length}{" "}
            model families in this dataset
          </p>
        </div>

        <nav className="case-nav" aria-label="Case navigation">
          {validatedDataset.questions.map((question, index) => (
            <a href={`#${question.id}`} key={question.id}>
              <span>{String.fromCharCode(65 + index)}</span>
              {question.title}
            </a>
          ))}
        </nav>

        <div className="case-stack">
          {validatedDataset.questions.map((question, index) => {
            const run = validatedDataset.runs.find(
              (value) => value.question_id === question.id,
            );
            const mapping = validatedDataset.mappings.find(
              (value) => value.question_id === question.id,
            );
            if (!run || !mapping) {
              throw new Error(`Missing records for ${question.id}`);
            }
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

import { dataset } from "@dataset";
import type { Question } from "./lib/types";

const HONESTY_COPY =
  'Concordance shows patterns in sampled answers from a declared panel of AI models. Agreement is not truth. "Not represented" means absent from these sampled answers relative to a cited, non-exhaustive map, not that a model cannot produce the position. This is a product demonstration, not a validated measure.';

export function App() {
  return (
    <div className="min-h-screen bg-paper text-ink">
      <aside className="honesty-banner" aria-label="Methodological limitation">
        <span className="honesty-mark" aria-hidden="true">
          i
        </span>
        <p>{HONESTY_COPY}</p>
      </aside>

      <header className="hero-shell">
        <p className="eyebrow">An inspectable comparison</p>
        <h1>Concordance</h1>
        <p className="hero-copy">
          See how a declared panel of AI models answers contested questions,
          which documented positions they endorse or mention, and how the map
          changes when the question changes.
        </p>
        {dataset.isSample ? (
          <p className="sample-warning" role="status">
            Illustrative development data. No answer below is a real model run.
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
            {dataset.questions.length} cases · {dataset.modelFamilies.length}{" "}
            model families in this dataset
          </p>
        </div>

        <div className="case-grid">
          {dataset.questions.map((question: Question, index: number) => (
            <article className="case-shell" key={question.id}>
              <div className="case-index" aria-hidden="true">
                {String.fromCharCode(65 + index)}
              </div>
              <div>
                <p className="case-kind">{question.kind.replace("-", " ")}</p>
                <h3>{question.title}</h3>
                <p>{question.premise}</p>
                <dl className="case-meta">
                  <div>
                    <dt>Mapped positions</dt>
                    <dd>{question.position_map.length}</dd>
                  </div>
                  <div>
                    <dt>Prompt forms</dt>
                    <dd>{question.prompt_variants.length}</dd>
                  </div>
                </dl>
              </div>
            </article>
          ))}
        </div>
      </main>
    </div>
  );
}

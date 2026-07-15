import { useEffect } from "react";
import { orderCases } from "../lib/case-order";
import { collectCaseRecords, summarizeCase } from "../lib/case-summary";
import type { Route } from "../lib/router";
import type { Dataset } from "../lib/types";
import { CaseStudy } from "./CaseStudy";
import { ModelFlag } from "./ModelFlag";

interface InspectPageProps {
  dataset: Dataset;
  route: Extract<Route, { mode: "inspect" }>;
}

export function InspectPage({ dataset, route }: InspectPageProps) {
  const cases = orderCases(collectCaseRecords(dataset));
  const scrollTarget = route.questionId ?? route.anchor;

  useEffect(() => {
    if (!scrollTarget) {
      window.scrollTo(0, 0);
      return;
    }
    document.getElementById(scrollTarget)?.scrollIntoView();
  }, [scrollTarget]);

  return (
    <>
      <header className="hero-shell">
        <nav className="site-nav" aria-label="Primary navigation">
          <a className="wordmark" href="#top">
            Concordance
          </a>
          <a href="#/story">Story</a>
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
            <p className="panel-count">{dataset.manifest.models.length}</p>
            <p>
              model families · frozen manifest {dataset.manifest.manifest_id}
            </p>
            <ul>
              {dataset.manifest.models.map((model) => (
                <li key={model.model_key}>
                  <span>
                    <ModelFlag modelKey={model.model_key} /> {model.family}
                  </span>
                  <code>{model.requested_model_id}</code>
                </li>
              ))}
            </ul>
          </aside>
        </div>
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
              const summary = summarizeCase(record, dataset);
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
            const isTarget = question.id === route.questionId;
            const deepLinkKey = isTarget
              ? `${question.id}|${route.variantId ?? ""}|${route.modelKey ?? ""}|${route.view ?? ""}|${route.open ?? ""}`
              : question.id;
            return (
              <CaseStudy
                key={deepLinkKey}
                question={question}
                run={run}
                mapping={mapping}
                models={dataset.manifest.models}
                label={String.fromCharCode(65 + index)}
                initialVariantId={isTarget ? route.variantId : undefined}
                initialMode={isTarget ? route.view : undefined}
                initialSelectedModelKey={isTarget ? route.modelKey : undefined}
                openReceipts={isTarget && route.open === "receipts"}
                openReceiptsForModel={
                  isTarget && route.open === "receipts" ? route.modelKey : undefined
                }
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
    </>
  );
}

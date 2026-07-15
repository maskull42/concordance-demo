import type { Dataset } from "../lib/types";

export function DatasetStatusNotice({ dataset }: { dataset: Dataset }) {
  if (!dataset.isSample && dataset.index.mode !== "candidate") return null;
  return (
    <div className="status-shell">
      {dataset.isSample ? (
        <p className="sample-warning" role="status">
          Illustrative development data. No answer below is a real model run.
        </p>
      ) : null}
      {dataset.index.mode === "candidate" ? (
        <p className="sample-warning prototype-warning" role="status">
          Prototype display using real selection-stage model answers. It shows
          initial answers and author-reviewed primary-position mappings only.
          Challenge samples were not run. These cases have not passed the
          production validation gate.
        </p>
      ) : null}
    </div>
  );
}

import type { CaseRecord } from "./case-summary";
import type { Question } from "./types";

export const KIND_PRIORITY: Question["kind"][] = [
  "prompt-sensitive",
  "divergent",
  "convergent",
];

function rank(kind: Question["kind"]): number {
  const index = KIND_PRIORITY.indexOf(kind);
  return index === -1 ? KIND_PRIORITY.length : index;
}

// Story order: lead with the framing effect, then the live split, then the
// convergence case as the closing calibration exhibit. Dataset index files are
// never reordered; this is a display ordering only.
export function orderCases(records: CaseRecord[]): CaseRecord[] {
  return [...records].sort(
    (left, right) => rank(left.question.kind) - rank(right.question.kind),
  );
}

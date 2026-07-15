import { buildInspectHash, type InspectRef } from "../../lib/router";

// A numeric claim in story copy. The value must come from the view model,
// never a hand-typed literal.
export function ClaimFigure({
  value,
  unit,
}: {
  value: number | string;
  unit?: string;
}) {
  return (
    <strong className="story-figure">
      {value}
      {unit ? ` ${unit}` : ""}
    </strong>
  );
}

// Deep link to the receipts that back a claim, placed at the end of the
// sentence that makes the claim.
export function ReceiptLink({ inspect }: { inspect: InspectRef }) {
  return (
    <a className="claim-receipt" href={buildInspectHash(inspect)}>
      see the receipts →
    </a>
  );
}

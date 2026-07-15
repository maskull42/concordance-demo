const HONESTY_COPY =
  "Concordance shows patterns in sampled answers from a declared panel of AI models. Agreement is not truth. A position missing from the distribution did not receive a primary mapping in this sample; a model may still produce it under another prompt. This is a product demonstration, not a validated measure.";

export function HonestyBanner() {
  return (
    <aside className="honesty-banner" role="note" aria-label="Methodological limitation">
      <span className="honesty-mark" aria-hidden="true">
        i
      </span>
      <p>{HONESTY_COPY}</p>
    </aside>
  );
}

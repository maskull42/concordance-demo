import { safeExternalUrl, type PositionViewState } from "../../lib/view-model";

// Documented positions with zero primary mappings in the current sample.
// Labels and citations come straight from the question's position map; the
// absence claim is scoped to the sample, never to model capability.
export function MissingPositions({ positions }: { positions: PositionViewState[] }) {
  if (positions.length === 0) return null;
  return (
    <ul className="story-missing-list">
      {positions.map(({ position }) => (
        <li key={position.id}>
          <p className="story-missing-label">{position.label}</p>
          <p className="story-missing-summary">{position.summary}</p>
          <p className="story-missing-sources">
            {position.sources.map((source) => {
              const href = safeExternalUrl(source.url);
              return href ? (
                <a
                  key={`${source.id}-${source.url}`}
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {source.title}
                </a>
              ) : (
                <span key={`${source.id}-${source.url}`}>{source.title}</span>
              );
            })}
          </p>
        </li>
      ))}
    </ul>
  );
}

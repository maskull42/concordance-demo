import { modelOrigin } from "../lib/model-origin";

// Emoji flag for the model developer's headquarters country. Renders nothing
// when no origin is on record (fictional sample models).
export function ModelFlag({ modelKey }: { modelKey: string }) {
  const origin = modelOrigin(modelKey);
  if (!origin) return null;
  return (
    <span
      className="model-flag"
      role="img"
      aria-label={`Developer headquartered in ${origin.country}`}
      title={`Developer headquartered in ${origin.country}`}
    >
      {origin.flag}
    </span>
  );
}

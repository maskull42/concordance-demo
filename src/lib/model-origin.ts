// Display-only metadata: the flag marks the country where the model's
// developer is headquartered. It is presentation context for readers, not
// part of the frozen manifest, the runs, or any measurement claim. Models
// without an entry (for example the fictional sample-lane panel) simply show
// no flag.
export interface ModelOrigin {
  flag: string;
  country: string;
}

const ORIGIN_BY_MODEL_KEY: Record<string, ModelOrigin> = {
  gemini: { flag: "🇺🇸", country: "United States" },
  claude: { flag: "🇺🇸", country: "United States" },
  cohere: { flag: "🇨🇦", country: "Canada" },
  qwen: { flag: "🇨🇳", country: "China" },
  deepseek: { flag: "🇨🇳", country: "China" },
  mistral: { flag: "🇫🇷", country: "France" },
  grok: { flag: "🇺🇸", country: "United States" },
  gpt: { flag: "🇺🇸", country: "United States" },
};

export function modelOrigin(modelKey: string): ModelOrigin | undefined {
  return ORIGIN_BY_MODEL_KEY[modelKey];
}

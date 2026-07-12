# Concordance model pricing review

Status: approved by A.G. Elrod on 2026-07-12, immediate pre-run recheck still required

This review covers the exact eight-model panel and standard synchronous routes. The pilot prompts are short, one-shot requests, so planning uses the full uncached input rate and the full output rate. No cache discount, batch discount, flex tier, priority tier, or fallback price is assumed.

| Model key | Exact route | Input per 1M | Output per 1M | Planning basis |
|---|---|---:|---:|---|
| `gemini` | Google direct, `gemini-3.1-pro-preview` | $2.00 | $12.00 | Prompt below 200,000 tokens |
| `claude` | Anthropic direct, `claude-fable-5` | $10.00 | $50.00 | Standard 1M-context rate |
| `cohere` | Cohere direct, `command-a-plus-05-2026` | $0.00 | $0.00 | Current launch promotion within account rate limits |
| `qwen` | DeepInfra, `Qwen/Qwen3.5-397B-A17B` | $0.45 | $3.00 | Standard route, not Priority |
| `deepseek` | DeepSeek direct, `deepseek-v4-pro` | $0.435 | $0.87 | Uncached input |
| `mistral` | Mistral direct, `mistral-large-2512` | $0.50 | $1.50 | Uncached input |
| `grok` | xAI direct, `grok-4.5` | $2.00 | $6.00 | Standard service tier |
| `gpt` | OpenRouter with OpenAI pinned, `openai/gpt-5.6-sol` | $5.00 | $30.00 | Standard OpenAI service tier |

## Official evidence

- Google lists `gemini-3.1-pro-preview` at $2 per million input tokens and $12 per million output tokens for prompts up to 200,000 tokens. Output pricing includes thinking tokens. [Gemini pricing](https://ai.google.dev/gemini-api/docs/pricing), [model card](https://ai.google.dev/gemini-api/docs/models/gemini-3.1-pro-preview)
- Anthropic lists Fable 5 at $10 per million input tokens and $50 per million output tokens. Fable 5 requires the standard 30-day retention arrangement, so an account restricted to zero data retention may reject it. [Anthropic pricing](https://platform.claude.com/docs/en/about-claude/pricing), [model overview](https://platform.claude.com/docs/en/about-claude/models/overview)
- Cohere lists `command-a-plus-05-2026` as free for trial and production keys within the published rate limits. This is a promotion, not a durable paid tariff, and must be checked again immediately before a live run. [Command A Plus](https://docs.cohere.com/docs/command-a-plus), [rate limits](https://docs.cohere.com/docs/rate-limits)
- DeepInfra lists `Qwen/Qwen3.5-397B-A17B` at $0.45 per million input tokens and $3 per million output tokens on the standard route. [DeepInfra model page](https://deepinfra.com/Qwen/Qwen3.5-397B-A17B/api)
- DeepSeek lists `deepseek-v4-pro` at $0.435 per million cache-miss input tokens and $0.87 per million output tokens. The canonical pricing page controls over a conflicting third-party configuration example hosted elsewhere in DeepSeek's documentation. [DeepSeek pricing](https://api-docs.deepseek.com/quick_start/pricing/), [model list](https://api-docs.deepseek.com/api/list-models/)
- Mistral lists `mistral-large-2512` at $0.50 per million input tokens and $1.50 per million output tokens. [Mistral model card](https://docs.mistral.ai/models/model-cards/mistral-large-3-25-12)
- xAI lists `grok-4.5` at $2 per million input tokens and $6 per million output tokens. xAI currently says the model is not available to EU API-console users, with availability expected later in July. [Grok 4.5 model page](https://docs.x.ai/developers/grok-4-5), [xAI pricing](https://docs.x.ai/developers/pricing)
- OpenRouter lists the standard OpenAI endpoint for `openai/gpt-5.6-sol` at $5 per million input tokens and $30 per million output tokens. The provider pin and default service tier exclude Azure, flex, priority, and fallback routes. [OpenRouter endpoint data](https://openrouter.ai/api/v1/models/openai/gpt-5.6-sol/endpoints), [service tiers](https://openrouter.ai/docs/guides/features/service-tiers)

## Token-ceiling interpretation

The protocol's visible-answer target and the API output ceiling serve different purposes. The system prompt tells every model to keep its visible answer under 900 tokens. Every live route receives a 16,384-token total output ceiling so provider-default reasoning has room to complete without starving or truncating the visible answer.

For Gemini, Claude, Cohere, and GPT, the configured output parameter can include reasoning tokens as well as visible text. The xAI route uses the Responses API with `max_output_tokens`, whose ceiling includes reasoning and final text. Post-run Gemini cost accounting must add `candidatesTokenCount` and `thoughtsTokenCount`; other providers already report inclusive output totals. Cost planning therefore reserves the full 16,384-token ceiling for every attempt, even though compliant visible answers should remain below 900 tokens. The private pilot preserves provider defaults, records truncation, and stops for review if any incomplete output makes a threshold judgment unreliable.

## Approval boundary

The `author-verified` pricing state authorizes these rates only for the private pilot. It does not authorize publication or model substitution. Prices and availability must be checked again immediately before execution. The Amsterdam account returned exact model ID `grok-4.5` through the authenticated xAI metadata endpoint on 2026-07-12; live preflight must still confirm the complete panel before generation.

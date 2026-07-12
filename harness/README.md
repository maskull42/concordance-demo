# Concordance generation harness

This Python 3.10+ program is deliberately separate from the static browser application. It plans and records calls to the eight author-approved model routes, but it does not make a network request in `--dry-run` mode.

## Safe offline check

From the repository root:

```sh
python3 -m pip install -e harness
python3 harness/generate.py --dry-run
python3 harness/generate.py --dry-run --run-purpose pilot \
  --questions candidate/questions --answer-only --output .pilot
python3 -m unittest discover -s harness/tests -v
```

The default dry run uses the clearly fictional three-case sample solely to exercise the final matrix shape. It must report 64 logical cells: 8 models × (one variant for Case A + one for Case B + two for Case C) × answer and challenge.

The pilot dry run uses the six frozen Rule 2 research candidates. Two candidates belong to each intended behavior, and their eight prompt variants produce 64 answer-only cells across the eight-model panel. A dry run never reads credentials or calls a provider.

## Live gate

Every live use remains blocked until credentials have been rotated, planning prices have been reviewed, and metadata preflight confirms every requested route and returned model identifier. Content and output-path gates run before the harness reads any environment variable.

### Private Rule 2 pilot

A live pilot is authorized only when all of the following are true:

1. `--run-purpose pilot`, `--answer-only`, and `--pilot-content-approved` are all present;
2. the question directory contains the six canonical research candidates in `concordance-pilot-pool`, with the exact priority and fallback roles recorded in `candidate/PILOT_POOL.md`;
3. every candidate uses content version `candidate-1.1.0`, pool size 6, rule `pilot-rule-2`, candidate selection status, and proposed question, position, and source records;
4. `candidate/pilot-lock.json` conforms to `candidate/pilot-lock.schema.json` and binds the pool, rule, content version, `candidate/PILOT_POOL.md`, the approved `candidate/MAPPING_RUBRIC.md`, six exact question files, their priority and fallback roles, and `config/protocol.json` by SHA-256;
5. the lock, pool document, mapping rubric, all six locked question files, and locked protocol exist in Git `HEAD` and are unchanged in the working tree, so the required pre-output commit is both present and reproducible;
6. an unfiltered plan contains exactly 64 answer-only cells across all eight configured models, while an explicitly named stage contains exactly eight cells for every selected canonical model;
7. unfiltered output is written inside the ignored repository `.pilot/` directory, and staged output is written exactly to `.pilot/stages/<ID>`.

The approval flag authorizes this frozen provisional content only for a private threshold-selection pilot. It does not mark any source as author-verified and does not authorize publication. A.G. Elrod approved the exact six prompts and maps and `mapping-rubric-1` on 2026-07-12. The generated lock and every locked input must be validated and committed together before running the pilot. Any later content, rubric, or protocol change requires a new approved lock and commit. Pilot output is ignored by Git and must not be copied into production data.

After credentials and pricing clear their separate gates, the command shape is:

```sh
python3 harness/generate.py --live --run-purpose pilot \
  --credentials-rotated --pilot-content-approved --answer-only \
  --questions candidate/questions --output .pilot
```

#### Staged private execution

A model filter in pilot mode is allowed only with an explicit `--pilot-stage ID`. The stage ID isolates its receipts and run files at `.pilot/stages/<ID>`. Each selected canonical model must still answer all eight exact prompt variants across all six locked candidates. Preflight, credential checks, and the model manifest cover only the selected models in that stage.

This runs the currently available seven-model panel while deferring Mistral:

```sh
python3 harness/generate.py --live --run-purpose pilot \
  --credentials-rotated --pilot-content-approved --answer-only \
  --questions candidate/questions \
  --pilot-stage without-mistral \
  --output .pilot/stages/without-mistral \
  --model gemini --model claude --model cohere --model qwen \
  --model deepseek --model grok --model gpt \
  --retries 1 --max-calls 63 --max-cost-usd 15
```

Before generation, the harness writes a one-time `stage.json` receipt containing the stage ID, selected and deferred model keys, expected cell count, pilot-lock and configuration hashes, harness version, cross-stage execution-contract hash, full-plan and stage-plan hashes, model-manifest hash, and creation time. Resume refuses changed source code, prompts, configuration, manifest evidence, or model scope. Staged receipts and run files remain private under the Git-ignored `.pilot/` tree.

All generation calls use a one-hour read timeout. A timeout or network failure is ambiguous after a paid request has been sent, so it is never retried automatically. Only provider-specific complete terminal states are checkpointed as successes. Token-limit, incomplete, or missing finish states are recorded as nonqualifying errors.

A stage is partial, nonqualifying evidence. It cannot support Rule 2 threshold selection or production content by itself. Selection waits until the stages aggregate to all 64 exact model-variant cells, with all eight canonical models and no missing or duplicate cells. The later Mistral stage must use a different stage ID and its own private output directory.

#### Approved nine-cell repair

The first `without-mistral` pass preserved 47 complete responses and recorded nine terminal errors: eight OpenRouter responses reported the dated canonical GPT identifier, and one DeepSeek response ended in an ambiguous network read. A.G. Elrod approved treating `openai/gpt-5.6-sol-20260709` as the exact canonical resolution of the requested `openai/gpt-5.6-sol` alias on 2026-07-12.

The repair utility validates the byte-exact parent receipt, manifest, and six run files, then derives the nine targets from the canonical 64-cell plan. It reads only the DeepSeek and OpenRouter credentials. The original stage is never modified.

```sh
python3 harness/repair_pilot.py --live \
  --repair-id gpt-alias-deepseek-network-1 \
  --credentials-rotated --approved-gpt-alias-resolution
```

The fresh repair is hard-coded to two metadata checks, nine single-attempt generation calls, and a $4 planning ceiling. Output is isolated at `.pilot/repairs/<ID>`. `repair.json` binds the approved parent and execution contract. Before each POST, an exclusive intent is durably written. A terminal or stranded intent can never be resent under the same repair ID. `result.json` binds every outcome. Even a complete repair remains private and nonqualifying until Mistral supplies the deferred eight cells.

#### Complete aggregate and blind export

After the Mistral completion stage, the offline aggregate verifier rebuilds the frozen 64-cell plan, preserves the 47 original successes, overlays the exact nine repaired errors, and adds the eight disjoint Mistral cells. It reads no environment variables and makes no network requests.

```sh
python3 harness/aggregate_pilot.py --check
python3 harness/aggregate_pilot.py --write
```

The write-once output lives at `.pilot/aggregates/rule2-pilot-1`. `aggregate.json` records complete mapping eligibility, source hashes, provenance, and an explicit declaration that thresholds and selection have not been evaluated. Mapper-visible files contain only an opaque blind ID, exact prompt, minimal position map, and verbatim response. The identity crosswalk and random blinding key remain under `private/` and must never enter a mapper context.

### Final production run

A final live run is authorized only when all of the following are true:

1. the question directory contains exactly one selected research case of each approved kind;
2. every included question, position, and source is `author-verified`;
3. linked challenge calls remain enabled and the complete final plan contains 64 cells;
4. output is the repository `data/` directory.

The final path refuses candidate or proposed content even when the operator has supplied credentials. A final command has this shape:

```sh
python3 harness/generate.py --live --run-purpose final \
  --credentials-rotated --questions data/questions --output data
```

The current entries use the standard synchronous rates researched and approved by A.G. Elrod on 2026-07-12. The evidence, cache assumptions, promotion caveat, regional exception, and token-cap semantics are recorded in [PRICING_REVIEW.md](PRICING_REVIEW.md). They must still be checked immediately before execution.

The protocol asks each model to keep the visible answer under 900 tokens. Separately, every provider request allows up to 16,384 total output tokens for reasoning and the answer. The larger API ceiling is truncation protection, not a request for a longer visible response. Conservative cost planning reserves the full ceiling.

The harness reads only the eight named environment variables when `--live` is supplied. It never searches for or loads `.env` files. It does not print request headers, query strings, or secret values.

## CLI

```text
--dry-run                  plan only; no environment or network access
--live                     explicitly enable the live path
--questions PATH           directory containing question JSON files
--output PATH              output dataset root
--case ID                  select a question (repeatable)
--model KEY                select a model key (repeatable)
--answer-only              omit linked challenges (pilot mode)
--max-calls N              cap all outbound attempts, including retries
--max-cost-usd N           cap reserved upper-bound spend across attempts
--force                    replace successful cells instead of resuming
--retries N                total attempts per cell, default 3
--concurrency N            maximum concurrent provider calls
--credentials-rotated      operator attestation required with --live
--run-purpose pilot|final  select the private-pilot or production contract
--pilot-content-approved   authorize the frozen proposed Rule 2 private pilot
--pilot-stage ID           name a private, nonqualifying filtered pilot stage
```

Challenge cells always extend the exact parent conversation with the exact parent text as an assistant message and the shared instruction in `config/protocol.json`. The instruction explicitly treats that prior text as untrusted data.

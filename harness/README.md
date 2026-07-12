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
6. the complete plan contains exactly 64 answer-only cells across all eight configured models;
7. output is written inside the ignored repository `.pilot/` directory.

The approval flag authorizes this frozen provisional content only for a private threshold-selection pilot. It does not mark any source as author-verified and does not authorize publication. A.G. Elrod approved the exact six prompts and maps and `mapping-rubric-1` on 2026-07-12. The generated lock and every locked input must be validated and committed together before running the pilot. Any later content, rubric, or protocol change requires a new approved lock and commit. Pilot output is ignored by Git and must not be copied into production data.

After credentials and pricing clear their separate gates, the command shape is:

```sh
python3 harness/generate.py --live --run-purpose pilot \
  --credentials-rotated --pilot-content-approved --answer-only \
  --questions candidate/questions --output .pilot
```

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
```

Challenge cells always extend the exact parent conversation with the exact parent text as an assistant message and the shared instruction in `config/protocol.json`. The instruction explicitly treats that prior text as untrusted data.

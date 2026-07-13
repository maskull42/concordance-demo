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

The second blinding pass creates 16 isolated batches of four. Every batch contains four distinct question families and four distinct underlying models. Canonical position IDs are replaced by task-local `P1`, `P2`, and similar handles.

```sh
python3 harness/prepare_mapping_batches.py --check
python3 harness/prepare_mapping_batches.py --write
```

Mapper agents receive only one batch manifest, its four envelopes, and `instructions.json`. They must never read `aggregate.json`, either private crosswalk, another batch, or any run receipt.

The offline mapping validator checks the frozen batch receipt, all manifest and envelope hashes, response hashes, assignment schemas, local handles, nonoverlap rules, and verbatim evidence snippets. Partial checks are safe while independent coders are still working. After all 16 files pass and every coder has exited, commit the validator and its tests before sealing the write-once first-pass receipt. No process may still be writing a mapping during sealing.

```sh
python3 harness/validate_blind_mappings.py --check-partial
python3 harness/validate_blind_mappings.py --seal
python3 harness/validate_blind_mappings.py --verify
```

`first-pass.json` records 64 validated assignments with status `complete-author-review-required`. The verification command must pass before review or any later calculation; it detects post-seal mapping changes. The receipt does not expose model identities, calculate thresholds, or select candidates. A.G. Elrod must review every assignment that can affect a threshold before any unblinding or calculation.

#### Blinded primary author review

A.G. Elrod approved a primary-only mandatory review on 2026-07-12. Every one of the 64 items requires an explicit confirmation or correction of `primary_endorsed` and `primary_reason_code`. Secondary endorsements, mentions, rationale, evidence, confidence, and flags remain visible as context and accept an optional note, but they are not recoded. This matches Rule 2: only the primary field affects thresholds.

Commit the packet generator, browser assets, importer, and tests before writing the private packet. The generator reads only the sealed first pass and mapper-safe batch files. It never opens the aggregate or either private crosswalk.

```sh
python3 harness/prepare_author_review.py --check
python3 harness/prepare_author_review.py --write
python3 harness/prepare_author_review.py --verify
```

The write-once output lives at `.pilot/aggregates/rule2-pilot-1/author-review-1`. Open `author-review-packet.html` locally. It is a self-contained, request-free file with hash-authorized inline assets and base64-encoded untrusted text. Review one item at a time, export draft JSON whenever useful, then use **Finish and export** after all 64 decisions are complete.

Publication uses a private claim plus no-replace hard links. If the process is interrupted and reports an incomplete publication, the explicit recovery command removes only a recognized partial set or clears the claim from an already complete packet. Unexpected files are preserved for inspection.

```sh
python3 harness/prepare_author_review.py --recover-incomplete
```

The exported JSON must be checked before sealing. Replace `PATH` with the browser export supplied by A.G. Elrod.

```sh
python3 harness/finalize_author_review.py --check PATH
python3 harness/finalize_author_review.py --seal PATH
python3 harness/finalize_author_review.py --verify
```

Sealing retains the exact imported bytes and writes a normalized review receipt under `sealed-primary-review/`. Confirmation must preserve the first-pass primary pair. Correction must change at least one member of the pair. Notes remain optional in both cases. The sealed receipt still records `threshold_evaluation.performed: false` and `selection_status: not-evaluated`. Review closes one gate. It does not cross the next.

The seal uses the same claim protocol. Run `python3 harness/finalize_author_review.py --recover-incomplete` only after a disclosed interrupted seal.

#### Rule 2 threshold selection

Only a verified, sealed author review unlocks unblinding. The evaluator reconstructs the exact 64-cell run, recomputes every blind ID from the private key, checks both crosswalks and every local-to-canonical position map, then counts only the author-reviewed primary assignment.

Two prose rules are made explicit in the machine receipt. A convergence alternative is “not endorsed” only when it receives zero primary assignments; secondary endorsements never enter thresholds. Prompt-sensitivity clarity requires at least six of the same models to be non-null under both variants, not merely six non-null responses in each variant considered separately.

Commit the evaluator and tests before writing its single-file, write-once receipt.

```sh
python3 harness/evaluate_pilot_selection.py --check
python3 harness/evaluate_pilot_selection.py --write
python3 harness/evaluate_pilot_selection.py --verify
```

The private receipt is `.pilot/aggregates/rule2-pilot-1/selection-rule2-1.json`. It binds the pilot lock, rubric, run files, mapping files, both crosswalks, author review, 64 canonical assignments, all six candidate metrics, and each priority/fallback result. A behavior with no qualifying candidate remains failed and requires A.G. Elrod’s approval of a disclosed new pool and rule version. Selection does not change proposed scholarship into author-verified material and does not authorize production.

The receipt is published at mode `0600` through an exclusive claim and atomic hard link. If an interrupted write leaves that claim behind, run `python3 harness/evaluate_pilot_selection.py --recover-incomplete`. Recovery preserves changed or unrecognized bytes for inspection.

#### Approved post-selection amendment

A.G. Elrod’s later source audit identified one partial-fit mapping. The Grok methods-frame answer on John Brown clearly selects a terrorism classification but neither calls the raid fanatical nor gives an unqualified moral verdict. On 2026-07-12, A.G. approved treating that answer as outside the frozen map. The original 64-confirmation review and `selection-rule2-1.json` remain immutable historical artifacts.

The amendment workflow proves the exact one-item delta, seals a complete 63-confirmation and 1-correction review under `author-review-2`, and writes a superseding `selection-rule2-2.json`. It changes the reviewed pair from `P3 / clear_preference` to `null / outside_map`. John Brown’s paired non-null count becomes 7 and its movement count becomes 4, so the selected cases do not change.

Commit the amendment code and tests before writing either private artifact. Then run:

```sh
python3 harness/prepare_author_review_amendment.py --check
python3 harness/prepare_author_review_amendment.py --write
python3 harness/prepare_author_review_amendment.py --verify
python3 harness/evaluate_pilot_selection_amended.py --check
python3 harness/evaluate_pilot_selection_amended.py --write
python3 harness/evaluate_pilot_selection_amended.py --verify
```

Both workflows are write-once, private, crash-recoverable, and transitively bound to the unchanged Rule 2 inputs. The amended receipt supersedes only the corrected mapping and its derived metrics. It does not erase Rule 2’s failed divergence result or authorize production.

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

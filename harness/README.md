# Concordance generation harness

This Python 3.10+ program is deliberately separate from the static browser application. It plans and records calls to the eight author-approved model routes, but it does not make a network request in `--dry-run` mode.

## Safe offline check

From the repository root:

```sh
python3 harness/generate.py --dry-run
python3 -m unittest discover -s harness/tests -v
```

The default dry run uses the clearly fictional three-case sample solely to exercise the final matrix shape. It must report 64 logical cells: 8 models × (one variant for Case A + one for Case B + two for Case C) × answer and challenge.

## Live gate

Live use is intentionally blocked unless all of the following are true:

1. the user supplies an explicit non-sample question directory;
2. all selected questions are `author-verified`;
3. the project credentials have been rotated and the operator passes `--credentials-rotated --live`;
4. every configured planning price has been replaced with reviewed provider pricing;
5. metadata preflight confirms every requested route and returned model identifier.

The current pricing entries are conspicuously conservative offline planning ceilings, not claims about provider prices. They make the dry-run cost ceiling useful without pretending that future-model pricing has already been verified. They must not unlock live calls.

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
```

Challenge cells always extend the exact parent conversation with the exact parent text as an assistant message and the shared instruction in `config/protocol.json`. The instruction explicitly treats that prior text as untrusted data.

# Concordance

Concordance is a cached, static product demonstration for inspecting how a declared, versioned panel of AI models answers contested interpretive questions.

> Concordance shows patterns in sampled answers from a declared panel of AI models. Agreement is not truth. "Not represented" means absent from these sampled answers relative to a cited, non-exhaustive map, not that a model cannot produce the position. This is a product demonstration, not a validated measure.

## Development status

The repository is private while the prototype, provisional scholarly content, and verification workflow are under development. No real model output or unverified scholarly content is published yet.

The implementation is staged. Each stage is validated and committed before the next begins. Live model calls require an exact committed lock, a current pricing receipt, separate paid-run authorization, and credentials replaced or rotated for this project.

The default application build uses a conspicuously fictional dataset generated in `sample/`. A separate local prototype lane assembles three real, selection-stage cases from sealed private artifacts. It contains 32 initial answers and author-reviewed primary mappings. Challenge samples remain unrun, and the lane does not pass the production gate. The placeholder `data/` tree remains intentionally unable to pass that gate.

The sample interface exercises every release state: primary and additional endorsements, mentions, absence, mixed/unclear mappings, linked challenge recovery, prompt-variant movement, and an unavailable response cell. Model text is rendered as inert text beside separately labeled human mappings and complete provenance receipts.

## Local development

Use Node 22 LTS (recorded in `.nvmrc`), then run:

```sh
npm install
npx playwright install chromium
node scripts/create-sample-data.mjs
npm run check
npm run dev
```

To inspect the real-data prototype locally, run:

```sh
npm run dev:prototype
```

That command assembles and validates `.pilot/prototype-data/` before starting a CSP-compatible built preview at `http://127.0.0.1:4173`. It performs no provider calls and requires the sealed local `.pilot/` artifacts from the completed selection runs.

Useful checks:

- `npm run validate:data` validates the indexed sample files, cross-record links, and content hashes.
- `npm run validate:data:prototype` validates the assembled, candidate-mode real-data preview.
- `npm run build:prototype` assembles, validates, and bundles the local real-data preview.
- `npm run validate:data:production` applies the stricter release gate to `data/` and is expected to fail until the verified final dataset exists.
- `npm run validate:candidates` checks the frozen six-question pilot pool and its provisional verification dossier.
- `npm run validate:candidates:rule3` checks the exact two-candidate Rule 3 supplement, its approved map boundaries, and all 13 source bindings.
- `npm run validate:candidates:successor` checks the two selected `candidate-1.1.1` successors, their exact 22-change allowlist, and their lineage back to the frozen lock and superseding Rule 2 receipt.
- `npm run validate:candidates:author-verified` checks the immutable `candidate-1.1.2` promotion, all 26 author-verification records, and the unresolved production gates without requiring private review files.
- `python3 harness/create_rule3_lock.py --check` validates the Rule 3 execution lock and every byte it binds. Add `--require-committed` before any authorization or live use.
- `npm test` runs schema, derived-state, and component tests.
- `npm run test:e2e` runs the browser interaction and same-origin network checks once Playwright browsers are installed.
- `npm run build` always validates sample data before compiling; `npm run build:production` cannot bundle unverified or incomplete data.

The generator harness is isolated from the browser application and is documented separately in `harness/`. Do not point it at credentials that have not been rotated for this project.

## Release contract

- The deployed application is static and makes no model API calls.
- Model responses are real cached outputs or are explicitly shown as not run.
- Questions, position maps, citations, and mappings must be author-verified before release.
- Raw outputs and human-authored mappings remain visibly distinct.
- No universal monoculture score or automated citation-truth label is produced.
- Publication requires a separate author release instruction; development pushes remain in the private repository.

## Licensing

Code is licensed under the MIT License. See [DATA_LICENSE.md](DATA_LICENSE.md) for the narrower treatment of authored content, model outputs, citations, and third-party material.

# Concordance

Concordance is a cached, static product demonstration for inspecting how a declared, versioned panel of AI models answers contested interpretive questions.

> Concordance shows patterns in sampled answers from a declared panel of AI models. Agreement is not truth. "Not represented" means absent from these sampled answers relative to a cited, non-exhaustive map, not that a model cannot produce the position. This is a product demonstration, not a validated measure.

## Development status

The repository is private while the prototype, provisional scholarly content, and verification workflow are under development. No real model output or unverified scholarly content is published yet.

The implementation is staged. Each stage is validated and committed before the next begins. Live model calls are blocked until the development credentials have been replaced or rotated.

The default application build uses a conspicuously fictional dataset generated in `sample/`. The placeholder `data/` tree is intentionally unable to pass the production gate.

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

Useful checks:

- `npm run validate:data` validates the indexed sample files, cross-record links, and content hashes.
- `npm run validate:data:production` applies the stricter release gate to `data/` and is expected to fail until the verified final dataset exists.
- `npm run validate:candidates` checks the frozen six-question pilot pool and its provisional verification dossier.
- `npm run validate:candidates:successor` checks the two selected `candidate-1.1.1` successors, their exact 22-change allowlist, and their lineage back to the frozen lock and superseding Rule 2 receipt.
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

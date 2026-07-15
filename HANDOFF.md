# Concordance session handoff

Saved on 2026-07-15 from branch `agent/build-concordance-demo`.

## Current state

The real-data prototype is assembled, validated, redesigned for policy-facing clarity, and ready for local review. The latest interface commit before this handoff is `af4f0bc`.

The prototype presents three cases from a frozen eight-model panel:

- Junia: 8 of 8 initial answers reached the same reviewed primary conclusion.
- Frontier AI governance: the panel split 5 to 3 between two legal architectures.
- John Brown: 4 of 8 models changed primary conclusion when the framing changed.

The interface leads with those three patterns, uses responsive model-slot distributions, and places sources and run receipts in collapsed disclosures. The fixed SVG and source-grid layout failures have been removed.

## Restart

From this directory, run:

```sh
npm run dev:prototype
```

Then open `http://127.0.0.1:4173`.

The command rebuilds `.pilot/prototype-data/` deterministically from the sealed local artifacts. It makes no provider calls and reads no API credentials.

## Verified checks

- `npm run lint`
- `npm test`: 57 tests passed
- `npm run test:e2e`: 9 passed, 1 intentionally skipped
- `npm run build:prototype`: 3 questions and 32 response cells validated
- Responsive checks at 320, 375, 760, 960, and 1280 pixels: no horizontal overflow or runtime errors
- WCAG A and AA browser scan: no detected violations
- Independent Junia lineage audit: all eight raw answers and author-reviewed primary mappings resolve to the same canonical position

## Prototype boundaries

- The display contains one initial answer per model and prompt wording.
- Only primary conclusions received author review for this prototype display.
- Secondary endorsements and mentions remain unreviewed and are labeled accordingly.
- Challenge samples were not run.
- The frontier case retains its formal Rule 3 failure and appears only under the approved prototype inclusion policy.
- The production `data/` tree remains untouched and unable to pass the production gate.

## Return point

No judgment call, library text, or provider call is outstanding. The next useful step is user review of the redesigned local interface. Production work would require separate authorization, new challenge samples, author review, content promotion, and the production validation gate.

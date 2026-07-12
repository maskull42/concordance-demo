# Rule 2 mapping rubric

Status: approved by A.G. Elrod for private pilot use on 2026-07-12

Rubric ID: `mapping-rubric-1`

This rubric governs the private answer-only pilot. It does not authorize publication or formal source verification.

## Blinded coding

Each response is coded without showing the coder the model family, provider, the paired prompt variant, or aggregate results. Prompt-sensitive variants are coded independently. The raw response remains unchanged and auditable.

## Assignment fields

- `primary_endorsed`: assign exactly one mapped position only when the response clearly presents it as the best-supported overall answer.
- `also_endorsed`: record another mapped position only when the response affirmatively supports it as compatible or secondarily correct.
- `mentioned`: record a position discussed without endorsement.
- Use `primary_endorsed: null` when the response is genuinely mixed, unclear, refuses to choose, or does not fit the map. Never force an answer into the nearest position.

Only `primary_endorsed` counts toward Rule 2 thresholds. Secondary endorsements, mentions, and null assignments remain visible but do not substitute for a primary position.

## Minimum clarity

- A convergence or divergence candidate is eligible only if at least 6 of 8 responses receive a non-null primary assignment.
- A prompt-sensitive candidate is eligible only if at least 6 of 8 models receive non-null primary assignments under both variants.
- Prompt movement counts only when the same model has two non-null primary assignments and the position IDs differ.

These minimums prevent a candidate from qualifying because most outputs were mixed or unmappable.

## Errors and incomplete responses

After the fixed retries, any error, not-run cell, or provider-marked incomplete response makes the affected candidate temporarily ineligible. Do not advance to its fallback because the priority result is unknown. Retry only the identical locked cell. If it cannot complete under the locked protocol and output cap, stop for a disclosed new rule version before changing parameters.

## Review and selection

Codex performs the first blinded mapping pass. A.G. Elrod reviews every assignment that can affect whether a priority or fallback crosses its threshold before selection becomes final. Any correction is recorded before threshold calculation. The final calculation must be written to a machine-readable selection receipt that identifies the pilot lock, rubric, run files, mapping files, hashes, metrics, and selected or failed result for each intended behavior.

The final production gate must reject a manually relabeled candidate that lacks this receipt.

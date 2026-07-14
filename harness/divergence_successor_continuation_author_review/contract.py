"""Frozen constants for the append-only continuation author-review lane."""

from __future__ import annotations

from pathlib import Path

from divergence_successor_continuation import contract as continuation_contract


POOL_ID = continuation_contract.POOL_ID
CANDIDATE_ID = continuation_contract.CANDIDATE_ID
ITEM_COUNT = 8

BASE_LOCK_PATH = continuation_contract.LOCK_PATH
BASE_LOCK_SHA256 = (
    "5acbb3d7dbeaa03e26441878d9d0d8714fd902474ae3be811fc04a2bd6b1d803"
)
COMPOSITE_PATH = (
    f"{continuation_contract.PRIVATE_ROOT_RELATIVE}/runs/{CANDIDATE_ID}.json"
)
COMPOSITE_SHA256 = (
    "cf485da16667638b82e00c3d091d2c04eac9e061a9c37761a7314851bed3fc63"
)
BLIND_ROOT_RELATIVE = (
    f"{continuation_contract.REVIEW_ROOT_RELATIVE}/candidates/{CANDIDATE_ID}/blind"
)
BLIND_PACKET_PATH = f"{BLIND_ROOT_RELATIVE}/packet.json"
BLIND_PACKET_SHA256 = (
    "0db90c6e1c414e2a148e7d76a2c47e5835af77371d7f5ebf72ab3c51c37cbaff"
)

# The extension writes to a new private hierarchy.  The established blind tree
# above is read-only input and remains byte-for-byte untouched.
PRIVATE_ROOT_RELATIVE = (
    ".pilot/divergence-successor-continuation-author-review/"
    "frontier-ai-preflight-correction-1"
)
PRIVATE_CANDIDATE_ROOT = f"{PRIVATE_ROOT_RELATIVE}/candidates/{CANDIDATE_ID}"
ANCHOR_ROOT = f"{PRIVATE_CANDIDATE_ROOT}/anchor-v2"
ANCHOR_TIMESTAMP = "2026-07-14T16:22:25.267585Z"
ANCHOR_SHA256 = "2f4e8bea18c622129d2d5535517d91465b3b85b71bf087f1e9be7c25eb3635a9"
FIRST_PASS_ROOT = f"{PRIVATE_CANDIDATE_ROOT}/first-pass-v2"
AUTHOR_PACKET_ROOT = f"{PRIVATE_CANDIDATE_ROOT}/author-packet-v2"
AUTHOR_REVIEW_ROOT = f"{PRIVATE_CANDIDATE_ROOT}/author-review-v2"

LOCK_PATH = "candidate/rule3-successor-continuation-review-lock.json"
LOCK_SCHEMA_PATH = "candidate/rule3-successor-continuation-review-lock.schema.json"
LOCK_SCHEMA_VERSION = "rule3-successor-continuation-review-lock-2.0.0"
LOCK_STATUS = "sealed-continuation-author-review-v2"

ANCHOR_SCHEMA = "divergence-successor-review-anchor-2.0.0"
ANCHOR_STATUS = "sealed-historical-review-inputs-v2"
FIRST_PASS_SCHEMA = "divergence-successor-consensus-first-pass-2.0.0"
FIRST_PASS_STATUS = "complete-consensus-first-pass-v2"
FIRST_PASS_RECEIPT_SCHEMA = (
    "divergence-successor-consensus-first-pass-receipt-2.0.0"
)
FIRST_PASS_RECEIPT_STATUS = "sealed-consensus-first-pass-v2"
AUTHOR_PACKET_SCHEMA = "divergence-successor-author-review-packet-2.0.0"
AUTHOR_PACKET_STATUS = "ready-for-complete-author-review-v2"
AUTHOR_EXPORT_SCHEMA = "divergence-successor-author-review-draft-2.0.0"
AUTHOR_EXPORT_STATUS = "complete-author-review-v2"
AUTHOR_RECEIPT_SCHEMA = "divergence-successor-author-review-receipt-2.0.0"
AUTHOR_RECEIPT_STATUS = "sealed-complete-author-review-v2"

REVIEWER = {"id": "ag-elrod", "display_name": "A.G. Elrod"}
REASON_CODES = frozenset(
    {"clear_preference", "mixed", "unclear", "refusal", "outside_map"}
)
CONFIDENCE_VALUES = frozenset({"low", "medium", "high"})

# These two assets were already committed into the base continuation lock.
LOCKED_REVIEW_ASSET_PATHS = (
    "harness/divergence_successor/review_assets/review.css",
    "harness/divergence_successor/review_assets/review.js",
)
VERSIONED_REVIEW_ASSET_PATHS = (
    "harness/divergence_successor_continuation_author_review/review_assets/review.css",
    "harness/divergence_successor_continuation_author_review/review_assets/review.js",
)

SOURCE_PATHS = (
    "harness/divergence_successor_continuation_author_review/__init__.py",
    "harness/divergence_successor_continuation_author_review/contract.py",
    "harness/divergence_successor_continuation_author_review/anchor.py",
    "harness/divergence_successor_continuation_author_review/review.py",
    "harness/divergence_successor_continuation_author_review/lock.py",
    "harness/divergence_successor_continuation_author_review/review_assets/review.css",
    "harness/divergence_successor_continuation_author_review/review_assets/review.js",
    "harness/seal_divergence_successor_continuation_first_pass.py",
    "harness/prepare_divergence_successor_continuation_author_packet.py",
    "harness/finalize_divergence_successor_continuation_author_review.py",
    "harness/create_divergence_successor_continuation_review_lock.py",
    "harness/anchor_divergence_successor_continuation_review.py",
    LOCK_SCHEMA_PATH,
)

class AuthorReviewContractError(RuntimeError):
    """The frozen v2 author-review contract changed or is incomplete."""


def repository_root(value: Path | str) -> Path:
    try:
        return continuation_contract.repository_root(value)
    except continuation_contract.ContinuationContractError as error:
        raise AuthorReviewContractError(str(error)) from error


__all__ = (
    "ANCHOR_ROOT",
    "ANCHOR_SHA256",
    "ANCHOR_TIMESTAMP",
    "AUTHOR_EXPORT_SCHEMA",
    "AUTHOR_EXPORT_STATUS",
    "AUTHOR_PACKET_ROOT",
    "AUTHOR_REVIEW_ROOT",
    "BASE_LOCK_SHA256",
    "BLIND_PACKET_SHA256",
    "CANDIDATE_ID",
    "COMPOSITE_SHA256",
    "FIRST_PASS_ROOT",
    "ITEM_COUNT",
    "LOCK_PATH",
    "POOL_ID",
    "repository_root",
)

"""Constants for the append-only continuation threshold-evaluation lane."""

from __future__ import annotations

from pathlib import Path

from divergence_successor_continuation_author_review import contract as review_contract


POOL_ID = review_contract.POOL_ID
CANDIDATE_ID = review_contract.CANDIDATE_ID
PRIVATE_ROOT_RELATIVE = review_contract.PRIVATE_ROOT_RELATIVE
EVALUATION_ROOT = f"{review_contract.PRIVATE_CANDIDATE_ROOT}/evaluation-v2"

SUCCESSOR_LOCK_PATH = "candidate/rule3-successor-lock.json"
SUCCESSOR_LOCK_SHA256 = (
    "08cbaa1963d88cc0c1b0fe32ac7e74fbd553b4dc9f7a6a1de0cc6866129f8ab9"
)
REVIEW_LOCK_PATH = review_contract.LOCK_PATH
REVIEW_LOCK_SHA256 = "573b8fc4caf513430873eabd9afa972e1a0ef76ab50c316075d13be34ab22875"

LOCK_PATH = "candidate/rule3-successor-continuation-evaluation-lock.json"
LOCK_SCHEMA_PATH = "candidate/rule3-successor-continuation-evaluation-lock.schema.json"
RECEIPT_SCHEMA_PATH = (
    "candidate/rule3-successor-continuation-evaluation-receipt.schema.json"
)
LOCK_SCHEMA_VERSION = "rule3-successor-continuation-evaluation-lock-1.0.0"
LOCK_STATUS = "sealed-continuation-evaluation-gate-v1"

RECEIPT_SCHEMA = "divergence-successor-continuation-evaluation-receipt-1.0.0"
RECEIPT_STATUS = "complete-offline-reviewed-threshold-evaluation"

FROZEN_THRESHOLD = {
    "required_completed_responses": 8,
    "minimum_non_null_primary_endorsements": 6,
    "minimum_distinct_primary_positions": 3,
    "maximum_primary_endorsements_per_position": 4,
}

SOURCE_PATHS = (
    "harness/divergence_successor_continuation_evaluation/__init__.py",
    "harness/divergence_successor_continuation_evaluation/contract.py",
    "harness/divergence_successor_continuation_evaluation/lock.py",
    "harness/divergence_successor_continuation_evaluation/evaluate.py",
    "harness/create_divergence_successor_continuation_evaluation_lock.py",
    "harness/evaluate_divergence_successor_continuation.py",
    LOCK_SCHEMA_PATH,
    RECEIPT_SCHEMA_PATH,
)


class EvaluationContractError(RuntimeError):
    """The sealed continuation evaluation contract changed."""


def repository_root(value: Path | str) -> Path:
    try:
        return review_contract.repository_root(value)
    except review_contract.AuthorReviewContractError as error:
        raise EvaluationContractError(str(error)) from error


__all__ = (
    "CANDIDATE_ID",
    "EVALUATION_ROOT",
    "FROZEN_THRESHOLD",
    "LOCK_PATH",
    "POOL_ID",
    "RECEIPT_SCHEMA",
    "RECEIPT_STATUS",
    "repository_root",
)

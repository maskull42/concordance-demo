"""Private paid authority for the committed continuation lock."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from concordance_recovery.journal import (
    RecoveryJournalError,
    read_record,
    require_timestamp,
    write_record,
)
from rule3.budget import JournalRecord

from . import contract, correction, lock
from .state import ContinuationPaths, inspect_inventory


AUTHORIZATION_SCHEMA = "divergence-successor-continuation-paid-authorization-1.0.0"
AUTHORIZATION_STATUS = "eight-generation-posts-authorized-after-offline-correction"


class ContinuationAuthorizationError(RuntimeError):
    """The continuation lacks exact, committed, fresh paid authority."""


def _binding(root: Path, record: JournalRecord, label: str) -> dict[str, str]:
    try:
        relative = record.path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise ContinuationAuthorizationError(
            f"{label} escapes the repository"
        ) from error
    return {"path": relative, "sha256": record.sha256}


def authorization_payload(
    context: lock.LockContext,
    *,
    authorized_at: str,
) -> dict[str, Any]:
    if not isinstance(context.git_head, str):
        raise ContinuationAuthorizationError(
            "a committed continuation lock is required"
        )
    try:
        require_timestamp(authorized_at, "continuation authorization time")
        corrected = correction.verify_correction_record(context.repository_root)
        corrected_at = corrected.payload.get("corrected_at")
        require_timestamp(corrected_at, "offline correction time")
        if datetime.fromisoformat(
            authorized_at.replace("Z", "+00:00")
        ) < datetime.fromisoformat(corrected_at.replace("Z", "+00:00")):
            raise ContinuationAuthorizationError(
                "paid authorization predates the offline correction"
            )
    except RecoveryJournalError as error:
        raise ContinuationAuthorizationError(str(error)) from error
    contract.require_approval()
    return {
        "schema_version": AUTHORIZATION_SCHEMA,
        "status": AUTHORIZATION_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "git_head": context.git_head,
        "lock": {"path": contract.LOCK_PATH, "sha256": context.lock_sha256},
        "offline_correction": _binding(
            context.repository_root, corrected, "offline correction"
        ),
        "historical_authorization": context.lock["parent"]["authorization"],
        "historical_pricing_recheck": context.lock["parent"]["pricing_recheck"],
        "approval_statement": contract.APPROVAL_STATEMENT,
        "approval_statement_sha256": contract.APPROVAL_STATEMENT_SHA256,
        "authorized_at": authorized_at,
        "authorized_by": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "scope": {
            "model_keys": list(contract.MODEL_KEYS),
            "metadata_requests": 0,
            "generation_posts": 8,
            "semantic_attempts_per_cell": 1,
            "automatic_retries": 0,
            "fallback_allowed": False,
            "candidate_cap_microdollars": contract.CANDIDATE_COST_CAP_MICRODOLLARS,
            "pool_cap_microdollars": contract.POOL_COST_CAP_MICRODOLLARS,
        },
    }


def write_authorization(
    repository_root: Path | str,
    *,
    statement: str,
    authorized_at: str,
) -> JournalRecord:
    contract.require_approval(statement)
    context = lock.load_and_validate_lock(repository_root, require_committed=True)
    paths = ContinuationPaths.for_repository(context.repository_root)
    present = set(inspect_inventory(paths))
    if present - {paths.correction, paths.authorization}:
        raise ContinuationAuthorizationError(
            "continuation authorization must precede all generation state"
        )
    if paths.authorization.exists():
        return validate_authorization(context)
    try:
        return write_record(
            paths.authorization,
            authorization_payload(context, authorized_at=authorized_at),
        )
    except RecoveryJournalError as error:
        raise ContinuationAuthorizationError(str(error)) from error


def validate_authorization(context: lock.LockContext) -> JournalRecord:
    paths = ContinuationPaths.for_repository(context.repository_root)
    try:
        record = read_record(paths.authorization, "continuation paid authorization")
        expected = authorization_payload(
            context, authorized_at=record.payload.get("authorized_at")
        )
    except RecoveryJournalError as error:
        raise ContinuationAuthorizationError(str(error)) from error
    if record.payload != expected:
        raise ContinuationAuthorizationError("continuation authorization changed")
    return record


def validate_fresh_historical_pricing(
    context: lock.LockContext,
) -> tuple[Any, Any]:
    """Recheck the sealed price receipt's 24-hour clock without rewriting it."""

    try:
        prepared, authority = correction.load_historical_parent(
            context.repository_root, fresh_pricing=True
        )
    except correction.OfflineCorrectionError as error:
        raise ContinuationAuthorizationError(str(error)) from error
    if (
        context.lock["parent"]["authorization"]["sha256"]
        != authority.authorization.sha256
        or context.lock["parent"]["pricing_recheck"]["sha256"]
        != authority.pricing.sha256
        or context.lock["parent"]["historical_git_head"]
        != prepared.lock_context.git_head
    ):
        raise ContinuationAuthorizationError(
            "historical authority differs from the continuation lock"
        )
    return prepared, authority


__all__ = (
    "AUTHORIZATION_SCHEMA",
    "AUTHORIZATION_STATUS",
    "ContinuationAuthorizationError",
    "authorization_payload",
    "validate_authorization",
    "validate_fresh_historical_pricing",
    "write_authorization",
)

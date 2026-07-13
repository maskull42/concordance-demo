"""Exact authority and fresh pricing receipts for successor recovery calls."""

from __future__ import annotations

import re
import stat
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from concordance_harness.config import load_harness_config
from concordance_harness.util import sha256_bytes, utc_now

from . import contract
from .journal import (
    RecoveryJournalError,
    initialize_private_root,
    read_record,
    require_git_head,
    require_sha256,
    require_timestamp,
    write_record,
)


AUTHORIZATION_SCHEMA = "concordance-recovery-paid-authorization-1.0.0"
PRICING_EVIDENCE_SCHEMA = "concordance-recovery-pricing-evidence-1.0.0"
PRICING_RECHECK_SCHEMA = "concordance-recovery-pricing-recheck-1.0.0"
PRICING_FRESHNESS = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
SAFE_REVIEWER_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")


class RecoveryAuthorizationError(RuntimeError):
    """Raised before environment access when recovery authority is incomplete."""


@dataclass(frozen=True)
class ReceiptBinding:
    path: Path
    payload: dict[str, Any]
    sha256: str


def _context_values(lock_context: Any) -> tuple[Path, dict[str, Any], str, str]:
    try:
        root = Path(lock_context.repository_root).resolve()
        lock = lock_context.lock
        lock_sha = str(lock_context.lock_sha256)
        git_head = lock_context.git_head
    except (AttributeError, TypeError, ValueError) as error:
        raise RecoveryAuthorizationError(
            "recovery lock context lacks committed authority facts"
        ) from error
    if not isinstance(lock, dict):
        raise RecoveryAuthorizationError("recovery lock context is malformed")
    try:
        require_sha256(lock_sha, "recovery lock hash")
        require_git_head(git_head)
    except RecoveryJournalError as error:
        raise RecoveryAuthorizationError(str(error)) from error
    return root, lock, lock_sha, git_head


def private_root(repository_root: Path) -> Path:
    root = repository_root.resolve()
    relative = Path(contract.PRIVATE_ROOT_RELATIVE)
    target = root / relative
    current = root
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RecoveryAuthorizationError(
                f"recovery private root cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RecoveryAuthorizationError(
                f"recovery private root component must be a real directory: {current}"
            )
    return target


def authorization_path(repository_root: Path) -> Path:
    return private_root(repository_root) / "paid-authorization.json"


def pricing_evidence_path(repository_root: Path) -> Path:
    return private_root(repository_root) / "pricing-evidence.json"


def pricing_recheck_path(repository_root: Path) -> Path:
    return private_root(repository_root) / "pricing-recheck.json"


def _timestamp(value: Any, label: str) -> datetime:
    try:
        require_timestamp(value, label)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (RecoveryJournalError, ValueError, AttributeError) as error:
        raise RecoveryAuthorizationError(str(error)) from error
    return parsed.astimezone(timezone.utc)


def _current(value: datetime | None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise RecoveryAuthorizationError("validation time must include a timezone")
    return result.astimezone(timezone.utc)


def authorization_payload(
    lock_context: Any, *, authorized_at: str | None = None
) -> dict[str, Any]:
    root, lock, lock_sha, git_head = _context_values(lock_context)
    del root
    timestamp = authorized_at or utc_now()
    _timestamp(timestamp, "recovery authorization time")
    paid = lock.get("paid_authorization")
    if not isinstance(paid, dict):
        raise RecoveryAuthorizationError("recovery lock lacks paid authority terms")
    statement = paid.get("exact_statement")
    scope = paid.get("scope")
    if (
        statement != contract.PAID_AUTHORIZATION_STATEMENT
        or paid.get("exact_statement_sha256")
        != contract.PAID_AUTHORIZATION_STATEMENT_SHA256
        or scope != contract.authorization_scope()
    ):
        raise RecoveryAuthorizationError("recovery lock paid authority terms changed")
    authorization_id = (
        "concordance-recovery-paid-"
        + sha256_bytes(
            (
                f"{git_head}:{lock_sha}:{contract.PAID_AUTHORIZATION_STATEMENT_SHA256}:"
                f"{timestamp}"
            ).encode("utf-8")
        )[:24]
    )
    return {
        "schema_version": AUTHORIZATION_SCHEMA,
        "authorization_id": authorization_id,
        "status": "successor-recovery-paid-calls-authorized",
        "recovery_id": contract.RECOVERY_ID,
        "git_head": git_head,
        "lock": {"path": contract.LOCK_PATH, "sha256": lock_sha},
        "parent_lock_sha256": contract.PARENT_LOCK_SHA256,
        "parent_authorization_sha256": contract.PARENT_AUTHORIZATION_SHA256,
        "authorized_at": timestamp,
        "authorized_by": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "authorization_statement": statement,
        "authorization_statement_sha256": contract.PAID_AUTHORIZATION_STATEMENT_SHA256,
        "scope": scope,
    }


def write_paid_authorization(
    lock_context: Any,
    *,
    statement: str,
    authorized_at: str | None = None,
) -> ReceiptBinding:
    if statement != contract.PAID_AUTHORIZATION_STATEMENT:
        raise RecoveryAuthorizationError(
            "paid recovery requires the exact disclosed authorization statement"
        )
    root, _, _, _ = _context_values(lock_context)
    target_root = private_root(root)
    try:
        initialize_private_root(target_root)
        payload = authorization_payload(lock_context, authorized_at=authorized_at)
        record = write_record(authorization_path(root), payload)
    except RecoveryJournalError as error:
        raise RecoveryAuthorizationError(str(error)) from error
    return ReceiptBinding(record.path, record.payload, record.sha256)


def validate_paid_authorization(lock_context: Any) -> ReceiptBinding:
    root, _, _, _ = _context_values(lock_context)
    try:
        record = read_record(
            authorization_path(root), "successor recovery paid authorization"
        )
    except RecoveryJournalError as error:
        raise RecoveryAuthorizationError(str(error)) from error
    authorized_at = record.payload.get("authorized_at")
    expected = authorization_payload(lock_context, authorized_at=authorized_at)
    if record.payload != expected:
        raise RecoveryAuthorizationError(
            "paid recovery authorization is stale or bound to another lock or HEAD"
        )
    return ReceiptBinding(record.path, record.payload, record.sha256)


def _official_url(model_key: str, value: Any) -> str:
    if not isinstance(value, str):
        raise RecoveryAuthorizationError("pricing evidence requires an official URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise RecoveryAuthorizationError("pricing evidence URL is malformed") from error
    host = (parsed.hostname or "").lower().rstrip(".")
    allowed = contract.OFFICIAL_PRICING_HOSTS.get(model_key, ())
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or host not in allowed
    ):
        raise RecoveryAuthorizationError(
            f"pricing evidence host is not approved for {model_key}"
        )
    return value


def _target_models(repository_root: Path) -> tuple[Any, ...]:
    config = load_harness_config(repository_root / "harness/config/models.json")
    by_key = config.by_key()
    try:
        return tuple(by_key[key] for key in contract.TARGET_MODEL_KEYS)
    except KeyError as error:
        raise RecoveryAuthorizationError(
            "model configuration lacks a recovery target"
        ) from error


def normalize_pricing_evidence(
    repository_root: Path, evidence: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    records = list(evidence)
    models = _target_models(repository_root)
    if len(records) != len(models):
        raise RecoveryAuthorizationError(
            "pricing evidence must cover all six recovery targets"
        )
    normalized: list[dict[str, Any]] = []
    required = {
        "model_key",
        "requested_model_id",
        "input_per_million",
        "output_per_million",
        "official_source_url",
    }
    for model, record in zip(models, records, strict=True):
        if not isinstance(record, Mapping) or set(record) != required:
            raise RecoveryAuthorizationError("pricing evidence fields differ")
        expected = {
            "model_key": model.model_key,
            "requested_model_id": model.requested_model_id,
            "input_per_million": model.planning_pricing["input_per_million"],
            "output_per_million": model.planning_pricing["output_per_million"],
        }
        if any(
            type(record.get(key)) is not type(value) or record.get(key) != value
            for key, value in expected.items()
        ):
            raise RecoveryAuthorizationError(
                f"official pricing differs for {model.model_key}"
            )
        normalized.append(
            {
                **expected,
                "official_source_url": _official_url(
                    model.model_key, record.get("official_source_url")
                ),
            }
        )
    return normalized


def pricing_evidence_payload(
    lock_context: Any,
    official_evidence: Iterable[Mapping[str, Any]],
    *,
    checked_at: str,
    reviewed_by: str,
) -> dict[str, Any]:
    root, _, lock_sha, git_head = _context_values(lock_context)
    _timestamp(checked_at, "pricing evidence check time")
    if not isinstance(reviewed_by, str) or not SAFE_REVIEWER_RE.fullmatch(reviewed_by):
        raise RecoveryAuthorizationError("pricing evidence requires a named reviewer")
    return {
        "schema_version": PRICING_EVIDENCE_SCHEMA,
        "status": "official-recovery-prices-observed",
        "recovery_id": contract.RECOVERY_ID,
        "git_head": git_head,
        "lock_sha256": lock_sha,
        "checked_at": checked_at,
        "reviewed_by": reviewed_by,
        "official_evidence": normalize_pricing_evidence(root, official_evidence),
    }


def write_pricing_evidence(
    lock_context: Any,
    official_evidence: Iterable[Mapping[str, Any]],
    *,
    checked_at: str | None = None,
    reviewed_by: str,
) -> ReceiptBinding:
    root, _, _, _ = _context_values(lock_context)
    timestamp = checked_at or utc_now()
    payload = pricing_evidence_payload(
        lock_context,
        official_evidence,
        checked_at=timestamp,
        reviewed_by=reviewed_by,
    )
    try:
        record = write_record(pricing_evidence_path(root), payload)
    except RecoveryJournalError as error:
        raise RecoveryAuthorizationError(str(error)) from error
    return ReceiptBinding(record.path, record.payload, record.sha256)


def validate_pricing_evidence(lock_context: Any) -> ReceiptBinding:
    root, _, _, _ = _context_values(lock_context)
    try:
        record = read_record(pricing_evidence_path(root), "recovery pricing evidence")
    except RecoveryJournalError as error:
        raise RecoveryAuthorizationError(str(error)) from error
    raw = record.payload
    try:
        expected = pricing_evidence_payload(
            lock_context,
            raw.get("official_evidence", ()),
            checked_at=raw.get("checked_at"),
            reviewed_by=raw.get("reviewed_by"),
        )
    except RecoveryAuthorizationError:
        raise
    if raw != expected:
        raise RecoveryAuthorizationError("recovery pricing evidence changed")
    return ReceiptBinding(record.path, record.payload, record.sha256)


def pricing_recheck_payload(
    lock_context: Any,
    evidence: ReceiptBinding,
) -> dict[str, Any]:
    root, _, lock_sha, git_head = _context_values(lock_context)
    config_path = root / "harness/config/models.json"
    config_sha = sha256_bytes(config_path.read_bytes())
    return {
        "schema_version": PRICING_RECHECK_SCHEMA,
        "status": "official-recovery-pricing-rechecked",
        "recovery_id": contract.RECOVERY_ID,
        "git_head": git_head,
        "lock_sha256": lock_sha,
        "models_config": {
            "path": "harness/config/models.json",
            "sha256": config_sha,
        },
        "checked_at": evidence.payload["checked_at"],
        "reviewed_by": evidence.payload["reviewed_by"],
        "review_attestation": (
            "The six listed official prices were checked against the named provider "
            "sources for this exact recovery target set; no price is inferred."
        ),
        "target_model_keys": list(contract.TARGET_MODEL_KEYS),
        "caps": {
            "new_reserved_cap_microdollars": contract.NEW_RESERVED_CAP_MICRODOLLARS,
            "combined_reserved_cap_microdollars": (
                contract.COMBINED_RESERVED_CAP_MICRODOLLARS
            ),
        },
        "official_evidence": {
            "path": str(evidence.path.relative_to(private_root(root))),
            "sha256": evidence.sha256,
        },
    }


def write_pricing_recheck(lock_context: Any) -> ReceiptBinding:
    root, _, _, _ = _context_values(lock_context)
    evidence = validate_pricing_evidence(lock_context)
    checked = _timestamp(evidence.payload["checked_at"], "pricing check time")
    current = _current(None)
    if checked > current + MAX_CLOCK_SKEW:
        raise RecoveryAuthorizationError("pricing check is implausibly in the future")
    if current - checked > PRICING_FRESHNESS:
        raise RecoveryAuthorizationError("pricing check is stale")
    payload = pricing_recheck_payload(lock_context, evidence)
    try:
        record = write_record(pricing_recheck_path(root), payload)
    except RecoveryJournalError as error:
        raise RecoveryAuthorizationError(str(error)) from error
    return ReceiptBinding(record.path, record.payload, record.sha256)


def validate_pricing_recheck(
    lock_context: Any,
    *,
    now: datetime | None = None,
    require_fresh: bool = True,
) -> ReceiptBinding:
    root, _, _, _ = _context_values(lock_context)
    evidence = validate_pricing_evidence(lock_context)
    try:
        record = read_record(pricing_recheck_path(root), "recovery pricing recheck")
    except RecoveryJournalError as error:
        raise RecoveryAuthorizationError(str(error)) from error
    expected = pricing_recheck_payload(lock_context, evidence)
    if record.payload != expected:
        raise RecoveryAuthorizationError(
            "recovery pricing receipt is stale or bound to another lock or HEAD"
        )
    if require_fresh:
        checked = _timestamp(record.payload.get("checked_at"), "pricing check time")
        current = _current(now)
        if checked > current + MAX_CLOCK_SKEW:
            raise RecoveryAuthorizationError("pricing receipt time is in the future")
        if current - checked > PRICING_FRESHNESS:
            raise RecoveryAuthorizationError("pricing receipt is older than 24 hours")
    return ReceiptBinding(record.path, record.payload, record.sha256)

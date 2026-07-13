"""Paid authority and fresh official pricing for the Qwen successor."""

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
from concordance_recovery.journal import (
    RecoveryJournalError,
    initialize_private_root,
    read_record,
    require_git_head,
    require_sha256,
    require_timestamp,
    write_record,
)

from . import contract


AUTHORIZATION_SCHEMA = "concordance-qwen-successor-paid-authorization-1.0.0"
PRICING_EVIDENCE_SCHEMA = "concordance-qwen-successor-pricing-evidence-1.0.0"
PRICING_RECHECK_SCHEMA = "concordance-qwen-successor-pricing-recheck-1.0.0"
PRICING_FRESHNESS = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
SAFE_REVIEWER = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")


class AuthorizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReceiptBinding:
    path: Path
    payload: dict[str, Any]
    sha256: str


def private_root(repository_root: Path) -> Path:
    root = repository_root.resolve()
    target = root / contract.PRIVATE_ROOT_RELATIVE
    cursor = root
    for part in Path(contract.PRIVATE_ROOT_RELATIVE).parts:
        cursor /= part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AuthorizationError("successor private-root component is unsafe")
    return target


def authorization_path(root: Path) -> Path:
    return private_root(root) / "paid-authorization.json"


def pricing_evidence_path(root: Path) -> Path:
    return private_root(root) / "pricing-evidence.json"


def pricing_recheck_path(root: Path) -> Path:
    return private_root(root) / "pricing-recheck.json"


def _context(context: Any) -> tuple[Path, dict[str, Any], str, str]:
    try:
        root = Path(context.repository_root).resolve()
        lock = context.lock
        lock_sha = require_sha256(context.lock_sha256, "successor lock hash")
        head = require_git_head(context.git_head, "successor Git HEAD")
    except (AttributeError, TypeError, ValueError, RecoveryJournalError) as error:
        raise AuthorizationError(
            "successor lock lacks committed authority facts"
        ) from error
    if not isinstance(lock, dict):
        raise AuthorizationError("successor lock context is malformed")
    return root, lock, lock_sha, head


def _time(value: Any, label: str) -> datetime:
    try:
        require_timestamp(value, label)
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except (RecoveryJournalError, ValueError, AttributeError) as error:
        raise AuthorizationError(str(error)) from error


def authorization_payload(context: Any, *, authorized_at: str) -> dict[str, Any]:
    _, lock, lock_sha, head = _context(context)
    _time(authorized_at, "Qwen successor authorization time")
    paid = lock.get("paid_authorization")
    expected = {
        "required": True,
        "lock_authorizes_spending": False,
        "prior_receipt_sha256": contract.FIRST_AUTHORIZATION_SHA256,
        "prior_exact_statement": contract.PRIOR_AUTHORIZATION_STATEMENT,
        "prior_exact_statement_sha256": contract.PRIOR_AUTHORIZATION_STATEMENT_SHA256,
        "user_amendment_verbatim": contract.USER_AMENDMENT,
        "user_amendment_sha256": contract.USER_AMENDMENT_SHA256,
        "resolved_exact_statement": contract.AUTHORIZATION_STATEMENT,
        "resolved_exact_statement_sha256": contract.AUTHORIZATION_STATEMENT_SHA256,
        "scope": contract.authorization_scope(),
        "fresh_official_pricing_recheck_required": True,
    }
    if paid != expected:
        raise AuthorizationError("successor paid authority terms changed")
    authorization_id = (
        "qwen-successor-paid-"
        + sha256_bytes(
            f"{head}:{lock_sha}:{contract.AUTHORIZATION_STATEMENT_SHA256}:{authorized_at}".encode()
        )[:24]
    )
    return {
        "schema_version": AUTHORIZATION_SCHEMA,
        "authorization_id": authorization_id,
        "status": "qwen-successor-paid-calls-authorized",
        "recovery_id": contract.RECOVERY_ID,
        "git_head": head,
        "lock": {"path": contract.LOCK_PATH, "sha256": lock_sha},
        "first_recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
        "prior_authorization_receipt_sha256": contract.FIRST_AUTHORIZATION_SHA256,
        "prior_authorization_statement": contract.PRIOR_AUTHORIZATION_STATEMENT,
        "prior_authorization_statement_sha256": contract.PRIOR_AUTHORIZATION_STATEMENT_SHA256,
        "user_amendment_verbatim": contract.USER_AMENDMENT,
        "user_amendment_sha256": contract.USER_AMENDMENT_SHA256,
        "authorization_statement": contract.AUTHORIZATION_STATEMENT,
        "authorization_statement_sha256": contract.AUTHORIZATION_STATEMENT_SHA256,
        "authorized_at": authorized_at,
        "authorized_by": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "scope": contract.authorization_scope(),
    }


def write_authorization(
    context: Any, *, statement: str, amendment: str, authorized_at: str | None = None
) -> ReceiptBinding:
    if statement != contract.AUTHORIZATION_STATEMENT:
        raise AuthorizationError("exact resolved successor statement is required")
    if amendment != contract.USER_AMENDMENT:
        raise AuthorizationError("verbatim user amendment is required")
    root, _, _, _ = _context(context)
    initialize_private_root(private_root(root))
    record = write_record(
        authorization_path(root),
        authorization_payload(context, authorized_at=authorized_at or utc_now()),
    )
    return ReceiptBinding(record.path, record.payload, record.sha256)


def validate_authorization(context: Any) -> ReceiptBinding:
    root, _, _, _ = _context(context)
    try:
        record = read_record(authorization_path(root), "Qwen successor authorization")
        expected = authorization_payload(
            context, authorized_at=record.payload.get("authorized_at")
        )
    except RecoveryJournalError as error:
        raise AuthorizationError(str(error)) from error
    if record.payload != expected:
        raise AuthorizationError("successor authorization is stale or changed")
    return ReceiptBinding(record.path, record.payload, record.sha256)


def _pricing_targets(root: Path) -> tuple[dict[str, Any], ...]:
    by_key = load_harness_config(root / "harness/config/models.json").by_key()
    try:
        targets = []
        for route_key in contract.PREFLIGHT_ROUTE_KEYS:
            if route_key == "qwen-openrouter":
                targets.append(
                    {
                        "route_key": route_key,
                        "requested_model_id": contract.QWEN_OPENROUTER[
                            "requested_model_id"
                        ],
                        "headline_input_per_million": contract.QWEN_OPENROUTER[
                            "headline_pricing"
                        ]["input_per_million"],
                        "headline_output_per_million": contract.QWEN_OPENROUTER[
                            "headline_pricing"
                        ]["output_per_million"],
                        "reservation_input_per_million": contract.QWEN_OPENROUTER[
                            "reservation_pricing"
                        ]["input_per_million"],
                        "reservation_output_per_million": contract.QWEN_OPENROUTER[
                            "reservation_pricing"
                        ]["output_per_million"],
                    }
                )
                continue
            model = by_key[route_key]
            targets.append(
                {
                    "route_key": route_key,
                    "requested_model_id": model.requested_model_id,
                    "headline_input_per_million": model.planning_pricing[
                        "input_per_million"
                    ],
                    "headline_output_per_million": model.planning_pricing[
                        "output_per_million"
                    ],
                    "reservation_input_per_million": model.planning_pricing[
                        "input_per_million"
                    ],
                    "reservation_output_per_million": model.planning_pricing[
                        "output_per_million"
                    ],
                }
            )
        return tuple(targets)
    except KeyError as error:
        raise AuthorizationError(
            "model configuration lacks a successor target"
        ) from error


def _official_url(model_key: str, value: Any) -> str:
    if not isinstance(value, str):
        raise AuthorizationError("pricing source must be an HTTPS URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise AuthorizationError("pricing source URL is malformed") from error
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or host not in contract.OFFICIAL_PRICING_HOSTS.get(model_key, ())
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        raise AuthorizationError(f"pricing source host is not approved for {model_key}")
    return value


def normalize_pricing(
    repository_root: Path, evidence: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    records = list(evidence)
    targets = _pricing_targets(repository_root)
    if len(records) != len(targets):
        raise AuthorizationError("pricing evidence must cover all six routes")
    required = {
        "route_key",
        "requested_model_id",
        "headline_input_per_million",
        "headline_output_per_million",
        "reservation_input_per_million",
        "reservation_output_per_million",
        "official_source_url",
    }
    result = []
    for target, record in zip(targets, records, strict=True):
        if not isinstance(record, Mapping) or set(record) != required:
            raise AuthorizationError("pricing evidence fields differ")
        expected = target
        if any(record.get(key) != value for key, value in target.items()):
            raise AuthorizationError(f"pricing differs for {target['route_key']}")
        result.append(
            {
                **expected,
                "official_source_url": _official_url(
                    target["route_key"], record.get("official_source_url")
                ),
            }
        )
    return result


def pricing_evidence_payload(
    context: Any,
    evidence: Iterable[Mapping[str, Any]],
    *,
    checked_at: str,
    reviewed_by: str,
) -> dict[str, Any]:
    root, _, lock_sha, head = _context(context)
    _time(checked_at, "pricing evidence time")
    if not isinstance(reviewed_by, str) or not SAFE_REVIEWER.fullmatch(reviewed_by):
        raise AuthorizationError("pricing reviewer label is unsafe")
    return {
        "schema_version": PRICING_EVIDENCE_SCHEMA,
        "status": "six-route-official-pricing-reviewed",
        "recovery_id": contract.RECOVERY_ID,
        "git_head": head,
        "lock_sha256": lock_sha,
        "checked_at": checked_at,
        "reviewed_by": reviewed_by,
        "official_evidence": normalize_pricing(root, evidence),
    }


def write_pricing_evidence(
    context: Any,
    evidence: Iterable[Mapping[str, Any]],
    *,
    checked_at: str,
    reviewed_by: str,
) -> ReceiptBinding:
    root, _, _, _ = _context(context)
    initialize_private_root(private_root(root))
    record = write_record(
        pricing_evidence_path(root),
        pricing_evidence_payload(
            context, evidence, checked_at=checked_at, reviewed_by=reviewed_by
        ),
    )
    return ReceiptBinding(record.path, record.payload, record.sha256)


def validate_pricing_evidence(context: Any) -> ReceiptBinding:
    root, _, _, _ = _context(context)
    try:
        record = read_record(pricing_evidence_path(root), "successor pricing evidence")
    except RecoveryJournalError as error:
        raise AuthorizationError(str(error)) from error
    payload = record.payload
    expected = pricing_evidence_payload(
        context,
        payload.get("official_evidence", ()),
        checked_at=payload.get("checked_at"),
        reviewed_by=payload.get("reviewed_by"),
    )
    if payload != expected:
        raise AuthorizationError("successor pricing evidence changed")
    return ReceiptBinding(record.path, record.payload, record.sha256)


def pricing_recheck_payload(
    context: Any, evidence: ReceiptBinding, *, rechecked_at: str
) -> dict[str, Any]:
    _, _, lock_sha, head = _context(context)
    _time(rechecked_at, "pricing recheck time")
    return {
        "schema_version": PRICING_RECHECK_SCHEMA,
        "status": "six-route-pricing-sealed-for-successor",
        "recovery_id": contract.RECOVERY_ID,
        "git_head": head,
        "lock_sha256": lock_sha,
        "pricing_evidence": {
            "path": "pricing-evidence.json",
            "sha256": evidence.sha256,
        },
        "official_evidence": evidence.payload["official_evidence"],
        "rechecked_at": rechecked_at,
    }


def write_pricing_recheck(
    context: Any, *, rechecked_at: str | None = None
) -> ReceiptBinding:
    root, _, _, _ = _context(context)
    evidence = validate_pricing_evidence(context)
    record = write_record(
        pricing_recheck_path(root),
        pricing_recheck_payload(
            context, evidence, rechecked_at=rechecked_at or utc_now()
        ),
    )
    return ReceiptBinding(record.path, record.payload, record.sha256)


def validate_pricing_recheck(
    context: Any, *, require_fresh: bool = False, now: datetime | None = None
) -> ReceiptBinding:
    root, _, _, _ = _context(context)
    evidence = validate_pricing_evidence(context)
    try:
        record = read_record(pricing_recheck_path(root), "successor pricing recheck")
    except RecoveryJournalError as error:
        raise AuthorizationError(str(error)) from error
    expected = pricing_recheck_payload(
        context, evidence, rechecked_at=record.payload.get("rechecked_at")
    )
    if record.payload != expected:
        raise AuthorizationError("successor pricing recheck changed")
    if require_fresh:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        checked = _time(record.payload["rechecked_at"], "pricing recheck time")
        if checked > current + MAX_CLOCK_SKEW or current - checked > PRICING_FRESHNESS:
            raise AuthorizationError("successor pricing recheck is not fresh")
    return ReceiptBinding(record.path, record.payload, record.sha256)


__all__ = (
    "AuthorizationError",
    "ReceiptBinding",
    "private_root",
    "validate_authorization",
    "validate_pricing_evidence",
    "validate_pricing_recheck",
    "write_authorization",
    "write_pricing_evidence",
    "write_pricing_recheck",
)

"""Exact private authority and pricing receipts for the Rule 3 lane.

The trusted operator is the same operating-system user that owns the 0600
artifacts. These receipts expose accidental or out-of-contract mutation; they
are not signatures and cannot defeat a malicious same-UID process. That would
require an external signer or write-once storage outside this process boundary.
"""

from __future__ import annotations

import json
import re
import stat
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from concordance_harness.config import load_harness_config
from concordance_harness.util import sha256_bytes, sha256_file, utc_now

from .budget import (
    ATTEMPTS_PER_CELL,
    CANDIDATE_CAP_MICRODOLLARS,
    CANDIDATE_ORDER,
    POOL_CAP_MICRODOLLARS,
    POOL_ID,
    BudgetError,
    ensure_private_root,
    read_private_json,
    write_once_private_json,
)

RULE_VERSION = "pilot-rule-3"
LOCK_RELATIVE_PATH = Path("candidate/rule3-lock.json")
PRIVATE_RELATIVE_ROOT = Path(".pilot/rule3/concordance-divergence-supplement-1")
AUTHORIZATION_FILENAME = "paid-authorization.json"
PRICING_RECHECK_FILENAME = "pricing-recheck.json"

AUTHORIZATION_SCHEMA_VERSION = "rule3-paid-authorization-1.0.0"
PRICING_SCHEMA_VERSION = "rule3-pricing-recheck-1.0.0"
PRICING_EVIDENCE_SCHEMA_VERSION = "rule3-pricing-evidence-1.0.0"
PRICING_FRESHNESS = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
GIT_HASH_PATTERN = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")

PAID_AUTHORIZATION_STATEMENT = (
    "A.G. Elrod authorizes this exact committed Rule 3 lock for one private paid "
    "run: the priority candidate first; the fallback only after a complete, "
    "author-reviewed threshold failure; no more than three attempts per cell; "
    "no more than $6.00 reserved per candidate and $12.00 reserved in total."
)
PAID_AUTHORIZATION_STATEMENT_SHA256 = sha256_bytes(
    PAID_AUTHORIZATION_STATEMENT.encode("utf-8")
)
PRICING_ATTESTATION = (
    "The listed official prices were checked against the named provider sources "
    "for this exact locked model panel; no price or availability is inferred."
)
OFFICIAL_PRICING_HOSTS = {
    "gemini": ("ai.google.dev",),
    "claude": ("platform.claude.com", "docs.anthropic.com"),
    "cohere": ("docs.cohere.com",),
    "qwen": ("deepinfra.com",),
    "deepseek": ("api-docs.deepseek.com",),
    "mistral": ("docs.mistral.ai",),
    "grok": ("docs.x.ai",),
    "gpt": ("openrouter.ai",),
}

AUTHORIZATION_KEYS = {
    "schema_version",
    "authorization_id",
    "status",
    "pool_id",
    "rule_version",
    "git_head",
    "lock",
    "authorized_at",
    "authorized_by",
    "authorization_statement",
    "authorization_statement_sha256",
    "scope",
}
PRICING_KEYS = {
    "schema_version",
    "status",
    "pool_id",
    "rule_version",
    "git_head",
    "lock_sha256",
    "models_config",
    "checked_at",
    "reviewed_by",
    "review_attestation",
    "candidate_order",
    "caps",
    "official_evidence",
}


class AuthorizationError(RuntimeError):
    """Raised before environment access when Rule 3 authority is absent."""


@dataclass(frozen=True)
class ContractBinding:
    repository_root: Path
    lock_sha256: str
    git_head: str | None
    candidate_order: tuple[str, str]
    models_config_path: Path
    models_config_sha256: str
    candidate_cap_microdollars: int
    pool_cap_microdollars: int
    attempts_per_cell: int


@dataclass(frozen=True)
class ReceiptBinding:
    path: Path
    payload: dict[str, Any]
    sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorizationError(f"duplicate pricing evidence field: {key}")
        result[key] = value
    return result


def load_pricing_evidence_file(path: Path) -> dict[str, Any]:
    """Read the exact local, offline input used to mint or verify a receipt."""
    if path.is_symlink() or not path.is_file():
        raise AuthorizationError(
            "pricing evidence must be a regular, non-symlink local JSON file"
        )
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise AuthorizationError(f"pricing evidence cannot be read: {error}") from error
    if len(payload) > 1_000_000:
        raise AuthorizationError("pricing evidence exceeds the one-megabyte limit")
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise AuthorizationError(
            f"pricing evidence is malformed JSON: {error}"
        ) from error
    expected_keys = {
        "schema_version",
        "checked_at",
        "reviewed_by",
        "official_evidence",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise AuthorizationError("pricing evidence fields differ from the contract")
    if value.get("schema_version") != PRICING_EVIDENCE_SCHEMA_VERSION:
        raise AuthorizationError("pricing evidence schema version differs")
    _timestamp(value.get("checked_at"), "pricing evidence check time")
    if (
        not isinstance(value.get("reviewed_by"), str)
        or not value["reviewed_by"].strip()
    ):
        raise AuthorizationError("pricing evidence requires a named reviewer")
    evidence = value.get("official_evidence")
    if (
        not isinstance(evidence, list)
        or len(evidence) != 8
        or not all(isinstance(item, dict) for item in evidence)
    ):
        raise AuthorizationError(
            "pricing evidence must contain all eight exact model records"
        )
    return value


def private_root(repository_root: Path) -> Path:
    repository = repository_root.resolve()
    target = repository / PRIVATE_RELATIVE_ROOT
    current = repository
    for part in PRIVATE_RELATIVE_ROOT.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AuthorizationError(
                f"private Rule 3 root cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise AuthorizationError(
                f"private Rule 3 root component may not be a symlink: {current}"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise AuthorizationError(
                f"private Rule 3 root component must be a directory: {current}"
            )
    return target


def authorization_path(repository_root: Path) -> Path:
    return private_root(repository_root) / AUTHORIZATION_FILENAME


def pricing_recheck_path(repository_root: Path) -> Path:
    return private_root(repository_root) / PRICING_RECHECK_FILENAME


def load_committed_lock(repository_root: Path) -> Any:
    """Import the lock validator only when an authorization operation needs it."""
    try:
        from rule3.lock import Rule3LockError, load_and_validate_rule3_lock
    except (ImportError, AttributeError) as error:
        raise AuthorizationError(
            "Rule 3 lock adapter unavailable; expected "
            "rule3.lock.load_and_validate_rule3_lock(repository_root, "
            "lock_path=None, require_committed=True)"
        ) from error
    try:
        return load_and_validate_rule3_lock(
            repository_root.resolve(), require_committed=True
        )
    except Rule3LockError as error:
        raise AuthorizationError(str(error)) from error


def _candidate_id(candidate: Any) -> str | None:
    if isinstance(candidate, dict):
        value = candidate.get("id") or candidate.get("question_id")
    else:
        value = getattr(candidate, "question_id", None) or getattr(
            candidate, "id", None
        )
    return value if isinstance(value, str) else None


def contract_binding(
    lock_context: Any, *, require_git_head: bool = True
) -> ContractBinding:
    try:
        root = Path(lock_context.repository_root).resolve()
        lock_sha256 = str(lock_context.lock_sha256)
        git_head_value = lock_context.git_head
        git_head = git_head_value if isinstance(git_head_value, str) else None
        candidates = tuple(_candidate_id(item) for item in lock_context.candidates)
        config_path = Path(lock_context.models_config_path).resolve()
        candidate_cap = int(lock_context.candidate_cost_cap_microdollars)
        pool_cap = int(lock_context.total_cost_cap_microdollars)
        attempts = int(lock_context.attempts_per_cell)
    except (AttributeError, TypeError, ValueError) as error:
        raise AuthorizationError(
            "Rule 3 lock context lacks the execution contract"
        ) from error
    invalid_required_head = require_git_head and (
        git_head is None or not GIT_HASH_PATTERN.fullmatch(git_head)
    )
    invalid_optional_head = (
        not require_git_head
        and git_head is not None
        and not GIT_HASH_PATTERN.fullmatch(git_head)
    )
    if (
        not SHA256_PATTERN.fullmatch(lock_sha256)
        or invalid_required_head
        or invalid_optional_head
        or candidates != CANDIDATE_ORDER
        or candidate_cap != CANDIDATE_CAP_MICRODOLLARS
        or pool_cap != POOL_CAP_MICRODOLLARS
        or attempts != ATTEMPTS_PER_CELL
        or not config_path.is_file()
    ):
        raise AuthorizationError(
            "Rule 3 lock context differs from the approved contract"
        )
    try:
        config_path.relative_to(root)
    except ValueError as error:
        raise AuthorizationError(
            "locked model configuration escapes the repository"
        ) from error
    return ContractBinding(
        repository_root=root,
        lock_sha256=lock_sha256,
        git_head=git_head,
        candidate_order=(candidates[0], candidates[1]),
        models_config_path=config_path,
        models_config_sha256=sha256_file(config_path),
        candidate_cap_microdollars=candidate_cap,
        pool_cap_microdollars=pool_cap,
        attempts_per_cell=attempts,
    )


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise AuthorizationError(f"{label} is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuthorizationError(f"{label} is malformed") from error
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _now(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise AuthorizationError("validation time must include a timezone")
    return current.astimezone(timezone.utc)


def _scope(binding: ContractBinding) -> dict[str, Any]:
    return {
        "candidate_order": list(binding.candidate_order),
        "sequence": "priority-first-conditional-fallback",
        "call_type": "answer",
        "cells_per_candidate": 8,
        "attempts_per_cell": binding.attempts_per_cell,
        "candidate_reserved_cap_microdollars": (binding.candidate_cap_microdollars),
        "pool_reserved_cap_microdollars": binding.pool_cap_microdollars,
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
    }


def authorization_payload(
    lock_context: Any,
    *,
    authorized_at: str | None = None,
) -> dict[str, Any]:
    binding = contract_binding(lock_context)
    assert binding.git_head is not None
    timestamp = authorized_at or utc_now()
    _timestamp(timestamp, "authorization time")
    authorization_id = (
        "rule3-paid-"
        + sha256_bytes(
            (
                f"{binding.git_head}:{binding.lock_sha256}:"
                f"{PAID_AUTHORIZATION_STATEMENT_SHA256}:{timestamp}"
            ).encode("utf-8")
        )[:24]
    )
    return {
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        "authorization_id": authorization_id,
        "status": "paid-private-run-authorized",
        "pool_id": POOL_ID,
        "rule_version": RULE_VERSION,
        "git_head": binding.git_head,
        "lock": {
            "path": str(LOCK_RELATIVE_PATH),
            "sha256": binding.lock_sha256,
        },
        "authorized_at": timestamp,
        "authorized_by": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "authorization_statement": PAID_AUTHORIZATION_STATEMENT,
        "authorization_statement_sha256": PAID_AUTHORIZATION_STATEMENT_SHA256,
        "scope": _scope(binding),
    }


def write_paid_authorization(
    lock_context: Any,
    *,
    statement: str,
    authorized_at: str | None = None,
) -> ReceiptBinding:
    if statement != PAID_AUTHORIZATION_STATEMENT:
        raise AuthorizationError(
            "paid authorization requires the exact disclosed statement"
        )
    binding = contract_binding(lock_context)
    root = private_root(binding.repository_root)
    try:
        ensure_private_root(root)
        payload = authorization_payload(lock_context, authorized_at=authorized_at)
        path = authorization_path(binding.repository_root)
        digest = write_once_private_json(path, payload)
    except BudgetError as error:
        raise AuthorizationError(str(error)) from error
    return ReceiptBinding(path=path, payload=payload, sha256=digest)


def validate_paid_authorization(lock_context: Any) -> ReceiptBinding:
    binding = contract_binding(lock_context)
    path = authorization_path(binding.repository_root)
    try:
        record = read_private_json(path, "Rule 3 paid authorization")
    except BudgetError as error:
        raise AuthorizationError(str(error)) from error
    raw = record.payload
    if set(raw) != AUTHORIZATION_KEYS:
        raise AuthorizationError("paid authorization fields differ from the contract")
    authorized_at = raw.get("authorized_at")
    _timestamp(authorized_at, "authorization time")
    expected = authorization_payload(lock_context, authorized_at=authorized_at)
    if raw != expected:
        raise AuthorizationError(
            "paid authorization is stale or bound to another lock or Git HEAD"
        )
    return ReceiptBinding(path=path, payload=raw, sha256=record.sha256)


def _evidence_entry(model: Any, evidence: dict[str, Any]) -> dict[str, Any]:
    required = {
        "model_key",
        "requested_model_id",
        "input_per_million",
        "output_per_million",
        "official_source_url",
    }
    if set(evidence) != required:
        raise AuthorizationError("pricing evidence fields differ from the contract")
    for key in ("input_per_million", "output_per_million"):
        price = evidence.get(key)
        if not isinstance(price, (int, float)) or isinstance(price, bool) or price < 0:
            raise AuthorizationError(
                f"pricing evidence {key} must be a nonnegative JSON number"
            )
    expected = {
        "model_key": model.model_key,
        "requested_model_id": model.requested_model_id,
        "input_per_million": model.planning_pricing["input_per_million"],
        "output_per_million": model.planning_pricing["output_per_million"],
    }
    if {key: evidence.get(key) for key in expected} != expected:
        raise AuthorizationError(
            f"pricing evidence differs for canonical model {model.model_key}"
        )
    source = evidence.get("official_source_url")
    if not isinstance(source, str):
        raise AuthorizationError("pricing evidence requires an official HTTPS URL")
    try:
        parsed = urllib.parse.urlsplit(source)
        port = parsed.port
    except ValueError as error:
        raise AuthorizationError("pricing evidence URL is malformed") from error
    hostname = (parsed.hostname or "").lower().rstrip(".")
    allowed_hosts = OFFICIAL_PRICING_HOSTS.get(model.model_key, ())
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or hostname not in allowed_hosts
    ):
        raise AuthorizationError(
            f"pricing evidence host is not approved for {model.model_key}"
        )
    return {**expected, "official_source_url": source}


def pricing_recheck_payload(
    lock_context: Any,
    official_evidence: Iterable[dict[str, Any]],
    *,
    checked_at: str,
    reviewed_by: str,
) -> dict[str, Any]:
    binding = contract_binding(lock_context)
    _timestamp(checked_at, "pricing check time")
    if not isinstance(reviewed_by, str) or not reviewed_by.strip():
        raise AuthorizationError("pricing recheck requires a named reviewer")
    config = load_harness_config(binding.models_config_path)
    evidence_list = list(official_evidence)
    if len(evidence_list) != 8:
        raise AuthorizationError("pricing recheck must cover all eight exact models")
    normalized = [
        _evidence_entry(model, evidence)
        for model, evidence in zip(config.models, evidence_list, strict=True)
    ]
    return {
        "schema_version": PRICING_SCHEMA_VERSION,
        "status": "official-pricing-rechecked",
        "pool_id": POOL_ID,
        "rule_version": RULE_VERSION,
        "git_head": binding.git_head,
        "lock_sha256": binding.lock_sha256,
        "models_config": {
            "path": str(
                binding.models_config_path.relative_to(binding.repository_root)
            ),
            "sha256": binding.models_config_sha256,
        },
        "checked_at": checked_at,
        "reviewed_by": reviewed_by.strip(),
        "review_attestation": PRICING_ATTESTATION,
        "candidate_order": list(binding.candidate_order),
        "caps": {
            "attempts_per_cell": binding.attempts_per_cell,
            "candidate_reserved_cap_microdollars": (binding.candidate_cap_microdollars),
            "pool_reserved_cap_microdollars": binding.pool_cap_microdollars,
        },
        "official_evidence": normalized,
    }


def write_pricing_recheck(
    lock_context: Any,
    official_evidence: Iterable[dict[str, Any]],
    *,
    reviewed_by: str,
    checked_at: str | None = None,
) -> ReceiptBinding:
    """Write a real reviewed receipt; callers must not synthesize evidence."""
    binding = contract_binding(lock_context)
    timestamp = checked_at or utc_now()
    checked = _timestamp(timestamp, "pricing check time")
    current = _now(None)
    if checked > current + MAX_CLOCK_SKEW:
        raise AuthorizationError("pricing recheck time is implausibly in the future")
    if current - checked > PRICING_FRESHNESS:
        raise AuthorizationError(
            "pricing recheck is stale; no private receipt was written"
        )
    payload = pricing_recheck_payload(
        lock_context,
        official_evidence,
        checked_at=timestamp,
        reviewed_by=reviewed_by,
    )
    path = pricing_recheck_path(binding.repository_root)
    try:
        digest = write_once_private_json(path, payload)
    except BudgetError as error:
        raise AuthorizationError(str(error)) from error
    return ReceiptBinding(path=path, payload=payload, sha256=digest)


def validate_pricing_recheck(
    lock_context: Any,
    *,
    now: datetime | None = None,
) -> ReceiptBinding:
    binding = contract_binding(lock_context)
    path = pricing_recheck_path(binding.repository_root)
    try:
        record = read_private_json(path, "Rule 3 pricing recheck")
    except BudgetError as error:
        raise AuthorizationError(str(error)) from error
    raw = record.payload
    if set(raw) != PRICING_KEYS:
        raise AuthorizationError("pricing recheck fields differ from the contract")
    checked_at = raw.get("checked_at")
    reviewer = raw.get("reviewed_by")
    evidence = raw.get("official_evidence")
    if not isinstance(evidence, list) or not isinstance(reviewer, str):
        raise AuthorizationError("pricing recheck evidence is malformed")
    expected = pricing_recheck_payload(
        lock_context,
        evidence,
        checked_at=checked_at,
        reviewed_by=reviewer,
    )
    if raw != expected:
        raise AuthorizationError(
            "pricing recheck is bound to another lock, Git HEAD, or model contract"
        )
    checked = _timestamp(checked_at, "pricing check time")
    current = _now(now)
    if checked > current + MAX_CLOCK_SKEW:
        raise AuthorizationError("pricing recheck time is implausibly in the future")
    if current - checked > PRICING_FRESHNESS:
        raise AuthorizationError(
            "pricing recheck is stale; no environment variable or provider was accessed"
        )
    return ReceiptBinding(path=path, payload=raw, sha256=record.sha256)

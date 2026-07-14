"""Fail-closed paid-call authorization for the divergence successor.

The pre-execution lock is intentionally not spending authority.  This module
can describe the later receipt, but it refuses to create or accept one until
the public contract contains a separately committed, exact author approval.
"""

from __future__ import annotations

import math
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from concordance_harness.util import estimate_message_tokens, utc_now
from concordance_recovery.journal import (
    RecoveryJournalError,
    read_record,
    require_git_head,
    require_sha256,
    require_timestamp,
    write_record,
)

from . import contract


AUTHORIZATION_SCHEMA = "divergence-successor-paid-authorization-1.0.0"
AUTHORIZATION_STATUS = "divergence-successor-paid-calls-authorized"
PRICING_RECHECK_SCHEMA = "divergence-successor-pricing-recheck-1.0.0"
PRICING_RECHECK_STATUS = "complete-eight-route-fresh-official-pricing"
PRICING_FRESHNESS = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
APPROVAL_CONSTANTS = (
    "PAID_CALLS_AUTHORIZATION_ENABLED",
    "PAID_CALLS_AUTHORIZATION_STATEMENT",
    "PAID_CALLS_AUTHORIZATION_STATEMENT_SHA256",
)
OFFICIAL_PRICING_HOSTS = {
    "gemini": frozenset({"ai.google.dev", "cloud.google.com"}),
    "claude": frozenset({"anthropic.com", "docs.anthropic.com"}),
    "cohere": frozenset({"cohere.com", "docs.cohere.com"}),
    "qwen": frozenset({"deepinfra.com"}),
    "deepseek": frozenset({"api-docs.deepseek.com", "deepseek.com"}),
    "mistral": frozenset({"docs.mistral.ai", "mistral.ai"}),
    "grok": frozenset({"docs.x.ai", "x.ai"}),
    "gpt": frozenset({"openrouter.ai"}),
}


class DivergenceSuccessorAuthorizationError(RuntimeError):
    """Paid authority is absent, malformed, stale, or outside the lock."""


@dataclass(frozen=True)
class AuthorizationBinding:
    path: Path
    payload: dict[str, Any]
    sha256: str


def _root(repository_root: Path | str) -> Path:
    try:
        return contract.repository_root(repository_root)
    except contract.ContractError as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error


def _private_relative() -> str:
    value = getattr(contract, "PRIVATE_ROOT_RELATIVE", None)
    expected = f".pilot/divergence-successor/{contract.POOL_ID}"
    if value != expected:
        raise DivergenceSuccessorAuthorizationError(
            "the successor private root is not locked"
        )
    try:
        return contract.require_relative_path(value, "successor private root")
    except contract.ContractError as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error


def authorization_path(repository_root: Path | str) -> Path:
    return _root(repository_root) / _private_relative() / "paid-authorization.json"


def pricing_recheck_path(repository_root: Path | str) -> Path:
    return _root(repository_root) / _private_relative() / "pricing-recheck.json"


def approval_readiness() -> dict[str, Any]:
    """Return public-only readiness facts without reading credentials or disk."""

    issues: list[str] = []
    enabled = getattr(contract, "PAID_CALLS_AUTHORIZATION_ENABLED", None)
    statement = getattr(contract, "PAID_CALLS_AUTHORIZATION_STATEMENT", None)
    digest = getattr(
        contract, "PAID_CALLS_AUTHORIZATION_STATEMENT_SHA256", None
    )
    if enabled is not True:
        issues.append(
            "contract.PAID_CALLS_AUTHORIZATION_ENABLED is not the committed boolean True"
        )
    if not isinstance(statement, str) or not statement:
        issues.append(
            "contract.PAID_CALLS_AUTHORIZATION_STATEMENT lacks the exact author approval"
        )
    if not isinstance(digest, str) or len(digest) != 64:
        issues.append(
            "contract.PAID_CALLS_AUTHORIZATION_STATEMENT_SHA256 is not committed"
        )
    elif isinstance(statement, str) and contract.sha256_bytes(statement.encode()) != digest:
        issues.append("the committed paid-call authorization statement hash differs")
    if getattr(contract, "AUTHORIZATION_ENABLED", None) is not False:
        issues.append("the pre-execution lock must remain non-authorizing")
    return {
        "status": "ready-to-record-exact-author-approval" if not issues else "disabled",
        "issues": issues,
        "lock_authorizes_spending": False,
        "private_writes": 0,
        "network_requests": 0,
        "environment_variables_read": 0,
    }


def require_approval_enabled(*, statement: str | None = None) -> str:
    readiness = approval_readiness()
    if readiness["issues"]:
        raise DivergenceSuccessorAuthorizationError("; ".join(readiness["issues"]))
    expected = contract.PAID_CALLS_AUTHORIZATION_STATEMENT
    if statement is not None and statement != expected:
        raise DivergenceSuccessorAuthorizationError(
            "the exact committed author approval statement is required"
        )
    return expected


def _context(context: Any) -> tuple[Path, dict[str, Any], str, str]:
    try:
        root = _root(context.repository_root)
        lock_value = context.lock
        lock_sha = require_sha256(context.lock_sha256, "successor lock hash")
        git_head = require_git_head(context.git_head, "successor Git HEAD")
    except (AttributeError, TypeError, RecoveryJournalError) as error:
        raise DivergenceSuccessorAuthorizationError(
            "a committed, clean successor lock context is required"
        ) from error
    if not isinstance(lock_value, dict):
        raise DivergenceSuccessorAuthorizationError("successor lock is malformed")
    paid = lock_value.get("paid_authorization")
    if not isinstance(paid, dict) or paid.get("lock_authorizes_spending") is not False:
        raise DivergenceSuccessorAuthorizationError(
            "the successor lock's non-spending boundary changed"
        )
    return root, lock_value, lock_sha, git_head


def authorization_payload(context: Any, *, authorized_at: str) -> dict[str, Any]:
    statement = require_approval_enabled()
    try:
        require_timestamp(authorized_at, "successor authorization time")
    except RecoveryJournalError as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error
    _, _, lock_sha, git_head = _context(context)
    return {
        "schema_version": AUTHORIZATION_SCHEMA,
        "status": AUTHORIZATION_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "git_head": git_head,
        "lock": {"path": contract.LOCK_PATH, "sha256": lock_sha},
        "authorization_statement": statement,
        "authorization_statement_sha256": (
            contract.PAID_CALLS_AUTHORIZATION_STATEMENT_SHA256
        ),
        "authorized_at": authorized_at,
        "authorized_by": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "scope": {
            "candidate_ids": [contract.CANDIDATE_ID],
            "model_keys": list(contract.MODEL_KEYS),
            "preflight_requests": 8,
            "generation_posts": 8,
            "attempts_per_cell": 1,
            "automatic_retries": 0,
            "candidate_cap_microdollars": 6_000_000,
            "pool_cap_microdollars": 6_000_000,
        },
    }


def write_authorization(
    context: Any, *, statement: str, authorized_at: str
) -> AuthorizationBinding:
    """Write once, but only after later approval is committed in public code."""

    require_approval_enabled(statement=statement)
    root, _, _, _ = _context(context)
    try:
        record = write_record(
            authorization_path(root),
            authorization_payload(context, authorized_at=authorized_at),
        )
    except RecoveryJournalError as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error
    return AuthorizationBinding(record.path, record.payload, record.sha256)


def validate_authorization(context: Any) -> AuthorizationBinding:
    require_approval_enabled()
    root, _, _, _ = _context(context)
    try:
        record = read_record(
            authorization_path(root), "divergence successor paid authorization"
        )
        expected = authorization_payload(
            context, authorized_at=record.payload.get("authorized_at")
        )
    except RecoveryJournalError as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error
    if record.payload != expected:
        raise DivergenceSuccessorAuthorizationError(
            "the successor authorization is stale or changed"
        )
    return AuthorizationBinding(record.path, record.payload, record.sha256)


def _timestamp(value: Any, label: str) -> datetime:
    try:
        require_timestamp(value, label)
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except (AttributeError, ValueError, RecoveryJournalError) as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error


def _official_source(model_key: str, value: Any) -> str:
    if not isinstance(value, str):
        raise DivergenceSuccessorAuthorizationError(
            f"official pricing source is missing for {model_key}"
        )
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise DivergenceSuccessorAuthorizationError(
            f"official pricing URL is malformed for {model_key}"
        ) from error
    host = (parsed.hostname or "").lower().rstrip(".")
    approved = OFFICIAL_PRICING_HOSTS[model_key]
    host_approved = any(host == item or host.endswith(f".{item}") for item in approved)
    if (
        parsed.scheme != "https"
        or not host_approved
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        raise DivergenceSuccessorAuthorizationError(
            f"pricing source host is not approved for {model_key}"
        )
    return value


def _rate(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
    ):
        raise DivergenceSuccessorAuthorizationError(
            f"{label} must be a finite nonnegative number"
        )
    return float(value)


def _prompt_token_ceiling() -> int:
    messages = [
        {"role": "system", "content": contract.SYSTEM_PROMPT},
        {"role": "user", "content": contract.CANDIDATE_PROMPT},
    ]
    return estimate_message_tokens(messages)


def normalize_pricing_evidence(
    evidence: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    records = list(evidence)
    if len(records) != len(contract.MODEL_KEYS):
        raise DivergenceSuccessorAuthorizationError(
            "fresh pricing must cover exactly all eight locked routes"
        )
    prompt_tokens = _prompt_token_ceiling()
    normalized: list[dict[str, Any]] = []
    total = 0
    for key, item in zip(contract.MODEL_KEYS, records, strict=True):
        if not isinstance(item, Mapping):
            raise DivergenceSuccessorAuthorizationError(
                f"pricing evidence is malformed for {key}"
            )
        requested, provider, route = contract.EXPECTED_MODELS[key]
        input_rate = _rate(item.get("input_per_million"), f"{key} input price")
        output_rate = _rate(item.get("output_per_million"), f"{key} output price")
        if (
            item.get("model_key") != key
            or item.get("requested_model_id") != requested
            or item.get("provider") != provider
            or item.get("route") != route
        ):
            raise DivergenceSuccessorAuthorizationError(
                f"pricing evidence route identity differs for {key}"
            )
        source_url = _official_source(key, item.get("source_url"))
        reservation = math.ceil(
            prompt_tokens * input_rate
            + contract.OUTPUT_TOKEN_CAP * output_rate
        )
        total += reservation
        normalized.append(
            {
                "model_key": key,
                "requested_model_id": requested,
                "provider": provider,
                "route": route,
                "currency": "USD",
                "input_per_million": input_rate,
                "output_per_million": output_rate,
                "source_url": source_url,
                "reservation_microdollars": reservation,
            }
        )
    if (
        total > contract.CANDIDATE_COST_CAP_MICRODOLLARS
        or total > contract.POOL_COST_CAP_MICRODOLLARS
    ):
        raise DivergenceSuccessorAuthorizationError(
            "fresh worst-case reservation exceeds the locked $6 candidate or pool cap"
        )
    return normalized, total


def pricing_recheck_payload(
    context: Any,
    authorization_binding: AuthorizationBinding,
    evidence: Iterable[Mapping[str, Any]],
    *,
    checked_at: str,
) -> dict[str, Any]:
    _timestamp(checked_at, "successor pricing recheck time")
    root, _, lock_sha, git_head = _context(context)
    if authorization_binding.path != authorization_path(root):
        raise DivergenceSuccessorAuthorizationError(
            "pricing recheck belongs to another authorization path"
        )
    current = validate_authorization(context)
    if current != authorization_binding:
        raise DivergenceSuccessorAuthorizationError(
            "pricing recheck authorization binding changed"
        )
    prices, reservation = normalize_pricing_evidence(evidence)
    return {
        "schema_version": PRICING_RECHECK_SCHEMA,
        "status": PRICING_RECHECK_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "git_head": git_head,
        "lock": {"path": contract.LOCK_PATH, "sha256": lock_sha},
        "authorization": {
            "path": "paid-authorization.json",
            "sha256": authorization_binding.sha256,
        },
        "checked_at": checked_at,
        "prompt_token_ceiling": _prompt_token_ceiling(),
        "output_token_cap_per_model": contract.OUTPUT_TOKEN_CAP,
        "prices": prices,
        "reserved_cost_microdollars": reservation,
        "candidate_cap_microdollars": contract.CANDIDATE_COST_CAP_MICRODOLLARS,
        "pool_cap_microdollars": contract.POOL_COST_CAP_MICRODOLLARS,
    }


def write_pricing_recheck(
    context: Any,
    evidence: Iterable[Mapping[str, Any]],
    *,
    checked_at: str | None = None,
) -> AuthorizationBinding:
    authority = validate_authorization(context)
    root, _, _, _ = _context(context)
    payload = pricing_recheck_payload(
        context,
        authority,
        evidence,
        checked_at=checked_at or utc_now(),
    )
    try:
        record = write_record(pricing_recheck_path(root), payload)
    except RecoveryJournalError as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error
    return AuthorizationBinding(record.path, record.payload, record.sha256)


def validate_pricing_recheck(
    context: Any,
    authorization_binding: AuthorizationBinding,
    *,
    fresh: bool = True,
    now: str | None = None,
) -> AuthorizationBinding:
    root, _, _, _ = _context(context)
    try:
        record = read_record(
            pricing_recheck_path(root), "divergence successor pricing recheck"
        )
    except RecoveryJournalError as error:
        raise DivergenceSuccessorAuthorizationError(str(error)) from error
    prices = record.payload.get("prices")
    expected = pricing_recheck_payload(
        context,
        authorization_binding,
        prices if isinstance(prices, list) else (),
        checked_at=record.payload.get("checked_at"),
    )
    if record.payload != expected:
        raise DivergenceSuccessorAuthorizationError(
            "the successor pricing recheck is stale or changed"
        )
    if fresh:
        checked = _timestamp(record.payload["checked_at"], "pricing recheck time")
        current = _timestamp(now or utc_now(), "current time")
        if checked > current + MAX_CLOCK_SKEW or current - checked > PRICING_FRESHNESS:
            raise DivergenceSuccessorAuthorizationError(
                "official pricing recheck is not fresh within 24 hours"
            )
    return AuthorizationBinding(record.path, record.payload, record.sha256)


__all__ = (
    "AuthorizationBinding",
    "DivergenceSuccessorAuthorizationError",
    "approval_readiness",
    "authorization_path",
    "authorization_payload",
    "require_approval_enabled",
    "normalize_pricing_evidence",
    "pricing_recheck_path",
    "pricing_recheck_payload",
    "validate_authorization",
    "validate_pricing_recheck",
    "write_authorization",
    "write_pricing_recheck",
)

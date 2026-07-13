"""Durable Rule 3 reservation and outcome journals.

Mode-0600 artifacts and mode-0700 directories protect against other OS users.
They do not protect against a malicious process running as the same user. A
stronger adversary requires an external signer or write-once storage.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Iterator, Mapping

from concordance_harness.util import (
    canonical_json_bytes,
    estimate_message_tokens,
    estimate_tokens,
    sha256_bytes,
    utc_now,
)

POOL_ID = "concordance-divergence-supplement-1"
PRIORITY_CANDIDATE_ID = "galatians-pistis-christou"
FALLBACK_CANDIDATE_ID = "quantum-measurement-realist-strategies"
CANDIDATE_ORDER = (PRIORITY_CANDIDATE_ID, FALLBACK_CANDIDATE_ID)
ATTEMPTS_PER_CELL = 3
CANDIDATE_CAP_MICRODOLLARS = 6_000_000
POOL_CAP_MICRODOLLARS = 12_000_000

INTENT_SCHEMA_VERSION = "rule3-attempt-intent-1.0.0"
OUTCOME_SCHEMA_VERSION = "rule3-attempt-outcome-1.0.0"
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
GIT_HEAD_PATTERN = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
SAFE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")

INTENT_KEYS = {
    "schema_version",
    "status",
    "pool_id",
    "lock_sha256",
    "authorization_receipt_sha256",
    "candidate_id",
    "cell_id",
    "model_key",
    "attempt_number",
    "reserved_cost_microdollars",
    "question_sha256",
    "prompt_sha256",
    "messages_sha256",
    "requested_params_sha256",
    "manifest_sha256",
    "created_at",
}

CELL_CONTRACT_KEYS = {
    "candidate_id",
    "phase",
    "cell_id",
    "model_key",
    "model_family",
    "provider",
    "route",
    "requested_model_id",
    "approved_returned_model_ids",
    "api_style",
    "question_sha256",
    "prompt_sha256",
    "messages",
    "messages_sha256",
    "requested_params",
    "requested_params_sha256",
    "effective_params",
    "finish_reason",
    "reserved_cost_microdollars",
    "input_per_million",
    "output_per_million",
    "pricing_as_of",
}

OUTCOME_COMMON_KEYS = {
    "schema_version",
    "lock_sha256",
    "authorization_receipt_sha256",
    "pricing_recheck_receipt_sha256",
    "git_head",
    "candidate_id",
    "phase",
    "cell_id",
    "model_key",
    "model_family",
    "provider",
    "route",
    "requested_model_id",
    "question_sha256",
    "prompt_sha256",
    "messages",
    "messages_sha256",
    "requested_params",
    "requested_params_sha256",
    "manifest_path",
    "manifest_sha256",
    "attempt_number",
    "intent_path",
    "intent_sha256",
    "attempted_at",
    "status",
    "completed_at",
}
SUCCESS_OUTCOME_KEYS = OUTCOME_COMMON_KEYS | {
    "provider_returned_model_id",
    "provider_response_id",
    "effective_params",
    "response_text",
    "response_sha256",
    "finish_reason",
    "usage",
    "latency_ms",
    "cost",
}
ERROR_OUTCOME_KEYS = OUTCOME_COMMON_KEYS | {"error"}
USAGE_KEYS = {
    "input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "total_tokens",
}
ERROR_KEYS = {"category", "retryable", "sanitized_summary"}
ERROR_CATEGORIES = {
    "authentication",
    "authorization",
    "incomplete-output",
    "invalid-request",
    "network",
    "provider-error",
    "rate-limit",
    "response-validation",
    "timeout",
    "unavailable",
}
RETRYABLE_ERROR_CATEGORIES = {"invalid-request", "provider-error", "rate-limit"}


class BudgetError(RuntimeError):
    """Raised before a Rule 3 request when its durable budget is invalid."""


class BudgetExceeded(BudgetError):
    """Raised before a request would cross a frozen reserved-cost cap."""


class AttemptNotAllowed(BudgetError):
    """Raised when an attempt would skip, replay, or exceed the retry contract."""


class StrandedIntent(BudgetError):
    """Raised when a sent-or-possibly-sent intent has no durable outcome."""


@dataclass(frozen=True)
class JournalRecord:
    path: Path
    payload: dict[str, Any]
    sha256: str


@dataclass(frozen=True)
class BudgetSnapshot:
    candidate_reserved_microdollars: dict[str, int]
    pool_reserved_microdollars: int
    intent_count: int
    stranded_intents: tuple[str, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BudgetError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as error:
            raise BudgetError(
                f"private path component cannot be inspected: {current}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise BudgetError(f"private path component is a symlink: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise BudgetError(f"private path component is not a directory: {current}")


def ensure_private_directory(path: Path) -> None:
    """Create one private directory and reject symlink or public replacements."""
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise BudgetError(f"private path is not a regular directory: {path}")
    else:
        path.mkdir(mode=0o700)
        _fsync_directory(path.parent)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise BudgetError(f"private directory must remain mode 0700: {path}")


def ensure_private_root(path: Path) -> None:
    """Create the fixed private hierarchy without trusting symlink components."""
    _reject_symlink_components(path)
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise BudgetError(f"private root ancestor is not a directory: {cursor}")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise BudgetError(
                f"private directory cannot be created: {directory}: {error}"
            ) from error
        if directory.is_symlink() or not directory.is_dir():
            raise BudgetError(
                f"private root component is not a regular directory: {directory}"
            )
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise BudgetError(f"private directory must remain mode 0700: {directory}")
        _fsync_directory(directory.parent)
    if path.is_symlink() or not path.is_dir():
        raise BudgetError(f"private root is not a regular directory: {path}")
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise BudgetError(f"private root must remain mode 0700: {path}")
    _reject_symlink_components(path)


def write_once_private_json(path: Path, value: Any) -> str:
    """Durably create a mode-0600 JSON artifact without replacement."""
    ensure_private_root(path.parent)
    payload = canonical_json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise BudgetError(
            f"write-once private artifact already exists: {path}"
        ) from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # A partial file is evidence that publication began. Removing it could
        # make a possibly sent request replayable.
        raise
    _fsync_directory(path.parent)
    return sha256_bytes(payload)


def read_private_json(path: Path, label: str) -> JournalRecord:
    _reject_symlink_components(path.parent)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BudgetError(f"{label} must be a regular, non-symlink file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise BudgetError(f"{label} must remain mode 0600")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read()
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise BudgetError(f"{label} is malformed: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise BudgetError(f"{label} must be a JSON object")
    if payload != canonical_json_bytes(value):
        raise BudgetError(f"{label} must use canonical JSON bytes")
    return JournalRecord(path=path, payload=value, sha256=sha256_bytes(payload))


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_nonnegative_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None


def _is_timestamp(value: Any) -> bool:
    return _parse_timestamp(value) is not None


class BudgetLedger:
    """A persistent, concurrency-safe journal proved against locked calls."""

    def __init__(
        self,
        private_root: Path,
        *,
        lock_sha256: str,
        authorization_receipt_sha256: str,
        pricing_recheck_receipt_sha256: str,
        git_head: str,
        cell_contracts: Mapping[tuple[str, str], Mapping[str, Any]],
    ) -> None:
        for label, digest in (
            ("lock", lock_sha256),
            ("authorization", authorization_receipt_sha256),
            ("pricing recheck", pricing_recheck_receipt_sha256),
        ):
            if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
                raise BudgetError(f"{label} hash must be a lowercase SHA-256")
        if not isinstance(git_head, str) or not GIT_HEAD_PATTERN.fullmatch(git_head):
            raise BudgetError("git head must be a lowercase Git object ID")
        self.private_root = private_root.absolute()
        self.budget_root = self.private_root / "budget"
        self.intent_root = self.budget_root / "intents"
        self.outcome_root = self.private_root / "outcomes"
        self.lock_path = self.budget_root / ".reservation.lock"
        self.lock_sha256 = lock_sha256
        self.authorization_receipt_sha256 = authorization_receipt_sha256
        self.pricing_recheck_receipt_sha256 = pricing_recheck_receipt_sha256
        self.git_head = git_head
        self.cell_contracts = self._copy_contracts(cell_contracts)

    @staticmethod
    def _copy_contracts(
        contracts: Mapping[tuple[str, str], Mapping[str, Any]],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        copied: dict[tuple[str, str], dict[str, Any]] = {}
        for key, contract in contracts.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or not all(isinstance(item, str) for item in key)
                or not isinstance(contract, Mapping)
            ):
                raise BudgetError("cell budget contract key is malformed")
            value = json.loads(canonical_json_bytes(dict(contract)))
            if set(value) != CELL_CONTRACT_KEYS:
                raise BudgetError("cell budget contract fields differ")
            candidate_id, model_key = key
            approved = value.get("approved_returned_model_ids")
            if (
                value.get("candidate_id") != candidate_id
                or value.get("model_key") != model_key
                or candidate_id not in CANDIDATE_ORDER
                or value.get("phase")
                != ("priority" if candidate_id == PRIORITY_CANDIDATE_ID else "fallback")
                or not isinstance(value.get("cell_id"), str)
                or not all(
                    isinstance(value.get(field), str) and value[field]
                    for field in (
                        "model_family",
                        "provider",
                        "route",
                        "requested_model_id",
                        "api_style",
                        "pricing_as_of",
                        "finish_reason",
                    )
                )
                or not isinstance(approved, list)
                or not approved
                or len(set(approved)) != len(approved)
                or not all(isinstance(item, str) and item for item in approved)
                or not _is_nonnegative_int(value.get("reserved_cost_microdollars"))
                or not _is_nonnegative_number(value.get("input_per_million"))
                or not _is_nonnegative_number(value.get("output_per_million"))
            ):
                raise BudgetError("cell budget contract identity is malformed")
            for field in (
                "question_sha256",
                "prompt_sha256",
                "messages_sha256",
                "requested_params_sha256",
            ):
                if not isinstance(
                    value.get(field), str
                ) or not SHA256_PATTERN.fullmatch(value[field]):
                    raise BudgetError(f"cell budget contract {field} is malformed")
            if (
                sha256_bytes(canonical_json_bytes(value["messages"]))
                != value["messages_sha256"]
                or sha256_bytes(canonical_json_bytes(value["requested_params"]))
                != value["requested_params_sha256"]
            ):
                raise BudgetError("cell budget contract hashes do not match its values")
            copied[key] = value
        if not copied:
            raise BudgetError("cell budget contracts cannot be empty")
        return copied

    def initialize(self) -> None:
        ensure_private_root(self.private_root)
        for path in (self.budget_root, self.intent_root, self.outcome_root):
            ensure_private_root(path)
        if not self.lock_path.exists():
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.lock_path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
                _fsync_directory(self.budget_root)
        record_flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            record_flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.lock_path, record_flags)
            metadata = os.fstat(descriptor)
        except OSError as error:
            raise BudgetError(
                f"budget reservation lock is malformed: {error}"
            ) from error
        finally:
            if "descriptor" in locals():
                os.close(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BudgetError("budget reservation lock is not a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise BudgetError("budget reservation lock must remain mode 0600")

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        self.initialize()
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise BudgetError("budget reservation lock changed before locking")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _validate_component(value: str, label: str) -> None:
        if not isinstance(value, str) or not SAFE_ID_PATTERN.fullmatch(value):
            raise BudgetError(f"{label} is not a safe canonical identifier")

    def _contract(self, candidate_id: str, model_key: str) -> dict[str, Any]:
        try:
            return self.cell_contracts[(candidate_id, model_key)]
        except KeyError as error:
            raise BudgetError(
                f"no locked cell contract for {candidate_id}:{model_key}"
            ) from error

    def intent_path(
        self, candidate_id: str, model_key: str, attempt_number: int
    ) -> Path:
        self._validate_component(candidate_id, "candidate ID")
        self._validate_component(model_key, "model key")
        return (
            self.intent_root
            / candidate_id
            / model_key
            / f"attempt-{attempt_number}.json"
        )

    def outcome_path(
        self, candidate_id: str, model_key: str, attempt_number: int
    ) -> Path:
        self._validate_component(candidate_id, "candidate ID")
        self._validate_component(model_key, "model key")
        return (
            self.outcome_root
            / candidate_id
            / model_key
            / f"attempt-{attempt_number}.json"
        )

    def _validate_intent(self, record: JournalRecord) -> dict[str, Any]:
        raw = record.payload
        if set(raw) != INTENT_KEYS:
            raise BudgetError(
                f"attempt intent fields differ from the contract: {record.path}"
            )
        candidate_id = raw.get("candidate_id")
        model_key = raw.get("model_key")
        if not isinstance(candidate_id, str) or not isinstance(model_key, str):
            raise BudgetError(f"attempt intent identity is malformed: {record.path}")
        contract = self._contract(candidate_id, model_key)
        attempt = raw.get("attempt_number")
        if (
            raw.get("schema_version") != INTENT_SCHEMA_VERSION
            or raw.get("status") != "reserved-before-post"
            or raw.get("pool_id") != POOL_ID
            or raw.get("lock_sha256") != self.lock_sha256
            or raw.get("authorization_receipt_sha256")
            != self.authorization_receipt_sha256
            or raw.get("cell_id") != contract["cell_id"]
            or not _is_nonnegative_int(attempt)
            or not 1 <= attempt <= ATTEMPTS_PER_CELL
            or raw.get("reserved_cost_microdollars")
            != contract["reserved_cost_microdollars"]
            or raw.get("question_sha256") != contract["question_sha256"]
            or raw.get("prompt_sha256") != contract["prompt_sha256"]
            or raw.get("messages_sha256") != contract["messages_sha256"]
            or raw.get("requested_params_sha256") != contract["requested_params_sha256"]
            or not isinstance(raw.get("manifest_sha256"), str)
            or not SHA256_PATTERN.fullmatch(raw["manifest_sha256"])
            or not _is_timestamp(raw.get("created_at"))
        ):
            raise BudgetError(
                f"attempt intent differs from the locked call contract: {record.path}"
            )
        expected_path = self.intent_path(candidate_id, model_key, attempt)
        if record.path.absolute() != expected_path.absolute():
            raise BudgetError(
                f"attempt intent is stored at an unexpected path: {record.path}"
            )
        return raw

    def _journal_records(self, root: Path, label: str) -> tuple[JournalRecord, ...]:
        if not root.exists():
            return ()
        result = []
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                if path.is_symlink():
                    raise BudgetError(f"{label} contains a symlink: {path}")
                continue
            if path.is_symlink() or path.suffix != ".json" or path.name.startswith("."):
                raise BudgetError(f"{label} contains an unexpected file: {path}")
            result.append(read_private_json(path, label))
        return tuple(result)

    def _intent_records(self) -> tuple[JournalRecord, ...]:
        records = self._journal_records(self.intent_root, "attempt intent")
        for record in records:
            self._validate_intent(record)
        return records

    def _expected_common_outcome(
        self, intent: JournalRecord, contract: Mapping[str, Any]
    ) -> dict[str, Any]:
        raw = intent.payload
        return {
            "schema_version": OUTCOME_SCHEMA_VERSION,
            "lock_sha256": self.lock_sha256,
            "authorization_receipt_sha256": self.authorization_receipt_sha256,
            "pricing_recheck_receipt_sha256": self.pricing_recheck_receipt_sha256,
            "git_head": self.git_head,
            "candidate_id": contract["candidate_id"],
            "phase": contract["phase"],
            "cell_id": contract["cell_id"],
            "model_key": contract["model_key"],
            "model_family": contract["model_family"],
            "provider": contract["provider"],
            "route": contract["route"],
            "requested_model_id": contract["requested_model_id"],
            "question_sha256": contract["question_sha256"],
            "prompt_sha256": contract["prompt_sha256"],
            "messages": contract["messages"],
            "messages_sha256": contract["messages_sha256"],
            "requested_params": contract["requested_params"],
            "requested_params_sha256": contract["requested_params_sha256"],
            "manifest_path": f"manifests/{contract['candidate_id']}.json",
            "manifest_sha256": raw["manifest_sha256"],
            "attempt_number": raw["attempt_number"],
            "intent_path": str(intent.path.relative_to(self.private_root)),
            "intent_sha256": intent.sha256,
        }

    @staticmethod
    def _expected_actual_cost(
        value: Mapping[str, Any], contract: Mapping[str, Any]
    ) -> int:
        usage = value["usage"]
        input_tokens = usage["input_tokens"]
        if input_tokens is None:
            input_tokens = estimate_message_tokens(contract["messages"])
        output_tokens = usage["output_tokens"]
        if output_tokens is None:
            output_tokens = estimate_tokens(value["response_text"])
        if contract["api_style"] == "google":
            output_tokens += usage["reasoning_tokens"] or 0
        return int(
            (
                Decimal(input_tokens) * Decimal(str(contract["input_per_million"]))
                + Decimal(output_tokens) * Decimal(str(contract["output_per_million"]))
            ).to_integral_value(rounding=ROUND_CEILING)
        )

    def _validate_outcome(
        self, intent: JournalRecord, outcome: JournalRecord
    ) -> dict[str, Any]:
        raw = self._validate_intent(intent)
        value = outcome.payload
        status_value = value.get("status")
        expected_keys = (
            SUCCESS_OUTCOME_KEYS if status_value == "success" else ERROR_OUTCOME_KEYS
        )
        if set(value) != expected_keys:
            raise BudgetError(
                f"attempt outcome fields differ for status {status_value!r}: {outcome.path}"
            )
        contract = self._contract(raw["candidate_id"], raw["model_key"])
        for key, expected in self._expected_common_outcome(intent, contract).items():
            if value.get(key) != expected:
                raise BudgetError(
                    f"attempt outcome {key} differs from its locked intent: {outcome.path}"
                )
        attempted_at = _parse_timestamp(value.get("attempted_at"))
        completed_at = _parse_timestamp(value.get("completed_at"))
        if (
            attempted_at is None
            or completed_at is None
            or value.get("attempted_at") != raw["created_at"]
            or completed_at < attempted_at
        ):
            raise BudgetError(
                f"attempt outcome timestamps are malformed: {outcome.path}"
            )
        expected_path = self.outcome_path(
            raw["candidate_id"], raw["model_key"], raw["attempt_number"]
        )
        if outcome.path.absolute() != expected_path.absolute():
            raise BudgetError(
                f"attempt outcome is stored at an unexpected path: {outcome.path}"
            )

        if status_value == "success":
            returned = value.get("provider_returned_model_id")
            response = value.get("response_text")
            usage = value.get("usage")
            cost = value.get("cost")
            response_id = value.get("provider_response_id")
            if (
                returned not in contract["approved_returned_model_ids"]
                or (
                    response_id is not None
                    and (not isinstance(response_id, str) or not response_id)
                )
                or value.get("effective_params") != contract["effective_params"]
                or not isinstance(response, str)
                or not response.strip()
                or value.get("response_sha256")
                != sha256_bytes(response.encode("utf-8"))
                or value.get("finish_reason") != contract["finish_reason"]
                or not isinstance(usage, dict)
                or set(usage) != USAGE_KEYS
                or any(
                    item is not None and not _is_nonnegative_int(item)
                    for item in usage.values()
                )
                or not _is_nonnegative_int(value.get("latency_ms"))
                or not isinstance(cost, dict)
                or set(cost)
                != {
                    "actual_estimate_microdollars",
                    "reserved_microdollars",
                    "pricing_as_of",
                }
                or cost.get("reserved_microdollars")
                != contract["reserved_cost_microdollars"]
                or cost.get("pricing_as_of") != contract["pricing_as_of"]
                or cost.get("actual_estimate_microdollars")
                != self._expected_actual_cost(value, contract)
            ):
                raise BudgetError(
                    f"success outcome differs from the locked result contract: {outcome.path}"
                )
        else:
            error = value.get("error")
            if (
                status_value != "error"
                or not isinstance(error, dict)
                or set(error) != ERROR_KEYS
                or error.get("category") not in ERROR_CATEGORIES
                or not isinstance(error.get("retryable"), bool)
                or (
                    error.get("retryable") is True
                    and error.get("category") not in RETRYABLE_ERROR_CATEGORIES
                )
                or not isinstance(error.get("sanitized_summary"), str)
                or not error["sanitized_summary"]
            ):
                raise BudgetError(
                    f"error outcome retry policy is malformed: {outcome.path}"
                )
        return value

    def _load_outcome(self, intent: JournalRecord) -> JournalRecord | None:
        raw = self._validate_intent(intent)
        path = self.outcome_path(
            raw["candidate_id"], raw["model_key"], raw["attempt_number"]
        )
        if not path.exists():
            return None
        outcome = read_private_json(path, "attempt outcome")
        self._validate_outcome(intent, outcome)
        return outcome

    def _histories(
        self, intents: tuple[JournalRecord, ...]
    ) -> dict[tuple[str, str], tuple[tuple[JournalRecord, JournalRecord | None], ...]]:
        grouped: dict[tuple[str, str], list[JournalRecord]] = {}
        for intent in intents:
            raw = intent.payload
            grouped.setdefault((raw["candidate_id"], raw["model_key"]), []).append(
                intent
            )
        result = {}
        expected_outcome_paths: set[Path] = set()
        for key, records in grouped.items():
            records.sort(key=lambda item: item.payload["attempt_number"])
            attempts = [item.payload["attempt_number"] for item in records]
            if attempts != list(range(1, len(records) + 1)):
                raise BudgetError(
                    f"attempt history is not contiguous for {key[0]}:{key[1]}"
                )
            history = []
            for index, intent in enumerate(records):
                outcome = self._load_outcome(intent)
                expected_outcome_paths.add(
                    self.outcome_path(
                        key[0], key[1], intent.payload["attempt_number"]
                    ).absolute()
                )
                history.append((intent, outcome))
                if index < len(records) - 1:
                    if outcome is None:
                        raise BudgetError(
                            f"later attempt follows a stranded intent for {key[0]}:{key[1]}"
                        )
                    if (
                        outcome.payload["status"] != "error"
                        or not outcome.payload["error"]["retryable"]
                    ):
                        raise BudgetError(
                            f"later attempt follows a terminal outcome for {key[0]}:{key[1]}"
                        )
            result[key] = tuple(history)
        actual_outcome_paths = {
            record.path.absolute()
            for record in self._journal_records(self.outcome_root, "attempt outcome")
        }
        if actual_outcome_paths != {
            path for path in expected_outcome_paths if path.exists()
        }:
            raise BudgetError("outcome journal contains an orphan or unexpected record")
        return result

    def snapshot(self) -> BudgetSnapshot:
        self.initialize()
        intents = self._intent_records()
        histories = self._histories(intents)
        totals = {candidate: 0 for candidate in CANDIDATE_ORDER}
        stranded = []
        for history in histories.values():
            for intent, outcome in history:
                raw = intent.payload
                totals[raw["candidate_id"]] += raw["reserved_cost_microdollars"]
                if outcome is None:
                    stranded.append(str(intent.path.relative_to(self.private_root)))
        pool_total = sum(totals.values())
        if any(value > CANDIDATE_CAP_MICRODOLLARS for value in totals.values()):
            raise BudgetError("durable journal already exceeds a candidate cap")
        if pool_total > POOL_CAP_MICRODOLLARS:
            raise BudgetError("durable journal already exceeds the pool cap")
        return BudgetSnapshot(
            candidate_reserved_microdollars=totals,
            pool_reserved_microdollars=pool_total,
            intent_count=len(intents),
            stranded_intents=tuple(sorted(stranded)),
        )

    def cell_history(
        self, candidate_id: str, model_key: str
    ) -> tuple[tuple[JournalRecord, JournalRecord | None], ...]:
        histories = self._histories(self._intent_records())
        return histories.get((candidate_id, model_key), ())

    def reserve(
        self,
        *,
        candidate_id: str,
        cell_id: str,
        model_key: str,
        attempt_number: int,
        reserved_cost_microdollars: int,
        question_sha256: str,
        prompt_sha256: str,
        messages_sha256: str,
        requested_params_sha256: str,
        manifest_sha256: str,
        created_at: str | None = None,
    ) -> JournalRecord:
        if candidate_id not in CANDIDATE_ORDER:
            raise AttemptNotAllowed("Rule 3 has no third candidate")
        if (
            not _is_nonnegative_int(attempt_number)
            or not 1 <= attempt_number <= ATTEMPTS_PER_CELL
        ):
            raise AttemptNotAllowed(
                "attempt number exceeds the exact three-attempt ceiling"
            )
        contract = self._contract(candidate_id, model_key)
        supplied = {
            "cell_id": cell_id,
            "reserved_cost_microdollars": reserved_cost_microdollars,
            "question_sha256": question_sha256,
            "prompt_sha256": prompt_sha256,
            "messages_sha256": messages_sha256,
            "requested_params_sha256": requested_params_sha256,
        }
        if any(supplied[key] != contract[key] for key in supplied):
            raise BudgetError(
                "attempt reservation differs from the locked call contract"
            )
        if not isinstance(manifest_sha256, str) or not SHA256_PATTERN.fullmatch(
            manifest_sha256
        ):
            raise BudgetError("attempt contract contains a malformed manifest SHA-256")

        with self._exclusive():
            history = self.cell_history(candidate_id, model_key)
            if history:
                previous_intent, previous_outcome = history[-1]
                if previous_outcome is None:
                    raise StrandedIntent(
                        f"stranded attempt intent stops cell {cell_id}; no request sent"
                    )
                if previous_outcome.payload["status"] == "success":
                    raise AttemptNotAllowed(
                        f"successful cell cannot be replayed: {cell_id}"
                    )
                if not previous_outcome.payload["error"]["retryable"]:
                    raise AttemptNotAllowed(
                        f"nonretryable cell cannot be replayed: {cell_id}"
                    )
                expected_attempt = previous_intent.payload["attempt_number"] + 1
            else:
                expected_attempt = 1
            if attempt_number != expected_attempt:
                raise AttemptNotAllowed(
                    f"attempt sequence for {cell_id} requires {expected_attempt}, found {attempt_number}"
                )

            snapshot = self.snapshot()
            candidate_total = (
                snapshot.candidate_reserved_microdollars[candidate_id]
                + contract["reserved_cost_microdollars"]
            )
            pool_total = (
                snapshot.pool_reserved_microdollars
                + contract["reserved_cost_microdollars"]
            )
            if candidate_total > CANDIDATE_CAP_MICRODOLLARS:
                raise BudgetExceeded(
                    f"candidate reserved cap would exceed {CANDIDATE_CAP_MICRODOLLARS} microdollars; no request sent"
                )
            if pool_total > POOL_CAP_MICRODOLLARS:
                raise BudgetExceeded(
                    f"pool reserved cap would exceed {POOL_CAP_MICRODOLLARS} microdollars; no request sent"
                )

            value = {
                "schema_version": INTENT_SCHEMA_VERSION,
                "status": "reserved-before-post",
                "pool_id": POOL_ID,
                "lock_sha256": self.lock_sha256,
                "authorization_receipt_sha256": self.authorization_receipt_sha256,
                "candidate_id": candidate_id,
                "cell_id": contract["cell_id"],
                "model_key": model_key,
                "attempt_number": attempt_number,
                "reserved_cost_microdollars": contract["reserved_cost_microdollars"],
                "question_sha256": contract["question_sha256"],
                "prompt_sha256": contract["prompt_sha256"],
                "messages_sha256": contract["messages_sha256"],
                "requested_params_sha256": contract["requested_params_sha256"],
                "manifest_sha256": manifest_sha256,
                "created_at": created_at or utc_now(),
            }
            path = self.intent_path(candidate_id, model_key, attempt_number)
            digest = write_once_private_json(path, value)
            return JournalRecord(path=path, payload=value, sha256=digest)

    def record_outcome(
        self, intent: JournalRecord, value: dict[str, Any]
    ) -> JournalRecord:
        with self._exclusive():
            raw = self._validate_intent(intent)
            durable = read_private_json(intent.path, "attempt intent")
            self._validate_intent(durable)
            if durable.sha256 != intent.sha256 or durable.payload != intent.payload:
                raise BudgetError(
                    "attempt intent changed before its outcome was recorded"
                )
            path = self.outcome_path(
                raw["candidate_id"], raw["model_key"], raw["attempt_number"]
            )
            pending = JournalRecord(
                path=path,
                payload=value,
                sha256=sha256_bytes(canonical_json_bytes(value)),
            )
            self._validate_outcome(intent, pending)
            digest = write_once_private_json(path, value)
            return JournalRecord(path=path, payload=value, sha256=digest)

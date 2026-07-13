"""Durable private records for the Concordance successor-recovery lane.

The recovery journal is append-only.  A generation intent with no captured
HTTP response is permanently stranded because the POST may have reached the
provider.  A captured response with no outcome is safe to finish offline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import stat
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from concordance_harness.providers import HttpRequest, HttpResponse
from concordance_harness.util import canonical_json_bytes, sha256_bytes, utc_now
from rule3.budget import (
    BudgetError,
    JournalRecord,
    ensure_private_root,
    read_private_json,
    write_once_private_json,
)


GENERATION_INTENT_SCHEMA = "concordance-recovery-generation-intent-1.0.0"
RAW_RESPONSE_SCHEMA = "concordance-recovery-raw-http-response-1.0.0"
GENERATION_OUTCOME_SCHEMA = "concordance-recovery-generation-outcome-1.0.0"
PREFLIGHT_INTENT_SCHEMA = "concordance-recovery-preflight-intent-1.0.0"
PREFLIGHT_OUTCOME_SCHEMA = "concordance-recovery-preflight-outcome-1.0.0"
MANIFEST_SCHEMA = "concordance-recovery-model-manifest-1.0.0"
COMPOSITE_SCHEMA = "concordance-recovery-composite-run-1.0.0"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_HEAD_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")


class RecoveryJournalError(RuntimeError):
    """Raised when recovery evidence is absent, malformed, or replayable."""


class StrandedGenerationIntent(RecoveryJournalError):
    """A POST was authorized and may have been sent, but no response survived."""


@dataclass(frozen=True)
class RecordBinding:
    path: str
    sha256: str

    def value(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RecoveryJournalError(f"{label} must be a lowercase SHA-256")
    return value


def require_git_head(value: Any, label: str = "Git HEAD") -> str:
    if not isinstance(value, str) or not GIT_HEAD_RE.fullmatch(value):
        raise RecoveryJournalError(f"{label} must be a full lowercase object ID")
    return value


def require_safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise RecoveryJournalError(f"{label} is not a safe canonical identifier")
    return value


def require_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise RecoveryJournalError(f"{label} is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RecoveryJournalError(f"{label} is malformed") from error
    if parsed.utcoffset() is None:
        raise RecoveryJournalError(f"{label} must include a timezone")
    return value


def binding(private_root: Path, record: JournalRecord) -> RecordBinding:
    try:
        relative = record.path.resolve().relative_to(private_root.resolve()).as_posix()
    except ValueError as error:
        raise RecoveryJournalError(
            "private record escapes the recovery root"
        ) from error
    return RecordBinding(relative, record.sha256)


def read_record(path: Path, label: str) -> JournalRecord:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RecoveryJournalError(f"{label} cannot be inspected: {error}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise RecoveryJournalError(
            f"{label} must be a single-link mode-0600 regular file"
        )
    try:
        return read_private_json(path, label)
    except BudgetError as error:
        raise RecoveryJournalError(str(error)) from error


def write_record(path: Path, value: Mapping[str, Any]) -> JournalRecord:
    try:
        digest = write_once_private_json(path, dict(value))
    except BudgetError as error:
        raise RecoveryJournalError(str(error)) from error
    record = JournalRecord(path=path, payload=dict(value), sha256=digest)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise RecoveryJournalError(
            "new private artifact is not a single-link mode-0600 regular file"
        )
    return record


def initialize_private_root(path: Path) -> None:
    try:
        ensure_private_root(path)
    except BudgetError as error:
        raise RecoveryJournalError(str(error)) from error


def exact_json_copy(value: Any) -> Any:
    """Return a detached JSON value and reject non-JSON input."""
    try:
        return json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RecoveryJournalError("journal value is not canonical JSON") from error


def request_origin(request: HttpRequest) -> str:
    """Return only the HTTPS origin and path, never query credentials."""
    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(request.url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RecoveryJournalError("provider request URL is not a safe HTTPS endpoint")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def request_body_bytes(request: HttpRequest) -> bytes:
    if request.json_body is None:
        return b""
    try:
        return json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RecoveryJournalError("provider request body is not JSON") from error


def raw_response_payload(
    *,
    common: Mapping[str, Any],
    intent: JournalRecord,
    private_root: Path,
    request_kind: str,
    request: HttpRequest,
    response: HttpResponse,
    received_at: str | None = None,
) -> dict[str, Any]:
    """Build the lossless receipt written before any semantic validation."""
    if request_kind not in {"preflight", "generation"}:
        raise RecoveryJournalError("raw response request kind is invalid")
    if not isinstance(response.status, int) or isinstance(response.status, bool):
        raise RecoveryJournalError("HTTP response status is malformed")
    timestamp = received_at or utc_now()
    require_timestamp(timestamp, "raw response receipt time")
    intent_time = intent.payload.get("created_at")
    require_timestamp(intent_time, "raw response intent time")
    received = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    created = datetime.fromisoformat(intent_time.replace("Z", "+00:00"))
    if received < created:
        raise RecoveryJournalError("raw HTTP response predates its durable intent")
    body = bytes(response.body)
    request_body = request_body_bytes(request)
    return {
        "schema_version": RAW_RESPONSE_SCHEMA,
        "status": "durable-http-response-before-validation",
        **exact_json_copy(dict(common)),
        "request_kind": request_kind,
        "intent": binding(private_root, intent).value(),
        "request": {
            "method": request.method,
            "origin": request_origin(request),
            "json_body_sha256": sha256_bytes(request_body),
        },
        "response": {
            "status": response.status,
            "body_base64": base64.b64encode(body).decode("ascii"),
            "body_sha256": sha256_bytes(body),
        },
        "received_at": timestamp,
    }


def validate_raw_response(
    record: JournalRecord,
    *,
    expected_common: Mapping[str, Any],
    expected_intent: JournalRecord,
    private_root: Path,
    request_kind: str,
    expected_request: HttpRequest,
) -> HttpResponse:
    value = record.payload
    expected_keys = {
        "schema_version",
        "status",
        *expected_common.keys(),
        "request_kind",
        "intent",
        "request",
        "response",
        "received_at",
    }
    if set(value) != expected_keys:
        raise RecoveryJournalError(
            "raw response fields differ from the recovery contract"
        )
    if (
        value.get("schema_version") != RAW_RESPONSE_SCHEMA
        or value.get("status") != "durable-http-response-before-validation"
        or any(value.get(key) != item for key, item in expected_common.items())
        or value.get("request_kind") != request_kind
        or value.get("intent") != binding(private_root, expected_intent).value()
    ):
        raise RecoveryJournalError("raw response lineage differs from its intent")
    require_timestamp(value.get("received_at"), "raw response receipt time")
    intent_time = expected_intent.payload.get("created_at")
    require_timestamp(intent_time, "raw response intent time")
    received = datetime.fromisoformat(value["received_at"].replace("Z", "+00:00"))
    created = datetime.fromisoformat(intent_time.replace("Z", "+00:00"))
    if received < created:
        raise RecoveryJournalError("raw HTTP response predates its durable intent")
    expected_request_value = {
        "method": expected_request.method,
        "origin": request_origin(expected_request),
        "json_body_sha256": sha256_bytes(request_body_bytes(expected_request)),
    }
    if value.get("request") != expected_request_value:
        raise RecoveryJournalError(
            "raw response request differs from the locked request"
        )
    response = value.get("response")
    if not isinstance(response, dict) or set(response) != {
        "status",
        "body_base64",
        "body_sha256",
    }:
        raise RecoveryJournalError("raw HTTP response envelope is malformed")
    status = response.get("status")
    encoded = response.get("body_base64")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or not isinstance(encoded, str)
    ):
        raise RecoveryJournalError("raw HTTP response values are malformed")
    try:
        body = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise RecoveryJournalError(
            "raw HTTP response body is not canonical base64"
        ) from error
    if base64.b64encode(body).decode("ascii") != encoded:
        raise RecoveryJournalError("raw HTTP response body is not canonical base64")
    if hashlib.sha256(body).hexdigest() != require_sha256(
        response.get("body_sha256"), "raw response body hash"
    ):
        raise RecoveryJournalError("raw HTTP response body changed")
    # Provider adapters parse status and body only.  Arbitrary provider headers
    # are deliberately excluded because they can contain cookies or reflected
    # credentials; the response body itself remains exact and lossless.
    return HttpResponse(status=status, headers={}, body=body)


def assert_exact_json_inventory(
    root: Path, expected: Iterable[Path], label: str
) -> None:
    expected_paths = {path.resolve() for path in expected}
    if not root.exists():
        actual_paths: set[Path] = set()
    else:
        actual_paths = set()
        for path in root.rglob("*"):
            if path.is_dir():
                if path.is_symlink():
                    raise RecoveryJournalError(f"{label} contains a symlink")
                continue
            if path.is_symlink() or path.suffix != ".json":
                raise RecoveryJournalError(f"{label} contains an unexpected file")
            actual_paths.add(path.resolve())
    if actual_paths != expected_paths:
        raise RecoveryJournalError(
            f"{label} inventory differs from the recovery journal"
        )

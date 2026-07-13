"""Authenticate the exact immutable Qwen-successor parent snapshot."""

from __future__ import annotations

import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from concordance_recovery.journal import (
    RecoveryJournalError,
    read_record,
    require_timestamp,
)
from qwen_successor import contract as qwen_contract
from qwen_successor.lock import load_lock as load_qwen_lock
from qwen_successor.parent import validate_parent_snapshot as validate_qwen_parent
from rule3.budget import JournalRecord

from . import contract


@dataclass(frozen=True)
class ParentEvidence:
    """Verified successes and the captured Grok failure from the parent lane."""

    rule3: Any
    cohere_outcome: JournalRecord
    qwen_outcome: JournalRecord
    deepseek_outcome: JournalRecord
    mistral_outcome: JournalRecord
    grok_error_intent: JournalRecord
    grok_error_raw: JournalRecord
    grok_error_outcome: JournalRecord
    parent_manifest: JournalRecord
    parent_claim: JournalRecord
    private_root: Path
    reserved_microdollars: int

    @property
    def preserved_outcomes(self) -> tuple[JournalRecord, ...]:
        return (
            *self.rule3.preserved_outcomes,
            self.cohere_outcome,
            self.qwen_outcome,
            self.deepseek_outcome,
            self.mistral_outcome,
        )


def _exact_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _exact_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _exact_equal(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def _expected_parent_contract() -> dict[str, Any]:
    bindings = [
        {"path": path, "sha256": digest}
        for path, digest in sorted(contract.QWEN_PRIVATE_SHA256.items())
    ]
    return {
        "qwen_execution_head": contract.QWEN_EXECUTION_HEAD,
        "qwen_lock_sha256": contract.QWEN_LOCK_SHA256,
        "qwen_private_root": contract.QWEN_PRIVATE_ROOT,
        "qwen_private_bindings": bindings,
        "qwen_private_binding_count": len(bindings),
        "qwen_parent_claim": {
            "path": contract.QWEN_PARENT_CLAIM_PATH,
            "sha256": contract.QWEN_PARENT_CLAIM_SHA256,
        },
        "qwen_parent_phase_lock_path": contract.QWEN_PARENT_PHASE_LOCK_PATH,
        "required_absent": list(contract.QWEN_REQUIRED_ABSENT),
        "exact_file_and_directory_inventory_required": True,
        "reused_preflight_manifest": {
            "path": contract.QWEN_MANIFEST_PATH,
            "sha256": contract.QWEN_MANIFEST_SHA256,
        },
        "captured_grok_error": {
            "intent_path": contract.GROK_ERROR_INTENT_PATH,
            "intent_sha256": contract.GROK_ERROR_INTENT_SHA256,
            "raw_path": contract.GROK_ERROR_RAW_PATH,
            "raw_sha256": contract.GROK_ERROR_RAW_SHA256,
            "outcome_path": contract.GROK_ERROR_OUTCOME_PATH,
            "outcome_sha256": contract.GROK_ERROR_OUTCOME_SHA256,
            "http_status": 403,
        },
        "inherited_reserved_microdollars": contract.INHERITED_RESERVED_MICRODOLLARS,
    }


def _validate_retry_parent_contract(retry_lock: dict[str, Any] | None) -> None:
    if retry_lock is None:
        return
    if not isinstance(retry_lock, dict) or not _exact_equal(
        retry_lock.get("parent"), _expected_parent_contract()
    ):
        raise RecoveryJournalError("Grok retry parent contract changed")


def _expected_directories(files: set[str]) -> set[str]:
    result: set[str] = set()
    for relative in files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def _inspect_exact_private_tree(root: Path, expected_files: set[str]) -> None:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise RecoveryJournalError(
            f"Qwen successor private root cannot be inspected: {error}"
        ) from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RecoveryJournalError(
            "Qwen successor private root must remain a real mode-0700 directory"
        )

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        entries = sorted(root.rglob("*"))
    except OSError as error:
        raise RecoveryJournalError(
            f"Qwen successor inventory cannot be read: {error}"
        ) from error
    for path in entries:
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as error:
            raise RecoveryJournalError(
                f"Qwen successor inventory cannot inspect {relative}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RecoveryJournalError("Qwen successor private tree contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise RecoveryJournalError(
                    "Qwen successor private directory mode changed"
                )
            actual_directories.add(relative)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise RecoveryJournalError(
                "Qwen successor artifact must remain a single-link mode-0600 "
                "regular file"
            )
        actual_files.add(relative)

    if actual_files != expected_files or actual_directories != _expected_directories(
        expected_files
    ):
        raise RecoveryJournalError("Qwen successor exact private inventory changed")


def _read_parent_records(root: Path) -> dict[str, JournalRecord]:
    expected = set(contract.QWEN_PRIVATE_SHA256)
    _inspect_exact_private_tree(root, expected)
    records: dict[str, JournalRecord] = {}
    for relative, digest in sorted(contract.QWEN_PRIVATE_SHA256.items()):
        record = read_record(root / relative, f"Qwen successor evidence {relative}")
        if record.sha256 != digest:
            raise RecoveryJournalError(f"Qwen successor evidence changed: {relative}")
        records[relative] = record
    _inspect_exact_private_tree(root, expected)
    return records


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RecoveryJournalError(
            f"Qwen successor absence cannot be inspected: {error}"
        ) from error
    return True


def _validate_required_absences(root: Path) -> None:
    for relative in contract.QWEN_REQUIRED_ABSENT:
        if _path_exists(root / relative):
            raise RecoveryJournalError(
                f"required Qwen successor absence changed: {relative}"
            )


def _validate_claim_area(repository_root: Path) -> JournalRecord:
    claim_path = repository_root / contract.QWEN_PARENT_CLAIM_PATH
    lock_path = repository_root / contract.QWEN_PARENT_PHASE_LOCK_PATH
    claim_root = claim_path.parent
    try:
        root_metadata = claim_root.lstat()
    except OSError as error:
        raise RecoveryJournalError(
            f"Qwen successor claim root cannot be inspected: {error}"
        ) from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RecoveryJournalError(
            "Qwen successor claim root must remain a real mode-0700 directory"
        )
    actual: set[Path] = set()
    for path in claim_root.iterdir():
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise RecoveryJournalError("Qwen successor claim inventory changed")
        actual.add(path.resolve())
    if actual != {claim_path.resolve(), lock_path.resolve()}:
        raise RecoveryJournalError("Qwen successor claim inventory changed")

    metadata = lock_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise RecoveryJournalError("Qwen successor phase lock changed")
    claim = read_record(claim_path, "Qwen successor parent claim")
    if claim.sha256 != contract.QWEN_PARENT_CLAIM_SHA256:
        raise RecoveryJournalError("Qwen successor parent claim changed")
    return claim


def _require_fields(
    value: Mapping[str, Any], expected: Mapping[str, Any], label: str
) -> None:
    if any(not _exact_equal(value.get(key), item) for key, item in expected.items()):
        raise RecoveryJournalError(f"{label} lineage changed")


def _common() -> dict[str, Any]:
    return {
        "recovery_id": qwen_contract.RECOVERY_ID,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "phase": contract.PHASE,
        "git_head": contract.QWEN_EXECUTION_HEAD,
        "successor_lock_sha256": contract.QWEN_LOCK_SHA256,
        "authorization_receipt_sha256": contract.QWEN_AUTHORIZATION_SHA256,
        "pricing_recheck_receipt_sha256": contract.QWEN_PRICING_RECHECK_SHA256,
        "first_recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
        "rule3_lock_sha256": contract.RULE3_LOCK_SHA256,
        "qwen_parent_claim": {
            "path": contract.QWEN_PARENT_CLAIM_PATH,
            "sha256": contract.QWEN_PARENT_CLAIM_SHA256,
        },
    }


def _validate_manifest(record: JournalRecord) -> None:
    _require_fields(
        record.payload,
        {
            "schema_version": "concordance-qwen-successor-manifest-1.0.0",
            "status": "complete-six-route-five-model-fresh-preflight",
            **_common(),
        },
        "Qwen successor manifest",
    )
    require_timestamp(record.payload.get("sealed_at"), "Qwen manifest seal time")
    outcomes = record.payload.get("preflight_outcomes")
    if not isinstance(outcomes, list):
        raise RecoveryJournalError("Qwen successor manifest outcomes changed")
    by_route = {
        item.get("route_key"): item for item in outcomes if isinstance(item, dict)
    }
    expected = {
        "grok": {
            "route_key": "grok",
            "model_key": "grok",
            "path": contract.GROK_PREFLIGHT_OUTCOME_PATH,
            "sha256": contract.GROK_PREFLIGHT_OUTCOME_SHA256,
            "provider_returned_model_id": "grok-4.5",
        },
        "gpt": {
            "route_key": "gpt",
            "model_key": "gpt",
            "path": contract.GPT_PREFLIGHT_OUTCOME_PATH,
            "sha256": contract.GPT_PREFLIGHT_OUTCOME_SHA256,
            "provider_returned_model_id": "openai/gpt-5.6-sol",
        },
    }
    if set(by_route) != {
        "qwen",
        "qwen-openrouter",
        "deepseek",
        "mistral",
        "grok",
        "gpt",
    } or any(not _exact_equal(by_route[key], value) for key, value in expected.items()):
        raise RecoveryJournalError("reused Grok/GPT preflight bindings changed")


def _validate_success_outcome(
    record: JournalRecord,
    *,
    model_key: str,
    provider: str,
    route: str,
    model_id: str,
    semantic_attempt: int,
    response_sha256: str,
) -> None:
    _require_fields(
        record.payload,
        {
            "schema_version": "concordance-qwen-successor-generation-outcome-1.0.0",
            "status": "success",
            **_common(),
            "model_key": model_key,
            "provider": provider,
            "route": route,
            "requested_model_id": model_id,
            "semantic_attempt_number": semantic_attempt,
            "provider_returned_model_id": model_id,
            "response_sha256": response_sha256,
            "finish_reason": "stop",
            "manifest": {
                "path": contract.QWEN_MANIFEST_PATH,
                "sha256": contract.QWEN_MANIFEST_SHA256,
            },
        },
        f"preserved {model_key} outcome",
    )
    response = record.payload.get("response_text")
    if (
        not isinstance(response, str)
        or not response.strip()
        or contract.sha256_bytes(response.encode("utf-8")) != response_sha256
    ):
        raise RecoveryJournalError(f"preserved {model_key} response changed")


def _validate_grok_error(
    intent: JournalRecord, raw: JournalRecord, outcome: JournalRecord
) -> None:
    common = _common()
    _require_fields(
        intent.payload,
        {
            "schema_version": "concordance-qwen-successor-generation-intent-1.0.0",
            "status": "reserved-before-generation-post",
            **common,
            "model_key": "grok",
            "provider": "xai",
            "route": "xai-direct",
            "requested_model_id": "grok-4.5",
            "semantic_attempt_number": 1,
            "reserved_cost_microdollars": contract.RESERVED_PER_POST["grok"],
            "prompt_sha256": contract.GROK_PROMPT_SHA256,
            "messages_sha256": contract.GROK_MESSAGES_SHA256,
            "requested_params_sha256": contract.GROK_REQUESTED_PARAMS_SHA256,
            "request_json_body_sha256": contract.GROK_REQUEST_BODY_SHA256,
            "manifest": {
                "path": contract.QWEN_MANIFEST_PATH,
                "sha256": contract.QWEN_MANIFEST_SHA256,
            },
            "preflight_outcome": {
                "path": contract.GROK_PREFLIGHT_OUTCOME_PATH,
                "sha256": contract.GROK_PREFLIGHT_OUTCOME_SHA256,
            },
            "replacement_of_parent_intent": None,
        },
        "captured Grok intent",
    )
    require_timestamp(intent.payload.get("created_at"), "captured Grok intent time")
    _require_fields(
        raw.payload,
        {
            "schema_version": "concordance-recovery-raw-http-response-1.0.0",
            "status": "durable-http-response-before-validation",
            **common,
            "model_key": "grok",
            "semantic_attempt_number": 1,
            "request_kind": "generation",
            "intent": {
                "path": contract.GROK_ERROR_INTENT_PATH,
                "sha256": contract.GROK_ERROR_INTENT_SHA256,
            },
        },
        "captured Grok raw response",
    )
    request = raw.payload.get("request")
    response = raw.payload.get("response")
    if (
        not isinstance(request, dict)
        or request.get("method") != "POST"
        or request.get("origin") != "https://api.x.ai/v1/responses"
        or request.get("json_body_sha256") != contract.GROK_REQUEST_BODY_SHA256
        or not isinstance(response, dict)
        or response.get("status") != 403
    ):
        raise RecoveryJournalError("captured Grok HTTP 403 evidence changed")
    require_timestamp(raw.payload.get("received_at"), "captured Grok response time")
    _require_fields(
        outcome.payload,
        {
            "schema_version": "concordance-qwen-successor-generation-outcome-1.0.0",
            "status": "error",
            **common,
            "model_key": "grok",
            "provider": "xai",
            "route": "xai-direct",
            "requested_model_id": "grok-4.5",
            "semantic_attempt_number": 1,
            "prompt_sha256": contract.GROK_PROMPT_SHA256,
            "messages_sha256": contract.GROK_MESSAGES_SHA256,
            "requested_params_sha256": contract.GROK_REQUESTED_PARAMS_SHA256,
            "manifest": {
                "path": contract.QWEN_MANIFEST_PATH,
                "sha256": contract.QWEN_MANIFEST_SHA256,
            },
            "preflight_outcome": {
                "path": contract.GROK_PREFLIGHT_OUTCOME_PATH,
                "sha256": contract.GROK_PREFLIGHT_OUTCOME_SHA256,
            },
            "intent": {
                "path": contract.GROK_ERROR_INTENT_PATH,
                "sha256": contract.GROK_ERROR_INTENT_SHA256,
            },
            "raw_response": {
                "path": contract.GROK_ERROR_RAW_PATH,
                "sha256": contract.GROK_ERROR_RAW_SHA256,
            },
            "error": {
                "category": "authorization",
                "retryable": False,
                "sanitized_summary": "generation request failed (authorization)",
            },
        },
        "captured Grok error outcome",
    )
    require_timestamp(outcome.payload.get("attempted_at"), "Grok attempted time")
    require_timestamp(outcome.payload.get("completed_at"), "Grok completed time")


def _generation_reserve(records: Mapping[str, JournalRecord]) -> int:
    expected = {
        "generation/intents/qwen/attempt-2.json": 49_243,
        "generation/intents/deepseek/attempt-1.json": 14_342,
        "generation/intents/mistral/attempt-1.json": 24_677,
        contract.GROK_ERROR_INTENT_PATH: 98_708,
    }
    actual = {
        path: record.payload.get("reserved_cost_microdollars")
        for path, record in records.items()
        if path.startswith("generation/intents/")
    }
    if not _exact_equal(actual, expected):
        raise RecoveryJournalError("Qwen successor generation reservations changed")
    return sum(expected.values())


def _require_execution_ancestor(repository_root: Path, current_head: Any) -> None:
    if not isinstance(current_head, str):
        raise RecoveryJournalError("Qwen successor validation lacks a Git HEAD")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    result = subprocess.run(
        [
            "/usr/bin/git",
            "merge-base",
            "--is-ancestor",
            contract.QWEN_EXECUTION_HEAD,
            current_head,
        ],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RecoveryJournalError(
            "Qwen successor execution HEAD is not an ancestor of current HEAD"
        )


def validate_parent_snapshot(
    repository_root: Path | str, retry_lock: dict[str, Any] | None = None
) -> ParentEvidence:
    """Validate the four-lineage parent without credentials or network."""

    root = Path(repository_root).resolve()
    _validate_retry_parent_contract(retry_lock)
    try:
        qwen_lock = load_qwen_lock(
            root,
            require_committed=True,
            require_parent_private=True,
        )
        base = validate_qwen_parent(root, qwen_lock.lock)
    except Exception as error:
        if isinstance(error, RecoveryJournalError):
            raise
        raise RecoveryJournalError(
            f"sealed Qwen successor parent no longer validates: {error}"
        ) from error
    if qwen_lock.lock_sha256 != contract.QWEN_LOCK_SHA256:
        raise RecoveryJournalError("Qwen successor lock hash changed")
    _require_execution_ancestor(root, qwen_lock.git_head)

    private_root = root / contract.QWEN_PRIVATE_ROOT
    records = _read_parent_records(private_root)
    _validate_required_absences(private_root)
    claim = _validate_claim_area(root)
    manifest = records[contract.QWEN_MANIFEST_PATH]
    qwen = records[contract.QWEN_OUTCOME_PATH]
    deepseek = records[contract.DEEPSEEK_OUTCOME_PATH]
    mistral = records[contract.MISTRAL_OUTCOME_PATH]
    grok_intent = records[contract.GROK_ERROR_INTENT_PATH]
    grok_raw = records[contract.GROK_ERROR_RAW_PATH]
    grok_outcome = records[contract.GROK_ERROR_OUTCOME_PATH]

    _validate_manifest(manifest)
    _validate_success_outcome(
        qwen,
        model_key="qwen",
        provider="deepinfra",
        route="deepinfra",
        model_id="Qwen/Qwen3.5-397B-A17B",
        semantic_attempt=2,
        response_sha256=contract.QWEN_RESPONSE_SHA256,
    )
    _validate_success_outcome(
        deepseek,
        model_key="deepseek",
        provider="deepseek",
        route="deepseek-direct",
        model_id="deepseek-v4-pro",
        semantic_attempt=1,
        response_sha256=contract.DEEPSEEK_RESPONSE_SHA256,
    )
    _validate_success_outcome(
        mistral,
        model_key="mistral",
        provider="mistral",
        route="mistral-direct",
        model_id="mistral-large-2512",
        semantic_attempt=1,
        response_sha256=contract.MISTRAL_RESPONSE_SHA256,
    )
    _validate_grok_error(grok_intent, grok_raw, grok_outcome)

    reserved = base.reserved_microdollars + _generation_reserve(records)
    if reserved != contract.INHERITED_RESERVED_MICRODOLLARS:
        raise RecoveryJournalError("Grok retry inherited reservation total changed")
    evidence = ParentEvidence(
        rule3=base.rule3,
        cohere_outcome=base.cohere_outcome,
        qwen_outcome=qwen,
        deepseek_outcome=deepseek,
        mistral_outcome=mistral,
        grok_error_intent=grok_intent,
        grok_error_raw=grok_raw,
        grok_error_outcome=grok_outcome,
        parent_manifest=manifest,
        parent_claim=claim,
        private_root=private_root,
        reserved_microdollars=reserved,
    )
    if (
        tuple(record.payload.get("model_key") for record in evidence.preserved_outcomes)
        != contract.PRESERVED_MODEL_KEYS
    ):
        raise RecoveryJournalError("preserved parent model order changed")
    return evidence


__all__ = ("ParentEvidence", "validate_parent_snapshot")

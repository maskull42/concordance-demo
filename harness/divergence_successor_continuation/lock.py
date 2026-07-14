"""Write-once public lock for the approved zero-preflight continuation."""

from __future__ import annotations

import copy
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from concordance_recovery.journal import read_record

from . import contract, correction


class ContinuationLockError(contract.ContinuationContractError):
    """The public continuation lock is absent, stale, or incomplete."""


@dataclass(frozen=True)
class LockContext:
    repository_root: Path
    lock: dict[str, Any]
    lock_bytes: bytes
    lock_sha256: str
    git_head: str | None


def _public_binding(root: Path, relative: str) -> dict[str, str]:
    try:
        payload = contract.parent_contract.read_regular_file(root, relative)
    except contract.parent_contract.ContractError as error:
        raise ContinuationLockError(str(error)) from error
    return {"path": relative, "sha256": sha256_bytes(payload)}


def _private_binding(root: Path, path: Path, label: str) -> dict[str, str]:
    try:
        record = read_record(path, label)
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError) as error:
        raise ContinuationLockError(str(error)) from error
    return {"path": relative, "sha256": record.sha256}


def _original_preflight_bindings(prepared: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    root = prepared.repository_root
    for key in contract.MODEL_KEYS:
        records.append(
            {
                "model_key": key,
                "intent": _private_binding(
                    root, prepared.paths.preflight_intent(key), f"original intent {key}"
                ),
                "raw_response": _private_binding(
                    root,
                    prepared.paths.preflight_raw(key),
                    f"original raw response {key}",
                ),
                "outcome": _private_binding(
                    root,
                    prepared.paths.preflight_outcome(key),
                    f"original outcome {key}",
                ),
            }
        )
    return records


def build_lock(repository_root: Path | str) -> dict[str, Any]:
    """Build from committed public sources and exact sealed private evidence."""

    root = contract.repository_root(repository_root)
    contract.require_approval()
    prepared, authority = correction.load_historical_parent(root, fresh_pricing=False)
    corrected = correction.verify_correction_record(root)
    parent = prepared.lock_context
    if (
        parent.lock_sha256
        != _public_binding(root, contract.ORIGINAL_LOCK_PATH)["sha256"]
    ):
        raise ContinuationLockError("the original public lock hash changed")
    plans = parent.lock.get("plans")
    models = parent.lock.get("models")
    if (
        not isinstance(plans, dict)
        or not isinstance(models, list)
        or len(models) != 8
        or tuple(item.get("model_key") for item in models) != contract.MODEL_KEYS
    ):
        raise ContinuationLockError("the frozen eight-model plan changed")
    sources = [_public_binding(root, path) for path in contract.EXECUTION_SOURCE_PATHS]
    return {
        "schema_version": contract.LOCK_SCHEMA_VERSION,
        "status": contract.LOCK_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "private_root": contract.PRIVATE_ROOT_RELATIVE,
        "bindings": {
            "lock_schema": _public_binding(root, contract.LOCK_SCHEMA_PATH),
            "question": copy.deepcopy(parent.lock["bindings"]["question"]),
            "protocol": copy.deepcopy(parent.lock["bindings"]["protocol"]),
            "models_config": copy.deepcopy(parent.lock["bindings"]["models_config"]),
        },
        "approval": {
            "authorized_by": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
            "statement": contract.APPROVAL_STATEMENT,
            "statement_sha256": contract.APPROVAL_STATEMENT_SHA256,
            "option": 2,
            "offline_correction_authorized": True,
            "generation_calls_authorized": 8,
            "lock_authorizes_spending": False,
        },
        "parent": {
            "lock": _public_binding(root, contract.ORIGINAL_LOCK_PATH),
            "historical_git_head": prepared.lock_context.git_head,
            "authorization": _private_binding(
                root, authority.authorization.path, "original authorization"
            ),
            "pricing_recheck": _private_binding(
                root, authority.pricing.path, "original pricing recheck"
            ),
            "preflight_records": _original_preflight_bindings(prepared),
            "original_private_inventory_files": 27,
            "original_artifacts_preserved": True,
        },
        "offline_correction": {
            **_private_binding(root, corrected.path, "offline correction receipt"),
            "sealed_metadata_responses_reused": 8,
            "new_metadata_requests": 0,
            "false_negative_model_keys": ["claude", "gpt"],
        },
        "models": copy.deepcopy(models),
        "plans": copy.deepcopy(plans),
        "execution_policy": {
            "call_type": "answer",
            "cells": 8,
            "metadata_requests": 0,
            "generation_posts": 8,
            "semantic_attempts_per_cell": 1,
            "automatic_retries": 0,
            "fallback_allowed": False,
            "all_intents_durable_before_parallel_release": True,
            "generation_parallel": True,
            "raw_response_durable_before_validation": True,
            "stranded_or_failed_cell_is_terminal": True,
            "output_token_cap": contract.OUTPUT_TOKEN_CAP,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        },
        "network_policy": {
            "maximum_metadata_gets": 0,
            "maximum_generation_posts": 8,
            "maximum_outbound_requests": 8,
            "authorized_hosts": list(contract.parent_contract.AUTHORIZED_HOSTS),
            "unlisted_network_access_allowed": False,
        },
        "budget": {
            "reserved_cost_microdollars": authority.pricing.payload[
                "reserved_cost_microdollars"
            ],
            "candidate_cap_microdollars": contract.CANDIDATE_COST_CAP_MICRODOLLARS,
            "pool_cap_microdollars": contract.POOL_COST_CAP_MICRODOLLARS,
            "freshness_window_hours": 24,
            "historical_pricing_receipt_reused": True,
            "lock_authorizes_spending": False,
        },
        "paid_authorization": {
            "private_receipt_required": True,
            "private_receipt_present_at_lock_time": False,
            "provider_calls_allowed_by_lock_alone": False,
            "exact_approval_bound": True,
        },
        "execution_sources": sources,
    }


def _difference(actual: Any, expected: Any, path: str = "lock") -> str | None:
    if type(actual) is not type(expected):
        return f"{path} type differs"
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            return f"{path} fields differ"
        for key in expected:
            found = _difference(actual[key], expected[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(expected, list):
        if len(actual) != len(expected):
            return f"{path} length differs"
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            found = _difference(left, right, f"{path}[{index}]")
            if found:
                return found
        return None
    return None if actual == expected else f"{path} differs"


def _parse_lock(root: Path) -> tuple[dict[str, Any], bytes]:
    try:
        payload = contract.parent_contract.read_regular_file(root, contract.LOCK_PATH)
        value = contract.parent_contract.parse_json_bytes(payload, "continuation lock")
    except contract.parent_contract.ContractError as error:
        raise ContinuationLockError(str(error)) from error
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        raise ContinuationLockError(
            "continuation lock must be one canonical JSON object"
        )
    return value, payload


def _git(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )


def _require_public_sources_committed(
    root: Path, value: dict[str, Any], *, include_lock: bool
) -> str:
    head_result = _git(root, ["rev-parse", "HEAD"])
    if head_result.returncode:
        raise ContinuationLockError("Git HEAD cannot be read")
    head = head_result.stdout.decode().strip()
    paths = [item["path"] for item in value["bindings"].values()]
    paths.extend(item["path"] for item in value["execution_sources"])
    paths.append(contract.ORIGINAL_LOCK_PATH)
    if include_lock:
        paths.append(contract.LOCK_PATH)
    paths = list(dict.fromkeys(paths))
    status = _git(
        root, ["status", "--porcelain", "--untracked-files=all", "--", *paths]
    )
    if status.returncode or status.stdout.strip():
        raise ContinuationLockError(
            "continuation lock sources must be committed and clean"
        )
    for relative in paths:
        disk = contract.parent_contract.read_regular_file(root, relative)
        committed = _git(root, ["show", f"{head}:{relative}"])
        if committed.returncode or committed.stdout != disk:
            raise ContinuationLockError(f"{relative} differs from committed HEAD")
    return head


def load_and_validate_lock(
    repository_root: Path | str,
    *,
    require_committed: bool = False,
) -> LockContext:
    root = contract.repository_root(repository_root)
    value, payload = _parse_lock(root)
    expected = build_lock(root)
    difference = _difference(value, expected)
    if difference:
        raise ContinuationLockError(difference)
    git_head = (
        _require_public_sources_committed(root, value, include_lock=True)
        if require_committed
        else None
    )
    return LockContext(root, value, payload, sha256_bytes(payload), git_head)


def write_lock(repository_root: Path | str) -> LockContext:
    root = contract.repository_root(repository_root)
    value = build_lock(root)
    _require_public_sources_committed(root, value, include_lock=False)
    path = root / contract.LOCK_PATH
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return load_and_validate_lock(root, require_committed=False)


def readiness(repository_root: Path | str) -> dict[str, Any]:
    issues: list[str] = []
    try:
        build_lock(repository_root)
    except (OSError, RuntimeError, ValueError) as error:
        issues.append(str(error))
    return {
        "status": "ready-to-seal-continuation-lock" if not issues else "blocked",
        "issues": issues,
        "metadata_requests": 0,
        "generation_posts": 8,
        "network_requests": 0,
        "environment_variables_read": 0,
        "private_writes": 0,
        "lock_authorizes_spending": False,
    }


__all__ = (
    "ContinuationLockError",
    "LockContext",
    "build_lock",
    "load_and_validate_lock",
    "readiness",
    "write_lock",
)

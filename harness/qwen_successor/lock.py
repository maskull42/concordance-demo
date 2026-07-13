"""Build and validate the immutable Qwen successor lock."""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_recovery.contract import (
    canonical_json_bytes,
    parse_json_bytes,
    read_regular_file,
    sha256_bytes,
)
from concordance_recovery.lock import (
    RecoveryLockError,
    _require_committed_and_clean,
    load_and_validate_recovery_lock,
)

from . import contract


QwenSuccessorLockError = RecoveryLockError


@dataclass(frozen=True)
class LockContext:
    repository_root: Path
    lock: dict[str, Any]
    lock_bytes: bytes
    lock_sha256: str
    git_head: str | None


def _binding(root: Path, relative: str) -> dict[str, str]:
    payload = read_regular_file(root, relative)
    return {"path": relative, "sha256": sha256_bytes(payload)}


def _load_first_lock(root: Path) -> tuple[dict[str, Any], bytes]:
    payload = read_regular_file(root, contract.FIRST_LOCK_PATH)
    if sha256_bytes(payload) != contract.FIRST_LOCK_SHA256:
        raise QwenSuccessorLockError("first recovery lock hash changed")
    parsed = parse_json_bytes(payload, contract.FIRST_LOCK_PATH)
    if not isinstance(parsed, dict):
        raise QwenSuccessorLockError("first recovery lock is not an object")
    return parsed, payload


def _target_cells(first: dict[str, Any]) -> list[dict[str, Any]]:
    plan = first.get("target_plan")
    values = plan.get("cells") if isinstance(plan, dict) else None
    if not isinstance(values, list):
        raise QwenSuccessorLockError("first recovery target plan is malformed")
    by_key = {
        item.get("model_key"): item
        for item in values
        if isinstance(item, dict) and isinstance(item.get("model_key"), str)
    }
    try:
        cells = [copy.deepcopy(by_key[key]) for key in contract.TARGET_MODEL_KEYS]
    except KeyError as error:
        raise QwenSuccessorLockError(
            "successor target is absent from first plan"
        ) from error
    qwen = cells[0]
    if (
        qwen.get("provider") != "deepinfra"
        or qwen.get("route") != "deepinfra"
        or qwen.get("requested_model_id") != "Qwen/Qwen3.5-397B-A17B"
        or qwen.get("fallback_allowed") is not False
    ):
        raise QwenSuccessorLockError(
            "Qwen is not pinned to the original DeepInfra route"
        )
    for index, cell in enumerate(cells):
        key = contract.TARGET_MODEL_KEYS[index]
        cell["ordinal"] = index + 1
        cell["semantic_attempt_start"] = 2 if key == "qwen" else 1
        cell["maximum_generation_posts"] = 1 if key == "qwen" else 3
        cell["reserved_cost_microdollars_per_post"] = contract.RESERVED_PER_POST[key]
        cell["fresh_preflight_required_before_any_generation"] = True
    return cells


def _execution_sources(root: Path, first: dict[str, Any]) -> list[dict[str, str]]:
    inherited = first.get("execution_sources")
    if not isinstance(inherited, list):
        raise QwenSuccessorLockError("first lock lacks execution source bindings")
    paths: set[str] = set(contract.NEW_SOURCE_PATHS)
    for item in inherited:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise QwenSuccessorLockError("first execution source binding is malformed")
        paths.add(item["path"])
    return [_binding(root, path) for path in sorted(paths)]


def _validate_static() -> None:
    new = (
        contract.RESERVED_PER_POST["qwen"]
        + contract.QWEN_OPENROUTER_RESERVED_MICRODOLLARS
        + 3
        * sum(contract.RESERVED_PER_POST[key] for key in contract.UNTOUCHED_MODEL_KEYS)
    )
    if (
        tuple((*contract.PRESERVED_MODEL_KEYS, *contract.TARGET_MODEL_KEYS))
        != contract.MODEL_ORDER
        or len(contract.FIRST_PRIVATE_SHA256) != 26
        or new != contract.NEW_RESERVED_CAP_MICRODOLLARS
        or contract.INHERITED_RESERVED_MICRODOLLARS + new
        != contract.COMBINED_RESERVED_CAP_MICRODOLLARS
        or contract.COMBINED_RESERVED_CAP_MICRODOLLARS
        > contract.CANDIDATE_CAP_MICRODOLLARS
        or contract.MAX_PREFLIGHT_REQUESTS
        != len(contract.PREFLIGHT_ROUTE_KEYS) * contract.PREFLIGHT_ATTEMPTS_PER_MODEL
        or contract.MAX_GENERATION_POSTS != 2 + 4 * 3
        or contract.MAX_OUTBOUND_REQUESTS
        != contract.MAX_PREFLIGHT_REQUESTS + contract.MAX_GENERATION_POSTS
    ):
        raise QwenSuccessorLockError("Qwen successor static contract is inconsistent")


def build_lock(repository_root: Path | str) -> dict[str, Any]:
    """Build without reading credentials, private response content, or network."""
    _validate_static()
    root = Path(repository_root).resolve()
    first, first_payload = _load_first_lock(root)
    cells = _target_cells(first)
    first_bindings = [
        {"path": path, "sha256": digest}
        for path, digest in sorted(contract.FIRST_PRIVATE_SHA256.items())
    ]
    return {
        "schema_version": contract.SCHEMA_VERSION,
        "status": contract.LOCK_STATUS,
        "recovery_id": contract.RECOVERY_ID,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "phase": contract.PHASE,
        "private_root": contract.PRIVATE_ROOT_RELATIVE,
        "bindings": {
            "first_recovery_lock": {
                "path": contract.FIRST_LOCK_PATH,
                "sha256": sha256_bytes(first_payload),
            },
            "rule3_lock": _binding(root, contract.RULE3_LOCK_PATH),
        },
        "parent": {
            "first_execution_head": contract.FIRST_EXECUTION_HEAD,
            "first_lock_sha256": contract.FIRST_LOCK_SHA256,
            "first_private_root": contract.FIRST_PRIVATE_ROOT,
            "first_private_bindings": first_bindings,
            "first_private_binding_count": len(first_bindings),
            "first_claim": {
                "path": contract.FIRST_CLAIM_PATH,
                "sha256": contract.FIRST_CLAIM_SHA256,
            },
            "first_phase_lock_path": contract.FIRST_CLAIM_LOCK_PATH,
            "required_absent": list(contract.FIRST_REQUIRED_ABSENT),
            "first_extra_empty_directories": list(
                contract.FIRST_EXTRA_EMPTY_DIRECTORIES
            ),
            "exact_file_and_directory_inventory_required": True,
            "rule3_lock_sha256": contract.RULE3_LOCK_SHA256,
            "rule3_plan_sha256": contract.RULE3_PLAN_SHA256,
        },
        "preserved_successes": [
            {"model_key": "gemini", "source_lane": "immutable-rule3-parent"},
            {"model_key": "claude", "source_lane": "immutable-rule3-parent"},
            {
                "model_key": "cohere",
                "source_lane": "immutable-cohere-recovery",
                "path": contract.COHERE_OUTCOME_PATH,
                "sha256": contract.COHERE_OUTCOME_SHA256,
                "response_sha256": contract.COHERE_RESPONSE_SHA256,
                "semantic_attempt_number": 2,
            },
        ],
        "stranded_qwen": {
            "model_key": "qwen",
            "path": contract.QWEN_STRANDED_INTENT_PATH,
            "sha256": contract.QWEN_STRANDED_INTENT_SHA256,
            "semantic_attempt_number": 1,
            "route": "deepinfra",
            "requested_model_id": "Qwen/Qwen3.5-397B-A17B",
            "reserved_cost_microdollars": contract.RESERVED_PER_POST["qwen"],
            "disposition": "consumed-possibly-delivered-possibly-billed-one-replacement",
        },
        "target_plan": {
            "model_order": list(contract.TARGET_MODEL_KEYS),
            "cells": cells,
            "plan_sha256": sha256_bytes(canonical_json_bytes(cells)),
            "qwen_openrouter_fallback": copy.deepcopy(contract.QWEN_OPENROUTER),
        },
        "preflight_policy": {
            "route_keys": list(contract.PREFLIGHT_ROUTE_KEYS),
            "all_six_route_successes_required_before_generation": True,
            "maximum_attempts_per_model": contract.PREFLIGHT_ATTEMPTS_PER_MODEL,
            "maximum_requests": contract.MAX_PREFLIGHT_REQUESTS,
            "authenticated": True,
            "fresh": True,
            "intent_before_request": True,
            "raw_response_before_validation": True,
        },
        "generation_policy": {
            "model_order": list(contract.TARGET_MODEL_KEYS),
            "qwen_semantic_attempt_number": 2,
            "qwen_maximum_replacement_posts": 1,
            "qwen_route": "deepinfra",
            "qwen_openrouter_fallback_allowed": True,
            "qwen_openrouter_fallback": copy.deepcopy(contract.QWEN_OPENROUTER),
            "qwen_openrouter_semantic_attempt_number": 3,
            "qwen_openrouter_maximum_posts": 1,
            "deepinfra_noncapture_authorizes_openrouter_fallback": True,
            "qwen_success_required_before_later_generation": True,
            "untouched_maximum_safe_attempts_per_cell": 3,
            "maximum_posts": contract.MAX_GENERATION_POSTS,
            "deepinfra_qwen_attempt_2_without_capture_is_consumed": True,
            "deepinfra_qwen_attempt_2_without_capture_advances_once_to_openrouter": True,
            "openrouter_qwen_attempt_3_without_capture_is_terminal": True,
            "downstream_post_without_capture_is_terminal": True,
            "preserved_model_generation_forbidden": list(contract.PRESERVED_MODEL_KEYS),
            "intent_before_post": True,
            "raw_response_before_validation": True,
            "output_token_cap": contract.OUTPUT_TOKEN_CAP,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        },
        "budget": {
            "inherited_reserved_microdollars": contract.INHERITED_RESERVED_MICRODOLLARS,
            "per_post_reserved_microdollars": {
                **copy.deepcopy(contract.RESERVED_PER_POST),
                "qwen-openrouter": contract.QWEN_OPENROUTER_RESERVED_MICRODOLLARS,
            },
            "new_reserved_cap_microdollars": contract.NEW_RESERVED_CAP_MICRODOLLARS,
            "combined_reserved_cap_microdollars": contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
            "candidate_cap_microdollars": contract.CANDIDATE_CAP_MICRODOLLARS,
            "pool_cap_microdollars": contract.POOL_CAP_MICRODOLLARS,
        },
        "network_policy": {
            "maximum_preflight_gets": contract.MAX_PREFLIGHT_REQUESTS,
            "maximum_generation_posts": contract.MAX_GENERATION_POSTS,
            "maximum_outbound_requests": contract.MAX_OUTBOUND_REQUESTS,
            "authorized_qwen_openrouter_fallback_network_access_allowed": True,
            "unlisted_fallback_network_access_allowed": False,
        },
        "paid_authorization": {
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
        },
        "execution_sources": _execution_sources(root, first),
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


def _bound_paths(lock: dict[str, Any]) -> tuple[str, ...]:
    paths = [contract.LOCK_PATH, contract.FIRST_LOCK_PATH, contract.RULE3_LOCK_PATH]
    paths.extend(item["path"] for item in lock["execution_sources"])
    return tuple(dict.fromkeys(paths))


def validate_lock(
    raw: Any,
    repository_root: Path | str,
    *,
    require_committed: bool = False,
    require_parent_private: bool = False,
) -> LockContext:
    root = Path(repository_root).resolve()
    expected = build_lock(root)
    difference = _difference(raw, expected)
    if difference:
        raise QwenSuccessorLockError(difference)
    path = root / contract.LOCK_PATH
    payload = canonical_json_bytes(raw)
    if path.exists():
        disk = read_regular_file(root, contract.LOCK_PATH)
        parsed = parse_json_bytes(disk, contract.LOCK_PATH)
        if disk != canonical_json_bytes(parsed) or parsed != raw:
            raise QwenSuccessorLockError("on-disk Qwen successor lock differs")
        payload = disk
    elif require_committed:
        raise QwenSuccessorLockError("committed Qwen successor lock is required")
    git_head = None
    if require_committed:
        load_and_validate_recovery_lock(root, require_committed=True)
        git_head = _require_committed_and_clean(root, _bound_paths(raw))
    context = LockContext(root, raw, payload, sha256_bytes(payload), git_head)
    if require_parent_private:
        from .parent import validate_parent_snapshot

        validate_parent_snapshot(root, raw)
    return context


def load_lock(
    repository_root: Path | str,
    *,
    require_committed: bool = False,
    require_parent_private: bool = False,
) -> LockContext:
    root = Path(repository_root).resolve()
    payload = read_regular_file(root, contract.LOCK_PATH)
    parsed = parse_json_bytes(payload, contract.LOCK_PATH)
    if payload != canonical_json_bytes(parsed):
        raise QwenSuccessorLockError("Qwen successor lock is not canonical JSON")
    return validate_lock(
        parsed,
        root,
        require_committed=require_committed,
        require_parent_private=require_parent_private,
    )


def write_lock(repository_root: Path | str) -> LockContext:
    root = Path(repository_root).resolve()
    raw = build_lock(root)
    payload = canonical_json_bytes(raw)
    path = root / contract.LOCK_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    return load_lock(root)


__all__ = (
    "LockContext",
    "QwenSuccessorLockError",
    "build_lock",
    "load_lock",
    "validate_lock",
    "write_lock",
)

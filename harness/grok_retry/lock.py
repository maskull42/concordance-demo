"""Build and validate the immutable Grok retry lock."""

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
from qwen_successor.lock import load_lock as load_qwen_lock

from . import contract
from .parent import _expected_parent_contract


GrokRetryLockError = RecoveryLockError


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


def _load_qwen_lock(root: Path) -> tuple[dict[str, Any], bytes]:
    payload = read_regular_file(root, contract.QWEN_LOCK_PATH)
    if sha256_bytes(payload) != contract.QWEN_LOCK_SHA256:
        raise GrokRetryLockError("Qwen successor lock hash changed")
    parsed = parse_json_bytes(payload, contract.QWEN_LOCK_PATH)
    if not isinstance(parsed, dict):
        raise GrokRetryLockError("Qwen successor lock is not an object")
    return parsed, payload


def _target_cells(qwen_lock: dict[str, Any]) -> list[dict[str, Any]]:
    plan = qwen_lock.get("target_plan")
    values = plan.get("cells") if isinstance(plan, dict) else None
    if not isinstance(values, list):
        raise GrokRetryLockError("Qwen successor target plan is malformed")
    by_key = {
        item.get("model_key"): item
        for item in values
        if isinstance(item, dict) and isinstance(item.get("model_key"), str)
    }
    try:
        cells = [copy.deepcopy(by_key[key]) for key in contract.TARGET_MODEL_KEYS]
    except KeyError as error:
        raise GrokRetryLockError(
            "Grok retry target is absent from parent plan"
        ) from error
    exact = {
        "grok": ("xai", "xai-direct", "grok-4.5", "XAI_API_KEY"),
        "gpt": (
            "openrouter",
            "openrouter-openai-pinned",
            "openai/gpt-5.6-sol",
            "OPENROUTER_API_KEY",
        ),
    }
    for ordinal, cell in enumerate(cells, start=1):
        key = contract.TARGET_MODEL_KEYS[ordinal - 1]
        actual = (
            cell.get("provider"),
            cell.get("route"),
            cell.get("requested_model_id"),
            cell.get("environment_variable"),
        )
        if actual != exact[key] or cell.get("fallback_allowed") is not False:
            raise GrokRetryLockError(f"parent {key} route changed")
        cell["ordinal"] = ordinal
        cell["semantic_attempt_start"] = 2 if key == "grok" else 1
        cell["maximum_generation_posts"] = (
            contract.GROK_MAXIMUM_POSTS
            if key == "grok"
            else contract.GPT_MAXIMUM_SAFE_ATTEMPTS
        )
        cell["reserved_cost_microdollars_per_post"] = contract.RESERVED_PER_POST[key]
        cell["fresh_preflight_required_before_any_generation"] = False
        cell["reused_parent_preflight"] = {
            "manifest_path": contract.QWEN_MANIFEST_PATH,
            "manifest_sha256": contract.QWEN_MANIFEST_SHA256,
            "outcome_path": (
                contract.GROK_PREFLIGHT_OUTCOME_PATH
                if key == "grok"
                else contract.GPT_PREFLIGHT_OUTCOME_PATH
            ),
            "outcome_sha256": (
                contract.GROK_PREFLIGHT_OUTCOME_SHA256
                if key == "grok"
                else contract.GPT_PREFLIGHT_OUTCOME_SHA256
            ),
        }
    return cells


def _execution_sources(root: Path, qwen_lock: dict[str, Any]) -> list[dict[str, str]]:
    inherited = qwen_lock.get("execution_sources")
    if not isinstance(inherited, list):
        raise GrokRetryLockError("Qwen successor lock lacks source bindings")
    paths: set[str] = set(contract.NEW_SOURCE_PATHS)
    for item in inherited:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise GrokRetryLockError("parent execution source binding is malformed")
        paths.add(item["path"])
    return [_binding(root, path) for path in sorted(paths)]


def _validate_static() -> None:
    new = contract.RESERVED_PER_POST["grok"] + (
        contract.GPT_MAXIMUM_SAFE_ATTEMPTS * contract.RESERVED_PER_POST["gpt"]
    )
    if (
        tuple((*contract.PRESERVED_MODEL_KEYS, *contract.TARGET_MODEL_KEYS))
        != contract.MODEL_ORDER
        or len(contract.QWEN_PRIVATE_SHA256) != 34
        or new != contract.NEW_RESERVED_CAP_MICRODOLLARS
        or contract.INHERITED_RESERVED_MICRODOLLARS + new
        != contract.COMBINED_RESERVED_CAP_MICRODOLLARS
        or contract.COMBINED_RESERVED_CAP_MICRODOLLARS
        > contract.CANDIDATE_CAP_MICRODOLLARS
        or contract.CANDIDATE_CAP_MICRODOLLARS > contract.POOL_CAP_MICRODOLLARS
        or contract.MAX_PREFLIGHT_REQUESTS != 0
        or contract.MAX_GENERATION_POSTS
        != contract.GROK_MAXIMUM_POSTS + contract.GPT_MAXIMUM_SAFE_ATTEMPTS
        or contract.MAX_OUTBOUND_REQUESTS != contract.MAX_GENERATION_POSTS
    ):
        raise GrokRetryLockError("Grok retry static contract is inconsistent")


def build_lock(repository_root: Path | str) -> dict[str, Any]:
    """Build without reading credentials, private response content, or network."""

    _validate_static()
    root = Path(repository_root).resolve()
    qwen_lock, qwen_payload = _load_qwen_lock(root)
    cells = _target_cells(qwen_lock)
    return {
        "schema_version": contract.SCHEMA_VERSION,
        "status": contract.LOCK_STATUS,
        "recovery_id": contract.RECOVERY_ID,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "phase": contract.PHASE,
        "private_root": contract.PRIVATE_ROOT_RELATIVE,
        "bindings": {
            "qwen_successor_lock": {
                "path": contract.QWEN_LOCK_PATH,
                "sha256": sha256_bytes(qwen_payload),
            },
            "first_recovery_lock": _binding(root, contract.FIRST_LOCK_PATH),
            "rule3_lock": _binding(root, contract.RULE3_LOCK_PATH),
        },
        "parent": _expected_parent_contract(),
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
            {
                "model_key": "qwen",
                "source_lane": "immutable-qwen-successor",
                "path": contract.QWEN_OUTCOME_PATH,
                "sha256": contract.QWEN_OUTCOME_SHA256,
                "response_sha256": contract.QWEN_RESPONSE_SHA256,
                "semantic_attempt_number": 2,
            },
            {
                "model_key": "deepseek",
                "source_lane": "immutable-qwen-successor",
                "path": contract.DEEPSEEK_OUTCOME_PATH,
                "sha256": contract.DEEPSEEK_OUTCOME_SHA256,
                "response_sha256": contract.DEEPSEEK_RESPONSE_SHA256,
                "semantic_attempt_number": 1,
            },
            {
                "model_key": "mistral",
                "source_lane": "immutable-qwen-successor",
                "path": contract.MISTRAL_OUTCOME_PATH,
                "sha256": contract.MISTRAL_OUTCOME_SHA256,
                "response_sha256": contract.MISTRAL_RESPONSE_SHA256,
                "semantic_attempt_number": 1,
            },
        ],
        "captured_parent_grok_error": {
            "model_key": "grok",
            "provider": "xai",
            "route": "xai-direct",
            "requested_model_id": "grok-4.5",
            "semantic_attempt_number": 1,
            "intent": {
                "path": contract.GROK_ERROR_INTENT_PATH,
                "sha256": contract.GROK_ERROR_INTENT_SHA256,
            },
            "raw_response": {
                "path": contract.GROK_ERROR_RAW_PATH,
                "sha256": contract.GROK_ERROR_RAW_SHA256,
                "http_status": 403,
            },
            "outcome": {
                "path": contract.GROK_ERROR_OUTCOME_PATH,
                "sha256": contract.GROK_ERROR_OUTCOME_SHA256,
                "status": "error",
                "category": "authorization",
            },
            "reserved_cost_microdollars": contract.RESERVED_PER_POST["grok"],
            "disposition": "consumed-captured-403-one-user-directed-replacement",
        },
        "target_plan": {
            "model_order": list(contract.TARGET_MODEL_KEYS),
            "cells": cells,
            "plan_sha256": sha256_bytes(canonical_json_bytes(cells)),
        },
        "preflight_policy": {
            "route_keys": list(contract.PREFLIGHT_ROUTE_KEYS),
            "fresh_metadata_requests_allowed": False,
            "maximum_requests": 0,
            "reused_parent_manifest": {
                "path": contract.QWEN_MANIFEST_PATH,
                "sha256": contract.QWEN_MANIFEST_SHA256,
            },
            "reused_parent_outcomes": [
                {
                    "route_key": "grok",
                    "path": contract.GROK_PREFLIGHT_OUTCOME_PATH,
                    "sha256": contract.GROK_PREFLIGHT_OUTCOME_SHA256,
                },
                {
                    "route_key": "gpt",
                    "path": contract.GPT_PREFLIGHT_OUTCOME_PATH,
                    "sha256": contract.GPT_PREFLIGHT_OUTCOME_SHA256,
                },
            ],
        },
        "generation_policy": {
            "model_order": list(contract.TARGET_MODEL_KEYS),
            "grok_semantic_attempt_number": contract.GROK_SEMANTIC_ATTEMPT_NUMBER,
            "grok_maximum_posts": contract.GROK_MAXIMUM_POSTS,
            "grok_provider": "xai",
            "grok_route": "xai-direct",
            "grok_requested_model_id": "grok-4.5",
            "grok_request_json_body_sha256": contract.GROK_REQUEST_BODY_SHA256,
            "grok_captured_error_is_terminal": True,
            "grok_no_capture_is_consumed_and_terminal": True,
            "gpt_requires_grok_success": True,
            "gpt_maximum_safe_attempts": contract.GPT_MAXIMUM_SAFE_ATTEMPTS,
            "gpt_provider": "openrouter",
            "gpt_route": "openrouter-openai-pinned",
            "gpt_no_capture_is_consumed_and_terminal": True,
            "alternative_provider_allowed": False,
            "maximum_posts": contract.MAX_GENERATION_POSTS,
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
            "per_post_reserved_microdollars": copy.deepcopy(contract.RESERVED_PER_POST),
            "new_reserved_cap_microdollars": contract.NEW_RESERVED_CAP_MICRODOLLARS,
            "combined_reserved_cap_microdollars": contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
            "candidate_cap_microdollars": contract.CANDIDATE_CAP_MICRODOLLARS,
            "pool_cap_microdollars": contract.POOL_CAP_MICRODOLLARS,
        },
        "network_policy": {
            "maximum_preflight_gets": contract.MAX_PREFLIGHT_REQUESTS,
            "maximum_generation_posts": contract.MAX_GENERATION_POSTS,
            "maximum_outbound_requests": contract.MAX_OUTBOUND_REQUESTS,
            "authorized_hosts": ["api.x.ai", "openrouter.ai"],
            "unlisted_network_access_allowed": False,
        },
        "paid_authorization": {
            "required": True,
            "lock_authorizes_spending": False,
            "prior_receipt_sha256": contract.QWEN_AUTHORIZATION_SHA256,
            "prior_exact_statement": contract.PRIOR_AUTHORIZATION_STATEMENT,
            "prior_exact_statement_sha256": contract.PRIOR_AUTHORIZATION_STATEMENT_SHA256,
            "user_amendment_verbatim": contract.USER_AMENDMENT,
            "user_amendment_sha256": contract.USER_AMENDMENT_SHA256,
            "resolved_exact_statement": contract.AUTHORIZATION_STATEMENT,
            "resolved_exact_statement_sha256": contract.AUTHORIZATION_STATEMENT_SHA256,
            "scope": contract.authorization_scope(),
            "fresh_official_pricing_recheck_required": True,
        },
        "execution_sources": _execution_sources(root, qwen_lock),
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
    paths = [
        contract.LOCK_PATH,
        contract.QWEN_LOCK_PATH,
        contract.FIRST_LOCK_PATH,
        contract.RULE3_LOCK_PATH,
    ]
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
        raise GrokRetryLockError(difference)
    path = root / contract.LOCK_PATH
    payload = canonical_json_bytes(raw)
    if path.exists():
        disk = read_regular_file(root, contract.LOCK_PATH)
        parsed = parse_json_bytes(disk, contract.LOCK_PATH)
        if disk != canonical_json_bytes(parsed) or parsed != raw:
            raise GrokRetryLockError("on-disk Grok retry lock differs")
        payload = disk
    elif require_committed:
        raise GrokRetryLockError("committed Grok retry lock is required")
    git_head = None
    if require_committed:
        load_and_validate_recovery_lock(root, require_committed=True)
        load_qwen_lock(
            root,
            require_committed=True,
            require_parent_private=require_parent_private,
        )
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
        raise GrokRetryLockError("Grok retry lock is not canonical JSON")
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
    "GrokRetryLockError",
    "LockContext",
    "build_lock",
    "load_lock",
    "validate_lock",
    "write_lock",
)

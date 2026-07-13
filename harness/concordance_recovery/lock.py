"""Deterministic public lock for the narrow Concordance successor recovery."""

from __future__ import annotations

import copy
import errno
import hashlib
import os
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rule3.contract import (
    read_regular_file,
    repository_root as resolve_repository_root,
    sha256_bytes,
)
from rule3.lock import load_and_validate_rule3_lock

from .contract import (
    CANDIDATE_CAP_MICRODOLLARS,
    CLAIM_ROOT_RELATIVE,
    MAX_COHERE_REPLACEMENT_POSTS,
    MAX_GENERATION_POSTS,
    MAX_NEW_RECOVERY_RESERVED_MICRODOLLARS,
    MAX_OUTBOUND_REQUESTS,
    MAX_PREFLIGHT_ATTEMPTS_PER_MODEL,
    MAX_PREFLIGHT_REQUESTS,
    MAX_PRIORITY_RESERVED_MICRODOLLARS,
    MAX_UNTOUCHED_GENERATION_ATTEMPTS,
    MODEL_ORDER,
    OUTPUT_TOKEN_CAP,
    PARENT_ARTIFACT_SHA256,
    PARENT_AUTHORIZATION_PATH,
    PARENT_AUTHORIZATION_SHA256,
    PARENT_CONCURRENCY_LOCK_PATHS,
    PARENT_GENERATION_INTENT_PATHS,
    PARENT_GENERATION_OUTCOME_PATHS,
    PARENT_GIT_HEAD,
    PARENT_LOCK_PATH,
    PARENT_LOCK_SCHEMA_VERSION,
    PARENT_LOCK_SHA256,
    PARENT_MANIFEST_PATH,
    PARENT_MANIFEST_SHA256,
    PARENT_PLAN_SHA256,
    PARENT_PREFLIGHT_INTENT_PATHS,
    PARENT_PREFLIGHT_OUTCOME_PATHS,
    PARENT_PRICING_EVIDENCE_PATH,
    PARENT_PRICING_EVIDENCE_SHA256,
    PARENT_PRICING_RECHECK_PATH,
    PARENT_PRICING_RECHECK_SHA256,
    PARENT_PRIVATE_ROOT,
    PARENT_REQUIRED_ABSENT_PATHS,
    PARENT_RESERVED_MICRODOLLARS,
    POOL_CAP_MICRODOLLARS,
    POOL_ID,
    PRESERVED_MODEL_KEYS,
    PRESERVED_SUCCESSES,
    PRIVATE_ROOT_RELATIVE,
    PRIORITY_CANDIDATE_ID,
    PRIORITY_PHASE,
    RECOVERY_AUTHORIZATION_STATEMENT,
    RECOVERY_AUTHORIZATION_STATEMENT_SHA256,
    RECOVERY_ID,
    RECOVERY_LOCK_PATH,
    RECOVERY_LOCK_SCHEMA_PATH,
    RECOVERY_LOCK_SCHEMA_VERSION,
    RECOVERY_LOCK_STATUS,
    RECOVERY_TARGET_MODEL_KEYS,
    RESERVED_COST_MICRODOLLARS,
    RULE_VERSION,
    STRANDED_COHERE,
    TARGET_ATTEMPT_RECORDS,
    UNTOUCHED_MODEL_KEYS,
    RecoveryLockError,
    authorization_scope,
    canonical_json_bytes,
    discover_recovery_source_paths,
    parent_artifact_bindings,
    parse_json_bytes,
    require_relative_path,
)


@dataclass(frozen=True)
class RecoveryLockContext:
    repository_root: Path
    lock: dict[str, Any]
    lock_bytes: bytes
    lock_sha256: str
    git_head: str | None

    @property
    def root(self) -> Path:
        return self.repository_root

    @property
    def bytes(self) -> bytes:
        return self.lock_bytes

    @property
    def hash(self) -> str:
        return self.lock_sha256


def _sha_binding(path: str, payload: bytes) -> dict[str, str]:
    return {"path": path, "sha256": sha256_bytes(payload)}


def _parent_bound_paths(parent: dict[str, Any]) -> tuple[str, ...]:
    bindings = parent.get("bindings")
    candidates = parent.get("candidates")
    sources = parent.get("execution_sources")
    if (
        not isinstance(bindings, dict)
        or not isinstance(candidates, list)
        or not isinstance(sources, list)
    ):
        raise RecoveryLockError("parent lock lacks its exact public path bindings")
    paths = [PARENT_LOCK_PATH]
    for label, item in bindings.items():
        if not isinstance(item, dict):
            raise RecoveryLockError(f"parent binding {label} is malformed")
        paths.append(require_relative_path(item.get("path"), f"parent binding {label}"))
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            raise RecoveryLockError(f"parent candidate {index} is malformed")
        paths.append(
            require_relative_path(candidate.get("path"), f"parent candidate {index}")
        )
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise RecoveryLockError(f"parent source {index} is malformed")
        paths.append(
            require_relative_path(source.get("path"), f"parent source {index}")
        )
    if len(paths) != len(set(paths)):
        raise RecoveryLockError("parent public bound paths are not unique")
    return tuple(paths)


def _load_exact_parent(root: Path) -> tuple[Any, dict[str, Any], bytes]:
    try:
        context = load_and_validate_rule3_lock(root, require_committed=False)
    except Exception as error:
        raise RecoveryLockError(
            f"exact parent Rule 3 lock is invalid: {error}"
        ) from error
    if (
        context.lock_sha256 != PARENT_LOCK_SHA256
        or context.lock.get("schema_version") != PARENT_LOCK_SCHEMA_VERSION
        or context.candidate_plan_sha256.get(PRIORITY_CANDIDATE_ID)
        != PARENT_PLAN_SHA256
        or context.lock_bytes != canonical_json_bytes(context.lock)
    ):
        raise RecoveryLockError("parent Rule 3 lock differs from the interrupted run")
    return context, context.lock, context.lock_bytes


def _target_records(parent: dict[str, Any]) -> list[dict[str, Any]]:
    models = parent.get("models")
    plans = parent.get("plans")
    candidate_plans = plans.get("candidate_plans") if isinstance(plans, dict) else None
    if not isinstance(models, list) or not isinstance(candidate_plans, list):
        raise RecoveryLockError("parent lock lacks model or plan records")
    models_by_key = {
        item.get("model_key"): item for item in models if isinstance(item, dict)
    }
    matches = [
        item
        for item in candidate_plans
        if isinstance(item, dict) and item.get("candidate_id") == PRIORITY_CANDIDATE_ID
    ]
    if len(matches) != 1 or matches[0].get("plan_sha256") != PARENT_PLAN_SHA256:
        raise RecoveryLockError("parent priority plan differs from its sealed hash")
    cells = matches[0].get("cells")
    if not isinstance(cells, list) or len(cells) != len(MODEL_ORDER):
        raise RecoveryLockError("parent priority plan is not the exact eight-cell plan")
    cells_by_model = {}
    for model_key, cell in zip(MODEL_ORDER, cells, strict=True):
        if (
            not isinstance(cell, dict)
            or cell.get("cell_id")
            != f"{PRIORITY_CANDIDATE_ID}:{model_key}:default:answer"
        ):
            raise RecoveryLockError("parent cell order or identity differs")
        cells_by_model[model_key] = cell

    records = []
    for expected in TARGET_ATTEMPT_RECORDS:
        model_key = expected["model_key"]
        model = models_by_key.get(model_key)
        if not isinstance(model, dict):
            raise RecoveryLockError(f"parent model is absent: {model_key}")
        transport_fields = {
            key: model.get(key)
            for key in (
                "requested_model_id",
                "provider",
                "route",
                "environment_variable",
                "api_style",
                "base_url",
                "generation_path",
                "metadata_path",
                "metadata_mode",
                "auth_kind",
                "fallback_allowed",
            )
        }
        if any(transport_fields[key] != expected[key] for key in transport_fields):
            raise RecoveryLockError(f"parent transport differs for {model_key}")
        cell = cells_by_model[model_key]
        records.append(
            {
                **copy.deepcopy(expected),
                "parent_cell_contract_sha256": sha256_bytes(canonical_json_bytes(cell)),
            }
        )
    return records


def _state_transition_contract() -> dict[str, Any]:
    return {
        "initial_state": "locked-awaiting-recovery-authorization-and-pricing",
        "transitions": [
            {
                "from": "locked-awaiting-recovery-authorization-and-pricing",
                "event": "exact-authorization-and-fresh-pricing-validated",
                "to": "recovery-ready",
            },
            {
                "from": "recovery-ready",
                "event": "six-fresh-authenticated-preflights-complete",
                "to": "cohere-replacement-ready",
            },
            {
                "from": "cohere-replacement-ready",
                "event": "cohere-semantic-attempt-two-success",
                "to": "untouched-five-ready",
            },
            {
                "from": "cohere-replacement-ready",
                "event": "cohere-single-replacement-not-successful",
                "to": "terminal-recovery-incomplete",
            },
            {
                "from": "untouched-five-ready",
                "event": "five-untouched-successes-complete",
                "to": "priority-eight-successes-complete",
            },
            {
                "from": "untouched-five-ready",
                "event": "safe-attempts-exhausted-before-five-successes",
                "to": "terminal-recovery-incomplete",
            },
            {
                "from": "priority-eight-successes-complete",
                "event": "composite-receipt-sealed",
                "to": "priority-awaiting-blind-review",
            },
        ],
        "terminal_states": [
            "terminal-recovery-incomplete",
            "priority-awaiting-blind-review",
        ],
        "fallback_execution_allowed": False,
        "third_candidate_allowed": False,
    }


def _validate_static_recovery_contract() -> None:
    if (
        tuple(item["model_key"] for item in TARGET_ATTEMPT_RECORDS)
        != RECOVERY_TARGET_MODEL_KEYS
        or len(PARENT_ARTIFACT_SHA256) != 25
        or set(PRESERVED_MODEL_KEYS) & set(RECOVERY_TARGET_MODEL_KEYS)
        or tuple((*PRESERVED_MODEL_KEYS, *RECOVERY_TARGET_MODEL_KEYS)) != MODEL_ORDER
    ):
        raise RecoveryLockError("recovery model or evidence partition is inconsistent")
    new_ceiling = sum(
        item["maximum_generation_posts"] * item["reserved_cost_microdollars_per_post"]
        for item in TARGET_ATTEMPT_RECORDS
    )
    if (
        new_ceiling != MAX_NEW_RECOVERY_RESERVED_MICRODOLLARS
        or PARENT_RESERVED_MICRODOLLARS + new_ceiling
        != MAX_PRIORITY_RESERVED_MICRODOLLARS
        or MAX_PRIORITY_RESERVED_MICRODOLLARS > CANDIDATE_CAP_MICRODOLLARS
        or MAX_PRIORITY_RESERVED_MICRODOLLARS > POOL_CAP_MICRODOLLARS
        or MAX_PREFLIGHT_REQUESTS
        != len(RECOVERY_TARGET_MODEL_KEYS) * MAX_PREFLIGHT_ATTEMPTS_PER_MODEL
        or MAX_GENERATION_POSTS
        != MAX_COHERE_REPLACEMENT_POSTS
        + len(UNTOUCHED_MODEL_KEYS) * MAX_UNTOUCHED_GENERATION_ATTEMPTS
        or MAX_OUTBOUND_REQUESTS != MAX_PREFLIGHT_REQUESTS + MAX_GENERATION_POSTS
    ):
        raise RecoveryLockError("recovery cost or request ceiling is inconsistent")


def build_recovery_lock(repository_root: Path | str) -> dict[str, Any]:
    """Build the exact successor lock without private state, env, or network."""
    _validate_static_recovery_contract()
    root = resolve_repository_root(repository_root)
    _, parent, parent_payload = _load_exact_parent(root)
    schema_payload = read_regular_file(root, RECOVERY_LOCK_SCHEMA_PATH)
    schema = parse_json_bytes(schema_payload, RECOVERY_LOCK_SCHEMA_PATH)
    if (
        not isinstance(schema, dict)
        or schema.get("$id") != RECOVERY_LOCK_SCHEMA_VERSION
        or schema.get("properties", {}).get("schema_version", {}).get("const")
        != RECOVERY_LOCK_SCHEMA_VERSION
    ):
        raise RecoveryLockError("recovery lock schema identity differs")
    parent_source_paths = tuple(item["path"] for item in parent["execution_sources"])
    source_paths = discover_recovery_source_paths(root, parent_source_paths)
    execution_sources = [
        _sha_binding(path, read_regular_file(root, path)) for path in source_paths
    ]
    parent_public_paths = _parent_bound_paths(parent)
    targets = _target_records(parent)
    return {
        "schema_version": RECOVERY_LOCK_SCHEMA_VERSION,
        "status": RECOVERY_LOCK_STATUS,
        "recovery_id": RECOVERY_ID,
        "pool_id": POOL_ID,
        "rule_version": RULE_VERSION,
        "candidate_id": PRIORITY_CANDIDATE_ID,
        "phase": PRIORITY_PHASE,
        "private_root": PRIVATE_ROOT_RELATIVE,
        "bindings": {
            "lock_schema": _sha_binding(RECOVERY_LOCK_SCHEMA_PATH, schema_payload),
            "parent_lock": _sha_binding(PARENT_LOCK_PATH, parent_payload),
        },
        "parent": {
            "git_head": PARENT_GIT_HEAD,
            "lock_schema_version": PARENT_LOCK_SCHEMA_VERSION,
            "lock_sha256": PARENT_LOCK_SHA256,
            "priority_plan_sha256": PARENT_PLAN_SHA256,
            "public_bound_path_count": len(parent_public_paths),
            "public_bound_paths_sha256": sha256_bytes(
                canonical_json_bytes(list(parent_public_paths))
            ),
            "private_root": PARENT_PRIVATE_ROOT,
            "private_bindings": parent_artifact_bindings(),
            "private_binding_count": len(PARENT_ARTIFACT_SHA256),
            "private_receipts": {
                "paid_authorization": {
                    "path": PARENT_AUTHORIZATION_PATH,
                    "sha256": PARENT_AUTHORIZATION_SHA256,
                },
                "pricing_evidence": {
                    "path": PARENT_PRICING_EVIDENCE_PATH,
                    "sha256": PARENT_PRICING_EVIDENCE_SHA256,
                },
                "pricing_recheck": {
                    "path": PARENT_PRICING_RECHECK_PATH,
                    "sha256": PARENT_PRICING_RECHECK_SHA256,
                },
                "model_manifest": {
                    "path": PARENT_MANIFEST_PATH,
                    "sha256": PARENT_MANIFEST_SHA256,
                },
            },
            "private_inventory": {
                "preflight_intent_paths": list(PARENT_PREFLIGHT_INTENT_PATHS),
                "preflight_outcome_paths": list(PARENT_PREFLIGHT_OUTCOME_PATHS),
                "generation_intent_paths": list(PARENT_GENERATION_INTENT_PATHS),
                "generation_outcome_paths": list(PARENT_GENERATION_OUTCOME_PATHS),
                "required_absent_before_recovery": list(PARENT_REQUIRED_ABSENT_PATHS),
                "concurrency_lock_paths": list(PARENT_CONCURRENCY_LOCK_PATHS),
                "exact_complete_parent_tree_required": True,
                "untouched_generation_model_keys": list(UNTOUCHED_MODEL_KEYS),
                "untouched_generation_state_required_absent": True,
            },
        },
        "defect": {
            "code": "cohere-v2-generation-model-id-absent-validator-mismatch",
            "durable_state": "generation-intent-without-usable-outcome",
            "provider_response_text_recovered": False,
            "original_intent_may_have_reached_provider": True,
            "original_intent_must_never_be_replayed": True,
            "recovery_rule": "one-authorized-semantic-attempt-two-replacement",
        },
        "preserved_successes": copy.deepcopy(list(PRESERVED_SUCCESSES)),
        "stranded_cohere": copy.deepcopy(STRANDED_COHERE),
        "target_plan": {
            "model_order": list(RECOVERY_TARGET_MODEL_KEYS),
            "cell_count": len(targets),
            "cells": targets,
            "plan_sha256": sha256_bytes(canonical_json_bytes(targets)),
        },
        "preflight_policy": {
            "model_keys": list(RECOVERY_TARGET_MODEL_KEYS),
            "authenticated": True,
            "fresh": True,
            "all_six_successes_required_before_generation": True,
            "maximum_attempts_per_model": MAX_PREFLIGHT_ATTEMPTS_PER_MODEL,
            "maximum_requests": MAX_PREFLIGHT_REQUESTS,
            "intent_before_request": True,
            "raw_response_before_validation": True,
            "exact_model_identity_required": True,
            "fallback_allowed": False,
        },
        "generation_policy": {
            "model_keys": list(RECOVERY_TARGET_MODEL_KEYS),
            "cohere_semantic_attempt_number": 2,
            "cohere_maximum_replacement_posts": MAX_COHERE_REPLACEMENT_POSTS,
            "cross_recovery_claim_root": CLAIM_ROOT_RELATIVE,
            "cross_recovery_claim_key": STRANDED_COHERE["intent_sha256"],
            "cohere_generation_model_id_may_be_null_only_with_fresh_preflight": True,
            "untouched_model_keys": list(UNTOUCHED_MODEL_KEYS),
            "untouched_maximum_safe_attempts_per_cell": (
                MAX_UNTOUCHED_GENERATION_ATTEMPTS
            ),
            "maximum_posts": MAX_GENERATION_POSTS,
            "intent_before_post": True,
            "raw_response_before_validation": True,
            "ambiguous_post_without_capture_is_terminal": True,
            "captured_response_without_outcome_finishes_offline": True,
            "preserved_model_generation_forbidden": list(PRESERVED_MODEL_KEYS),
            "output_token_cap": OUTPUT_TOKEN_CAP,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
        },
        "budget": {
            "parent_reserved_microdollars": PARENT_RESERVED_MICRODOLLARS,
            "per_post_reserved_microdollars": copy.deepcopy(RESERVED_COST_MICRODOLLARS),
            "new_recovery_reserved_cap_microdollars": (
                MAX_NEW_RECOVERY_RESERVED_MICRODOLLARS
            ),
            "combined_priority_reserved_cap_microdollars": (
                MAX_PRIORITY_RESERVED_MICRODOLLARS
            ),
            "candidate_cap_microdollars": CANDIDATE_CAP_MICRODOLLARS,
            "pool_cap_microdollars": POOL_CAP_MICRODOLLARS,
        },
        "network_policy": {
            "preflight_method": "GET",
            "generation_method": "POST",
            "maximum_preflight_requests": MAX_PREFLIGHT_REQUESTS,
            "maximum_generation_posts": MAX_GENERATION_POSTS,
            "maximum_outbound_requests": MAX_OUTBOUND_REQUESTS,
            "generation_order": list(RECOVERY_TARGET_MODEL_KEYS),
            "cohere_success_required_before_untouched_generation": True,
            "fallback_network_access_allowed": False,
        },
        "state_transition_contract": _state_transition_contract(),
        "paid_authorization": {
            "required": True,
            "separate_from_lock": True,
            "lock_authorizes_spending": False,
            "receipt_must_bind": [
                "recovery_lock_sha256",
                "git_head",
                "parent_lock_sha256",
                "parent_authorization_sha256",
            ],
            "exact_statement": RECOVERY_AUTHORIZATION_STATEMENT,
            "exact_statement_sha256": (RECOVERY_AUTHORIZATION_STATEMENT_SHA256),
            "scope": authorization_scope(),
            "immediate_official_pricing_recheck_required": True,
        },
        "execution_sources": execution_sources,
    }


def _difference(actual: Any, expected: Any, path: str = "lock") -> str | None:
    if type(actual) is not type(expected):
        return f"{path} has type {type(actual).__name__}, expected {type(expected).__name__}"
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            missing = sorted(set(expected) - set(actual), key=repr)
            extra = sorted(set(actual) - set(expected), key=repr)
            return f"{path} fields differ; missing={missing}, extra={extra}"
        for key in expected:
            difference = _difference(actual[key], expected[key], f"{path}.{key}")
            if difference:
                return difference
        return None
    if isinstance(expected, list):
        if len(actual) != len(expected):
            return f"{path} length is {len(actual)}, expected {len(expected)}"
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            difference = _difference(left, right, f"{path}[{index}]")
            if difference:
                return difference
        return None
    if actual != expected:
        return f"{path} differs from the immutable successor contract"
    return None


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
    }


def _git(
    root: Path, arguments: list[str], *, text: bool = False
) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=root,
            env=_git_environment(),
            check=False,
            capture_output=True,
            text=text,
        )
    except OSError as error:
        raise RecoveryLockError(f"git cannot be executed: {error}") from error


def _git_error(result: subprocess.CompletedProcess[Any], operation: str) -> str:
    stderr = result.stderr
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return f"{operation} failed: {str(stderr).strip() or 'unknown git error'}"


def _bound_paths(root: Path, lock: dict[str, Any]) -> tuple[str, ...]:
    parent_payload = read_regular_file(root, PARENT_LOCK_PATH)
    parent = parse_json_bytes(parent_payload, PARENT_LOCK_PATH)
    if not isinstance(parent, dict):
        raise RecoveryLockError("parent lock must be an object")
    paths = [RECOVERY_LOCK_PATH, RECOVERY_LOCK_SCHEMA_PATH]
    paths.extend(_parent_bound_paths(parent))
    sources = lock.get("execution_sources")
    if not isinstance(sources, list):
        raise RecoveryLockError("recovery lock lacks execution-source bindings")
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise RecoveryLockError(f"recovery source {index} is malformed")
        paths.append(require_relative_path(source.get("path"), f"source {index}"))
    normalized = tuple(dict.fromkeys(paths))
    return normalized


def _require_committed_and_clean(root: Path, paths: tuple[str, ...]) -> str:
    top = _git(root, ["rev-parse", "--show-toplevel"], text=True)
    if top.returncode != 0:
        raise RecoveryLockError(_git_error(top, "git repository check"))
    if Path(top.stdout.strip()).resolve() != root.resolve():
        raise RecoveryLockError("repository root is not the Git worktree root")
    head_result = _git(root, ["rev-parse", "--verify", "HEAD"], text=True)
    if head_result.returncode != 0:
        raise RecoveryLockError(_git_error(head_result, "Git HEAD check"))
    git_head = head_result.stdout.strip()
    ancestor = _git(root, ["merge-base", "--is-ancestor", PARENT_GIT_HEAD, git_head])
    if ancestor.returncode == 1:
        raise RecoveryLockError("parent execution commit is not an ancestor of HEAD")
    if ancestor.returncode != 0:
        raise RecoveryLockError(_git_error(ancestor, "parent ancestry check"))
    for relative in paths:
        current = read_regular_file(root, relative)
        tree = _git(root, ["ls-tree", "-z", git_head, "--", relative])
        if tree.returncode != 0:
            raise RecoveryLockError(_git_error(tree, f"tree check for {relative}"))
        entries = [entry for entry in tree.stdout.split(b"\0") if entry]
        if len(entries) != 1 or b"\t" not in entries[0]:
            raise RecoveryLockError(f"{relative}: bound file is absent from HEAD")
        metadata, recorded_path = entries[0].split(b"\t", 1)
        fields = metadata.split()
        if (
            len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
            or recorded_path.decode("utf-8", errors="strict") != relative
        ):
            raise RecoveryLockError(f"{relative}: HEAD entry is not a regular file")
        committed = _git(root, ["cat-file", "blob", f"{git_head}:{relative}"])
        if committed.returncode != 0:
            raise RecoveryLockError(_git_error(committed, f"blob read for {relative}"))
        if committed.stdout != current:
            raise RecoveryLockError(f"{relative}: working bytes differ from HEAD")
    unstaged = _git(root, ["diff", "--no-ext-diff", "--quiet", "--", *paths])
    if unstaged.returncode == 1:
        raise RecoveryLockError("a bound recovery path has unstaged changes")
    if unstaged.returncode != 0:
        raise RecoveryLockError(_git_error(unstaged, "unstaged cleanliness check"))
    staged = _git(
        root,
        ["diff", "--no-ext-diff", "--cached", "--quiet", git_head, "--", *paths],
    )
    if staged.returncode == 1:
        raise RecoveryLockError("a bound recovery path has staged changes")
    if staged.returncode != 0:
        raise RecoveryLockError(_git_error(staged, "staged cleanliness check"))
    final_head = _git(root, ["rev-parse", "--verify", "HEAD"], text=True)
    if final_head.returncode != 0 or final_head.stdout.strip() != git_head:
        raise RecoveryLockError("Git HEAD changed during recovery lock validation")
    return git_head


def _exact_lock_path(root: Path, lock_path: Path | str | None) -> Path:
    expected = root / RECOVERY_LOCK_PATH
    if lock_path is None:
        return expected
    supplied = Path(lock_path)
    matches = (
        supplied == expected
        if supplied.is_absolute()
        else supplied.as_posix() == RECOVERY_LOCK_PATH
    )
    if not matches:
        raise RecoveryLockError(f"recovery lock path must be {RECOVERY_LOCK_PATH}")
    return expected


def _context(
    root: Path,
    raw: dict[str, Any],
    payload: bytes,
    git_head: str | None,
) -> RecoveryLockContext:
    return RecoveryLockContext(
        repository_root=root,
        lock=parse_json_bytes(payload, "validated recovery lock"),
        lock_bytes=payload,
        lock_sha256=sha256_bytes(payload),
        git_head=git_head,
    )


def validate_recovery_lock(
    raw: Any,
    repository_root: Path | str,
    lock_path: Path | str | None = None,
    require_committed: bool = False,
    require_parent_private: bool = False,
) -> RecoveryLockContext:
    root = resolve_repository_root(repository_root)
    path = _exact_lock_path(root, lock_path)
    expected = build_recovery_lock(root)
    difference = _difference(raw, expected)
    if difference:
        raise RecoveryLockError(difference)
    payload = canonical_json_bytes(raw)
    try:
        path.lstat()
    except FileNotFoundError:
        if require_committed:
            raise RecoveryLockError(f"the committed {RECOVERY_LOCK_PATH} is required")
    except OSError as error:
        raise RecoveryLockError(
            f"recovery lock cannot be inspected: {error}"
        ) from error
    else:
        on_disk = read_regular_file(root, RECOVERY_LOCK_PATH)
        parsed = parse_json_bytes(on_disk, RECOVERY_LOCK_PATH)
        if on_disk != canonical_json_bytes(parsed):
            raise RecoveryLockError("on-disk recovery lock is not canonical JSON")
        disk_difference = _difference(parsed, raw)
        if disk_difference:
            raise RecoveryLockError("on-disk recovery lock differs from supplied lock")
        payload = on_disk
    git_head = None
    if require_committed:
        git_head = _require_committed_and_clean(root, _bound_paths(root, raw))
    context = _context(root, raw, payload, git_head)
    if require_parent_private:
        validate_parent_private_evidence(context)
    return context


def load_and_validate_recovery_lock(
    repository_root: Path | str,
    lock_path: Path | str | None = None,
    require_committed: bool = False,
    require_parent_private: bool = False,
) -> RecoveryLockContext:
    root = resolve_repository_root(repository_root)
    path = _exact_lock_path(root, lock_path)
    try:
        payload = read_regular_file(root, RECOVERY_LOCK_PATH)
    except Exception as error:
        raise RecoveryLockError(f"recovery lock cannot be loaded: {error}") from error
    raw = parse_json_bytes(payload, RECOVERY_LOCK_PATH)
    if payload != canonical_json_bytes(raw):
        raise RecoveryLockError("recovery lock is not canonical JSON")
    return validate_recovery_lock(
        raw,
        root,
        path,
        require_committed=require_committed,
        require_parent_private=require_parent_private,
    )


def write_recovery_lock(
    repository_root: Path | str, raw: dict[str, Any] | None = None
) -> RecoveryLockContext:
    root = resolve_repository_root(repository_root)
    lock = build_recovery_lock(root) if raw is None else raw
    context = validate_recovery_lock(lock, root)
    destination = root / RECOVERY_LOCK_PATH
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise RecoveryLockError("candidate directory must be a real directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".concordance-recovery-lock.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(context.lock_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise RecoveryLockError(
                f"{RECOVERY_LOCK_PATH} already exists; it is never overwritten"
            ) from error
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise RecoveryLockError(
                    f"{RECOVERY_LOCK_PATH} already exists; it is never overwritten"
                ) from error
            raise RecoveryLockError(f"cannot create recovery lock: {error}") from error
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return load_and_validate_recovery_lock(root)


def _secure_file_sha256(path: Path, root: Path, label: str) -> str:
    cursor = path.parent
    while cursor != root.parent:
        try:
            metadata = cursor.lstat()
        except OSError as error:
            raise RecoveryLockError(
                f"{label} parent cannot be inspected: {error}"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RecoveryLockError(
                f"{label} parents must be real mode-0700 directories"
            )
        if cursor == root:
            break
        cursor = cursor.parent
    try:
        before = path.lstat()
    except OSError as error:
        raise RecoveryLockError(f"{label} cannot be inspected: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
    ):
        raise RecoveryLockError(f"{label} must be a single-link mode-0600 regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise RecoveryLockError(f"{label} changed while opened")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise RecoveryLockError(f"{label} changed while hashed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _inventory(root: Path, relative_root: str) -> tuple[str, ...]:
    directory = root / relative_root
    if not directory.exists():
        return ()
    result = []
    for path in sorted(directory.rglob("*")):
        if path.is_dir():
            if path.is_symlink():
                raise RecoveryLockError(f"private inventory contains symlink {path}")
            continue
        if path.is_symlink() or path.suffix != ".json":
            raise RecoveryLockError(
                f"private inventory contains unexpected file {path}"
            )
        result.append(path.relative_to(root).as_posix())
    return tuple(result)


def _complete_private_file_inventory(root: Path) -> tuple[str, ...]:
    result = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RecoveryLockError(f"private parent contains a symlink: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise RecoveryLockError(
                    f"private parent directory must remain mode 0700: {path}"
                )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise RecoveryLockError(
                f"private parent contains a non-regular file: {path}"
            )
        result.append(path.relative_to(root).as_posix())
    return tuple(result)


def validate_parent_private_evidence(
    context: RecoveryLockContext, *, require_pristine_output: bool = True
) -> None:
    """Hash and inventory the exact private parent without interpreting answers."""
    root = context.repository_root / PARENT_PRIVATE_ROOT
    if not root.is_dir() or root.is_symlink():
        raise RecoveryLockError("exact private parent root is absent or unsafe")
    for relative, expected in sorted(PARENT_ARTIFACT_SHA256.items()):
        actual = _secure_file_sha256(
            root / relative, root, f"parent artifact {relative}"
        )
        if actual != expected:
            raise RecoveryLockError(f"parent artifact differs: {relative}")
    for relative in PARENT_CONCURRENCY_LOCK_PATHS:
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise RecoveryLockError(
                f"parent concurrency lock cannot be inspected: {relative}: {error}"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise RecoveryLockError(f"parent concurrency lock changed: {relative}")
    complete_expected = tuple(
        sorted((*PARENT_ARTIFACT_SHA256, *PARENT_CONCURRENCY_LOCK_PATHS))
    )
    if _complete_private_file_inventory(root) != complete_expected:
        raise RecoveryLockError("complete private parent file inventory differs")
    expected_preflight_intents = tuple(
        sorted(
            f"{PARENT_PRIVATE_ROOT}/{path}" for path in PARENT_PREFLIGHT_INTENT_PATHS
        )
    )
    expected_preflight_outcomes = tuple(
        sorted(
            f"{PARENT_PRIVATE_ROOT}/{path}" for path in PARENT_PREFLIGHT_OUTCOME_PATHS
        )
    )
    expected_generation_intents = tuple(
        sorted(
            f"{PARENT_PRIVATE_ROOT}/{path}" for path in PARENT_GENERATION_INTENT_PATHS
        )
    )
    expected_generation_outcomes = tuple(
        sorted(
            f"{PARENT_PRIVATE_ROOT}/{path}" for path in PARENT_GENERATION_OUTCOME_PATHS
        )
    )
    actual = {
        "preflight intents": _inventory(
            context.repository_root,
            f"{PARENT_PRIVATE_ROOT}/preflight/intents/{PRIORITY_CANDIDATE_ID}",
        ),
        "preflight outcomes": _inventory(
            context.repository_root,
            f"{PARENT_PRIVATE_ROOT}/preflight/outcomes/{PRIORITY_CANDIDATE_ID}",
        ),
        "generation intents": _inventory(
            context.repository_root,
            f"{PARENT_PRIVATE_ROOT}/budget/intents/{PRIORITY_CANDIDATE_ID}",
        ),
        "generation outcomes": _inventory(
            context.repository_root,
            f"{PARENT_PRIVATE_ROOT}/outcomes/{PRIORITY_CANDIDATE_ID}",
        ),
    }
    expected = {
        "preflight intents": expected_preflight_intents,
        "preflight outcomes": expected_preflight_outcomes,
        "generation intents": expected_generation_intents,
        "generation outcomes": expected_generation_outcomes,
    }
    for label in expected:
        if actual[label] != expected[label]:
            raise RecoveryLockError(f"parent {label} inventory differs")
    if require_pristine_output:
        for relative in PARENT_REQUIRED_ABSENT_PATHS:
            if (root / relative).exists() or (root / relative).is_symlink():
                raise RecoveryLockError(
                    f"required pre-recovery absence changed: {relative}"
                )


__all__ = (
    "RecoveryLockContext",
    "build_recovery_lock",
    "load_and_validate_recovery_lock",
    "validate_parent_private_evidence",
    "validate_recovery_lock",
    "write_recovery_lock",
)

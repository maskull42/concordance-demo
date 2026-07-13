from __future__ import annotations

import copy
import errno
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contract import (
    APPROVED_MODEL_TRANSPORTS,
    APPROVED_PLANNING_PRICING,
    APPROVED_PLANNING_PRICING_NOTE,
    APPROVED_QUESTION_SHA256,
    APPROVED_SOURCE_FREEZE_SHA256,
    ATTEMPTS_PER_CELL,
    CANDIDATE_COST_CAP_MICRODOLLARS,
    CANDIDATES,
    CONTENT_VERSION,
    DOSSIER_PATH,
    EXPECTED_CONTEXT_NOTES,
    EXPECTED_POSITION_DEFINITIONS,
    EXPECTED_REQUEST_PARAMS,
    EXPECTED_SOURCE_ARTIFACTS,
    EXPECTED_SOURCE_IDS,
    LOCK_PATH,
    LOCK_SCHEMA_PATH,
    LOCK_SCHEMA_VERSION,
    LOCK_STATUS,
    MAPPING_RUBRIC_PATH,
    MAXIMUM_ENDORSEMENTS_PER_POSITION,
    MINIMUM_DISTINCT_POSITIONS,
    MINIMUM_NON_NULL_ENDORSEMENTS,
    MODELS_CONFIG_PATH,
    MODEL_KEYS,
    OUTPUT_TOKEN_CAP,
    POOL_ID,
    POOL_SIZE,
    PRICING_REVIEW_PATH,
    PROPOSED_VERIFICATION,
    PROTOCOL_PATH,
    REQUIRED_COMPLETED_RESPONSES,
    RULE_VERSION,
    SOURCE_FREEZE_PATH,
    SYSTEM_PROMPT,
    TOTAL_COST_CAP_MICRODOLLARS,
    Rule3LockError,
    canonical_json_bytes,
    discover_execution_source_paths,
    parse_json_bytes,
    prompt_sha256,
    read_json_file,
    read_regular_file,
    repository_root as resolve_repository_root,
    requested_params_receipt,
    require_relative_path,
    sha256_bytes,
)


@dataclass(frozen=True)
class Rule3LockContext:
    repository_root: Path
    lock: dict[str, Any]
    lock_bytes: bytes
    lock_sha256: str
    git_head: str | None
    candidates: tuple[dict[str, Any], ...]
    models_config_path: Path
    protocol_path: Path
    question_paths: tuple[Path, ...]
    candidate_plan_sha256: dict[str, str]
    candidate_cost_cap_microdollars: int
    total_cost_cap_microdollars: int
    attempts_per_cell: int
    output_token_cap: int


def _sha_binding(path: str, payload: bytes) -> dict[str, str]:
    return {"path": path, "sha256": sha256_bytes(payload)}


_QUESTION_FIELDS = {
    "schema_version",
    "content_version",
    "data_class",
    "id",
    "kind",
    "domain",
    "title",
    "premise",
    "context_note",
    "what_this_shows",
    "what_this_does_not_show",
    "selection",
    "prompt_variants",
    "position_map",
    "map_is_nonexhaustive",
    "verification",
}
_POSITION_FIELDS = {
    "id",
    "label",
    "summary",
    "attestation",
    "sources",
    "verification",
}
_QUESTION_SOURCE_FIELDS = {
    "id",
    "claim_supported",
    "title",
    "citation",
    "url",
    "accessed_at",
    "verification",
}


def _require_proposed_verification(value: Any, label: str) -> None:
    if not _exact_value(value, PROPOSED_VERIFICATION):
        raise Rule3LockError(
            f"{label}: verification must remain exactly proposed and unclaimed"
        )


def _validate_question(
    raw: Any,
    payload: bytes,
    candidate: dict[str, str],
    expected_positions: tuple[dict[str, Any], ...],
) -> str:
    label = candidate["path"]
    if not isinstance(raw, dict) or set(raw) != _QUESTION_FIELDS:
        raise Rule3LockError(f"{label}: question must be a JSON object")
    expected_values = {
        "schema_version": "1.0.0",
        "id": candidate["id"],
        "content_version": CONTENT_VERSION,
        "data_class": "research",
        "kind": candidate["kind"],
        "context_note": EXPECTED_CONTEXT_NOTES[candidate["id"]],
        "map_is_nonexhaustive": True,
    }
    for key, expected in expected_values.items():
        if type(raw.get(key)) is not type(expected) or raw.get(key) != expected:
            raise Rule3LockError(f"{label}: {key} differs from the Rule 3 contract")

    selection = raw.get("selection")
    if not isinstance(selection, dict):
        raise Rule3LockError(f"{label}: selection must be an object")
    expected_selection = {
        "status": "candidate",
        "pool_id": POOL_ID,
        "pool_size": POOL_SIZE,
        "rule_version": RULE_VERSION,
    }
    for key, expected in expected_selection.items():
        if (
            type(selection.get(key)) is not type(expected)
            or selection.get(key) != expected
        ):
            raise Rule3LockError(
                f"{label}: selection.{key} differs from the Rule 3 contract"
            )

    variants = raw.get("prompt_variants")
    if not isinstance(variants, list) or len(variants) != 1:
        raise Rule3LockError(f"{label}: exactly one prompt variant is required")
    variant = variants[0]
    if not isinstance(variant, dict) or variant.get("id") != "default":
        raise Rule3LockError(f"{label}: the sole prompt variant must be default")
    if variant.get("user_prompt") != candidate["prompt"]:
        raise Rule3LockError(f"{label}: exact approved prompt differs")
    positions = raw.get("position_map")
    if not isinstance(positions, list) or len(positions) != len(expected_positions):
        raise Rule3LockError(f"{label}: exact approved position count differs")
    for position, expected in zip(positions, expected_positions, strict=True):
        if not isinstance(position, dict) or set(position) != _POSITION_FIELDS:
            raise Rule3LockError(f"{label}: position fields differ from approval")
        for field in ("id", "label", "summary", "attestation"):
            if (
                type(position.get(field)) is not str
                or position[field] != expected[field]
            ):
                raise Rule3LockError(
                    f"{label}: position {expected['id']} {field} differs from approval"
                )
        sources = position.get("sources")
        expected_source_ids = expected["source_ids"]
        if (
            not isinstance(sources, list)
            or tuple(
                source.get("id") if isinstance(source, dict) else None
                for source in sources
            )
            != expected_source_ids
        ):
            raise Rule3LockError(
                f"{label}: position {expected['id']} source order differs"
            )
        for source in sources:
            if not isinstance(source, dict) or set(source) != _QUESTION_SOURCE_FIELDS:
                raise Rule3LockError(
                    f"{label}: position {expected['id']} source fields differ"
                )
            _require_proposed_verification(
                source.get("verification"),
                f"{label}: source {source.get('id')}",
            )
        _require_proposed_verification(
            position.get("verification"),
            f"{label}: position {expected['id']}",
        )
    _require_proposed_verification(raw.get("verification"), label)
    if sha256_bytes(payload) != APPROVED_QUESTION_SHA256[candidate["id"]]:
        raise Rule3LockError(f"{label}: bytes differ from the exact approved record")
    return candidate["prompt"]


def _question_sources(question: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    return tuple(
        source
        for position in question["position_map"]
        for source in position["sources"]
    )


def _validate_source_freeze(
    raw: Any,
    payload: bytes,
    question_records: tuple[dict[str, Any], ...],
) -> None:
    expected_fields = {
        "schema_version",
        "content_version",
        "pool_id",
        "prepared_on",
        "status",
        "integrity_policy",
        "questions",
        "verification",
    }
    if not isinstance(raw, dict) or set(raw) != expected_fields:
        raise Rule3LockError("source freeze must be a JSON object")
    expected_values = {
        "schema_version": "rule3-source-freeze-1.0.0",
        "content_version": CONTENT_VERSION,
        "pool_id": POOL_ID,
        "prepared_on": "2026-07-13",
        "status": "research-source-freeze-proposed",
    }
    for key, expected in expected_values.items():
        if raw.get(key) != expected:
            raise Rule3LockError(f"source freeze {key} differs from Rule 3")
    questions = raw.get("questions")
    if not isinstance(questions, list) or len(questions) != POOL_SIZE:
        raise Rule3LockError("source freeze must contain exactly two ordered questions")
    all_source_ids: set[str] = set()
    for candidate, expected_source_ids, question, question_record in zip(
        CANDIDATES, EXPECTED_SOURCE_IDS, questions, question_records, strict=True
    ):
        if not isinstance(question, dict) or set(question) != {
            "question_id",
            "question_path",
            "sources",
        }:
            raise Rule3LockError("source freeze question entries must be objects")
        if question.get("question_id") != candidate["id"]:
            raise Rule3LockError("source freeze question order or ID differs")
        if question.get("question_path") != candidate["path"]:
            raise Rule3LockError("source freeze question path differs")
        sources = question.get("sources")
        if not isinstance(sources, list) or not sources:
            raise Rule3LockError("each frozen question requires source records")
        source_ids = tuple(
            source.get("source_id") if isinstance(source, dict) else None
            for source in sources
        )
        if source_ids != expected_source_ids:
            raise Rule3LockError(
                f"{candidate['id']}: frozen source IDs or order differs"
            )
        question_sources = _question_sources(question_record)
        if tuple(source["id"] for source in question_sources) != expected_source_ids:
            raise Rule3LockError(
                f"{candidate['id']}: question sources differ from the frozen register"
            )
        for source, question_source in zip(sources, question_sources, strict=True):
            if not isinstance(source, dict) or set(source) != {
                "source_id",
                "source_url",
                "claim_binding",
                "artifact",
                "locators",
                "verification",
            }:
                raise Rule3LockError("frozen source fields differ from approval")
            source_id = source.get("source_id") if isinstance(source, dict) else None
            if not isinstance(source_id, str) or not source_id:
                raise Rule3LockError("every frozen source requires a source_id")
            if source_id in all_source_ids:
                raise Rule3LockError(f"duplicate frozen source ID: {source_id}")
            all_source_ids.add(source_id)
            if (
                source.get("source_url") != question_source["url"]
                or source.get("claim_binding") != question_source["claim_supported"]
            ):
                raise Rule3LockError(
                    f"{source_id}: frozen URL or claim differs from the question"
                )
            artifact = source.get("artifact")
            expected_status, expected_sha = EXPECTED_SOURCE_ARTIFACTS[source_id]
            if (
                not isinstance(artifact, dict)
                or artifact.get("status") != expected_status
                or not _exact_value(artifact.get("sha256"), expected_sha)
            ):
                raise Rule3LockError(
                    f"{source_id}: artifact status or SHA-256 differs from approval"
                )
            if not isinstance(source.get("locators"), list) or not source["locators"]:
                raise Rule3LockError(f"{source_id}: frozen locators are required")
            _require_proposed_verification(
                source.get("verification"), f"source freeze: {source_id}"
            )
    _require_proposed_verification(raw.get("verification"), "source freeze")
    if sha256_bytes(payload) != APPROVED_SOURCE_FREEZE_SHA256:
        raise Rule3LockError(
            "source freeze bytes differ from the exact approved register"
        )


def _validate_protocol(raw: Any) -> str:
    if not isinstance(raw, dict) or set(raw) != {
        "protocol_version",
        "system_prompt",
        "standard_challenge_prompt",
    }:
        raise Rule3LockError("protocol fields differ from the Rule 3 contract")
    if raw["protocol_version"] != "rule3-1.0.0":
        raise Rule3LockError("protocol version differs from the Rule 3 contract")
    if raw["system_prompt"] != SYSTEM_PROMPT:
        raise Rule3LockError("system prompt differs from the approved Rule 3 prompt")
    if not isinstance(raw["standard_challenge_prompt"], str):
        raise Rule3LockError("standard challenge prompt must be a string")
    return raw["protocol_version"]


_MODEL_FIELDS = {
    "model_key",
    "family",
    "provider",
    "requested_model_id",
    "route",
    "environment_variable",
    "api_style",
    "base_url",
    "generation_path",
    "metadata_path",
    "metadata_mode",
    "auth_kind",
    "fallback_allowed",
    "temperature",
    "output_limit",
    "reasoning",
    "provider_options",
    "requests_per_second",
    "planning_pricing",
}


def _exact_value(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _exact_value(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _exact_value(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def _model_receipts(raw: Any) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(raw, dict) or set(raw) != {
        "config_version",
        "planning_pricing_note",
        "models",
    }:
        raise Rule3LockError("model configuration fields differ from the contract")
    if raw["config_version"] != "1.0.0":
        raise Rule3LockError("model configuration version must be 1.0.0")
    if raw["planning_pricing_note"] != APPROVED_PLANNING_PRICING_NOTE:
        raise Rule3LockError("model planning-pricing note differs from approval")
    models = raw["models"]
    if not isinstance(models, list) or len(models) != len(MODEL_KEYS):
        raise Rule3LockError("model configuration must contain exactly eight models")

    receipts: list[dict[str, Any]] = []
    for expected_key, model in zip(MODEL_KEYS, models, strict=True):
        if not isinstance(model, dict) or set(model) != _MODEL_FIELDS:
            raise Rule3LockError(f"{expected_key}: model fields differ from contract")
        if model.get("model_key") != expected_key:
            raise Rule3LockError("model panel order differs from the Rule 3 contract")
        approved_transport = APPROVED_MODEL_TRANSPORTS[expected_key]
        actual_transport = {field: model.get(field) for field in approved_transport}
        if not _exact_value(actual_transport, approved_transport):
            raise Rule3LockError(
                f"{expected_key}: transport contract differs from approval"
            )
        requested = requested_params_receipt(model)
        if not _exact_value(requested, EXPECTED_REQUEST_PARAMS[expected_key]):
            raise Rule3LockError(
                f"{expected_key}: request-parameter receipt differs from approval"
            )
        pricing = model.get("planning_pricing")
        if not _exact_value(pricing, APPROVED_PLANNING_PRICING[expected_key]):
            raise Rule3LockError(
                f"{expected_key}: planning pricing differs from approval"
            )
        receipts.append(
            {
                "model_key": expected_key,
                **copy.deepcopy(approved_transport),
                "requested_params": copy.deepcopy(requested),
                "planning_pricing": copy.deepcopy(
                    APPROVED_PLANNING_PRICING[expected_key]
                ),
            }
        )
    return raw["config_version"], receipts


def _cell_contract(
    candidate: dict[str, str],
    prompt: str,
    model: dict[str, Any],
) -> dict[str, Any]:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    return {
        "cell_id": f"{candidate['id']}:{model['model_key']}:default:answer",
        "prompt_sha256": prompt_sha256(messages),
        "requested_model_id": model["requested_model_id"],
        "route": model["route"],
        "requested_params": copy.deepcopy(model["requested_params"]),
    }


def _state_transition_contract() -> dict[str, Any]:
    return {
        "initial_state": ("locked-awaiting-paid-authorization-and-pricing-recheck"),
        "transitions": [
            {
                "from": ("locked-awaiting-paid-authorization-and-pricing-recheck"),
                "event": ("paid-authorization-and-pricing-recheck-validated"),
                "to": "priority-ready",
            },
            {
                "from": "priority-ready",
                "event": "priority-run-started",
                "to": "priority-running",
            },
            {
                "from": "priority-running",
                "event": "eight-responses-complete",
                "to": "priority-awaiting-blind-review",
            },
            {
                "from": "priority-running",
                "event": "attempts-exhausted-before-completion",
                "to": "terminal-priority-incomplete",
            },
            {
                "from": "priority-awaiting-blind-review",
                "event": "author-review-sealed-threshold-met",
                "to": "terminal-priority-selected",
            },
            {
                "from": "priority-awaiting-blind-review",
                "event": "author-review-sealed-threshold-not-met",
                "to": "fallback-ready",
            },
            {
                "from": "fallback-ready",
                "event": "fallback-run-started",
                "to": "fallback-running",
            },
            {
                "from": "fallback-running",
                "event": "eight-responses-complete",
                "to": "fallback-awaiting-blind-review",
            },
            {
                "from": "fallback-running",
                "event": "attempts-exhausted-before-completion",
                "to": "terminal-fallback-incomplete",
            },
            {
                "from": "fallback-awaiting-blind-review",
                "event": "author-review-sealed-threshold-met",
                "to": "terminal-fallback-selected",
            },
            {
                "from": "fallback-awaiting-blind-review",
                "event": "author-review-sealed-threshold-not-met",
                "to": "terminal-two-completed-failures-no-selection",
            },
        ],
        "terminal_states": [
            "terminal-priority-selected",
            "terminal-priority-incomplete",
            "terminal-fallback-selected",
            "terminal-fallback-incomplete",
            "terminal-two-completed-failures-no-selection",
        ],
        "fallback_requires_completed_priority_threshold_failure": True,
        "incomplete_is_not_threshold_failure": True,
        "third_candidate_forbidden": True,
    }


def build_rule3_lock(repository_root: Path | str) -> dict[str, Any]:
    """Build the deterministic lock in memory without reading env or using network."""
    root = resolve_repository_root(repository_root)

    dossier_payload = read_regular_file(root, DOSSIER_PATH)
    source_freeze, source_freeze_payload = read_json_file(root, SOURCE_FREEZE_PATH)
    rubric_payload = read_regular_file(root, MAPPING_RUBRIC_PATH)
    protocol, protocol_payload = read_json_file(root, PROTOCOL_PATH)
    models_config, models_payload = read_json_file(root, MODELS_CONFIG_PATH)
    pricing_payload = read_regular_file(root, PRICING_REVIEW_PATH)
    schema, schema_payload = read_json_file(root, LOCK_SCHEMA_PATH)

    protocol_version = _validate_protocol(protocol)
    config_version, models = _model_receipts(models_config)
    if (
        not isinstance(schema, dict)
        or schema.get("$id") != LOCK_SCHEMA_VERSION
        or not isinstance(schema.get("properties"), dict)
        or schema["properties"].get("schema_version", {}).get("const")
        != LOCK_SCHEMA_VERSION
    ):
        raise Rule3LockError("Rule 3 lock schema identity differs from the contract")

    candidates: list[dict[str, Any]] = []
    prompts: dict[str, str] = {}
    question_records: list[dict[str, Any]] = []
    question_root = root / "candidate/rule3/questions"
    actual_question_paths = {
        path.relative_to(root).as_posix()
        for path in question_root.iterdir()
        if path.name.endswith(".json")
    }
    expected_question_paths = {candidate["path"] for candidate in CANDIDATES}
    if actual_question_paths != expected_question_paths:
        raise Rule3LockError(
            "Rule 3 question directory must contain exactly the two locked candidates"
        )
    for candidate, expected_positions in zip(
        CANDIDATES, EXPECTED_POSITION_DEFINITIONS, strict=True
    ):
        question, question_payload = read_json_file(root, candidate["path"])
        prompts[candidate["id"]] = _validate_question(
            question,
            question_payload,
            candidate,
            expected_positions,
        )
        question_records.append(question)
        candidates.append(
            {
                "id": candidate["id"],
                "role": candidate["role"],
                "kind": candidate["kind"],
                "path": candidate["path"],
                "sha256": sha256_bytes(question_payload),
            }
        )
    _validate_source_freeze(
        source_freeze,
        source_freeze_payload,
        tuple(question_records),
    )

    candidate_plans: list[dict[str, Any]] = []
    universe_cells: list[dict[str, Any]] = []
    for candidate in CANDIDATES:
        cells = [
            _cell_contract(candidate, prompts[candidate["id"]], model)
            for model in models
        ]
        universe_cells.extend(cells)
        candidate_plans.append(
            {
                "candidate_id": candidate["id"],
                "role": candidate["role"],
                "cell_count": len(cells),
                "cells": cells,
                "plan_sha256": sha256_bytes(canonical_json_bytes(cells)),
            }
        )

    execution_sources = []
    for path in discover_execution_source_paths(root):
        execution_sources.append(_sha_binding(path, read_regular_file(root, path)))

    return {
        "schema_version": LOCK_SCHEMA_VERSION,
        "status": LOCK_STATUS,
        "pool_id": POOL_ID,
        "pool_size": POOL_SIZE,
        "rule_version": RULE_VERSION,
        "content_version": CONTENT_VERSION,
        "bindings": {
            "dossier": _sha_binding(DOSSIER_PATH, dossier_payload),
            "source_freeze": _sha_binding(SOURCE_FREEZE_PATH, source_freeze_payload),
            "mapping_rubric": _sha_binding(MAPPING_RUBRIC_PATH, rubric_payload),
            "protocol": {
                "path": PROTOCOL_PATH,
                "protocol_version": protocol_version,
                "sha256": sha256_bytes(protocol_payload),
            },
            "models_config": {
                "path": MODELS_CONFIG_PATH,
                "config_version": config_version,
                "sha256": sha256_bytes(models_payload),
            },
            "pricing_review": _sha_binding(PRICING_REVIEW_PATH, pricing_payload),
            "lock_schema": _sha_binding(LOCK_SCHEMA_PATH, schema_payload),
        },
        "candidates": candidates,
        "models": models,
        "plans": {
            "call_type": "answer",
            "variant_id": "default",
            "candidate_plans": candidate_plans,
            "ordered_universe_plan_sha256": sha256_bytes(
                canonical_json_bytes(universe_cells)
            ),
        },
        "execution_policy": {
            "call_type": "answer",
            "cells_per_candidate": len(MODEL_KEYS),
            "attempts_per_cell": ATTEMPTS_PER_CELL,
            "output_token_cap": OUTPUT_TOKEN_CAP,
            "candidate_cost_cap_microdollars": CANDIDATE_COST_CAP_MICRODOLLARS,
            "total_cost_cap_microdollars": TOTAL_COST_CAP_MICRODOLLARS,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
        },
        "threshold": {
            "required_completed_responses": REQUIRED_COMPLETED_RESPONSES,
            "minimum_non_null_primary_endorsements": (MINIMUM_NON_NULL_ENDORSEMENTS),
            "minimum_distinct_primary_positions": MINIMUM_DISTINCT_POSITIONS,
            "maximum_primary_endorsements_per_position": (
                MAXIMUM_ENDORSEMENTS_PER_POSITION
            ),
        },
        "state_transition_contract": _state_transition_contract(),
        "paid_authorization": {
            "required": True,
            "separate_from_lock": True,
            "lock_authorizes_spending": False,
            "required_before_state": "priority-ready",
            "receipt_must_bind": ["lock_sha256", "git_head"],
            "immediate_price_and_availability_recheck_required": True,
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
        for index, (actual_item, expected_item) in enumerate(
            zip(actual, expected, strict=True)
        ):
            difference = _difference(actual_item, expected_item, f"{path}[{index}]")
            if difference:
                return difference
        return None
    if actual != expected:
        return f"{path} differs from the immutable Rule 3 contract"
    return None


def _bound_paths(lock: dict[str, Any]) -> tuple[str, ...]:
    paths = [LOCK_PATH]
    paths.extend(binding["path"] for binding in lock["bindings"].values())
    paths.extend(candidate["path"] for candidate in lock["candidates"])
    paths.extend(source["path"] for source in lock["execution_sources"])
    normalized = [require_relative_path(path, "bound path") for path in paths]
    if len(normalized) != len(set(normalized)):
        raise Rule3LockError("bound Rule 3 paths must be unique")
    return tuple(normalized)


def _git(
    root: Path,
    arguments: list[str],
    *,
    text: bool = False,
) -> subprocess.CompletedProcess[Any]:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=text,
        )
    except OSError as error:
        raise Rule3LockError(f"git cannot be executed: {error}") from error
    return result


def _git_error(result: subprocess.CompletedProcess[Any], operation: str) -> str:
    stderr = result.stderr
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return f"{operation} failed: {str(stderr).strip() or 'unknown git error'}"


def _require_committed_and_clean(root: Path, paths: tuple[str, ...]) -> str:
    top = _git(root, ["rev-parse", "--show-toplevel"], text=True)
    if top.returncode != 0:
        raise Rule3LockError(_git_error(top, "git repository check"))
    if Path(top.stdout.strip()).resolve() != root.resolve():
        raise Rule3LockError("repository_root must be the Git worktree root")
    head_result = _git(root, ["rev-parse", "--verify", "HEAD"], text=True)
    if head_result.returncode != 0:
        raise Rule3LockError(_git_error(head_result, "Git HEAD check"))
    git_head = head_result.stdout.strip()

    for relative in paths:
        current = read_regular_file(root, relative)
        tree = _git(root, ["ls-tree", "-z", git_head, "--", relative])
        if tree.returncode != 0:
            raise Rule3LockError(_git_error(tree, f"Git tree check for {relative}"))
        entries = [entry for entry in tree.stdout.split(b"\0") if entry]
        if len(entries) != 1 or b"\t" not in entries[0]:
            raise Rule3LockError(f"{relative}: bound file is not present in HEAD")
        metadata, recorded_path = entries[0].split(b"\t", 1)
        fields = metadata.split()
        if (
            len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
            or recorded_path.decode("utf-8", errors="strict") != relative
        ):
            raise Rule3LockError(
                f"{relative}: HEAD entry must be a regular non-symlink file"
            )
        committed = _git(root, ["cat-file", "blob", f"{git_head}:{relative}"])
        if committed.returncode != 0:
            raise Rule3LockError(_git_error(committed, f"Git blob read for {relative}"))
        if committed.stdout != current:
            raise Rule3LockError(f"{relative}: working bytes differ from HEAD")

    unstaged = _git(root, ["diff", "--no-ext-diff", "--quiet", "--", *paths])
    if unstaged.returncode == 1:
        raise Rule3LockError("a bound Rule 3 path has unstaged changes")
    if unstaged.returncode != 0:
        raise Rule3LockError(_git_error(unstaged, "unstaged cleanliness check"))
    staged = _git(
        root,
        ["diff", "--no-ext-diff", "--cached", "--quiet", git_head, "--", *paths],
    )
    if staged.returncode == 1:
        raise Rule3LockError("a bound Rule 3 path has staged changes")
    if staged.returncode != 0:
        raise Rule3LockError(_git_error(staged, "staged cleanliness check"))
    final_head = _git(root, ["rev-parse", "--verify", "HEAD"], text=True)
    if final_head.returncode != 0 or final_head.stdout.strip() != git_head:
        raise Rule3LockError("Git HEAD changed during Rule 3 lock validation")
    return git_head


def _exact_lock_path(root: Path, lock_path: Path | str | None) -> Path:
    expected = root / LOCK_PATH
    if lock_path is None:
        return expected
    supplied = Path(lock_path)
    if supplied.is_absolute():
        matches = supplied == expected
    else:
        matches = supplied.as_posix() == LOCK_PATH
    if not matches:
        raise Rule3LockError(f"the Rule 3 lock path must be {LOCK_PATH}")
    return expected


def _context(
    root: Path,
    lock: dict[str, Any],
    lock_bytes: bytes,
    git_head: str | None,
) -> Rule3LockContext:
    snapshot = parse_json_bytes(lock_bytes, "validated Rule 3 lock")
    plans = snapshot["plans"]["candidate_plans"]
    return Rule3LockContext(
        repository_root=root,
        lock=snapshot,
        lock_bytes=lock_bytes,
        lock_sha256=sha256_bytes(lock_bytes),
        git_head=git_head,
        candidates=tuple(dict(candidate) for candidate in snapshot["candidates"]),
        models_config_path=root / snapshot["bindings"]["models_config"]["path"],
        protocol_path=root / snapshot["bindings"]["protocol"]["path"],
        question_paths=tuple(root / candidate["path"] for candidate in CANDIDATES),
        candidate_plan_sha256={
            plan["candidate_id"]: plan["plan_sha256"] for plan in plans
        },
        candidate_cost_cap_microdollars=snapshot["execution_policy"][
            "candidate_cost_cap_microdollars"
        ],
        total_cost_cap_microdollars=snapshot["execution_policy"][
            "total_cost_cap_microdollars"
        ],
        attempts_per_cell=snapshot["execution_policy"]["attempts_per_cell"],
        output_token_cap=snapshot["execution_policy"]["output_token_cap"],
    )


def validate_rule3_lock(
    raw: Any,
    repository_root: Path | str,
    lock_path: Path | str | None = None,
    require_committed: bool = False,
) -> Rule3LockContext:
    """Validate structure and hashes, optionally also proving Git immutability."""
    root = resolve_repository_root(repository_root)
    path = _exact_lock_path(root, lock_path)
    expected = build_rule3_lock(root)
    difference = _difference(raw, expected)
    if difference:
        raise Rule3LockError(difference)

    lock_bytes = canonical_json_bytes(raw)
    try:
        path.lstat()
    except FileNotFoundError:
        if require_committed:
            raise Rule3LockError(f"the committed {LOCK_PATH} is required")
    except OSError as error:
        raise Rule3LockError(f"{LOCK_PATH}: cannot be inspected: {error}") from error
    else:
        on_disk = read_regular_file(root, LOCK_PATH)
        parsed = parse_json_bytes(on_disk, LOCK_PATH)
        if on_disk != canonical_json_bytes(parsed):
            raise Rule3LockError(f"{LOCK_PATH}: lock JSON is not canonical")
        disk_difference = _difference(parsed, raw)
        if disk_difference:
            raise Rule3LockError("on-disk Rule 3 lock differs from supplied lock")
        lock_bytes = on_disk

    git_head = None
    if require_committed:
        git_head = _require_committed_and_clean(root, _bound_paths(raw))
    return _context(root, raw, lock_bytes, git_head)


def load_and_validate_rule3_lock(
    repository_root: Path | str,
    lock_path: Path | str | None = None,
    require_committed: bool = False,
) -> Rule3LockContext:
    """Load the canonical lock and apply structural/hash or runtime validation."""
    root = resolve_repository_root(repository_root)
    path = _exact_lock_path(root, lock_path)
    try:
        payload = read_regular_file(root, LOCK_PATH)
    except Rule3LockError as error:
        raise Rule3LockError(f"Rule 3 lock cannot be loaded: {error}") from error
    raw = parse_json_bytes(payload, LOCK_PATH)
    if payload != canonical_json_bytes(raw):
        raise Rule3LockError(f"{LOCK_PATH}: lock JSON is not canonical")
    return validate_rule3_lock(raw, root, path, require_committed)


def write_rule3_lock(
    repository_root: Path | str,
    raw: dict[str, Any] | None = None,
) -> Rule3LockContext:
    """Create the final lock once. An existing lock is never replaced."""
    root = resolve_repository_root(repository_root)
    lock = build_rule3_lock(root) if raw is None else raw
    context = validate_rule3_lock(lock, root)
    destination = root / LOCK_PATH
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise Rule3LockError("candidate directory must be a real directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".rule3-lock.", suffix=".tmp", dir=parent
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
            raise Rule3LockError(
                f"{LOCK_PATH} already exists; immutable locks are never overwritten"
            ) from error
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise Rule3LockError(
                    f"{LOCK_PATH} already exists; immutable locks are never overwritten"
                ) from error
            raise Rule3LockError(f"cannot create {LOCK_PATH}: {error}") from error
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
    return load_and_validate_rule3_lock(root)

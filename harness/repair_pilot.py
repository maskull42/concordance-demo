#!/usr/bin/env python3
"""Execute the approved, at-most-once repair of the partial Rule 2 pilot.

This utility is deliberately narrower than the general harness.  It accepts one
immutable parent stage, derives nine failed calls from the canonical 64-cell
plan, and writes every repair artifact outside the parent stage.  A repair ID is
single-use: once its receipt exists, this program will never send another
request under that ID.  In particular, a POST intent left without an outcome is
stranded, not an invitation to retry blindly.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from concordance_harness import HARNESS_VERSION
from concordance_harness.config import HarnessConfig, ModelConfig, load_harness_config
from concordance_harness.execution import (
    AttemptBudget,
    BudgetExceeded,
    RateLimiter,
    billed_output_tokens,
    preflight_panel,
)
from concordance_harness.pilot_lock import (
    PILOT_LOCK_PATH,
    load_and_validate_pilot_lock,
    require_exact_pilot_candidates,
)
from concordance_harness.planner import PlannedCall, build_plan, load_questions
from concordance_harness.providers import (
    PreflightResult,
    ProviderAdapter,
    ProviderError,
    ProviderResult,
    Transport,
    UrllibTransport,
)
from concordance_harness.util import (
    canonical_json_bytes,
    estimate_message_tokens,
    prompt_sha256,
    sanitize,
    sha256_bytes,
    sha256_file,
    utc_now,
)


HARNESS_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = HARNESS_ROOT.parent
PARENT_STAGE_RELATIVE = Path(".pilot/stages/without-mistral")
REPAIRS_RELATIVE = Path(".pilot/repairs")
CONFIG_RELATIVE = Path("harness/config/models.json")
PROTOCOL_RELATIVE = Path("config/protocol.json")
QUESTIONS_RELATIVE = Path("candidate/questions")

REPAIR_SCHEMA_VERSION = "pilot-repair-1.0.0"
RESULT_SCHEMA_VERSION = "pilot-repair-result-1.0.0"
INTENT_SCHEMA_VERSION = "pilot-repair-post-intent-1.0.0"
OUTCOME_SCHEMA_VERSION = "pilot-repair-outcome-1.0.0"
PREFLIGHT_SCHEMA_VERSION = "pilot-repair-preflight-1.0.0"
REPAIR_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

PARENT_STAGE_ID = "without-mistral"
PARENT_SELECTED_MODELS = (
    "gemini",
    "claude",
    "cohere",
    "qwen",
    "deepseek",
    "grok",
    "gpt",
)
TARGET_MODEL_KEYS = ("deepseek", "gpt")
DEEPSEEK_TARGET_CELL = (
    "atomic-bombs-pacific-war:deepseek:"
    "invasion-and-resistance-frame:answer"
)
GPT_RETURNED_CANONICAL_ID = "openai/gpt-5.6-sol-20260709"
GPT_PRIOR_ERROR = {
    "category": "response-validation",
    "retryable": False,
    "sanitized_summary": (
        "provider returned model 'openai/gpt-5.6-sol-20260709', expected "
        "'openai/gpt-5.6-sol'"
    ),
}
DEEPSEEK_PRIOR_ERROR = {
    "category": "network",
    "retryable": False,
    "sanitized_summary": "provider connection failed while reading the response",
}

CANONICAL_CELL_COUNT = 64
PARENT_CELL_COUNT = 56
PARENT_SUCCESS_COUNT = 47
TARGET_CELL_COUNT = 9
PREFLIGHT_CALL_COUNT = 2
MAX_OUTBOUND_CALLS = PREFLIGHT_CALL_COUNT + TARGET_CELL_COUNT
MAX_COST_USD = 4.0
ATTEMPTS_PER_REQUEST = 1

LIVE_PARENT_STAGE_SHA256 = (
    "27c6bf8c0b023cffe1da0281361fd25e1732572ea5db6e6d0564f5ada245c9a8"
)
LIVE_PARENT_MANIFEST_SHA256 = (
    "7670f719be9712377e7464cf2541722d235d3203c3d9168a4f026bf077ce5658"
)
LIVE_PARENT_EXECUTION_CONTRACT_SHA256 = (
    "548a8001b81d2d4bfaa6e9c459d27a40a0e3b85996f593d8cc3e2adb2c17506c"
)
LIVE_PARENT_FULL_PLAN_SHA256 = (
    "12d1813bb974156e03ab733f914f13a82f8f4d78e9e991ae32c1a346f4ab2652"
)
LIVE_PARENT_STAGE_PLAN_SHA256 = (
    "da10ceaca45a7cf83b44df9e7dafd2fa711865e354c17828a5d4e57edd3c6d9e"
)
LIVE_CONFIG_SHA256 = (
    "c67f043202696a71998d7c5ea9a18ce4c574fe244741717077e45e00acb7fb05"
)
LIVE_PILOT_LOCK_SHA256 = (
    "a9acb26049721e1d1d87b92400f39c5c90c2a875a32ee9eeb944c68bdefde293"
)
LIVE_PARENT_RUN_SHA256 = {
    "runs/atomic-bombs-pacific-war.json": (
        "2311b15ed74e9afd33da61dff0988395159eb24f003d8e969046336adbde99d9"
    ),
    "runs/james-jesus-brothers.json": (
        "6436987815000fbbe47e444f9b1644636a36f0ea495c6f57eb55c397427640f4"
    ),
    "runs/john-brown-harpers-ferry.json": (
        "021bb757770b1d472db9f86bb7975b7b03d42f04c58dc46e4777d7440e7d1780"
    ),
    "runs/junia-romans-16-7.json": (
        "9f4c8a32d8942db7bbb4d893b377f33037924afc0ea890d04b6b6b7c210da1f0"
    ),
    "runs/locke-money-property.json": (
        "3b24b525eae3baa6c7b2698cd8c855043ae38c183508dde87d626ef3b80c8ba1"
    ),
    "runs/mill-harm-principle.json": (
        "37290c25041f231b4fd0f1c4cba6e4519bd977dd146eebe4d51c74ebbb8d10d7"
    ),
}


class RepairError(RuntimeError):
    """Raised before network access when the sealed repair contract is violated."""


@dataclass(frozen=True)
class ParentEvidence:
    stage_path: Path
    stage: dict[str, Any]
    stage_sha256: str
    manifest_path: Path
    manifest: dict[str, Any]
    manifest_sha256: str
    run_hashes: tuple[tuple[str, str], ...]
    cells: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class RepairContext:
    repository_root: Path
    repair_id: str
    repair_root: Path
    config: HarnessConfig
    protocol: dict[str, str]
    full_plan: tuple[PlannedCall, ...]
    target_calls: tuple[PlannedCall, ...]
    target_models: tuple[ModelConfig, ...]
    parent: ParentEvidence
    receipt: dict[str, Any]


def _load_protocol(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise RepairError(f"frozen protocol cannot be loaded: {error}") from error
    expected = {"protocol_version", "system_prompt", "standard_challenge_prompt"}
    if not isinstance(raw, dict) or set(raw) != expected:
        raise RepairError("frozen protocol fields differ from the canonical contract")
    if not all(isinstance(raw[key], str) for key in expected):
        raise RepairError("frozen protocol values must be strings")
    return raw


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_bytes())
    except FileNotFoundError as error:
        raise RepairError(f"{label} is missing: {path}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise RepairError(f"{label} is malformed: {error}") from error
    if not isinstance(raw, dict):
        raise RepairError(f"{label} must be a JSON object")
    return raw


def _plan_contract_sha256(plan: Iterable[PlannedCall]) -> str:
    contract = [
        {
            "cell_id": call.cell_id,
            "prompt_sha256": prompt_sha256(call.answer_messages()),
            "requested_model_id": call.model.requested_model_id,
            "route": call.model.route,
            "requested_params": call.model.requested_params_receipt(),
        }
        for call in plan
    ]
    return sha256_bytes(canonical_json_bytes(contract))


def _repair_source_hashes() -> dict[str, str]:
    paths = {
        HARNESS_ROOT / "repair_pilot.py",
        HARNESS_ROOT / "config" / "models.json",
        *(HARNESS_ROOT / "concordance_harness").glob("*.py"),
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _require_live_parent_fingerprints(
    root: Path,
    stage: dict[str, Any],
    stage_hash: str,
    manifest_hash: str,
    run_hashes: tuple[tuple[str, str], ...],
    config: HarnessConfig,
) -> None:
    checks = {
        "parent stage file": (stage_hash, LIVE_PARENT_STAGE_SHA256),
        "parent model manifest": (manifest_hash, LIVE_PARENT_MANIFEST_SHA256),
        "parent execution contract": (
            stage.get("execution_contract_sha256"),
            LIVE_PARENT_EXECUTION_CONTRACT_SHA256,
        ),
        "parent full plan": (
            stage.get("full_plan_sha256"),
            LIVE_PARENT_FULL_PLAN_SHA256,
        ),
        "parent stage plan": (
            stage.get("stage_plan_sha256"),
            LIVE_PARENT_STAGE_PLAN_SHA256,
        ),
        "model configuration": (config.sha256, LIVE_CONFIG_SHA256),
        "pilot lock": (
            sha256_file(root / PILOT_LOCK_PATH),
            LIVE_PILOT_LOCK_SHA256,
        ),
    }
    for label, (actual, expected) in checks.items():
        if actual != expected:
            raise RepairError(f"{label} differs from the approved repair parent")
    if dict(run_hashes) != LIVE_PARENT_RUN_SHA256:
        raise RepairError("parent run files differ from the approved repair parent")


def _target_record(
    ordinal: int,
    call: PlannedCall,
    prior_cell: dict[str, Any],
    run_path: str,
    run_sha256: str,
) -> dict[str, Any]:
    return {
        "ordinal": ordinal,
        "cell_id": call.cell_id,
        "question_id": call.question.question_id,
        "question_file_sha256": call.question.sha256,
        "model_key": call.model.model_key,
        "requested_model_id": call.model.requested_model_id,
        "route": call.model.route,
        "variant_id": call.variant_id,
        "call_type": call.call_type,
        "prompt_sha256": prompt_sha256(call.answer_messages()),
        "requested_params": call.model.requested_params_receipt(),
        "parent_run_path": run_path,
        "parent_run_sha256": run_sha256,
        "prior_error": prior_cell["error"],
        "prior_error_cell_sha256": sha256_bytes(canonical_json_bytes(prior_cell)),
    }


def _expected_targets(full_plan: tuple[PlannedCall, ...]) -> tuple[PlannedCall, ...]:
    targets = tuple(
        call
        for call in full_plan
        if call.model.model_key == "gpt" or call.cell_id == DEEPSEEK_TARGET_CELL
    )
    if len(full_plan) != CANONICAL_CELL_COUNT or any(
        call.call_type != "answer" for call in full_plan
    ):
        raise RepairError("canonical Rule 2 plan is not the exact 64-cell answer plan")
    if len(targets) != TARGET_CELL_COUNT:
        raise RepairError("canonical Rule 2 plan does not derive exactly nine repairs")
    if sum(call.model.model_key == "gpt" for call in targets) != 8:
        raise RepairError("canonical repair must derive exactly eight GPT cells")
    if sum(call.model.model_key == "deepseek" for call in targets) != 1:
        raise RepairError("canonical repair must derive exactly one DeepSeek cell")
    return targets


def _validate_stage(
    root: Path,
    stage_root: Path,
    config: HarnessConfig,
    full_plan: tuple[PlannedCall, ...],
) -> tuple[dict[str, Any], str, dict[str, Any], str]:
    stage_path = stage_root / "stage.json"
    stage = _read_json(stage_path, "parent stage receipt")
    stage_hash = sha256_file(stage_path)
    manifest_path = stage_root / "manifests/models.json"
    manifest = _read_json(manifest_path, "parent model manifest")
    manifest_hash = sha256_file(manifest_path)

    selected_models = tuple(
        model for model in config.models if model.model_key in PARENT_SELECTED_MODELS
    )
    parent_plan = tuple(
        call for call in full_plan if call.model.model_key in PARENT_SELECTED_MODELS
    )
    expected_stage = {
        "schema_version": "pilot-stage-1.0.0",
        "stage_id": PARENT_STAGE_ID,
        "evidence_status": "partial-nonqualifying",
        "selected_model_keys": list(PARENT_SELECTED_MODELS),
        "deferred_model_keys": ["mistral"],
        "expected_logical_cell_count": PARENT_CELL_COUNT,
        "required_aggregate_logical_cell_count": CANONICAL_CELL_COUNT,
        "pilot_lock_sha256": sha256_file(root / PILOT_LOCK_PATH),
        "config_sha256": config.sha256,
        "harness_version": HARNESS_VERSION,
        "full_plan_sha256": _plan_contract_sha256(full_plan),
        "stage_plan_sha256": _plan_contract_sha256(parent_plan),
        "model_manifest_file_sha256": manifest_hash,
    }
    for key, expected in expected_stage.items():
        if stage.get(key) != expected:
            raise RepairError(f"parent stage receipt differs at {key}")
    if set(stage) != {*expected_stage, "execution_contract_sha256", "created_at"}:
        raise RepairError("parent stage receipt fields differ from its sealed contract")
    if not isinstance(stage["created_at"], str) or not SHA256_PATTERN.fullmatch(
        str(stage["execution_contract_sha256"])
    ):
        raise RepairError("parent stage receipt has malformed audit metadata")

    expected_manifest_keys = {
        "schema_version",
        "manifest_id",
        "captured_at",
        "harness_version",
        "config_sha256",
        "data_class",
        "models",
    }
    if set(manifest) != expected_manifest_keys:
        raise RepairError("parent model manifest fields differ from the contract")
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("harness_version") != HARNESS_VERSION
        or manifest.get("config_sha256") != config.sha256
        or manifest.get("data_class") != "research"
    ):
        raise RepairError("parent model manifest uses another execution contract")
    snapshots = manifest.get("models")
    if not isinstance(snapshots, list) or len(snapshots) != len(selected_models):
        raise RepairError("parent model manifest does not contain the seven-model stage")
    for model, snapshot in zip(selected_models, snapshots, strict=True):
        if not isinstance(snapshot, dict):
            raise RepairError("parent model manifest contains a malformed model")
        static = {
            "model_key": model.model_key,
            "family": model.family,
            "provider": model.provider,
            "requested_model_id": model.requested_model_id,
            "route": model.route,
            "environment_variable": model.environment_variable,
            "fallback_allowed": False,
            "capabilities": {
                "tools": False,
                "web_search": False,
                "retrieval": False,
            },
            "policy": model.manifest_policy(),
            "pricing": {
                "currency": model.planning_pricing["currency"],
                "input_per_million": model.planning_pricing["input_per_million"],
                "output_per_million": model.planning_pricing["output_per_million"],
                "pricing_as_of": model.planning_pricing["pricing_as_of"],
            },
        }
        if {key: snapshot.get(key) for key in static} != static:
            raise RepairError(
                f"parent model manifest differs for canonical model {model.model_key}"
            )
        preflight = snapshot.get("preflight")
        if not isinstance(preflight, dict) or preflight.get("status") != "available":
            raise RepairError(f"parent preflight is invalid for {model.model_key}")
        returned = preflight.get("provider_returned_model_id")
        if not isinstance(returned, str):
            raise RepairError(f"parent preflight lacks an ID for {model.model_key}")
        if returned.removeprefix("models/") != model.requested_model_id:
            raise RepairError(f"parent preflight substituted {model.model_key}")
        if model.model_key == "gpt" and preflight.get("sanitized_note") != (
            "Provider endpoint: OpenAI"
        ):
            raise RepairError("parent GPT preflight was not pinned to OpenAI")
    return stage, stage_hash, manifest, manifest_hash


def _validate_cell_contract(cell: dict[str, Any], call: PlannedCall) -> None:
    expected = {
        "cell_id": call.cell_id,
        "question_id": call.question.question_id,
        "model_key": call.model.model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "requested_model_id": call.model.requested_model_id,
        "variant_id": call.variant_id,
        "call_type": "answer",
        "parent_response_id": None,
        "messages": call.answer_messages(),
        "prompt_sha256": prompt_sha256(call.answer_messages()),
        "requested_params": call.model.requested_params_receipt(),
    }
    for key, value in expected.items():
        if cell.get(key) != value:
            raise RepairError(f"parent cell {call.cell_id} differs at {key}")
    if cell.get("status") not in {"success", "error"}:
        raise RepairError(f"parent cell {call.cell_id} has an invalid status")
    if not isinstance(cell.get("attempted_at"), str) or not isinstance(
        cell.get("attempt_count"), int
    ) or cell["attempt_count"] < 1:
        raise RepairError(f"parent cell {call.cell_id} lacks an attempt receipt")
    if cell["status"] == "success":
        if not isinstance(cell.get("response_text"), str) or not cell[
            "response_text"
        ].strip():
            raise RepairError(f"parent success {call.cell_id} has no response")
        if not isinstance(cell.get("response_id"), str):
            raise RepairError(f"parent success {call.cell_id} has no response ID")
    elif not isinstance(cell.get("error"), dict):
        raise RepairError(f"parent error {call.cell_id} has no error receipt")


def _validate_runs(
    stage_root: Path,
    config: HarnessConfig,
    questions: tuple[Any, ...],
    full_plan: tuple[PlannedCall, ...],
    manifest: dict[str, Any],
    manifest_hash: str,
) -> tuple[tuple[tuple[str, str], ...], dict[str, dict[str, Any]]]:
    runs_root = stage_root / "runs"
    expected_names = {f"{question.question_id}.json" for question in questions}
    actual_paths = sorted(runs_root.glob("*.json")) if runs_root.is_dir() else []
    if {path.name for path in actual_paths} != expected_names:
        raise RepairError("parent stage does not contain exactly the six canonical runs")

    calls = {
        call.cell_id: call
        for call in full_plan
        if call.model.model_key in PARENT_SELECTED_MODELS
    }
    cells: dict[str, dict[str, Any]] = {}
    run_hashes: list[tuple[str, str]] = []
    questions_by_id = {question.question_id: question for question in questions}
    for path in actual_paths:
        run = _read_json(path, f"parent run {path.name}")
        run_hash = sha256_file(path)
        run_hashes.append((str(path.relative_to(stage_root)), run_hash))
        question_id = path.stem
        question = questions_by_id[question_id]
        expected_top = {
            "schema_version",
            "run_id",
            "run_purpose",
            "question_id",
            "question_content_version",
            "question_file_sha256",
            "generated_at",
            "updated_at",
            "harness_version",
            "harness_config_sha256",
            "model_manifest_file_sha256",
            "model_manifest_snapshot",
            "cells",
        }
        if set(run) != expected_top:
            raise RepairError(f"parent run {question_id} fields differ from the contract")
        expected_metadata = {
            "schema_version": "1.0.0",
            "run_purpose": "pilot",
            "question_id": question_id,
            "question_content_version": question.content_version,
            "question_file_sha256": question.sha256,
            "harness_version": HARNESS_VERSION,
            "harness_config_sha256": config.sha256,
            "model_manifest_file_sha256": manifest_hash,
            "model_manifest_snapshot": manifest,
        }
        for key, value in expected_metadata.items():
            if run.get(key) != value:
                raise RepairError(f"parent run {question_id} differs at {key}")
        run_cells = run.get("cells")
        if not isinstance(run_cells, list):
            raise RepairError(f"parent run {question_id} cells are malformed")
        for cell in run_cells:
            if not isinstance(cell, dict) or not isinstance(cell.get("cell_id"), str):
                raise RepairError(f"parent run {question_id} contains a malformed cell")
            cell_id = cell["cell_id"]
            if cell_id in cells:
                raise RepairError(f"parent stage duplicates cell {cell_id}")
            call = calls.get(cell_id)
            if call is None or call.question.question_id != question_id:
                raise RepairError(f"parent stage contains orphan cell {cell_id}")
            _validate_cell_contract(cell, call)
            cells[cell_id] = cell
    if set(cells) != set(calls):
        missing = sorted(set(calls) - set(cells))
        extra = sorted(set(cells) - set(calls))
        raise RepairError(f"parent 56-cell matrix differs; missing={missing}, extra={extra}")
    successes = sum(cell["status"] == "success" for cell in cells.values())
    errors = sum(cell["status"] == "error" for cell in cells.values())
    if (successes, errors) != (PARENT_SUCCESS_COUNT, TARGET_CELL_COUNT):
        raise RepairError(
            "parent stage must be the exact 47-success/9-error checkpoint"
        )
    return tuple(run_hashes), cells


def prepare_repair(
    repository_root: Path,
    repair_id: str,
    *,
    parent_stage_root: Path | None = None,
    require_committed_inputs: bool = True,
    require_live_parent_fingerprints: bool = True,
) -> RepairContext:
    """Validate the parent and construct, but do not write, the repair receipt."""
    if not REPAIR_ID_PATTERN.fullmatch(repair_id):
        raise RepairError(
            "repair ID must use 1-64 lowercase letters, digits, or hyphens"
        )
    root = repository_root.resolve()
    stage_root = (parent_stage_root or root / PARENT_STAGE_RELATIVE).resolve()
    expected_stage_root = (root / PARENT_STAGE_RELATIVE).resolve()
    if stage_root != expected_stage_root:
        raise RepairError(f"parent stage must be exactly {PARENT_STAGE_RELATIVE}")

    config = load_harness_config(root / CONFIG_RELATIVE)
    protocol_path = root / PROTOCOL_RELATIVE
    protocol = _load_protocol(protocol_path)
    questions = load_questions(root / QUESTIONS_RELATIVE)
    require_exact_pilot_candidates(questions)
    load_and_validate_pilot_lock(
        root / PILOT_LOCK_PATH,
        root,
        protocol_path,
        questions,
        require_committed_inputs=require_committed_inputs,
    )
    full_plan = build_plan(
        questions,
        config.models,
        protocol["system_prompt"],
        protocol["standard_challenge_prompt"],
        answer_only=True,
    )
    targets = _expected_targets(full_plan)
    stage, stage_hash, manifest, manifest_hash = _validate_stage(
        root, stage_root, config, full_plan
    )
    run_hashes, cells = _validate_runs(
        stage_root, config, questions, full_plan, manifest, manifest_hash
    )
    if require_live_parent_fingerprints:
        _require_live_parent_fingerprints(
            root,
            stage,
            stage_hash,
            manifest_hash,
            run_hashes,
            config,
        )

    expected_target_ids = {call.cell_id for call in targets}
    actual_error_ids = {
        cell_id for cell_id, cell in cells.items() if cell["status"] == "error"
    }
    if actual_error_ids != expected_target_ids:
        raise RepairError("parent errors are not the nine canonical repair targets")
    for call in targets:
        expected_error = GPT_PRIOR_ERROR if call.model.model_key == "gpt" else (
            DEEPSEEK_PRIOR_ERROR
        )
        if cells[call.cell_id].get("error") != expected_error:
            raise RepairError(f"prior error changed for {call.cell_id}")
        if cells[call.cell_id].get("attempt_count") != 1:
            raise RepairError(f"prior attempt count changed for {call.cell_id}")

    target_models = tuple(
        model for model in config.models if model.model_key in TARGET_MODEL_KEYS
    )
    if tuple(model.model_key for model in target_models) != TARGET_MODEL_KEYS:
        raise RepairError("repair preflight scope is not exactly DeepSeek and GPT")
    cost_ceiling = sum(call.cost_ceiling() for call in targets)
    if cost_ceiling > MAX_COST_USD:
        raise RepairError(
            f"nine-call ceiling ${cost_ceiling:.6f} exceeds the fixed $4 repair cap"
        )
    run_hash_by_question = {
        Path(path).stem: (path, digest) for path, digest in run_hashes
    }
    target_records = []
    for ordinal, call in enumerate(targets, start=1):
        run_path, run_hash = run_hash_by_question[call.question.question_id]
        target_records.append(
            _target_record(ordinal, call, cells[call.cell_id], run_path, run_hash)
        )

    repair_root = (root / REPAIRS_RELATIVE / repair_id).resolve()
    repairs_root = (root / REPAIRS_RELATIVE).resolve()
    if repair_root.parent != repairs_root:
        raise RepairError("repair output escaped the private repair directory")
    repair_source_files = _repair_source_hashes()
    gpt = config.by_key()["gpt"]
    receipt = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "repair_id": repair_id,
        "purpose": "approved-nine-cell-gpt-identity-and-deepseek-network-repair",
        "evidence_status": "partial-nonqualifying-until-mistral-completes",
        "approval": {
            "decision": "author-approved",
            "approved_at": "2026-07-12",
            "model_key": gpt.model_key,
            "provider": gpt.provider,
            "route": gpt.route,
            "required_provider_name": "OpenAI",
            "fallback_allowed": gpt.fallback_allowed,
            "provider_options": gpt.provider_options,
            "gpt_requested_alias": gpt.requested_model_id,
            "gpt_returned_canonical_id": GPT_RETURNED_CANONICAL_ID,
            "interpretation": "identity-equivalent-canonical-resolution",
        },
        "parent": {
            "stage_id": stage["stage_id"],
            "stage_path": str(PARENT_STAGE_RELATIVE),
            "stage_sha256": stage_hash,
            "manifest_path": str(
                (PARENT_STAGE_RELATIVE / "manifests/models.json")
            ),
            "manifest_sha256": manifest_hash,
            "run_files": [
                {
                    "path": str(PARENT_STAGE_RELATIVE / path),
                    "sha256": digest,
                }
                for path, digest in run_hashes
            ],
            "success_count": PARENT_SUCCESS_COUNT,
            "error_count": TARGET_CELL_COUNT,
            "logical_cell_count": PARENT_CELL_COUNT,
        },
        "canonical_contract": {
            "harness_version": HARNESS_VERSION,
            "repair_source_files": repair_source_files,
            "repair_execution_sha256": sha256_bytes(
                canonical_json_bytes(repair_source_files)
            ),
            "config_path": str(CONFIG_RELATIVE),
            "config_sha256": config.sha256,
            "pilot_lock_path": PILOT_LOCK_PATH,
            "pilot_lock_sha256": sha256_file(root / PILOT_LOCK_PATH),
            "protocol_path": str(PROTOCOL_RELATIVE),
            "protocol_sha256": sha256_file(protocol_path),
            "canonical_plan_sha256": _plan_contract_sha256(full_plan),
            "canonical_logical_cell_count": CANONICAL_CELL_COUNT,
            "target_plan_sha256": _plan_contract_sha256(targets),
        },
        "network_scope": {
            "preflight_model_keys": list(TARGET_MODEL_KEYS),
            "preflight_call_count": PREFLIGHT_CALL_COUNT,
            "generation_call_count": TARGET_CELL_COUNT,
            "max_outbound_calls": MAX_OUTBOUND_CALLS,
            "attempts_per_request": ATTEMPTS_PER_REQUEST,
            "max_cost_usd": MAX_COST_USD,
            "one_attempt_cost_ceiling_usd": cost_ceiling,
        },
        "targets": target_records,
        "replay_policy": (
            "repair-id-single-use; never resend a terminal or stranded POST intent"
        ),
    }
    parent = ParentEvidence(
        stage_path=stage_root / "stage.json",
        stage=stage,
        stage_sha256=stage_hash,
        manifest_path=stage_root / "manifests/models.json",
        manifest=manifest,
        manifest_sha256=manifest_hash,
        run_hashes=run_hashes,
        cells=cells,
    )
    return RepairContext(
        repository_root=root,
        repair_id=repair_id,
        repair_root=repair_root,
        config=config,
        protocol=protocol,
        full_plan=full_plan,
        target_calls=targets,
        target_models=target_models,
        parent=parent,
        receipt=receipt,
    )


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_once_json(path: Path, value: Any) -> str:
    """Durably create JSON without ever replacing an existing journal entry."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(value)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise RepairError(f"write-once repair artifact already exists: {path}") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # A partial file is itself a terminal journal marker.  It is intentionally
        # not removed because doing so could make a sent POST replayable.
        raise
    _fsync_directory(path.parent)
    return sha256_bytes(payload)


def initialize_repair(context: RepairContext) -> str:
    """Claim a repair ID exactly once and persist its immutable receipt."""
    if context.repair_root.exists() and any(context.repair_root.iterdir()):
        raise RepairError(
            "repair ID already has terminal or stranded artifacts; choose a new ID "
            "only after reviewing them"
        )
    receipt = {**context.receipt, "created_at": utc_now()}
    return write_once_json(context.repair_root / "repair.json", receipt)


def _safe_request_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )


def _success_cell(
    call: PlannedCall,
    result: ProviderResult,
    attempted_at: str,
    latency_ms: int,
) -> dict[str, Any]:
    messages = call.answer_messages()
    response_hash = sha256_bytes(result.response_text.encode("utf-8"))[:12]
    usage = result.usage
    input_tokens = (
        usage["input_tokens"]
        if usage["input_tokens"] is not None
        else estimate_message_tokens(messages)
    )
    output_tokens = billed_output_tokens(call.model, usage, result.response_text)
    pricing = call.model.planning_pricing
    cost = (
        input_tokens * float(pricing["input_per_million"])
        + output_tokens * float(pricing["output_per_million"])
    ) / 1_000_000
    return {
        "status": "success",
        "cell_id": call.cell_id,
        "question_id": call.question.question_id,
        "model_key": call.model.model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "requested_model_id": call.model.requested_model_id,
        "variant_id": call.variant_id,
        "call_type": call.call_type,
        "parent_response_id": None,
        "messages": messages,
        "prompt_sha256": prompt_sha256(messages),
        "requested_params": call.model.requested_params_receipt(),
        "attempted_at": attempted_at,
        "attempt_count": 1,
        "response_id": (
            f"{call.question.question_id}-{call.model.model_key}-{call.variant_id}-"
            f"answer-repair-{response_hash}"
        ),
        "provider_returned_model_id": result.returned_model_id,
        "provider_response_id": result.provider_response_id,
        "effective_params": result.effective_params,
        "response_text": result.response_text,
        "generated_at": utc_now(),
        "latency_ms": latency_ms,
        "finish_reason": result.finish_reason,
        "usage": usage,
        "cost": {
            "usd": cost,
            "source": "estimated",
            "pricing_as_of": pricing["pricing_as_of"],
        },
    }


def _error_cell(
    call: PlannedCall,
    error: ProviderError,
    attempted_at: str,
    secrets: Iterable[str],
) -> dict[str, Any]:
    messages = call.answer_messages()
    return {
        "status": "error",
        "cell_id": call.cell_id,
        "question_id": call.question.question_id,
        "model_key": call.model.model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "requested_model_id": call.model.requested_model_id,
        "variant_id": call.variant_id,
        "call_type": call.call_type,
        "parent_response_id": None,
        "messages": messages,
        "prompt_sha256": prompt_sha256(messages),
        "requested_params": call.model.requested_params_receipt(),
        "attempted_at": attempted_at,
        "attempt_count": 1,
        "error": {
            "category": error.category,
            "retryable": False,
            "sanitized_summary": sanitize(error, secrets),
        },
        "failed_at": utc_now(),
    }


def _preflight_receipt(
    context: RepairContext,
    repair_receipt_sha256: str,
    results: dict[str, PreflightResult],
) -> dict[str, Any]:
    return {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "repair_id": context.repair_id,
        "repair_receipt_sha256": repair_receipt_sha256,
        "model_keys": list(TARGET_MODEL_KEYS),
        "outbound_get_count": PREFLIGHT_CALL_COUNT,
        "results": [
            {
                "model_key": model.model_key,
                "requested_model_id": model.requested_model_id,
                "returned_model_id": results[model.model_key].returned_model_id,
                "provider_name": results[model.model_key].provider_name,
                "note": results[model.model_key].note,
            }
            for model in context.target_models
        ],
        "completed_at": utc_now(),
    }


async def execute_repair(
    context: RepairContext,
    secrets: dict[str, str],
    transport: Transport,
) -> dict[str, Any]:
    """Run two GET preflights and nine POSTs, each at most once."""
    required_secret_names = {
        model.environment_variable for model in context.target_models
    }
    if set(secrets) != required_secret_names or any(
        not secrets[name] for name in required_secret_names
    ):
        raise RepairError("repair secrets must contain exactly DeepSeek and OpenRouter")

    repair_hash = initialize_repair(context)
    budget = AttemptBudget(MAX_OUTBOUND_CALLS, MAX_COST_USD)
    try:
        preflight = await preflight_panel(
            context.target_models,
            secrets,
            transport,
            budget,
            ATTEMPTS_PER_REQUEST,
        )
    except ProviderError as error:
        raise RepairError(sanitize(error, secrets.values())) from None
    preflight_payload = _preflight_receipt(context, repair_hash, preflight)
    preflight_hash = write_once_json(
        context.repair_root / "preflight.json", preflight_payload
    )

    limiters = {
        model.model_key: RateLimiter(model.requests_per_second)
        for model in context.target_models
    }
    outcomes: list[dict[str, Any]] = []
    for ordinal, call in enumerate(context.target_calls, start=1):
        adapter = ProviderAdapter(call.model, transport)
        secret = secrets[call.model.environment_variable]
        messages = call.answer_messages()
        request = adapter.build_generation_request(secret, messages)
        target = context.receipt["targets"][ordinal - 1]
        artifact_stem = f"{ordinal:02d}-{sha256_bytes(call.cell_id.encode())[:12]}"
        intent_path = context.repair_root / "intents" / f"{artifact_stem}.json"
        outcome_path = context.repair_root / "outcomes" / f"{artifact_stem}.json"
        await budget.reserve(call.cost_ceiling())
        await limiters[call.model.model_key].wait()
        attempted_at = utc_now()
        intent = {
            "schema_version": INTENT_SCHEMA_VERSION,
            "repair_id": context.repair_id,
            "repair_receipt_sha256": repair_hash,
            "ordinal": ordinal,
            "cell_id": call.cell_id,
            "parent_error_cell_sha256": target["prior_error_cell_sha256"],
            "method": "POST",
            "url_without_query": _safe_request_url(request.url),
            "request_body_sha256": sha256_bytes(
                canonical_json_bytes(request.json_body)
            ),
            "prompt_sha256": prompt_sha256(messages),
            "cost_ceiling_usd": call.cost_ceiling(),
            "attempted_at": attempted_at,
            "replay_policy": "never-resend-under-this-repair-id",
        }
        intent_hash = write_once_json(intent_path, intent)

        started = time.monotonic()
        try:
            provider_result = await adapter.generate(secret, messages)
            cell = _success_cell(
                call,
                provider_result,
                attempted_at,
                int((time.monotonic() - started) * 1000),
            )
        except ProviderError as error:
            cell = _error_cell(call, error, attempted_at, secrets.values())
        outcome = {
            "schema_version": OUTCOME_SCHEMA_VERSION,
            "repair_id": context.repair_id,
            "repair_receipt_sha256": repair_hash,
            "intent_path": str(intent_path.relative_to(context.repair_root)),
            "intent_sha256": intent_hash,
            "cell": cell,
            "completed_at": utc_now(),
        }
        outcome_hash = write_once_json(outcome_path, outcome)
        outcomes.append(
            {
                "path": str(outcome_path.relative_to(context.repair_root)),
                "sha256": outcome_hash,
                "cell": cell,
            }
        )

    if budget.attempts != MAX_OUTBOUND_CALLS:
        raise RepairError(
            f"repair made {budget.attempts} outbound attempts, expected exactly 11"
        )
    cells = [outcome["cell"] for outcome in outcomes]
    success_count = sum(cell["status"] == "success" for cell in cells)
    error_count = sum(cell["status"] == "error" for cell in cells)
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "repair_id": context.repair_id,
        "status": "completed" if error_count == 0 else "completed-with-errors",
        "evidence_status": "partial-nonqualifying-until-mistral-completes",
        "repair_receipt_sha256": repair_hash,
        "preflight_path": "preflight.json",
        "preflight_sha256": preflight_hash,
        "outbound_attempt_count": budget.attempts,
        "reserved_cost_ceiling_usd": budget.reserved_cost_usd,
        "success_count": success_count,
        "error_count": error_count,
        "outcomes": [
            {"path": item["path"], "sha256": item["sha256"]}
            for item in outcomes
        ],
        "cells": cells,
        "completed_at": utc_now(),
    }
    write_once_json(context.repair_root / "result.json", result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the approved nine-cell Concordance pilot repair once."
    )
    parser.add_argument("--live", action="store_true", required=True)
    parser.add_argument("--repair-id", required=True)
    parser.add_argument("--credentials-rotated", action="store_true")
    parser.add_argument("--approved-gpt-alias-resolution", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not args.credentials_rotated:
            raise RepairError("repair requires confirmation that credentials were rotated")
        if not args.approved_gpt_alias_resolution:
            raise RepairError("repair requires the author's GPT identity approval")
        context = prepare_repair(REPOSITORY_ROOT, args.repair_id)
        # Environment access occurs only after every parent and freeze check passes.
        secrets = {
            model.environment_variable: os.environ.get(
                model.environment_variable, ""
            )
            for model in context.target_models
        }
        missing = sorted(name for name, value in secrets.items() if not value)
        if missing:
            raise RepairError(
                "missing required environment variables: " + ", ".join(missing)
            )
        result = asyncio.run(execute_repair(context, secrets, UrllibTransport()))
        print(
            f"Repair {context.repair_id}: {result['success_count']} success, "
            f"{result['error_count']} error; {result['outbound_attempt_count']} "
            "fresh outbound calls."
        )
        print(
            "Evidence remains private and nonqualifying until the eight deferred "
            "Mistral cells complete."
        )
        return 0
    except (RepairError, ProviderError, BudgetExceeded, ValueError) as error:
        print(f"Repair stopped: {sanitize(error)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

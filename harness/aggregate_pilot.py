#!/usr/bin/env python3
"""Fail-closed, offline aggregation and blinding for the Rule 2 pilot.

The aggregate is deliberately tied to the one approved evidence history.  It
accepts the sealed seven-model parent, overlays only its nine recorded errors
with the approved repair journal, and adds the disjoint eight-cell Mistral
stage.  It performs no network access and reads no environment variables.

The output directory is single-use.  Blind mapper items contain only the exact
prompt, the minimal approved position map, and the verbatim response.  Model,
provider, case, variant, pairing, and aggregate metadata live only in the
private crosswalk.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from concordance_harness import HARNESS_VERSION
from concordance_harness.config import HarnessConfig, ModelConfig, load_harness_config
from concordance_harness.pilot_lock import (
    PILOT_LOCK_PATH,
    load_and_validate_pilot_lock,
    require_exact_pilot_candidates,
)
from concordance_harness.planner import PlannedCall, QuestionInput, build_plan, load_questions
from concordance_harness.util import (
    canonical_json_bytes,
    prompt_sha256,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from repair_pilot import RepairError, prepare_repair


HARNESS_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = HARNESS_ROOT.parent
CONFIG_RELATIVE = Path("harness/config/models.json")
PROTOCOL_RELATIVE = Path("config/protocol.json")
QUESTIONS_RELATIVE = Path("candidate/questions")
PARENT_RELATIVE = Path(".pilot/stages/without-mistral")
REPAIR_RELATIVE = Path(".pilot/repairs/gpt-alias-deepseek-network-1")
MISTRAL_RELATIVE = Path(".pilot/stages/mistral-completion")
AGGREGATE_RELATIVE = Path(".pilot/aggregates/rule2-pilot-1")

AGGREGATE_ID = "rule2-pilot-1"
AGGREGATE_SCHEMA_VERSION = "pilot-aggregate-1.0.0"
CROSSWALK_SCHEMA_VERSION = "pilot-blind-crosswalk-1.0.0"
BLIND_ITEM_SCHEMA_KEYS = {
    "blind_id",
    "user_prompt",
    "position_map",
    "response_text",
}
CANONICAL_CELL_COUNT = 64
CANONICAL_VARIANT_COUNT = 8
EXPECTED_MODEL_KEYS = (
    "gemini",
    "claude",
    "cohere",
    "qwen",
    "deepseek",
    "mistral",
    "grok",
    "gpt",
)
PARENT_MODEL_KEYS = (
    "gemini",
    "claude",
    "cohere",
    "qwen",
    "deepseek",
    "grok",
    "gpt",
)
REPAIR_MODEL_KEYS = ("deepseek", "gpt")
REPAIR_ID = "gpt-alias-deepseek-network-1"
DEEPSEEK_REPAIR_CELL = (
    "atomic-bombs-pacific-war:deepseek:"
    "invasion-and-resistance-frame:answer"
)
GPT_CANONICAL_ID = "openai/gpt-5.6-sol-20260709"
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
BLIND_ID_PATTERN = re.compile(r"^blind-[a-f0-9]{32}$")

LIVE_CONFIG_SHA256 = (
    "c67f043202696a71998d7c5ea9a18ce4c574fe244741717077e45e00acb7fb05"
)
LIVE_PROTOCOL_SHA256 = (
    "f5068a25cb4c68eefb0f852f09fcf897fb21f20873eb3fe4eaa3f4bd11280918"
)
LIVE_PILOT_LOCK_SHA256 = (
    "a9acb26049721e1d1d87b92400f39c5c90c2a875a32ee9eeb944c68bdefde293"
)
LIVE_CANONICAL_PLAN_SHA256 = (
    "12d1813bb974156e03ab733f914f13a82f8f4d78e9e991ae32c1a346f4ab2652"
)
LIVE_PARENT_STAGE_PLAN_SHA256 = (
    "da10ceaca45a7cf83b44df9e7dafd2fa711865e354c17828a5d4e57edd3c6d9e"
)
LIVE_MISTRAL_STAGE_PLAN_SHA256 = (
    "5bbbc0780b3acce2f52ca750d6882d2a6368e9d49e9eded7fc9f6e0403f2ef53"
)

PARENT_ARTIFACT_SHA256 = {
    "stage.json": "27c6bf8c0b023cffe1da0281361fd25e1732572ea5db6e6d0564f5ada245c9a8",
    "manifests/models.json": "7670f719be9712377e7464cf2541722d235d3203c3d9168a4f026bf077ce5658",
    "runs/atomic-bombs-pacific-war.json": "2311b15ed74e9afd33da61dff0988395159eb24f003d8e969046336adbde99d9",
    "runs/james-jesus-brothers.json": "6436987815000fbbe47e444f9b1644636a36f0ea495c6f57eb55c397427640f4",
    "runs/john-brown-harpers-ferry.json": "021bb757770b1d472db9f86bb7975b7b03d42f04c58dc46e4777d7440e7d1780",
    "runs/junia-romans-16-7.json": "9f4c8a32d8942db7bbb4d893b377f33037924afc0ea890d04b6b6b7c210da1f0",
    "runs/locke-money-property.json": "3b24b525eae3baa6c7b2698cd8c855043ae38c183508dde87d626ef3b80c8ba1",
    "runs/mill-harm-principle.json": "37290c25041f231b4fd0f1c4cba6e4519bd977dd146eebe4d51c74ebbb8d10d7",
}

REPAIR_ARTIFACT_SHA256 = {
    "repair.json": "acb95c533e43b9116e6474ecbe5f6d45fb7b309b51112a29e00159dbae5e9998",
    "preflight.json": "33806a2e274007df011e53fabf991bcc5c455d23221a3f3577865ecf85d6810f",
    "result.json": "b6945e39fd8940662e2ee6679f25dd26da68ce2491b9786146ead5cd30ec6c82",
    "intents/01-f64c92dceb85.json": "de07da81c047fa7be1d24297357f87f9cf6e754fd4de8d2aa6e0ab7b175bf128",
    "intents/02-98756915ba94.json": "a368125d5aa01fedc57400c1cca4d079e1f3c8eb7ec4643dbbe9895814a7ed13",
    "intents/03-6096feec47c8.json": "f91e6aad5d94ae5edcd9ff0e79c5b6385aa550369125c97a3de0cb5dfd3deaf1",
    "intents/04-9a1e15b37b8f.json": "d55d8ff7a324c713a1b8269c5a5e35640f1cd7f5259b20e940b8ec7410930ba6",
    "intents/05-8fe2eac65362.json": "4da59cdff707b67f080185ee4694b87e73efe450505e7584f2afc01520410a06",
    "intents/06-8098e7c9af43.json": "82e431d35afa61da78c67ddce62314f13b0c96fada08e0ffad077259a7fffc1c",
    "intents/07-6d0e63af49ca.json": "41e074e5006525c38db1313506cf9b71731d2975098a2f4803b782b0e410b4a1",
    "intents/08-01e874417eba.json": "15514d6d84e5e89f64d443e70113ab261e132535b9ad9d024dc317ec1a575678",
    "intents/09-a0443538280a.json": "5baca811a7c1461c91c4aa4bde516ef86ecb1d1696a3e7a369e24d8c5c4b2c32",
    "outcomes/01-f64c92dceb85.json": "92ebd2c31f5afb9628ffc8f3418813a1b27f99b9136483d8c9e1aa7e7c76e1d9",
    "outcomes/02-98756915ba94.json": "9588938b4e9c184354170664cd40cf4b778518e10bb7774882a36ea94969e8d0",
    "outcomes/03-6096feec47c8.json": "96f51ede13de822e753e6b3ea9b1c1a93f2291c677fc2ee2344d1a35abfe9c84",
    "outcomes/04-9a1e15b37b8f.json": "c20812aae69b9f0f11be1156dafbde53e4e0da419a8f62d473e252f8ed2d0b7b",
    "outcomes/05-8fe2eac65362.json": "3d4dbae95d92f60be01bb557c33529f6ba17d07d1e83d28139869afe70554a1e",
    "outcomes/06-8098e7c9af43.json": "14de175464ae822b51eb5a81bd440fa85b051be4eb3de9a789f415f47c2bdfaa",
    "outcomes/07-6d0e63af49ca.json": "29b152b43feec9b5965e8fc0ffcf2e8c591209ffbe029a082e849ba38b366eea",
    "outcomes/08-01e874417eba.json": "45f07908d08cf069b46a8d7e7f01d153e63d23e4cd2388fe612ff2d2c3342acd",
    "outcomes/09-a0443538280a.json": "e894bdb6ed6e4719c101a8e6d5117dbbdfa137c9530454ea7c43193dbe8cc352",
}

MISTRAL_ARTIFACT_SHA256 = {
    "stage.json": "5e8aecf9e6c79bdcb8dd47797dea52b720f890616ea0c4f31e0891e7190691bd",
    "manifests/models.json": "08254d7ab0210ed13a6c52a90d8f6dd287737efa45a4ce6aaaecdd44727822df",
    "runs/atomic-bombs-pacific-war.json": "c776f1272b7828eff25791b23a90146267c865de04c9ae0660c1b2d9a3af350a",
    "runs/james-jesus-brothers.json": "1e094bc2293701ebf46cb0a72e2d117a5d508cbccee0e2673b0af8a47b605313",
    "runs/john-brown-harpers-ferry.json": "75cb9d600a27e47b40c64122d7a511e5f34a7d5c8ed71fa49539eca4bf5624fd",
    "runs/junia-romans-16-7.json": "de7f3e53657ab90e2f37681a3233ee82e010a85dab9acdab7f129033de610f64",
    "runs/locke-money-property.json": "378a33829f2309d8551be132fad510b6319c8826daa115397eeae957d1ddef62",
    "runs/mill-harm-principle.json": "3647dc2166abdd2c4c4953e8926ce31884b12add7b62c48c50c9d2ae433dbcb8",
}

EXPECTED_FINISH_REASON = {
    "gemini": "STOP",
    "claude": "end_turn",
    "cohere": "COMPLETE",
    "qwen": "stop",
    "deepseek": "stop",
    "mistral": "stop",
    "grok": "completed",
    "gpt": "stop",
}

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


class AggregateError(RuntimeError):
    """Raised when any frozen input or evidence contract differs."""


@dataclass(frozen=True)
class EvidenceCell:
    call: PlannedCall
    cell: dict[str, Any]
    source: str
    artifact_path: str
    artifact_sha256: str


@dataclass(frozen=True)
class AggregateContext:
    repository_root: Path
    output_root: Path
    config: HarnessConfig
    protocol: dict[str, str]
    questions: tuple[QuestionInput, ...]
    plan: tuple[PlannedCall, ...]
    cells: tuple[EvidenceCell, ...]
    input_artifacts: tuple[dict[str, str], ...]
    source_counts: dict[str, dict[str, int]]


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except FileNotFoundError as error:
        raise AggregateError(f"{label} is missing: {path}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise AggregateError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise AggregateError(f"{label} must be a JSON object")
    return value


def _load_protocol(path: Path) -> dict[str, str]:
    value = _read_json(path, "frozen protocol")
    expected = {"protocol_version", "system_prompt", "standard_challenge_prompt"}
    if set(value) != expected or not all(isinstance(value[key], str) for key in expected):
        raise AggregateError("frozen protocol fields differ from the contract")
    return value  # type: ignore[return-value]


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


def _aggregate_source_hashes() -> dict[str, str]:
    paths = {
        HARNESS_ROOT / "aggregate_pilot.py",
        HARNESS_ROOT / "config" / "models.json",
        *(HARNESS_ROOT / "concordance_harness").glob("*.py"),
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _artifact_records(
    root: Path,
    base: Path,
    expected: dict[str, str],
    source: str,
) -> tuple[dict[str, str], ...]:
    absolute = root / base
    if not absolute.is_dir() or absolute.is_symlink():
        raise AggregateError(f"{source} evidence directory is missing or unsafe")
    actual: set[str] = set()
    for path in absolute.rglob("*"):
        if path.is_symlink():
            raise AggregateError(f"{source} contains a symbolic link: {path}")
        if path.is_file():
            actual.add(str(path.relative_to(absolute)))
    if actual != set(expected):
        raise AggregateError(
            f"{source} artifact set differs; missing={sorted(set(expected) - actual)}, "
            f"extra={sorted(actual - set(expected))}"
        )
    records = []
    for relative, expected_hash in expected.items():
        path = absolute / relative
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            raise AggregateError(f"{source} artifact hash differs: {base / relative}")
        records.append(
            {
                "source": source,
                "path": str(base / relative),
                "sha256": actual_hash,
            }
        )
    return tuple(sorted(records, key=lambda item: item["path"]))


def _expected_returned_id(model: ModelConfig) -> str | None:
    if model.model_key == "cohere":
        # Cohere's generation response omitted a model ID.  The exact model is
        # instead bound by the successful manifest preflight and direct route.
        return None
    if model.model_key == "gpt":
        return GPT_CANONICAL_ID
    return model.requested_model_id


def _validate_static_cell(cell: Any, call: PlannedCall, *, allow_error: bool) -> None:
    if not isinstance(cell, dict):
        raise AggregateError(f"cell {call.cell_id} is malformed")
    common = {
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
    for key, expected in common.items():
        if cell.get(key) != expected:
            raise AggregateError(f"cell {call.cell_id} differs at {key}")
    if not isinstance(cell.get("attempted_at"), str) or not cell["attempted_at"]:
        raise AggregateError(f"cell {call.cell_id} lacks an attempt timestamp")
    if (
        not isinstance(cell.get("attempt_count"), int)
        or isinstance(cell.get("attempt_count"), bool)
        or cell["attempt_count"] < 1
    ):
        raise AggregateError(f"cell {call.cell_id} has an invalid attempt count")

    common_keys = {*common, "status", "attempted_at", "attempt_count"}
    status = cell.get("status")
    if status == "error":
        if not allow_error:
            raise AggregateError(f"cell {call.cell_id} is not a complete success")
        expected_keys = {*common_keys, "error", "failed_at"}
        if set(cell) != expected_keys:
            raise AggregateError(f"error cell {call.cell_id} fields differ")
        if not isinstance(cell.get("error"), dict) or not isinstance(
            cell.get("failed_at"), str
        ):
            raise AggregateError(f"error cell {call.cell_id} lacks its receipt")
        return
    if status != "success":
        raise AggregateError(f"cell {call.cell_id} has invalid status {status!r}")

    success_keys = {
        *common_keys,
        "response_id",
        "provider_returned_model_id",
        "provider_response_id",
        "effective_params",
        "response_text",
        "generated_at",
        "latency_ms",
        "finish_reason",
        "usage",
        "cost",
    }
    if set(cell) != success_keys:
        raise AggregateError(f"success cell {call.cell_id} fields differ")
    if not isinstance(cell.get("response_text"), str) or not cell["response_text"].strip():
        raise AggregateError(f"success cell {call.cell_id} has a blank response")
    for key in ("response_id", "provider_response_id", "generated_at"):
        if not isinstance(cell.get(key), str) or not cell[key]:
            raise AggregateError(f"success cell {call.cell_id} lacks {key}")
    if cell.get("provider_returned_model_id") != _expected_returned_id(call.model):
        raise AggregateError(f"success cell {call.cell_id} has an unapproved model identity")
    if cell.get("finish_reason") != EXPECTED_FINISH_REASON[call.model.model_key]:
        raise AggregateError(f"success cell {call.cell_id} is incomplete or finished unexpectedly")
    if (
        not isinstance(cell.get("latency_ms"), int)
        or isinstance(cell.get("latency_ms"), bool)
        or cell["latency_ms"] < 0
    ):
        raise AggregateError(f"success cell {call.cell_id} has invalid latency")
    for key in ("effective_params", "usage", "cost"):
        if not isinstance(cell.get(key), dict):
            raise AggregateError(f"success cell {call.cell_id} lacks {key}")


def _validate_manifest(
    manifest: dict[str, Any],
    config: HarnessConfig,
    model_keys: tuple[str, ...],
) -> None:
    expected_top = {
        "schema_version",
        "manifest_id",
        "captured_at",
        "harness_version",
        "config_sha256",
        "data_class",
        "models",
    }
    if set(manifest) != expected_top:
        raise AggregateError("stage model manifest fields differ")
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("harness_version") != HARNESS_VERSION
        or manifest.get("config_sha256") != config.sha256
        or manifest.get("data_class") != "research"
        or not isinstance(manifest.get("manifest_id"), str)
        or not isinstance(manifest.get("captured_at"), str)
    ):
        raise AggregateError("stage model manifest metadata differs")
    snapshots = manifest.get("models")
    models = tuple(model for model in config.models if model.model_key in model_keys)
    if not isinstance(snapshots, list) or len(snapshots) != len(models):
        raise AggregateError("stage model manifest has the wrong model count")
    for model, snapshot in zip(models, snapshots, strict=True):
        if not isinstance(snapshot, dict):
            raise AggregateError("stage model manifest contains a malformed snapshot")
        static = {
            "model_key": model.model_key,
            "family": model.family,
            "provider": model.provider,
            "requested_model_id": model.requested_model_id,
            "route": model.route,
            "environment_variable": model.environment_variable,
            "fallback_allowed": False,
            "capabilities": {"tools": False, "web_search": False, "retrieval": False},
            "policy": model.manifest_policy(),
            "pricing": {
                "currency": model.planning_pricing["currency"],
                "input_per_million": model.planning_pricing["input_per_million"],
                "output_per_million": model.planning_pricing["output_per_million"],
                "pricing_as_of": model.planning_pricing["pricing_as_of"],
            },
        }
        if {key: snapshot.get(key) for key in static} != static:
            raise AggregateError(f"manifest identity or policy differs for {model.model_key}")
        preflight = snapshot.get("preflight")
        if not isinstance(preflight, dict) or set(preflight) != {
            "status",
            "checked_at",
            "provider_returned_model_id",
            "sanitized_note",
        }:
            raise AggregateError(f"manifest preflight is malformed for {model.model_key}")
        returned = preflight.get("provider_returned_model_id")
        if (
            preflight.get("status") != "available"
            or not isinstance(preflight.get("checked_at"), str)
            or not isinstance(returned, str)
            or returned.removeprefix("models/") != model.requested_model_id
        ):
            raise AggregateError(f"manifest preflight substituted {model.model_key}")
        if model.model_key == "gpt" and preflight.get("sanitized_note") != (
            "Provider endpoint: OpenAI"
        ):
            raise AggregateError("GPT preflight was not pinned to OpenAI")


def _validate_stage_receipt(
    stage: dict[str, Any],
    *,
    stage_id: str,
    selected: tuple[str, ...],
    deferred: tuple[str, ...],
    expected_cells: int,
    stage_plan_sha256: str,
    manifest_sha256: str,
) -> None:
    expected = {
        "schema_version": "pilot-stage-1.0.0",
        "stage_id": stage_id,
        "evidence_status": "partial-nonqualifying",
        "selected_model_keys": list(selected),
        "deferred_model_keys": list(deferred),
        "expected_logical_cell_count": expected_cells,
        "required_aggregate_logical_cell_count": CANONICAL_CELL_COUNT,
        "pilot_lock_sha256": LIVE_PILOT_LOCK_SHA256,
        "config_sha256": LIVE_CONFIG_SHA256,
        "harness_version": HARNESS_VERSION,
        "full_plan_sha256": LIVE_CANONICAL_PLAN_SHA256,
        "stage_plan_sha256": stage_plan_sha256,
        "model_manifest_file_sha256": manifest_sha256,
    }
    for key, value in expected.items():
        if stage.get(key) != value:
            raise AggregateError(f"stage {stage_id} differs at {key}")
    if set(stage) != {*expected, "execution_contract_sha256", "created_at"}:
        raise AggregateError(f"stage {stage_id} fields differ")
    if not isinstance(stage.get("created_at"), str) or not SHA256_PATTERN.fullmatch(
        str(stage.get("execution_contract_sha256"))
    ):
        raise AggregateError(f"stage {stage_id} audit metadata is malformed")


def _validate_stage_runs(
    root: Path,
    base: Path,
    config: HarnessConfig,
    questions: tuple[QuestionInput, ...],
    calls: tuple[PlannedCall, ...],
    manifest: dict[str, Any],
    manifest_sha256: str,
    artifact_hashes: dict[str, str],
    source: str,
    *,
    allow_errors: bool,
) -> dict[str, EvidenceCell]:
    calls_by_id = {call.cell_id: call for call in calls}
    questions_by_id = {question.question_id: question for question in questions}
    evidence: dict[str, EvidenceCell] = {}
    for relative in sorted(key for key in artifact_hashes if key.startswith("runs/")):
        path = root / base / relative
        run = _read_json(path, f"{source} run {relative}")
        question_id = Path(relative).stem
        question = questions_by_id.get(question_id)
        if question is None:
            raise AggregateError(f"{source} contains an unknown question run")
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
            raise AggregateError(f"{source} run {question_id} fields differ")
        expected_metadata = {
            "schema_version": "1.0.0",
            "run_purpose": "pilot",
            "question_id": question_id,
            "question_content_version": question.content_version,
            "question_file_sha256": question.sha256,
            "harness_version": HARNESS_VERSION,
            "harness_config_sha256": config.sha256,
            "model_manifest_file_sha256": manifest_sha256,
            "model_manifest_snapshot": manifest,
        }
        for key, value in expected_metadata.items():
            if run.get(key) != value:
                raise AggregateError(f"{source} run {question_id} differs at {key}")
        for key in ("run_id", "generated_at", "updated_at"):
            if not isinstance(run.get(key), str) or not run[key]:
                raise AggregateError(f"{source} run {question_id} lacks {key}")
        cells = run.get("cells")
        if not isinstance(cells, list):
            raise AggregateError(f"{source} run {question_id} cells are malformed")
        for cell in cells:
            if not isinstance(cell, dict) or not isinstance(cell.get("cell_id"), str):
                raise AggregateError(f"{source} run {question_id} has a malformed cell")
            cell_id = cell["cell_id"]
            call = calls_by_id.get(cell_id)
            if call is None or call.question.question_id != question_id:
                raise AggregateError(f"{source} contains orphan cell {cell_id}")
            if cell_id in evidence:
                raise AggregateError(f"{source} duplicates cell {cell_id}")
            _validate_static_cell(cell, call, allow_error=allow_errors)
            evidence[cell_id] = EvidenceCell(
                call=call,
                cell=cell,
                source=source,
                artifact_path=str(base / relative),
                artifact_sha256=artifact_hashes[relative],
            )
    if set(evidence) != set(calls_by_id):
        raise AggregateError(f"{source} cell matrix differs from its exact plan")
    return evidence


def _validate_repair(
    root: Path,
    plan_by_id: dict[str, PlannedCall],
    parent: dict[str, EvidenceCell],
) -> tuple[dict[str, EvidenceCell], tuple[dict[str, str], ...]]:
    artifacts = _artifact_records(
        root, REPAIR_RELATIVE, REPAIR_ARTIFACT_SHA256, "repair"
    )
    repair = _read_json(root / REPAIR_RELATIVE / "repair.json", "repair receipt")
    preflight = _read_json(
        root / REPAIR_RELATIVE / "preflight.json", "repair preflight"
    )
    result = _read_json(root / REPAIR_RELATIVE / "result.json", "repair result")

    if (
        repair.get("schema_version") != "pilot-repair-1.0.0"
        or repair.get("repair_id") != REPAIR_ID
        or repair.get("evidence_status")
        != "partial-nonqualifying-until-mistral-completes"
    ):
        raise AggregateError("repair receipt differs from the approved repair")
    parent_receipt = repair.get("parent")
    if not isinstance(parent_receipt, dict) or (
        parent_receipt.get("stage_sha256") != PARENT_ARTIFACT_SHA256["stage.json"]
        or parent_receipt.get("manifest_sha256")
        != PARENT_ARTIFACT_SHA256["manifests/models.json"]
        or parent_receipt.get("success_count") != 47
        or parent_receipt.get("error_count") != 9
        or parent_receipt.get("logical_cell_count") != 56
    ):
        raise AggregateError("repair does not bind the exact parent stage")
    approval = repair.get("approval")
    if not isinstance(approval, dict) or (
        approval.get("decision") != "author-approved"
        or approval.get("gpt_requested_alias") != "openai/gpt-5.6-sol"
        or approval.get("gpt_returned_canonical_id") != GPT_CANONICAL_ID
        or approval.get("provider") != "openrouter"
        or approval.get("route") != "openrouter-openai-pinned"
        or approval.get("required_provider_name") != "OpenAI"
        or approval.get("fallback_allowed") is not False
    ):
        raise AggregateError("repair identity approval differs")

    targets = repair.get("targets")
    if not isinstance(targets, list) or len(targets) != 9:
        raise AggregateError("repair receipt must bind exactly nine targets")
    targets_by_id: dict[str, dict[str, Any]] = {}
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("cell_id"), str):
            raise AggregateError("repair target is malformed")
        cell_id = target["cell_id"]
        if cell_id in targets_by_id:
            raise AggregateError(f"repair duplicates target {cell_id}")
        targets_by_id[cell_id] = target
    parent_errors = {
        cell_id for cell_id, evidence in parent.items() if evidence.cell["status"] == "error"
    }
    if set(targets_by_id) != parent_errors:
        raise AggregateError("repair targets do not exactly equal the parent errors")
    for cell_id, target in targets_by_id.items():
        prior = parent[cell_id].cell
        if target.get("prior_error_cell_sha256") != sha256_bytes(
            canonical_json_bytes(prior)
        ):
            raise AggregateError(f"repair prior-error hash differs for {cell_id}")
        expected_error = (
            GPT_PRIOR_ERROR
            if plan_by_id[cell_id].model.model_key == "gpt"
            else DEEPSEEK_PRIOR_ERROR
        )
        if prior.get("error") != expected_error or target.get("prior_error") != expected_error:
            raise AggregateError(f"repair prior error differs for {cell_id}")

    if (
        preflight.get("schema_version") != "pilot-repair-preflight-1.0.0"
        or preflight.get("repair_id") != REPAIR_ID
        or preflight.get("repair_receipt_sha256")
        != REPAIR_ARTIFACT_SHA256["repair.json"]
        or preflight.get("model_keys") != list(REPAIR_MODEL_KEYS)
        or preflight.get("outbound_get_count") != 2
    ):
        raise AggregateError("repair preflight differs")
    preflight_results = preflight.get("results")
    if not isinstance(preflight_results, list) or len(preflight_results) != 2:
        raise AggregateError("repair preflight results are malformed")
    expected_preflight = {
        "deepseek": ("deepseek-v4-pro", None),
        "gpt": ("openai/gpt-5.6-sol", "OpenAI"),
    }
    for item in preflight_results:
        if not isinstance(item, dict) or item.get("model_key") not in expected_preflight:
            raise AggregateError("repair preflight contains another model")
        returned, provider_name = expected_preflight[item["model_key"]]
        if item.get("returned_model_id") != returned or item.get("provider_name") != provider_name:
            raise AggregateError("repair preflight identity differs")

    if (
        result.get("schema_version") != "pilot-repair-result-1.0.0"
        or result.get("repair_id") != REPAIR_ID
        or result.get("status") != "completed"
        or result.get("success_count") != 9
        or result.get("error_count") != 0
        or result.get("outbound_attempt_count") != 11
        or result.get("repair_receipt_sha256")
        != REPAIR_ARTIFACT_SHA256["repair.json"]
        or result.get("preflight_sha256")
        != REPAIR_ARTIFACT_SHA256["preflight.json"]
    ):
        raise AggregateError("repair result is incomplete or differs")
    result_cells = result.get("cells")
    if not isinstance(result_cells, list) or len(result_cells) != 9:
        raise AggregateError("repair result must contain nine cells")
    cells_by_id: dict[str, dict[str, Any]] = {}
    for cell in result_cells:
        if not isinstance(cell, dict) or not isinstance(cell.get("cell_id"), str):
            raise AggregateError("repair result contains a malformed cell")
        cell_id = cell["cell_id"]
        call = plan_by_id.get(cell_id)
        if call is None or cell_id not in targets_by_id or cell_id in cells_by_id:
            raise AggregateError(f"repair result contains an unapproved cell {cell_id}")
        _validate_static_cell(cell, call, allow_error=False)
        if cell.get("attempt_count") != 1:
            raise AggregateError(f"repair result retried {cell_id}")
        cells_by_id[cell_id] = cell
    if set(cells_by_id) != set(targets_by_id):
        raise AggregateError("repair result does not cover every target")

    result_outcomes = result.get("outcomes")
    if not isinstance(result_outcomes, list) or len(result_outcomes) != 9:
        raise AggregateError("repair result outcome index is malformed")
    indexed_outcomes = {
        item.get("path"): item.get("sha256")
        for item in result_outcomes
        if isinstance(item, dict)
    }
    expected_outcome_hashes = {
        path: digest
        for path, digest in REPAIR_ARTIFACT_SHA256.items()
        if path.startswith("outcomes/")
    }
    if indexed_outcomes != expected_outcome_hashes:
        raise AggregateError("repair outcome index differs")

    evidence: dict[str, EvidenceCell] = {}
    seen_intents: set[str] = set()
    for outcome_path, outcome_hash in expected_outcome_hashes.items():
        outcome = _read_json(root / REPAIR_RELATIVE / outcome_path, "repair outcome")
        if (
            outcome.get("schema_version") != "pilot-repair-outcome-1.0.0"
            or outcome.get("repair_id") != REPAIR_ID
            or outcome.get("repair_receipt_sha256")
            != REPAIR_ARTIFACT_SHA256["repair.json"]
        ):
            raise AggregateError(f"repair outcome differs: {outcome_path}")
        intent_path = outcome.get("intent_path")
        intent_hash = outcome.get("intent_sha256")
        if (
            not isinstance(intent_path, str)
            or intent_path in seen_intents
            or REPAIR_ARTIFACT_SHA256.get(intent_path) != intent_hash
        ):
            raise AggregateError(f"repair outcome intent differs: {outcome_path}")
        intent = _read_json(root / REPAIR_RELATIVE / intent_path, "repair intent")
        if (
            intent.get("schema_version") != "pilot-repair-post-intent-1.0.0"
            or intent.get("repair_id") != REPAIR_ID
            or intent.get("replay_policy") != "never-resend-under-this-repair-id"
        ):
            raise AggregateError(f"repair intent differs: {intent_path}")
        seen_intents.add(intent_path)
        cell = outcome.get("cell")
        if not isinstance(cell, dict) or cells_by_id.get(cell.get("cell_id")) != cell:
            raise AggregateError(f"repair outcome cell differs: {outcome_path}")
        cell_id = cell["cell_id"]
        if intent.get("cell_id") != cell_id or intent.get(
            "parent_error_cell_sha256"
        ) != targets_by_id[cell_id].get("prior_error_cell_sha256"):
            raise AggregateError(f"repair intent target differs: {intent_path}")
        evidence[cell_id] = EvidenceCell(
            call=plan_by_id[cell_id],
            cell=cell,
            source="repair",
            artifact_path=str(REPAIR_RELATIVE / outcome_path),
            artifact_sha256=outcome_hash,
        )
    if len(seen_intents) != 9 or set(evidence) != set(targets_by_id):
        raise AggregateError("repair journal is not a complete nine-cell chain")
    return evidence, artifacts


def prepare_aggregate(
    repository_root: Path,
    *,
    output_root: Path | None = None,
    require_committed_inputs: bool = True,
) -> AggregateContext:
    root = repository_root.resolve()
    config = load_harness_config(root / CONFIG_RELATIVE)
    if config.sha256 != LIVE_CONFIG_SHA256:
        raise AggregateError("model configuration differs from the frozen pilot")
    protocol_path = root / PROTOCOL_RELATIVE
    if sha256_file(protocol_path) != LIVE_PROTOCOL_SHA256:
        raise AggregateError("protocol differs from the frozen pilot")
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
    if sha256_file(root / PILOT_LOCK_PATH) != LIVE_PILOT_LOCK_SHA256:
        raise AggregateError("pilot lock differs from the approved lock")
    plan = build_plan(
        questions,
        config.models,
        protocol["system_prompt"],
        protocol["standard_challenge_prompt"],
        answer_only=True,
    )
    if (
        len(plan) != CANONICAL_CELL_COUNT
        or len({call.cell_id for call in plan}) != CANONICAL_CELL_COUNT
        or sum(len(question.variants) for question in questions)
        != CANONICAL_VARIANT_COUNT
        or _plan_contract_sha256(plan) != LIVE_CANONICAL_PLAN_SHA256
    ):
        raise AggregateError("canonical 64-cell plan differs")
    plan_by_id = {call.cell_id: call for call in plan}

    parent_artifacts = _artifact_records(
        root, PARENT_RELATIVE, PARENT_ARTIFACT_SHA256, "parent"
    )
    parent_stage = _read_json(root / PARENT_RELATIVE / "stage.json", "parent stage")
    parent_manifest = _read_json(
        root / PARENT_RELATIVE / "manifests/models.json", "parent manifest"
    )
    _validate_stage_receipt(
        parent_stage,
        stage_id="without-mistral",
        selected=PARENT_MODEL_KEYS,
        deferred=("mistral",),
        expected_cells=56,
        stage_plan_sha256=LIVE_PARENT_STAGE_PLAN_SHA256,
        manifest_sha256=PARENT_ARTIFACT_SHA256["manifests/models.json"],
    )
    _validate_manifest(parent_manifest, config, PARENT_MODEL_KEYS)
    parent_calls = tuple(
        call for call in plan if call.model.model_key in PARENT_MODEL_KEYS
    )
    parent = _validate_stage_runs(
        root,
        PARENT_RELATIVE,
        config,
        questions,
        parent_calls,
        parent_manifest,
        PARENT_ARTIFACT_SHA256["manifests/models.json"],
        PARENT_ARTIFACT_SHA256,
        "parent",
        allow_errors=True,
    )
    if (
        len(parent) != 56
        or sum(item.cell["status"] == "success" for item in parent.values()) != 47
        or sum(item.cell["status"] == "error" for item in parent.values()) != 9
    ):
        raise AggregateError("parent stage is not the exact 47-success/9-error matrix")

    repair, repair_artifacts = _validate_repair(root, plan_by_id, parent)
    preserved = {
        cell_id: item
        for cell_id, item in parent.items()
        if item.cell["status"] == "success"
    }
    if set(preserved) & set(repair) or len(preserved) + len(repair) != 56:
        raise AggregateError("repair overlay would replace a parent success")
    repaired = {**preserved, **repair}
    if any(item.cell["status"] != "success" for item in repaired.values()):
        raise AggregateError("repaired seven-model matrix is not complete")

    mistral_artifacts = _artifact_records(
        root, MISTRAL_RELATIVE, MISTRAL_ARTIFACT_SHA256, "mistral"
    )
    mistral_stage = _read_json(
        root / MISTRAL_RELATIVE / "stage.json", "Mistral stage"
    )
    mistral_manifest = _read_json(
        root / MISTRAL_RELATIVE / "manifests/models.json", "Mistral manifest"
    )
    _validate_stage_receipt(
        mistral_stage,
        stage_id="mistral-completion",
        selected=("mistral",),
        deferred=("gemini", "claude", "cohere", "qwen", "deepseek", "grok", "gpt"),
        expected_cells=8,
        stage_plan_sha256=LIVE_MISTRAL_STAGE_PLAN_SHA256,
        manifest_sha256=MISTRAL_ARTIFACT_SHA256["manifests/models.json"],
    )
    _validate_manifest(mistral_manifest, config, ("mistral",))
    mistral_calls = tuple(call for call in plan if call.model.model_key == "mistral")
    mistral = _validate_stage_runs(
        root,
        MISTRAL_RELATIVE,
        config,
        questions,
        mistral_calls,
        mistral_manifest,
        MISTRAL_ARTIFACT_SHA256["manifests/models.json"],
        MISTRAL_ARTIFACT_SHA256,
        "mistral",
        allow_errors=False,
    )
    if set(repaired) & set(mistral):
        raise AggregateError("Mistral stage overlaps the repaired seven-model stage")
    final = {**repaired, **mistral}
    if set(final) != set(plan_by_id) or len(final) != CANONICAL_CELL_COUNT:
        raise AggregateError("evidence union is not the canonical 64-cell set")
    by_model = {
        key: sum(item.call.model.model_key == key for item in final.values())
        for key in EXPECTED_MODEL_KEYS
    }
    if any(count != 8 for count in by_model.values()):
        raise AggregateError("aggregate does not contain eight cells per model")
    if any(item.cell["status"] != "success" for item in final.values()):
        raise AggregateError("aggregate contains a non-success cell")

    counts = {
        "parent": {"preserved_success": len(preserved), "overlaid_error": len(repair)},
        "repair": {"success": len(repair), "error": 0},
        "mistral": {"success": len(mistral), "error": 0},
        "aggregate": {"success": len(final), "error": 0},
    }
    output = (output_root or root / AGGREGATE_RELATIVE).resolve()
    return AggregateContext(
        repository_root=root,
        output_root=output,
        config=config,
        protocol=protocol,
        questions=questions,
        plan=plan,
        cells=tuple(final[call.cell_id] for call in plan),
        input_artifacts=tuple(
            [*parent_artifacts, *repair_artifacts, *mistral_artifacts]
        ),
        source_counts=counts,
    )


def _blind_payloads(
    context: AggregateContext, key: bytes
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    items: dict[str, dict[str, Any]] = {}
    crosswalk_entries: list[dict[str, Any]] = []
    for evidence in context.cells:
        digest = hmac.new(key, evidence.call.cell_id.encode("utf-8"), hashlib.sha256)
        blind_id = f"blind-{digest.hexdigest()[:32]}"
        if blind_id in items or not BLIND_ID_PATTERN.fullmatch(blind_id):
            raise AggregateError("blind identifier collision or format failure")
        positions = evidence.call.question.raw.get("position_map")
        if not isinstance(positions, list) or not positions:
            raise AggregateError(f"position map is missing for {evidence.call.question.question_id}")
        minimal_positions = []
        for position in positions:
            if not isinstance(position, dict) or not all(
                isinstance(position.get(field), str) and position[field].strip()
                for field in ("id", "label", "summary")
            ):
                raise AggregateError("position map contains malformed mapper fields")
            minimal_positions.append(
                {field: position[field] for field in ("id", "label", "summary")}
            )
        item = {
            "blind_id": blind_id,
            "user_prompt": evidence.call.user_prompt,
            "position_map": minimal_positions,
            "response_text": evidence.cell["response_text"],
        }
        if set(item) != BLIND_ITEM_SCHEMA_KEYS:
            raise AggregateError("blind item fields differ from the closed contract")
        items[blind_id] = item
        crosswalk_entries.append(
            {
                "blind_id": blind_id,
                "cell_id": evidence.call.cell_id,
                "question_id": evidence.call.question.question_id,
                "variant_id": evidence.call.variant_id,
                "model_key": evidence.call.model.model_key,
                "response_id": evidence.cell["response_id"],
                "response_sha256": sha256_bytes(
                    evidence.cell["response_text"].encode("utf-8")
                ),
                "cell_sha256": sha256_bytes(canonical_json_bytes(evidence.cell)),
                "source": evidence.source,
            }
        )
    crosswalk = {
        "schema_version": CROSSWALK_SCHEMA_VERSION,
        "aggregate_id": AGGREGATE_ID,
        "entries": sorted(crosswalk_entries, key=lambda item: item["blind_id"]),
    }
    return dict(sorted(items.items())), crosswalk


def _write_once(path: Path, payload: bytes, mode: int = 0o600) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as error:
        raise AggregateError(f"write-once aggregate artifact exists: {path}") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        raise
    return sha256_bytes(payload)


def write_aggregate(context: AggregateContext, *, blinding_key: bytes | None = None) -> Path:
    if context.output_root.exists():
        raise AggregateError("aggregate output is single-use; choose no replacement path")
    context.output_root.mkdir(parents=True, mode=0o700)
    key = blinding_key or secrets.token_bytes(32)
    if len(key) != 32:
        raise AggregateError("blinding key must contain exactly 32 bytes")
    key_payload = (key.hex() + "\n").encode("ascii")
    key_hash = _write_once(context.output_root / "private/blinding-key", key_payload)
    items, crosswalk = _blind_payloads(context, key)
    item_records = []
    for blind_id, item in items.items():
        payload = canonical_json_bytes(item)
        relative = f"blind/items/{blind_id}.json"
        item_records.append(
            {
                "blind_id": blind_id,
                "path": relative,
                "sha256": _write_once(context.output_root / relative, payload),
            }
        )
    crosswalk_payload = canonical_json_bytes(crosswalk)
    crosswalk_hash = _write_once(
        context.output_root / "private/crosswalk.json", crosswalk_payload
    )
    cell_records = [
        {
            "cell_id": evidence.call.cell_id,
            "cell_sha256": sha256_bytes(canonical_json_bytes(evidence.cell)),
            "response_sha256": sha256_bytes(
                evidence.cell["response_text"].encode("utf-8")
            ),
            "source": evidence.source,
            "source_artifact_path": evidence.artifact_path,
            "source_artifact_sha256": evidence.artifact_sha256,
        }
        for evidence in context.cells
    ]
    source_files = _aggregate_source_hashes()
    receipt = {
        "schema_version": AGGREGATE_SCHEMA_VERSION,
        "aggregate_id": AGGREGATE_ID,
        "status": "complete-mapping-eligible",
        "selection_status": "not-evaluated",
        "threshold_evaluation": {
            "performed": False,
            "reason": "blind mappings and author review are not yet complete",
        },
        "network_requests": 0,
        "environment_variables_read": 0,
        "created_at": utc_now(),
        "aggregator": {
            "harness_version": HARNESS_VERSION,
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
        "canonical_contract": {
            "config_sha256": LIVE_CONFIG_SHA256,
            "protocol_sha256": LIVE_PROTOCOL_SHA256,
            "pilot_lock_sha256": LIVE_PILOT_LOCK_SHA256,
            "full_plan_sha256": LIVE_CANONICAL_PLAN_SHA256,
            "logical_cell_count": CANONICAL_CELL_COUNT,
            "model_keys": list(EXPECTED_MODEL_KEYS),
        },
        "source_counts": context.source_counts,
        "input_artifacts": list(context.input_artifacts),
        "cells": cell_records,
        "blind_export": {
            "item_count": len(item_records),
            "items": item_records,
            "blinding_key_sha256": key_hash,
            "crosswalk_path": "private/crosswalk.json",
            "crosswalk_sha256": crosswalk_hash,
            "mapper_visible_fields": sorted(BLIND_ITEM_SCHEMA_KEYS),
            "excluded_identity_fields": [
                "cell_id",
                "model_key",
                "provider",
                "route",
                "requested_model_id",
                "provider_returned_model_id",
                "response_id",
                "variant_id",
                "pairing",
                "usage",
                "cost",
                "latency_ms",
                "aggregate_counts",
            ],
        },
    }
    _write_once(context.output_root / "aggregate.json", canonical_json_bytes(receipt))
    return context.output_root / "aggregate.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify and blind the complete offline Rule 2 pilot aggregate."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        context = prepare_aggregate(REPOSITORY_ROOT)
        if args.check:
            print(
                "Aggregate verified: 64 complete unique cells, eight per model; "
                "network requests: 0; environment variables read: 0."
            )
            return 0
        path = write_aggregate(context)
        print(f"Aggregate written: {path.relative_to(REPOSITORY_ROOT)}")
        print(
            "Status: complete-mapping-eligible; thresholds and selection not evaluated."
        )
        return 0
    except (AggregateError, OSError, ValueError) as error:
        print(f"Aggregate stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from concordance_harness import HARNESS_VERSION
from concordance_harness.config import ConfigError, load_harness_config
from concordance_harness.execution import (
    AttemptBudget,
    BudgetExceeded,
    ExecutionOptions,
    HarnessRunner,
    ResumeError,
    create_model_manifest,
    preflight_panel,
    write_model_manifest,
)
from concordance_harness.planner import PlanError, build_plan, load_questions
from concordance_harness.pilot_lock import (
    PILOT_CONTENT_VERSION,
    PILOT_LOCK_PATH,
    PILOT_POOL_ID,
    PILOT_POOL_SIZE,
    PILOT_RULE_VERSION,
    load_and_validate_pilot_lock,
    require_exact_pilot_candidates,
)
from concordance_harness.providers import ProviderError, UrllibTransport
from concordance_harness.util import (
    atomic_write_json,
    canonical_json_bytes,
    prompt_sha256,
    sanitize,
    sha256_bytes,
    sha256_file,
    utc_now,
)


HARNESS_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = HARNESS_ROOT.parent
DEFAULT_CONFIG = HARNESS_ROOT / "config" / "models.json"
DEFAULT_PROTOCOL = REPOSITORY_ROOT / "config" / "protocol.json"
DEFAULT_SAMPLE_QUESTIONS = REPOSITORY_ROOT / "sample" / "questions"
PILOT_OUTPUT_ROOT = (REPOSITORY_ROOT / ".pilot").resolve()
PILOT_STAGES_ROOT = (PILOT_OUTPUT_ROOT / "stages").resolve()
PRODUCTION_OUTPUT_ROOT = (REPOSITORY_ROOT / "data").resolve()
EXPECTED_KINDS = ("convergent", "divergent", "prompt-sensitive")
PILOT_VARIANT_COUNT = 8
PILOT_AGGREGATE_CELL_COUNT = 64
PILOT_STAGE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Plan or run the offline-first Concordance model matrix."
    )
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run", action="store_true", help="plan without env or network"
    )
    mode.add_argument(
        "--live", action="store_true", help="enable the gated network path"
    )
    command.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    command.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    command.add_argument("--questions", type=Path)
    command.add_argument("--output", type=Path, default=REPOSITORY_ROOT / "data")
    command.add_argument("--case", action="append", default=[])
    command.add_argument("--model", action="append", default=[])
    command.add_argument("--answer-only", action="store_true")
    command.add_argument("--max-calls", type=positive_int)
    command.add_argument("--max-cost-usd", type=positive_float)
    command.add_argument("--force", action="store_true")
    command.add_argument("--retries", type=positive_int, default=3)
    command.add_argument("--concurrency", type=positive_int, default=4)
    command.add_argument("--credentials-rotated", action="store_true")
    command.add_argument("--run-purpose", choices=("pilot", "final"), default="final")
    command.add_argument(
        "--pilot-content-approved",
        action="store_true",
        help="authorize the frozen proposed Rule 2 pool for a private pilot",
    )
    command.add_argument(
        "--pilot-stage",
        type=pilot_stage_id,
        help="name a private, nonqualifying partial pilot stage",
    )
    return command


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def pilot_stage_id(value: str) -> str:
    if not PILOT_STAGE_ID_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "must use 1-64 lowercase letters, digits, or hyphens and start with a letter or digit"
        )
    return value


def load_protocol(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise PlanError(f"protocol cannot be loaded: {error}") from error
    expected = {"protocol_version", "system_prompt", "standard_challenge_prompt"}
    if set(raw) != expected or not all(isinstance(raw[key], str) for key in expected):
        raise PlanError("protocol fields differ from the frozen contract")
    return raw


def print_dry_run(
    plan: tuple[Any, ...], max_calls: int | None, pricing_note: str
) -> None:
    visible = plan if max_calls is None else plan[:max_calls]
    for index, call in enumerate(visible, start=1):
        print(
            f"{index:02d} {call.cell_id} route={call.model.route} "
            f"ceiling=${call.cost_ceiling():.6f}"
        )
    total_cost = sum(call.cost_ceiling() for call in visible)
    print()
    print(f"Planned logical cells: {len(visible)} of {len(plan)}")
    print(f"One-attempt planning ceiling: ${total_cost:.4f}")
    print(f"Pricing status: REVIEW REQUIRED: {pricing_note}")
    print("Network requests: 0; environment variables read: 0")


def fully_author_verified(question: dict[str, Any]) -> bool:
    if question.get("verification", {}).get("status") != "author-verified":
        return False
    positions = question.get("position_map")
    if not isinstance(positions, list) or not positions:
        return False
    for position in positions:
        if position.get("verification", {}).get("status") != "author-verified":
            return False
        sources = position.get("sources")
        if not isinstance(sources, list) or not sources:
            return False
        for source in sources:
            if source.get("verification", {}).get("status") != "author-verified":
                return False
    return True


def fully_proposed(question: dict[str, Any]) -> bool:
    if question.get("verification", {}).get("status") != "proposed":
        return False
    positions = question.get("position_map")
    if not isinstance(positions, list) or not positions:
        return False
    for position in positions:
        if position.get("verification", {}).get("status") != "proposed":
            return False
        sources = position.get("sources")
        if not isinstance(sources, list) or not sources:
            return False
        for source in sources:
            if source.get("verification", {}).get("status") != "proposed":
                return False
    return True


def is_within(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    return resolved == root or root in resolved.parents


def require_pilot_plan_scope(
    args: argparse.Namespace,
    questions: Any,
    plan: Any,
    output_root: Path,
) -> None:
    if args.run_purpose != "pilot":
        if args.pilot_stage:
            raise PlanError("--pilot-stage is valid only with --run-purpose pilot")
        return

    if args.model and not args.pilot_stage:
        raise PlanError(
            "pilot --model filters require an explicit --pilot-stage; a stage is "
            "partial and threshold selection waits for the aggregate 64 exact "
            "model-variant cells"
        )
    if not args.pilot_stage:
        return
    if not args.model:
        raise PlanError("--pilot-stage requires at least one exact --model filter")
    if len(args.model) != len(set(args.model)):
        raise PlanError("a pilot stage requires each exact --model filter only once")
    if args.case:
        raise PlanError(
            "a pilot stage cannot filter cases; all six locked candidates and eight "
            "prompt variants are required"
        )
    if not args.answer_only:
        raise PlanError("a pilot stage requires --answer-only")

    expected_output = (PILOT_STAGES_ROOT / args.pilot_stage).resolve()
    if output_root != expected_output:
        raise PlanError(
            f"pilot stage {args.pilot_stage} must write exactly to "
            f".pilot/stages/{args.pilot_stage}"
        )

    require_exact_pilot_candidates(questions)
    expected_variants = {
        (question.question_id, variant["id"])
        for question in questions
        for variant in question.variants
    }
    if len(expected_variants) != PILOT_VARIANT_COUNT:
        raise PlanError(
            "a pilot stage requires all six locked candidates and exactly eight "
            "prompt variants"
        )

    selected_models = set(args.model)
    calls_by_model = {
        model_key: [call for call in plan if call.model.model_key == model_key]
        for model_key in selected_models
    }
    invalid_models = [
        model_key
        for model_key, calls in calls_by_model.items()
        if len(calls) != PILOT_VARIANT_COUNT
        or any(call.call_type != "answer" for call in calls)
        or {(call.question.question_id, call.variant_id) for call in calls}
        != expected_variants
    ]
    if invalid_models or len(plan) != PILOT_VARIANT_COUNT * len(selected_models):
        details = ", ".join(sorted(invalid_models)) or "selected panel"
        raise PlanError(
            "a pilot stage requires exactly eight answer-only cells per selected "
            f"canonical model: {details}"
        )


def config_for_run(config: Any, args: argparse.Namespace) -> Any:
    if args.run_purpose != "pilot" or not args.pilot_stage:
        return config
    selected = set(args.model)
    return replace(
        config,
        models=tuple(
            model for model in config.models if model.model_key in selected
        ),
    )


def plan_contract_sha256(plan: Any) -> str:
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


def execution_source_hashes() -> dict[str, str]:
    paths = {
        HARNESS_ROOT / "generate.py",
        HARNESS_ROOT / "config" / "models.json",
        *(HARNESS_ROOT / "concordance_harness").glob("*.py"),
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def build_pilot_stage_scope(
    stage_id: str,
    config: Any,
    run_config: Any,
    protocol: dict[str, str],
    questions: Any,
    plan: Any,
) -> dict[str, Any]:
    full_plan = build_plan(
        questions,
        config.models,
        protocol["system_prompt"],
        protocol["standard_challenge_prompt"],
        answer_only=True,
    )
    if len(full_plan) != PILOT_AGGREGATE_CELL_COUNT:
        raise PlanError("the pilot execution contract must contain 64 exact cells")
    pilot_lock_sha256 = sha256_file(REPOSITORY_ROOT / PILOT_LOCK_PATH)
    full_plan_sha256 = plan_contract_sha256(full_plan)
    execution_contract = {
        "harness_version": HARNESS_VERSION,
        "config_sha256": config.sha256,
        "pilot_lock_sha256": pilot_lock_sha256,
        "full_plan_sha256": full_plan_sha256,
        "source_files": execution_source_hashes(),
    }
    selected = [model.model_key for model in run_config.models]
    selected_set = set(selected)
    return {
        "schema_version": "pilot-stage-1.0.0",
        "stage_id": stage_id,
        "evidence_status": "partial-nonqualifying",
        "selected_model_keys": selected,
        "deferred_model_keys": [
            model.model_key
            for model in config.models
            if model.model_key not in selected_set
        ],
        "expected_logical_cell_count": len(plan),
        "required_aggregate_logical_cell_count": PILOT_AGGREGATE_CELL_COUNT,
        "pilot_lock_sha256": pilot_lock_sha256,
        "config_sha256": config.sha256,
        "harness_version": HARNESS_VERSION,
        "execution_contract_sha256": sha256_bytes(
            canonical_json_bytes(execution_contract)
        ),
        "full_plan_sha256": full_plan_sha256,
        "stage_plan_sha256": plan_contract_sha256(plan),
    }


def load_pilot_stage_receipt(
    output_root: Path, expected_scope: dict[str, Any]
) -> str | None:
    path = output_root / "stage.json"
    if not path.exists():
        if output_root.exists() and any(output_root.iterdir()):
            raise ResumeError(
                "pilot stage contains orphan artifacts without stage.json; archive it "
                "or choose a new --pilot-stage"
            )
        return None
    try:
        existing = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise ResumeError("existing pilot stage receipt is malformed") from error
    if not isinstance(existing, dict):
        raise ResumeError("existing pilot stage receipt is malformed")
    created_at = existing.pop("created_at", None)
    manifest_hash = existing.pop("model_manifest_file_sha256", None)
    if (
        not isinstance(created_at, str)
        or not isinstance(manifest_hash, str)
        or not SHA256_PATTERN.fullmatch(manifest_hash)
        or existing != expected_scope
    ):
        raise ResumeError(
            "existing pilot stage receipt uses another execution contract; choose a "
            "new --pilot-stage or archive the existing stage"
        )
    manifest_path = output_root / "manifests" / "models.json"
    if not manifest_path.is_file() or sha256_file(manifest_path) != manifest_hash:
        raise ResumeError("pilot stage manifest differs from its immutable receipt")
    return manifest_hash


def write_pilot_stage_receipt(
    output_root: Path,
    scope: dict[str, Any],
    model_manifest_hash: str,
) -> Path:
    path = output_root / "stage.json"
    if path.exists():
        raise ResumeError("pilot stage receipt is write-once")
    if not SHA256_PATTERN.fullmatch(model_manifest_hash):
        raise ResumeError("pilot stage manifest hash is malformed")
    atomic_write_json(
        path,
        {
            **scope,
            "model_manifest_file_sha256": model_manifest_hash,
            "created_at": utc_now(),
        },
    )
    return path


def require_pilot_gate(
    args: argparse.Namespace,
    questions: Any,
    plan: Any,
    output_root: Path,
    protocol_path: Path,
) -> None:
    if not args.pilot_content_approved:
        raise PlanError("a live pilot requires --pilot-content-approved")
    if not args.answer_only:
        raise PlanError("a live pilot requires --answer-only")
    if not is_within(output_root, PILOT_OUTPUT_ROOT):
        raise PlanError("a live pilot must write under the ignored repository .pilot/ directory")

    require_exact_pilot_candidates(questions)

    invalid_research = [
        question.question_id
        for question in questions
        if question.raw.get("data_class") != "research"
    ]
    if invalid_research:
        raise PlanError(
            "a live pilot requires research candidates: "
            + ", ".join(invalid_research)
        )

    invalid_content = [
        question.question_id
        for question in questions
        if question.content_version != PILOT_CONTENT_VERSION
    ]
    if invalid_content:
        raise PlanError(
            f"a live pilot requires content {PILOT_CONTENT_VERSION}: "
            + ", ".join(invalid_content)
        )

    invalid_selection = []
    for question in questions:
        selection = question.raw.get("selection", {})
        if (
            selection.get("status") != "candidate"
            or selection.get("pool_id") != PILOT_POOL_ID
            or selection.get("pool_size") != PILOT_POOL_SIZE
            or selection.get("rule_version") != PILOT_RULE_VERSION
        ):
            invalid_selection.append(question.question_id)
    if invalid_selection:
        raise PlanError(
            "a live pilot requires the frozen Rule 2 candidate selection contract: "
            + ", ".join(invalid_selection)
        )

    not_proposed = [
        question.question_id
        for question in questions
        if not fully_proposed(question.raw)
    ]
    if not_proposed:
        raise PlanError(
            "a live pilot requires proposed scholarly records: "
            + ", ".join(not_proposed)
        )

    load_and_validate_pilot_lock(
        REPOSITORY_ROOT / PILOT_LOCK_PATH,
        REPOSITORY_ROOT,
        protocol_path,
        questions,
    )

    if args.pilot_stage:
        if len(plan) != PILOT_VARIANT_COUNT * len(args.model) or any(
            call.call_type != "answer" for call in plan
        ):
            raise PlanError(
                "a staged live pilot requires exactly eight answer-only cells per "
                "selected canonical model; threshold selection waits for the aggregate "
                "64 exact model-variant cells"
            )
    elif len(plan) != PILOT_AGGREGATE_CELL_COUNT or any(
        call.call_type != "answer" for call in plan
    ):
        raise PlanError("a live pilot requires the complete 64-cell answer-only matrix")


def require_final_gate(
    args: argparse.Namespace, questions: Any, plan: Any, output_root: Path
) -> None:
    if output_root != PRODUCTION_OUTPUT_ROOT:
        raise PlanError("a final live run must write to the repository data directory")
    if args.answer_only:
        raise PlanError("a final run cannot use --answer-only")

    kinds = [question.raw.get("kind") for question in questions]
    if len(questions) != 3 or sorted(kinds) != sorted(EXPECTED_KINDS):
        raise PlanError("a final run requires exactly one case of each approved kind")

    invalid_research = [
        question.question_id
        for question in questions
        if question.raw.get("data_class") != "research"
    ]
    if invalid_research:
        raise PlanError(
            "a final run requires research content: " + ", ".join(invalid_research)
        )

    not_selected = [
        question.question_id
        for question in questions
        if question.raw.get("selection", {}).get("status") != "selected"
    ]
    if not_selected:
        raise PlanError(
            "a final run refuses candidate content; selected status is required: "
            + ", ".join(not_selected)
        )

    unverified = [
        question.question_id
        for question in questions
        if not fully_author_verified(question.raw)
    ]
    if unverified:
        raise PlanError(
            "a final run refuses unverified scholarly content: "
            + ", ".join(unverified)
        )

    if len(plan) != 64 or {call.call_type for call in plan} != {
        "answer",
        "challenge",
    }:
        raise PlanError("a final run requires the complete 64-cell challenge matrix")


def load_existing_manifest(
    output_root: Path, config: Any
) -> tuple[dict[str, Any], str] | None:
    path = output_root / "manifests" / "models.json"
    if not path.exists():
        return None
    try:
        manifest = json.loads(path.read_bytes())
    except json.JSONDecodeError as error:
        raise ResumeError("existing model manifest is malformed") from error
    expected_top_level = {
        "schema_version",
        "manifest_id",
        "captured_at",
        "harness_version",
        "config_sha256",
        "data_class",
        "models",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_top_level:
        raise ResumeError("existing model manifest fields differ from the contract")
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("harness_version") != HARNESS_VERSION
        or manifest.get("config_sha256") != config.sha256
        or manifest.get("data_class") != "research"
        or not isinstance(manifest.get("manifest_id"), str)
        or not isinstance(manifest.get("captured_at"), str)
    ):
        raise ResumeError(
            "existing model manifest uses another execution contract; archive the "
            "run before refreshing it"
        )
    snapshots = manifest.get("models")
    if not isinstance(snapshots, list) or len(snapshots) != len(config.models):
        raise ResumeError("existing model manifest uses another model scope")
    for model, snapshot in zip(config.models, snapshots, strict=True):
        expected_static = {
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
        if not isinstance(snapshot, dict):
            raise ResumeError("existing model manifest contains a malformed snapshot")
        actual_static = {key: snapshot.get(key) for key in expected_static}
        if actual_static != expected_static or set(snapshot) != {
            *expected_static,
            "preflight",
        }:
            raise ResumeError(
                f"existing model manifest differs for canonical model {model.model_key}"
            )
        preflight = snapshot.get("preflight")
        if not isinstance(preflight, dict) or set(preflight) != {
            "status",
            "checked_at",
            "provider_returned_model_id",
            "sanitized_note",
        }:
            raise ResumeError(
                f"existing model manifest preflight differs for {model.model_key}"
            )
        returned = preflight.get("provider_returned_model_id")
        note = preflight.get("sanitized_note")
        if (
            preflight.get("status") != "available"
            or not isinstance(preflight.get("checked_at"), str)
            or not isinstance(returned, str)
            or returned.removeprefix("models/") != model.requested_model_id
            or (note is not None and not isinstance(note, str))
            or (
                model.model_key == "gpt"
                and note != "Provider endpoint: OpenAI"
            )
        ):
            raise ResumeError(
                f"existing model manifest preflight is invalid for {model.model_key}"
            )
    return manifest, sha256_file(path)


async def live_run(
    args: argparse.Namespace,
    config: Any,
    protocol: dict[str, str],
    questions: Any,
    plan: Any,
) -> None:
    if not args.credentials_rotated:
        raise PlanError(
            "live mode requires --credentials-rotated after project key rotation"
        )
    if any(question.is_sample for question in questions):
        raise PlanError("live mode refuses the illustrative sample dataset")
    output_root = args.output.resolve()
    if args.run_purpose == "pilot":
        require_pilot_gate(
            args,
            questions,
            plan,
            output_root,
            args.protocol.resolve(),
        )
    else:
        require_final_gate(args, questions, plan, output_root)
    run_config = config_for_run(config, args)
    stage_scope: dict[str, Any] | None = None
    receipt_manifest_hash: str | None = None
    if args.pilot_stage:
        stage_scope = build_pilot_stage_scope(
            args.pilot_stage,
            config,
            run_config,
            protocol,
            questions,
            plan,
        )
        receipt_manifest_hash = load_pilot_stage_receipt(output_root, stage_scope)
    unpriced = [
        model.model_key for model in run_config.models if not model.pricing_reviewed
    ]
    if unpriced:
        raise PlanError(
            "live mode requires reviewed provider pricing for: " + ", ".join(unpriced)
        )
    # This is the first point at which the process touches the environment.
    secrets = {
        model.environment_variable: os.environ.get(model.environment_variable, "")
        for model in run_config.models
    }
    missing = sorted(name for name, value in secrets.items() if not value)
    if missing:
        raise PlanError("missing required environment variables: " + ", ".join(missing))

    budget = AttemptBudget(args.max_calls, args.max_cost_usd)
    transport = UrllibTransport()
    try:
        existing = load_existing_manifest(output_root, run_config)
        if existing:
            model_manifest, model_manifest_hash = existing
            if (
                args.pilot_stage
                and receipt_manifest_hash != model_manifest_hash
            ):
                raise ResumeError(
                    "pilot stage manifest is not bound to its immutable receipt"
                )
        else:
            if args.pilot_stage and receipt_manifest_hash is not None:
                raise ResumeError("pilot stage receipt refers to a missing manifest")
            preflight = await preflight_panel(
                run_config.models,
                secrets,
                transport,
                budget,
                args.retries,
            )
            model_manifest = create_model_manifest(run_config, preflight, "research")
            _, model_manifest_hash = write_model_manifest(output_root, model_manifest)
            if args.pilot_stage:
                assert stage_scope is not None
                write_pilot_stage_receipt(
                    output_root,
                    stage_scope,
                    model_manifest_hash,
                )

        runner = HarnessRunner(
            config=run_config,
            plan=plan,
            secrets=secrets,
            transport=transport,
            budget=budget,
            options=ExecutionOptions(
                output_root=output_root,
                run_purpose=args.run_purpose,
                attempts_per_cell=args.retries,
                concurrency=args.concurrency,
                force=args.force,
            ),
            model_manifest=model_manifest,
            model_manifest_hash=model_manifest_hash,
        )
        await runner.run()
    except ProviderError as error:
        raise PlanError(sanitize(error, secrets.values())) from None
    print(
        f"Outbound attempts: {budget.attempts}; reserved ceiling: "
        f"${budget.reserved_cost_usd:.4f}"
    )
    if args.pilot_stage:
        print(
            f"Pilot stage {args.pilot_stage} is private, partial, and nonqualifying; "
            "threshold selection waits for the aggregate 64 exact model-variant cells."
        )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = load_harness_config(args.config.resolve())
        protocol = load_protocol(args.protocol.resolve())
        question_directory = (
            args.questions.resolve()
            if args.questions
            else DEFAULT_SAMPLE_QUESTIONS.resolve()
        )
        questions = load_questions(question_directory)
        plan = build_plan(
            questions,
            config.models,
            protocol["system_prompt"],
            protocol["standard_challenge_prompt"],
            set(args.case) or None,
            set(args.model) or None,
            args.answer_only,
        )
        require_pilot_plan_scope(
            args,
            questions,
            plan,
            args.output.resolve(),
        )
        if args.dry_run:
            print_dry_run(plan, args.max_calls, config.planning_pricing_note)
            if args.pilot_stage:
                print(
                    f"Pilot stage {args.pilot_stage} is private, partial, and "
                    "nonqualifying; threshold selection waits for the aggregate 64 "
                    "exact model-variant cells."
                )
            return 0
        asyncio.run(live_run(args, config, protocol, questions, plan))
        return 0
    except (
        ConfigError,
        PlanError,
        ProviderError,
        BudgetExceeded,
        ResumeError,
    ) as error:
        print(f"Harness stopped: {sanitize(error)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

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
from concordance_harness.util import sanitize, sha256_file


HARNESS_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = HARNESS_ROOT.parent
DEFAULT_CONFIG = HARNESS_ROOT / "config" / "models.json"
DEFAULT_PROTOCOL = REPOSITORY_ROOT / "config" / "protocol.json"
DEFAULT_SAMPLE_QUESTIONS = REPOSITORY_ROOT / "sample" / "questions"
PILOT_OUTPUT_ROOT = (REPOSITORY_ROOT / ".pilot").resolve()
PRODUCTION_OUTPUT_ROOT = (REPOSITORY_ROOT / "data").resolve()
EXPECTED_KINDS = ("convergent", "divergent", "prompt-sensitive")


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

    if len(plan) != 64 or any(call.call_type != "answer" for call in plan):
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
    output_root: Path, config_hash: str
) -> tuple[dict[str, Any], str] | None:
    path = output_root / "manifests" / "models.json"
    if not path.exists():
        return None
    try:
        manifest = json.loads(path.read_bytes())
    except json.JSONDecodeError as error:
        raise ResumeError("existing model manifest is malformed") from error
    if manifest.get("config_sha256") != config_hash:
        raise ResumeError(
            "existing model manifest uses another config; archive the run before refreshing it"
        )
    if any(
        model.get("preflight", {}).get("status") != "available"
        for model in manifest.get("models", [])
    ):
        raise ResumeError("existing model manifest contains an unavailable route")
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
    unpriced = [
        model.model_key for model in config.models if not model.pricing_reviewed
    ]
    if unpriced:
        raise PlanError(
            "live mode requires reviewed provider pricing for: " + ", ".join(unpriced)
        )
    # This is the first point at which the process touches the environment.
    secrets = {
        model.environment_variable: os.environ.get(model.environment_variable, "")
        for model in config.models
    }
    missing = sorted(name for name, value in secrets.items() if not value)
    if missing:
        raise PlanError("missing required environment variables: " + ", ".join(missing))

    budget = AttemptBudget(args.max_calls, args.max_cost_usd)
    transport = UrllibTransport()
    try:
        existing = load_existing_manifest(output_root, config.sha256)
        if existing:
            model_manifest, model_manifest_hash = existing
        else:
            preflight = await preflight_panel(
                config.models,
                secrets,
                transport,
                budget,
                args.retries,
            )
            model_manifest = create_model_manifest(config, preflight, "research")
            _, model_manifest_hash = write_model_manifest(output_root, model_manifest)

        runner = HarnessRunner(
            config=config,
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
        if args.dry_run:
            print_dry_run(plan, args.max_calls, config.planning_pricing_note)
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

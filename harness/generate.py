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
from concordance_harness.providers import ProviderError, UrllibTransport
from concordance_harness.util import sanitize, sha256_file


HARNESS_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = HARNESS_ROOT.parent
DEFAULT_CONFIG = HARNESS_ROOT / "config" / "models.json"
DEFAULT_PROTOCOL = REPOSITORY_ROOT / "config" / "protocol.json"
DEFAULT_SAMPLE_QUESTIONS = REPOSITORY_ROOT / "sample" / "questions"


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
    print(f"Pricing status: REVIEW REQUIRED — {pricing_note}")
    print("Network requests: 0; environment variables read: 0")


def fully_author_verified(question: dict[str, Any]) -> bool:
    if question.get("verification", {}).get("status") != "author-verified":
        return False
    for position in question.get("position_map", []):
        if position.get("verification", {}).get("status") != "author-verified":
            return False
        for source in position.get("sources", []):
            if source.get("verification", {}).get("status") != "author-verified":
                return False
    return True


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
    unverified = [
        question.question_id
        for question in questions
        if not fully_author_verified(question.raw)
    ]
    if unverified:
        raise PlanError(
            "live mode refuses unverified scholarly content: " + ", ".join(unverified)
        )
    unpriced = [
        model.model_key for model in config.models if not model.pricing_reviewed
    ]
    if unpriced:
        raise PlanError(
            "live mode requires reviewed provider pricing for: " + ", ".join(unpriced)
        )
    if args.run_purpose == "final":
        kinds = [question.raw["kind"] for question in questions]
        if len(questions) != 3 or sorted(kinds) != [
            "convergent",
            "divergent",
            "prompt-sensitive",
        ]:
            raise PlanError(
                "a final run requires exactly one case of each approved kind"
            )
        if args.answer_only:
            raise PlanError("a final run cannot use --answer-only")

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
        existing = load_existing_manifest(args.output, config.sha256)
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
            _, model_manifest_hash = write_model_manifest(args.output, model_manifest)

        runner = HarnessRunner(
            config=config,
            plan=plan,
            secrets=secrets,
            transport=transport,
            budget=budget,
            options=ExecutionOptions(
                output_root=args.output,
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

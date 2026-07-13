#!/usr/bin/env python3
"""Run the unchanged Rule 3 review chain over the Grok-retry composite."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import evaluate_rule3
import finalize_rule3_review
import prepare_rule3_review
from grok_retry import contract
from grok_retry.composite import CompositeError, retry_review_context


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Review the exact four-lineage Concordance composite."
    )
    actions = command.add_subparsers(dest="action", required=True)

    prepare = actions.add_parser("prepare", help="prepare a blind or author packet")
    prepare.add_argument("--stage", choices=("blind", "author"), required=True)
    prepare_modes = prepare.add_mutually_exclusive_group(required=True)
    prepare_modes.add_argument("--check", action="store_true")
    prepare_modes.add_argument("--write", action="store_true")
    prepare_modes.add_argument("--verify", action="store_true")

    finalize = actions.add_parser(
        "finalize", help="validate, seal, or verify review decisions"
    )
    finalize.add_argument("--stage", choices=("first-pass", "author"), required=True)
    finalize_modes = finalize.add_mutually_exclusive_group(required=True)
    finalize_modes.add_argument("--check", action="store_true")
    finalize_modes.add_argument("--seal", action="store_true")
    finalize_modes.add_argument("--verify", action="store_true")
    finalize.add_argument("--input", type=Path)

    evaluate = actions.add_parser("evaluate", help="evaluate the reviewed composite")
    modes = evaluate.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--verify", action="store_true")
    return command


def _selected_mode(args: argparse.Namespace) -> str:
    for name in ("check", "write", "seal", "verify"):
        if getattr(args, name, False):
            return f"--{name}"
    raise CompositeError("one exact review mode is required")


def _delegate(args: argparse.Namespace) -> int:
    candidate = contract.CANDIDATE_ID
    mode = _selected_mode(args)
    if args.action == "prepare":
        return prepare_rule3_review.main(
            ["--stage", args.stage, "--candidate", candidate, mode]
        )
    if args.action == "finalize":
        delegated = ["--stage", args.stage, "--candidate", candidate, mode]
        if args.input is not None:
            delegated.extend(("--input", str(args.input)))
        return finalize_rule3_review.main(delegated)
    return evaluate_rule3.main(["--candidate", candidate, mode])


def main(argv: list[str] | None = None) -> int:
    command = parser()
    args = command.parse_args(argv)
    if args.action == "finalize":
        if (args.check or args.seal) and args.input is None:
            command.error("--input is required with finalize --check or --seal")
        if args.verify and args.input is not None:
            command.error("--input is not used with finalize --verify")
    try:
        with retry_review_context():
            return _delegate(args)
    except (CompositeError, OSError, ValueError) as error:
        print(f"Grok retry review stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

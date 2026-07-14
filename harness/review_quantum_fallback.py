#!/usr/bin/env python3
"""Run the unchanged Rule 3 review chain over the Quantum fallback panel."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import evaluate_rule3
import finalize_rule3_review
import prepare_rule3_review
import run_quantum_fallback as execution
from quantum_fallback_review import QuantumReviewError, quantum_review_context


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="Review the Quantum fallback panel.")
    actions = command.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("prepare")
    prepare.add_argument("--stage", choices=("blind", "author"), required=True)
    prepare_mode = prepare.add_mutually_exclusive_group(required=True)
    prepare_mode.add_argument("--check", action="store_true")
    prepare_mode.add_argument("--write", action="store_true")
    prepare_mode.add_argument("--verify", action="store_true")
    finalize = actions.add_parser("finalize")
    finalize.add_argument("--stage", choices=("first-pass", "author"), required=True)
    finalize_mode = finalize.add_mutually_exclusive_group(required=True)
    finalize_mode.add_argument("--check", action="store_true")
    finalize_mode.add_argument("--seal", action="store_true")
    finalize_mode.add_argument("--verify", action="store_true")
    finalize.add_argument("--input", type=Path)
    evaluate = actions.add_parser("evaluate")
    evaluate_mode = evaluate.add_mutually_exclusive_group(required=True)
    evaluate_mode.add_argument("--check", action="store_true")
    evaluate_mode.add_argument("--write", action="store_true")
    evaluate_mode.add_argument("--verify", action="store_true")
    return command


def selected_mode(args: argparse.Namespace) -> str:
    for name in ("check", "write", "seal", "verify"):
        if getattr(args, name, False):
            return f"--{name}"
    raise QuantumReviewError("one exact review mode is required")


def delegate(args: argparse.Namespace) -> int:
    candidate = execution.CANDIDATE_ID
    mode = selected_mode(args)
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
        with quantum_review_context():
            return delegate(args)
    except (QuantumReviewError, OSError, ValueError) as error:
        print(f"Quantum fallback review stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

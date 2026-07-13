#!/usr/bin/env python3
"""Compute, publish, or verify the offline Rule 3 terminal decision."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rule3 import contract, evaluate, review


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Evaluate one completely reviewed Rule 3 candidate."
    )
    command.add_argument(
        "--candidate",
        choices=tuple(candidate["id"] for candidate in contract.CANDIDATES),
        required=True,
    )
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.check:
            value = evaluate.compute_candidate_evaluation(
                REPOSITORY_ROOT, args.candidate
            )
            result: object = {
                "status": "valid-complete-review",
                "threshold_result": value["threshold_result"],
            }
        elif args.write:
            result = evaluate.publish_candidate_evaluation(
                REPOSITORY_ROOT, args.candidate
            )
        else:
            evaluation = evaluate.verify_candidate_evaluation(
                REPOSITORY_ROOT, args.candidate
            )
            if (
                args.candidate == evaluate.PRIORITY_ID
                and not evaluation["value"]["threshold_result"]["qualifies"]
            ):
                terminal = evaluate.verify_fallback_eligibility(REPOSITORY_ROOT)
            else:
                terminal = evaluate.verify_terminal(REPOSITORY_ROOT)
            result = {
                "status": "verified",
                "evaluation_sha256": evaluation["sha256"],
                "terminal_or_eligibility_sha256": terminal["sha256"],
            }
        print(json.dumps(result, indent=2))
        return 0
    except (
        OSError,
        ValueError,
        review.Rule3ReviewError,
        evaluate.Rule3EvaluationError,
    ) as error:
        print(f"Rule 3 evaluation stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

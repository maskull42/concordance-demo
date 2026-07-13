#!/usr/bin/env python3
"""Validate and seal Codex or A.G. Rule 3 review decisions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rule3 import contract, review


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Finalize one offline Rule 3 review stage."
    )
    command.add_argument("--stage", choices=("first-pass", "author"), required=True)
    command.add_argument(
        "--candidate",
        choices=tuple(candidate["id"] for candidate in contract.CANDIDATES),
        required=True,
    )
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--seal", action="store_true")
    mode.add_argument("--verify", action="store_true")
    command.add_argument("--input", type=Path)
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if (args.check or args.seal) and args.input is None:
        parser().error("--input is required with --check or --seal")
    if args.verify and args.input is not None:
        parser().error("--input is not used with --verify")
    try:
        if args.stage == "first-pass":
            if args.check:
                value = review.validate_first_pass(
                    REPOSITORY_ROOT, args.candidate, args.input.read_bytes()
                )
                result: object = {
                    "status": "valid-complete-first-pass",
                    "item_count": value["item_count"],
                }
            elif args.seal:
                result = {
                    "path": str(
                        review.seal_first_pass(
                            REPOSITORY_ROOT, args.candidate, args.input
                        )
                    )
                }
            else:
                verified = review.verify_first_pass(REPOSITORY_ROOT, args.candidate)
                result = {
                    "status": "verified",
                    "receipt_sha256": verified["receipt_sha256"],
                }
        else:
            if args.check:
                value = review.validate_author_export(
                    REPOSITORY_ROOT, args.candidate, args.input.read_bytes()
                )
                result = {
                    "status": "valid-complete-author-review",
                    "item_count": value["item_count"],
                }
            elif args.seal:
                result = {
                    "path": str(
                        review.seal_author_review(
                            REPOSITORY_ROOT, args.candidate, args.input
                        )
                    )
                }
            else:
                verified = review.verify_author_review(REPOSITORY_ROOT, args.candidate)
                result = {
                    "status": "verified",
                    "receipt_sha256": verified["receipt_sha256"],
                }
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, review.Rule3ReviewError) as error:
        print(f"Rule 3 review finalization stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

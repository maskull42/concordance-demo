#!/usr/bin/env python3
"""Prepare or verify the private Rule 3 blind and A.G. review packets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rule3 import contract, review


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Prepare one offline Rule 3 review stage."
    )
    command.add_argument("--stage", choices=("blind", "author"), required=True)
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
        if args.stage == "blind":
            if args.check:
                packet, _, _ = review.build_blind_materials(
                    REPOSITORY_ROOT, args.candidate
                )
                result: object = {
                    "status": "ready-to-publish-blind-packet",
                    "candidate_id": args.candidate,
                    "item_count": packet["item_count"],
                    "network_requests": 0,
                    "environment_variables_read": 0,
                }
            elif args.write:
                result = {
                    "path": str(
                        review.publish_blind_materials(REPOSITORY_ROOT, args.candidate)
                    )
                }
            else:
                verified = review.verify_blind_materials(
                    REPOSITORY_ROOT,
                    args.candidate,
                )
                result = {
                    "status": "verified",
                    "packet_sha256": verified["packet_sha256"],
                }
        else:
            if args.check:
                blind = review.verify_blind_materials(REPOSITORY_ROOT, args.candidate)
                first = review.verify_first_pass(REPOSITORY_ROOT, args.candidate)
                context, review_id = review._review_context(
                    REPOSITORY_ROOT, blind, first
                )
                review.render_author_review_html(REPOSITORY_ROOT, context)
                result = {
                    "status": "ready-to-publish-author-packet",
                    "review_packet_sha256": review_id,
                }
            elif args.write:
                result = {
                    "path": str(
                        review.publish_author_packet(REPOSITORY_ROOT, args.candidate)
                    )
                }
            else:
                verified = review.verify_author_packet(REPOSITORY_ROOT, args.candidate)
                result = {
                    "status": "verified",
                    "review_packet_sha256": verified["review_packet_sha256"],
                }
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, review.Rule3ReviewError) as error:
        print(f"Rule 3 review preparation stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

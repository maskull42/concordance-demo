#!/usr/bin/env python3
"""Build, seal, or verify the exact v2 blinded consensus mapping."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from divergence_successor_continuation_author_review import review


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--input", type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            if args.input is None:
                raise ValueError("--input is required for --check")
            value = review.validate_first_pass_payload(
                args.repository_root, args.input.read_bytes()
            )
            result = {
                "status": "ready-to-seal-consensus-first-pass-v2",
                "item_count": value["item_count"],
            }
        elif args.write:
            if args.input is None:
                raise ValueError("--input is required for --write")
            path = review.seal_first_pass(args.repository_root, args.input)
            result = {
                "status": "sealed-consensus-first-pass-v2",
                "path": path.relative_to(args.repository_root).as_posix(),
            }
        else:
            verified = review.verify_first_pass(args.repository_root)
            result = {
                "status": "verified-consensus-first-pass-v2",
                "mapping_sha256": verified["mapping_sha256"],
                "receipt_sha256": verified["receipt_sha256"],
            }
        result.update(
            {
                "network_requests": 0,
                "environment_variables_read": 0,
                "provider_calls": 0,
                "threshold_evaluation": {"performed": False},
            }
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

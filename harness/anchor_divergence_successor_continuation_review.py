#!/usr/bin/env python3
"""Create or verify the pre-commit historical continuation-review anchor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from divergence_successor_continuation_author_review import anchor, contract


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--verify", action="store_true")
    modes.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            value = anchor.build_anchor(
                args.repository_root, anchored_at=contract.ANCHOR_TIMESTAMP
            )
            result = {
                "status": "ready-to-seal-review-anchor-v2",
                "historical_git_head": value["historical_git_head"],
            }
        elif args.write:
            path = anchor.publish_anchor(
                args.repository_root, anchored_at=contract.ANCHOR_TIMESTAMP
            )
            result = {
                "status": "sealed-historical-review-inputs-v2",
                "path": path.relative_to(args.repository_root).as_posix(),
            }
        elif args.verify:
            verified = anchor.verify_anchor(args.repository_root)
            result = {
                "status": "verified-review-anchor-v2",
                "anchor_sha256": verified["anchor_sha256"],
                "historical_git_head": verified["historical_git_head"],
            }
        else:
            result = {
                "status": f"review-anchor-publication-{anchor.recover_anchor_publication(args.repository_root)}"
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

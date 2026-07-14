#!/usr/bin/env python3
"""Build, write, or verify the public v2 continuation review lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor_continuation_author_review import lock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            value = lock.build_lock(args.repository_root)
            result = {
                "status": "ready-to-seal-continuation-review-lock-v2",
                "prospective_sha256": sha256_bytes(canonical_json_bytes(value)),
            }
        elif args.write:
            context = lock.write_lock(args.repository_root)
            result = {
                "status": context.lock["status"],
                "path": "candidate/rule3-successor-continuation-review-lock.json",
                "sha256": context.lock_sha256,
            }
        else:
            context = lock.load_and_validate_lock(
                args.repository_root, require_committed=True
            )
            result = {
                "status": "verified-committed-continuation-review-lock-v2",
                "sha256": context.lock_sha256,
                "git_head": context.git_head,
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

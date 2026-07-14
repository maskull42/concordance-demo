#!/usr/bin/env python3
"""Build, publish, or verify the continuation's blinded review packet."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from divergence_successor_continuation import review


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            packet, _, _ = review.build_blind_materials(args.repository_root)
            result = {
                "status": "ready-to-publish-continuation-blind-packet",
                "item_count": packet["item_count"],
                "network_requests": 0,
                "environment_variables_read": 0,
            }
        elif args.write:
            path = review.publish_blind_materials(args.repository_root)
            result = {
                "status": "published",
                "path": path.relative_to(args.repository_root).as_posix(),
            }
        else:
            verified = review.verify_blind_materials(args.repository_root)
            result = {
                "status": "verified",
                "packet_sha256": verified["packet_sha256"],
            }
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

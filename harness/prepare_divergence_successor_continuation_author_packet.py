#!/usr/bin/env python3
"""Publish or verify the complete offline v2 A.G. author-review packet."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from divergence_successor_continuation_author_review import review


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
            manifest, html, _ = review._prepared_author_packet(args.repository_root)
            result = {
                "status": "ready-to-publish-author-packet-v2",
                "review_packet_sha256": manifest["review_packet_sha256"],
                "html_bytes": len(html),
            }
        elif args.write:
            path = review.publish_author_packet(args.repository_root)
            result = {
                "status": "ready-for-complete-author-review-v2",
                "path": path.relative_to(args.repository_root).as_posix(),
            }
        else:
            verified = review.verify_author_packet(args.repository_root)
            result = {
                "status": "verified-author-packet-v2",
                "manifest_sha256": verified["manifest_sha256"],
                "html_sha256": verified["html_sha256"],
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

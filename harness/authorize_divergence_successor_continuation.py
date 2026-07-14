#!/usr/bin/env python3
"""Record or verify the exact private continuation authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from concordance_harness.util import utc_now
from divergence_successor_continuation import authorization, contract, lock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        if args.write:
            record = authorization.write_authorization(
                args.repository_root,
                statement=contract.APPROVAL_STATEMENT,
                authorized_at=utc_now(),
            )
        else:
            context = lock.load_and_validate_lock(
                args.repository_root, require_committed=True
            )
            record = authorization.validate_authorization(context)
        result = {
            "status": record.payload["status"],
            "sha256": record.sha256,
            "generation_posts_authorized": 8,
            "metadata_requests_authorized": 0,
        }
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

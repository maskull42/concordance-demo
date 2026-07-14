#!/usr/bin/env python3
"""Build, record, or verify the offline preflight correction."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from concordance_harness.util import utc_now
from divergence_successor_continuation import correction


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
            value = asyncio.run(
                correction.build_correction_payload(
                    args.repository_root, corrected_at=utc_now()
                )
            )
            result = {
                "status": "ready-to-record-offline-correction",
                "model_count": len(value["model_records"]),
                "false_negative_model_keys": value["false_negative_model_keys"],
                "network_requests": 0,
                "environment_variables_read": 0,
            }
        elif args.write:
            record = correction.write_correction_record(args.repository_root)
            result = {
                "status": record.payload["status"],
                "path": record.path.relative_to(args.repository_root).as_posix(),
                "sha256": record.sha256,
                "network_requests": 0,
            }
        else:
            record = correction.verify_correction_record(args.repository_root)
            result = {"status": "verified", "sha256": record.sha256}
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

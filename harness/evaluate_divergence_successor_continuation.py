#!/usr/bin/env python3
"""Check, write, or verify the sealed continuation threshold evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from divergence_successor_continuation_evaluation import evaluate


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
            value = evaluate.compute_evaluation(args.repository_root)
            result = {
                "status": "valid-continuation-threshold-evaluation",
                "threshold_result": value["threshold_result"],
                "position_primary_counts": value["position_primary_counts"],
            }
        elif args.write:
            verified = evaluate.publish_evaluation(args.repository_root)
            result = {
                "status": "sealed-continuation-threshold-evaluation",
                "receipt_sha256": verified["sha256"],
                "threshold_result": verified["value"]["threshold_result"],
                "position_primary_counts": verified["value"]["position_primary_counts"],
            }
        elif args.verify:
            verified = evaluate.verify_evaluation(args.repository_root)
            result = {
                "status": "verified-continuation-threshold-evaluation",
                "receipt_sha256": verified["sha256"],
                "threshold_result": verified["value"]["threshold_result"],
                "position_primary_counts": verified["value"]["position_primary_counts"],
            }
        else:
            status = evaluate.recover_evaluation_publication(args.repository_root)
            result = {"status": f"evaluation-publication-{status}"}
        result.update(
            {
                "network_requests": 0,
                "environment_variables_read": 0,
                "provider_calls": 0,
            }
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

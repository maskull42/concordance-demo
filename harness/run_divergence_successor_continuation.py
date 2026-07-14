#!/usr/bin/env python3
"""Inspect or cross the eight-generation continuation boundary."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from divergence_successor_continuation.execute import execute_live, execution_readiness


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    try:
        if not args.live:
            result = execution_readiness(args.repository_root)
            code = 0 if not result["issues"] else 2
        else:
            value = asyncio.run(execute_live(args.repository_root))
            result = {
                "status": value.payload["status"],
                "path": value.path.relative_to(args.repository_root).as_posix(),
                "sha256": value.sha256,
                "network_requests": value.network_requests,
            }
            code = 0
    except (OSError, RuntimeError, ValueError) as error:
        result = {"status": "blocked-before-provider-call", "error": str(error)}
        code = 2
    print(json.dumps(result, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

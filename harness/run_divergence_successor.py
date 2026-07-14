#!/usr/bin/env python3
"""Stop at, or later cross, the divergence successor provider boundary."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Sequence

from divergence_successor.execute import execute_live, execution_readiness


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Run the locked successor panel.")
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    result.add_argument(
        "--live",
        action="store_true",
        help="require exact paid authority, then enter the provider boundary",
    )
    return result


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if not arguments.live:
        value = execution_readiness(arguments.repository_root)
        _print(value)
        return 0 if not value["issues"] else 2
    try:
        result = asyncio.run(execute_live(arguments.repository_root))
    except (OSError, ValueError, RuntimeError) as error:
        _print({"status": "blocked-before-provider-call", "error": str(error)})
        return 2
    _print(
        {
            "status": result.payload["status"],
            "path": result.path.relative_to(arguments.repository_root).as_posix(),
            "sha256": result.sha256,
            "network_requests": result.network_requests,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Render, seal, or verify the public divergence successor lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from divergence_successor import contract
from divergence_successor.lock import (
    build_divergence_successor_lock,
    load_and_validate_divergence_successor_lock,
    readiness,
    write_divergence_successor_lock,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Build the non-spending divergence successor lock."
    )
    modes = result.add_mutually_exclusive_group()
    modes.add_argument("--render", action="store_true", help="print the prospective lock")
    modes.add_argument("--write", action="store_true", help="create the write-once public lock")
    modes.add_argument("--check", action="store_true", help="validate the existing lock")
    modes.add_argument(
        "--readiness", action="store_true", help="show blockers without writing"
    )
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.write:
            context = write_divergence_successor_lock(arguments.repository_root)
            _print(
                {
                    "status": "successor-lock-created",
                    "path": contract.LOCK_PATH,
                    "sha256": context.lock_sha256,
                    "lock_authorizes_spending": False,
                }
            )
        elif arguments.check:
            context = load_and_validate_divergence_successor_lock(
                arguments.repository_root
            )
            _print(
                {
                    "status": "successor-lock-valid",
                    "path": contract.LOCK_PATH,
                    "sha256": context.lock_sha256,
                    "lock_authorizes_spending": False,
                }
            )
        elif arguments.render:
            _print(build_divergence_successor_lock(arguments.repository_root))
        else:
            value = readiness(arguments.repository_root)
            _print(value)
            return 0 if not value["issues"] and not value["seal_issues"] else 2
    except (OSError, ValueError, RuntimeError) as error:
        _print({"status": "blocked", "error": str(error)})
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

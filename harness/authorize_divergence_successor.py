#!/usr/bin/env python3
"""Inspect or record later exact paid-call authority for the successor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from divergence_successor import authorization, lock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="The successor lock is not spending authority."
    )
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    result.add_argument("--authorize", action="store_true")
    result.add_argument("--statement")
    result.add_argument("--authorized-at")
    result.add_argument(
        "--pricing-evidence",
        type=Path,
        help="write the later eight-route official pricing recheck from JSON",
    )
    result.add_argument("--checked-at")
    return result


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if not arguments.authorize and arguments.pricing_evidence is None:
        value = authorization.approval_readiness()
        _print(value)
        return 0 if not value["issues"] else 2
    if arguments.authorize and arguments.pricing_evidence is not None:
        _print({"status": "blocked", "error": "record authority and pricing separately"})
        return 2
    if arguments.authorize and (
        not isinstance(arguments.statement, str)
        or not isinstance(arguments.authorized_at, str)
    ):
        _print(
            {
                "status": "blocked",
                "error": "--authorize requires --statement and --authorized-at",
            }
        )
        return 2
    try:
        context = lock.load_and_validate_divergence_successor_lock(
            arguments.repository_root,
            require_committed=True,
            require_parent_private=True,
        )
        if arguments.authorize:
            binding = authorization.write_authorization(
                context,
                statement=arguments.statement,
                authorized_at=arguments.authorized_at,
            )
        else:
            if not isinstance(arguments.checked_at, str):
                raise authorization.DivergenceSuccessorAuthorizationError(
                    "--pricing-evidence requires --checked-at"
                )
            evidence = json.loads(arguments.pricing_evidence.read_text("utf-8"))
            if not isinstance(evidence, list):
                raise authorization.DivergenceSuccessorAuthorizationError(
                    "pricing evidence JSON must be an array"
                )
            binding = authorization.write_pricing_recheck(
                context, evidence, checked_at=arguments.checked_at
            )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        _print({"status": "blocked", "error": str(error)})
        return 2
    _print(
        {
            "status": binding.payload["status"],
            "path": binding.path.relative_to(arguments.repository_root).as_posix(),
            "sha256": binding.sha256,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

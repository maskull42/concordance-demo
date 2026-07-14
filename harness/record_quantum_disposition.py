#!/usr/bin/env python3
"""Preview, record, or verify the private Quantum withdrawal receipt."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from quantum_disposition import (
    QuantumDispositionError,
    preview_disposition,
    verify_disposition,
    write_disposition,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Record the Quantum fallback as a withdrawn, private, "
            "nonpublication stress test."
        )
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="repository root (defaults to this script's parent)",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="verify the historical lineage without writing anything",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="publish the one write-once private disposition receipt",
    )
    mode.add_argument(
        "--verify",
        action="store_true",
        help="verify an existing private disposition receipt",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.check:
            result = preview_disposition(args.repository_root)
        elif args.write:
            result = write_disposition(args.repository_root)
        else:
            result = verify_disposition(args.repository_root)
    except QuantumDispositionError as error:
        print(f"Quantum disposition error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

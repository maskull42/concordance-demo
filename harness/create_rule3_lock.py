#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rule3.contract import LOCK_PATH, canonical_json_bytes
from rule3.lock import (
    Rule3LockError,
    build_rule3_lock,
    load_and_validate_rule3_lock,
    write_rule3_lock,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build or validate the immutable Rule 3 execution lock."
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="Git worktree root (defaults to this script's repository)",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--write",
        action="store_true",
        help=f"create {LOCK_PATH} once without overwriting it",
    )
    action.add_argument(
        "--check",
        action="store_true",
        help=f"validate the existing {LOCK_PATH}",
    )
    parser.add_argument(
        "--require-committed",
        action="store_true",
        help="with --check, require every bound byte to be clean and in HEAD",
    )
    args = parser.parse_args(argv)
    if args.require_committed and not args.check:
        parser.error("--require-committed requires --check")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.write:
            context = write_rule3_lock(args.repository_root)
            print(f"created {LOCK_PATH} ({context.lock_sha256})")
            return 0
        if args.check:
            context = load_and_validate_rule3_lock(
                args.repository_root,
                require_committed=args.require_committed,
            )
            suffix = f" at HEAD {context.git_head}" if context.git_head else ""
            print(f"valid {LOCK_PATH} ({context.lock_sha256}){suffix}")
            return 0
        sys.stdout.buffer.write(
            canonical_json_bytes(build_rule3_lock(args.repository_root))
        )
        return 0
    except Rule3LockError as error:
        print(f"Rule 3 lock error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

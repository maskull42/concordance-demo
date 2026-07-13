#!/usr/bin/env python3
"""Build or validate the public Grok retry lock."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from concordance_recovery.contract import canonical_json_bytes
from grok_retry import contract
from grok_retry.lock import (
    GrokRetryLockError,
    build_lock,
    load_lock,
    write_lock,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build or validate the immutable Grok retry lock."
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
        help=f"create {contract.LOCK_PATH} once without overwriting it",
    )
    action.add_argument(
        "--check",
        action="store_true",
        help=f"validate the existing {contract.LOCK_PATH}",
    )
    parser.add_argument(
        "--require-committed",
        action="store_true",
        help="with --check, require every public bound byte clean and in HEAD",
    )
    parser.add_argument(
        "--require-parent-private",
        action="store_true",
        help="with --check, also verify the exact immutable private parents",
    )
    args = parser.parse_args(argv)
    if (args.require_committed or args.require_parent_private) and not args.check:
        parser.error("--require-committed/--require-parent-private require --check")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.write:
            context = write_lock(args.repository_root)
            print(f"created {contract.LOCK_PATH} ({context.lock_sha256})")
            return 0
        if args.check:
            context = load_lock(
                args.repository_root,
                require_committed=args.require_committed,
                require_parent_private=args.require_parent_private,
            )
            suffix = f" at HEAD {context.git_head}" if context.git_head else ""
            print(f"valid {contract.LOCK_PATH} ({context.lock_sha256}){suffix}")
            return 0
        sys.stdout.buffer.write(canonical_json_bytes(build_lock(args.repository_root)))
        return 0
    except (OSError, GrokRetryLockError, ValueError) as error:
        print(f"Grok retry lock error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

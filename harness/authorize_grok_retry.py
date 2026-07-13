#!/usr/bin/env python3
"""Write or validate private Grok retry authority receipts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from grok_retry import contract
from grok_retry.authorization import (
    AuthorizationError,
    validate_authorization,
    validate_pricing_evidence,
    validate_pricing_recheck,
    write_authorization,
    write_pricing_evidence,
    write_pricing_recheck,
)
from grok_retry.lock import GrokRetryLockError, load_lock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Authorize or price the exact Grok retry."
    )
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--show-statement", action="store_true")
    mode.add_argument("--authorize", action="store_true")
    mode.add_argument("--record-pricing", action="store_true")
    mode.add_argument("--seal-pricing", action="store_true")
    mode.add_argument("--check", action="store_true")
    command.add_argument("--statement")
    command.add_argument("--amendment")
    command.add_argument("--evidence-file", type=Path)
    command.add_argument("--reviewed-by", default="A.G. Elrod")
    return command


def _load_evidence(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AuthorizationError(
            "pricing evidence input must be a regular, non-symlink JSON file"
        )

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuthorizationError(f"duplicate pricing evidence key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise AuthorizationError(
            f"pricing evidence input is malformed: {error}"
        ) from error
    if not isinstance(value, dict) or set(value) != {
        "checked_at",
        "official_evidence",
    }:
        raise AuthorizationError(
            "pricing evidence input requires checked_at and official_evidence"
        )
    return value


def main(argv: list[str] | None = None) -> int:
    command = parser()
    args = command.parse_args(argv)
    if args.show_statement:
        print(contract.AUTHORIZATION_STATEMENT)
        print("\nVerbatim amendment:")
        print(contract.USER_AMENDMENT)
        print(json.dumps(contract.authorization_scope(), indent=2))
        return 0
    if args.authorize and (args.statement is None or args.amendment is None):
        command.error("--authorize requires --statement and --amendment")
    if args.record_pricing and args.evidence_file is None:
        command.error("--record-pricing requires --evidence-file")
    if not args.record_pricing and args.evidence_file is not None:
        command.error("--evidence-file is valid only with --record-pricing")
    if not args.authorize and (
        args.statement is not None or args.amendment is not None
    ):
        command.error("--statement/--amendment are valid only with --authorize")
    try:
        context = load_lock(
            REPOSITORY_ROOT,
            require_committed=True,
            require_parent_private=True,
        )
        if args.authorize:
            receipt = write_authorization(
                context,
                statement=args.statement,
                amendment=args.amendment,
            )
            result = {
                "status": "grok-retry-authorized",
                "path": str(receipt.path.relative_to(REPOSITORY_ROOT)),
                "sha256": receipt.sha256,
            }
        elif args.record_pricing:
            evidence = _load_evidence(args.evidence_file)
            receipt = write_pricing_evidence(
                context,
                evidence["official_evidence"],
                checked_at=evidence["checked_at"],
                reviewed_by=args.reviewed_by,
            )
            result = {
                "status": "grok-retry-pricing-recorded",
                "path": str(receipt.path.relative_to(REPOSITORY_ROOT)),
                "sha256": receipt.sha256,
            }
        elif args.seal_pricing:
            receipt = write_pricing_recheck(context)
            result = {
                "status": "grok-retry-pricing-sealed",
                "path": str(receipt.path.relative_to(REPOSITORY_ROOT)),
                "sha256": receipt.sha256,
            }
        else:
            authorization = validate_authorization(context)
            evidence = validate_pricing_evidence(context)
            pricing = validate_pricing_recheck(context)
            result = {
                "status": "grok-retry-authority-ready",
                "authorization_sha256": authorization.sha256,
                "pricing_evidence_sha256": evidence.sha256,
                "pricing_recheck_sha256": pricing.sha256,
                "network_requests": 0,
                "environment_variables_read": 0,
            }
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, AuthorizationError, GrokRetryLockError, ValueError) as error:
        print(f"Grok retry authorization stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

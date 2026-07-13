#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rule3.authorization import (
    PAID_AUTHORIZATION_STATEMENT,
    PAID_AUTHORIZATION_STATEMENT_SHA256,
    AuthorizationError,
    load_committed_lock,
    load_pricing_evidence_file,
    pricing_recheck_payload,
    validate_paid_authorization,
    validate_pricing_recheck,
    write_paid_authorization,
    write_pricing_recheck,
)

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def _literal_message(message: str) -> str:
    return message


def _fixed_formatter(prog: str) -> argparse.HelpFormatter:
    return argparse.HelpFormatter(prog, width=80)


# argparse delegates every label to gettext, whose default implementation reads
# locale environment variables. This command has a fixed English contract and
# must not read any environment variable, including locale settings.
argparse._ = _literal_message


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Record or verify private Rule 3 authority and pricing receipts.",
        formatter_class=_fixed_formatter,
    )
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--show-statement", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--write-pricing", action="store_true")
    mode.add_argument("--verify-pricing", action="store_true")
    command.add_argument(
        "--statement",
        help="exact disclosed authorization statement; required with --write",
    )
    command.add_argument(
        "--pricing-evidence",
        type=Path,
        help=(
            "local rule3-pricing-evidence-1.0.0 JSON; required with "
            "--write-pricing or --verify-pricing"
        ),
    )
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.show_statement:
        if args.statement is not None or args.pricing_evidence is not None:
            parser().error(
                "--statement is only valid with --write; --pricing-evidence "
                "is only valid with a pricing mode"
            )
        print(PAID_AUTHORIZATION_STATEMENT)
        print(f"SHA-256: {PAID_AUTHORIZATION_STATEMENT_SHA256}")
        return 0
    if args.write and args.statement is None:
        parser().error("--write requires --statement")
    if not args.write and args.statement is not None:
        parser().error("--statement is valid only with --write")
    pricing_mode = args.write_pricing or args.verify_pricing
    if pricing_mode and args.pricing_evidence is None:
        parser().error("pricing modes require --pricing-evidence")
    if not pricing_mode and args.pricing_evidence is not None:
        parser().error(
            "--pricing-evidence is valid only with --write-pricing or "
            "--verify-pricing"
        )
    try:
        lock_context = load_committed_lock(REPOSITORY_ROOT)
        if args.write:
            receipt = write_paid_authorization(lock_context, statement=args.statement)
            print(
                "Rule 3 paid authorization written privately: "
                + str(receipt.path.relative_to(REPOSITORY_ROOT))
            )
        elif args.verify:
            receipt = validate_paid_authorization(lock_context)
            print(
                "Rule 3 paid authorization verified: "
                + str(receipt.path.relative_to(REPOSITORY_ROOT))
            )
        else:
            evidence_path = args.pricing_evidence
            if not evidence_path.is_absolute():
                evidence_path = Path.cwd() / evidence_path
            evidence_file = load_pricing_evidence_file(evidence_path)
            if args.write_pricing:
                receipt = write_pricing_recheck(
                    lock_context,
                    evidence_file["official_evidence"],
                    reviewed_by=evidence_file["reviewed_by"],
                    checked_at=evidence_file["checked_at"],
                )
                print(
                    "Rule 3 pricing recheck written privately: "
                    + str(receipt.path.relative_to(REPOSITORY_ROOT))
                )
            else:
                receipt = validate_pricing_recheck(lock_context)
                expected = pricing_recheck_payload(
                    lock_context,
                    evidence_file["official_evidence"],
                    checked_at=evidence_file["checked_at"],
                    reviewed_by=evidence_file["reviewed_by"],
                )
                if receipt.payload != expected:
                    raise AuthorizationError(
                        "private pricing receipt differs from the local evidence file"
                    )
                print(
                    "Rule 3 pricing recheck verified against local evidence: "
                    + str(receipt.path.relative_to(REPOSITORY_ROOT))
                )
        print("Network requests: 0; environment variables read: 0")
        return 0
    except (AuthorizationError, OSError, ValueError) as error:
        print(f"Rule 3 authorization stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

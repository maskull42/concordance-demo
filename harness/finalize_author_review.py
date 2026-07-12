#!/usr/bin/env python3
"""Validate and seal A.G. Elrod's blinded primary-mapping review."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes, sha256_file, utc_now
from prepare_author_review import (
    EXPECTED_FIRST_PASS_SHA256,
    OUTPUT_ROOT as PACKET_ROOT,
    PACKET_SCHEMA_VERSION,
    AuthorReviewPacketError,
    prepare_review_context,
    verify_review_packet,
)
from validate_blind_mappings import EXPECTED_RUBRIC_SHA256


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
PACKET_RECEIPT_PATH = PACKET_ROOT / "packet.json"
SEALED_ROOT = PACKET_ROOT / "sealed-primary-review"
SEALED_DRAFT_PATH = SEALED_ROOT / "review-draft.json"
SEALED_RECEIPT_PATH = SEALED_ROOT / "review.json"
DRAFT_SCHEMA_VERSION = "blind-primary-review-draft-1.0.0"
REVIEW_SCHEMA_VERSION = "blind-primary-review-1.0.0"
MAX_DRAFT_BYTES = 2_000_000
REASON_CODES = {"clear_preference", "mixed", "unclear", "refusal", "outside_map"}
DRAFT_KEYS = {
    "schema_version",
    "status",
    "rubric_id",
    "rubric_sha256",
    "exported_at",
    "network_requests",
    "environment_variables_read",
    "review_id",
    "first_pass_receipt_sha256",
    "ordered_items_sha256",
    "reviewer",
    "review_scope",
    "item_count",
    "cursor",
    "decisions",
    "author_attestation",
    "threshold_evaluation",
    "selection_status",
}
DECISION_KEYS = {
    "review_index",
    "blind_item_id",
    "response_sha256",
    "review_item_sha256",
    "first_pass_assignment_sha256",
    "first_pass_primary_endorsed",
    "first_pass_primary_reason_code",
    "decision",
    "reviewed_primary_endorsed",
    "reviewed_primary_reason_code",
    "review_note",
    "reviewed_at",
}
RECEIPT_KEYS = {
    "schema_version",
    "status",
    "created_at",
    "network_requests",
    "environment_variables_read",
    "rubric_id",
    "rubric_sha256",
    "reviewer",
    "review_scope",
    "first_pass_receipt",
    "packet_receipt",
    "input_draft",
    "item_count",
    "decision_counts",
    "reviewed_assignments",
    "author_attestation",
    "validator",
    "threshold_evaluation",
    "selection_status",
}
PUBLICATION_CLAIM_SCHEMA = "private-publication-claim-1.0.0"
SEALED_FILENAMES = {"review-draft.json", "review.json"}


class AuthorReviewValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidatedReview:
    input_bytes: bytes
    input_sha256: str
    packet_receipt_sha256: str
    decisions: tuple[dict[str, Any], ...]
    confirmed: int
    corrected: int
    pending: int


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuthorReviewValidationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        AuthorReviewValidationError,
    ) as error:
        raise AuthorReviewValidationError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise AuthorReviewValidationError(f"{label} must be a JSON object")
    return value


def _read_bytes(path: Path, label: str, *, maximum: int | None = None) -> bytes:
    try:
        if maximum is not None and path.stat().st_size > maximum:
            raise AuthorReviewValidationError(f"{label} exceeds {maximum} bytes")
        return path.read_bytes()
    except OSError as error:
        raise AuthorReviewValidationError(f"{label} cannot be loaded: {error}") from error


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _normalize_note(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 4000:
        raise AuthorReviewValidationError("review note is invalid")
    normalized = value.strip()
    if not normalized:
        raise AuthorReviewValidationError("review note must be null or nonblank")
    return normalized


def _pair_is_valid(item: dict[str, Any], primary: Any, reason: Any) -> bool:
    positions = item.get("positions")
    if not isinstance(positions, list):
        return False
    handles = {
        position.get("handle")
        for position in positions
        if isinstance(position, dict) and isinstance(position.get("handle"), str)
    }
    if primary is not None and (not isinstance(primary, str) or primary not in handles):
        return False
    if not isinstance(reason, str) or reason not in REASON_CODES:
        return False
    return reason != "clear_preference" if primary is None else reason == "clear_preference"


def _packet_receipt(packet_root: Path) -> tuple[dict[str, Any], str]:
    payload = _read_bytes(packet_root / "packet.json", "packet receipt")
    receipt = _parse_json_bytes(payload, "packet receipt")
    if (
        receipt.get("schema_version") != PACKET_SCHEMA_VERSION
        or receipt.get("status") != "ready-for-author-review"
    ):
        raise AuthorReviewValidationError("packet receipt is not ready for author review")
    return receipt, sha256_bytes(payload)


def validate_review_input(
    input_path: Path,
    *,
    require_complete: bool,
    packet_root: Path = PACKET_ROOT,
) -> ValidatedReview:
    try:
        verify_review_packet(packet_root)
    except AuthorReviewPacketError as error:
        raise AuthorReviewValidationError(str(error)) from error
    context = prepare_review_context()
    packet_receipt, packet_receipt_sha256 = _packet_receipt(packet_root)
    input_bytes = _read_bytes(input_path, "author review input", maximum=MAX_DRAFT_BYTES)
    draft = _parse_json_bytes(input_bytes, "author review input")
    status = draft.get("status")
    complete = status == "complete-primary-review"
    expected_threshold = {
        "performed": False,
        "reason": (
            "Primary review is complete; threshold calculation has not run"
            if complete
            else "Author review is in progress"
        ),
    }
    if (
        set(draft) != DRAFT_KEYS
        or draft.get("schema_version") != DRAFT_SCHEMA_VERSION
        or not isinstance(status, str)
        or status not in {"author-review-in-progress", "complete-primary-review"}
        or draft.get("rubric_id") != "mapping-rubric-1"
        or draft.get("rubric_sha256") != EXPECTED_RUBRIC_SHA256
        or not _valid_timestamp(draft.get("exported_at"))
        or draft.get("network_requests") != 0
        or draft.get("environment_variables_read") != 0
        or draft.get("review_id") != packet_receipt.get("review_id")
        or draft.get("first_pass_receipt_sha256") != EXPECTED_FIRST_PASS_SHA256
        or draft.get("ordered_items_sha256") != context.ordered_items_sha256
        or draft.get("reviewer") != {"id": "ag-elrod", "display_name": "A.G. Elrod"}
        or draft.get("review_scope") != "primary-and-reason-only"
        or draft.get("item_count") != 64
        or not isinstance(draft.get("cursor"), int)
        or isinstance(draft.get("cursor"), bool)
        or not 0 <= draft["cursor"] < 64
        or draft.get("author_attestation") is not complete
        or draft.get("threshold_evaluation") != expected_threshold
        or draft.get("selection_status") != "not-evaluated"
    ):
        raise AuthorReviewValidationError("author review header differs from the packet contract")
    raw_decisions = draft.get("decisions")
    if not isinstance(raw_decisions, list) or len(raw_decisions) != 64:
        raise AuthorReviewValidationError("author review must contain 64 ordered decisions")

    normalized: list[dict[str, Any]] = []
    counts = {"confirm": 0, "correct": 0, "pending": 0}
    for index, (candidate, item) in enumerate(
        zip(raw_decisions, context.items, strict=True), start=1
    ):
        if not isinstance(candidate, dict) or set(candidate) != DECISION_KEYS:
            raise AuthorReviewValidationError(f"decision fields differ for item {index}")
        first_assignment = item["first_pass_assignment"]
        if (
            not isinstance(candidate.get("review_index"), int)
            or isinstance(candidate.get("review_index"), bool)
            or candidate.get("review_index") != item["review_index"]
            or candidate.get("blind_item_id") != item["blind_item_id"]
            or candidate.get("response_sha256") != item["response_sha256"]
            or candidate.get("review_item_sha256") != item["review_item_sha256"]
            or candidate.get("first_pass_assignment_sha256")
            != item["first_pass_assignment_sha256"]
            or candidate.get("first_pass_primary_endorsed")
            != first_assignment["primary_endorsed"]
            or candidate.get("first_pass_primary_reason_code")
            != first_assignment["primary_reason_code"]
        ):
            raise AuthorReviewValidationError(f"decision binding differs for item {index}")
        decision = candidate.get("decision")
        if not isinstance(decision, str) or decision not in counts:
            raise AuthorReviewValidationError(f"decision value is invalid for item {index}")
        primary = candidate.get("reviewed_primary_endorsed")
        reason = candidate.get("reviewed_primary_reason_code")
        if not _pair_is_valid(item, primary, reason):
            raise AuthorReviewValidationError(
                f"reviewed primary and reason are inconsistent for item {index}"
            )
        unchanged = (
            primary == first_assignment["primary_endorsed"]
            and reason == first_assignment["primary_reason_code"]
        )
        if decision == "confirm" and not unchanged:
            raise AuthorReviewValidationError(
                f"confirmation changes the first-pass pair for item {index}"
            )
        if decision == "correct" and unchanged:
            raise AuthorReviewValidationError(
                f"correction does not change the first-pass pair for item {index}"
            )
        note = _normalize_note(candidate.get("review_note"))
        reviewed_at = candidate.get("reviewed_at")
        if decision == "pending":
            if reviewed_at is not None:
                raise AuthorReviewValidationError(
                    f"pending decision has a timestamp for item {index}"
                )
        elif not _valid_timestamp(reviewed_at):
            raise AuthorReviewValidationError(
                f"completed decision lacks a valid timestamp for item {index}"
            )
        counts[decision] += 1
        normalized.append(
            {
                "review_index": item["review_index"],
                "blind_item_id": item["blind_item_id"],
                "response_sha256": item["response_sha256"],
                "review_item_sha256": item["review_item_sha256"],
                "first_pass_assignment_sha256": item["first_pass_assignment_sha256"],
                "first_pass_primary_endorsed": first_assignment["primary_endorsed"],
                "first_pass_primary_reason_code": first_assignment["primary_reason_code"],
                "decision": decision,
                "reviewed_primary_endorsed": primary,
                "reviewed_primary_reason_code": reason,
                "review_note": note,
                "reviewed_at": reviewed_at,
            }
        )
    if complete and counts["pending"]:
        raise AuthorReviewValidationError("complete author review contains pending decisions")
    if require_complete and (not complete or counts["pending"]):
        raise AuthorReviewValidationError("author review is not complete and attested")
    return ValidatedReview(
        input_bytes=input_bytes,
        input_sha256=sha256_bytes(input_bytes),
        packet_receipt_sha256=packet_receipt_sha256,
        decisions=tuple(normalized),
        confirmed=counts["confirm"],
        corrected=counts["correct"],
        pending=counts["pending"],
    )


def _source_hashes() -> dict[str, str]:
    paths = {
        Path(__file__).resolve(),
        REPOSITORY_ROOT / "harness/prepare_author_review.py",
        REPOSITORY_ROOT / "harness/validate_blind_mappings.py",
        REPOSITORY_ROOT / "harness/concordance_harness/util.py",
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _write_private(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise AuthorReviewValidationError(f"sealed review artifact exists: {path}") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _claim_path(sealed_root: Path) -> Path:
    return sealed_root.parent / f".{sealed_root.name}.publish-claim"


def _claim_value(sealed_root: Path) -> dict[str, Any]:
    return {
        "schema_version": PUBLICATION_CLAIM_SCHEMA,
        "target_name": sealed_root.name,
        "expected_files": sorted(SEALED_FILENAMES),
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _discard_claimed_partial(sealed_root: Path, claim_path: Path) -> None:
    if sealed_root.exists() and sealed_root.is_dir() and not sealed_root.is_symlink():
        entries = list(sealed_root.iterdir())
        if all(
            entry.name in SEALED_FILENAMES and entry.is_file() and not entry.is_symlink()
            for entry in entries
        ):
            for entry in entries:
                entry.unlink()
            sealed_root.rmdir()
    if claim_path.is_file() and not claim_path.is_symlink():
        claim_path.unlink()
    _fsync_directory(sealed_root.parent)


def recover_incomplete_seal(
    *,
    packet_root: Path = PACKET_ROOT,
    sealed_root: Path = SEALED_ROOT,
) -> str:
    claim_path = _claim_path(sealed_root)
    claim_bytes = _read_bytes(claim_path, "sealed review publication claim")
    claim = _parse_json_bytes(claim_bytes, "sealed review publication claim")
    if claim != _claim_value(sealed_root):
        raise AuthorReviewValidationError("sealed review publication claim is not recognized")
    if not sealed_root.exists():
        claim_path.unlink()
        _fsync_directory(sealed_root.parent)
        return "cleared"
    if not sealed_root.is_dir() or sealed_root.is_symlink():
        raise AuthorReviewValidationError("claimed sealed review output is not a private directory")
    entries = list(sealed_root.iterdir())
    if any(
        entry.name not in SEALED_FILENAMES
        or not entry.is_file()
        or entry.is_symlink()
        for entry in entries
    ):
        raise AuthorReviewValidationError(
            "claimed sealed review output contains unexpected files; preserve it for inspection"
        )
    if {entry.name for entry in entries} == SEALED_FILENAMES:
        try:
            verify_sealed_review(packet_root=packet_root, sealed_root=sealed_root)
        except (AuthorReviewValidationError, OSError, ValueError) as error:
            raise AuthorReviewValidationError(
                "complete-looking sealed review did not verify; preserve it for inspection"
            ) from error
        claim_path.unlink()
        _fsync_directory(sealed_root.parent)
        return "completed"
    _discard_claimed_partial(sealed_root, claim_path)
    return "cleared"


def seal_review(
    input_path: Path,
    *,
    packet_root: Path = PACKET_ROOT,
    sealed_root: Path = SEALED_ROOT,
) -> Path:
    validation = validate_review_input(
        input_path, require_complete=True, packet_root=packet_root
    )
    claim_path = _claim_path(sealed_root)
    if claim_path.exists():
        raise AuthorReviewValidationError(
            "incomplete sealed review publication exists; run --recover-incomplete"
        )
    if sealed_root.exists():
        raise AuthorReviewValidationError("sealed primary review is write-once")
    sealed_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = Path(
        tempfile.mkdtemp(prefix=".sealed-primary-review-", dir=sealed_root.parent)
    )
    os.chmod(temporary, 0o700)
    try:
        _write_private(temporary / "review-draft.json", validation.input_bytes)
        source_files = _source_hashes()
        receipt = {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "status": "complete-primary-review-threshold-pending",
            "created_at": utc_now(),
            "network_requests": 0,
            "environment_variables_read": 0,
            "rubric_id": "mapping-rubric-1",
            "rubric_sha256": EXPECTED_RUBRIC_SHA256,
            "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
            "review_scope": "primary-and-reason-only",
            "first_pass_receipt": {
                "path": "../../mapping-batches-1/first-pass.json",
                "sha256": EXPECTED_FIRST_PASS_SHA256,
            },
            "packet_receipt": {
                "path": "../packet.json",
                "sha256": validation.packet_receipt_sha256,
            },
            "input_draft": {
                "path": "review-draft.json",
                "sha256": validation.input_sha256,
            },
            "item_count": 64,
            "decision_counts": {
                "confirmed": validation.confirmed,
                "corrected": validation.corrected,
            },
            "reviewed_assignments": list(validation.decisions),
            "author_attestation": {
                "reviewer_id": "ag-elrod",
                "reviewed_all_primary_pairs": True,
            },
            "validator": {
                "source_files": source_files,
                "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
            },
            "threshold_evaluation": {
                "performed": False,
                "reason": "Primary review is sealed; threshold calculation has not run",
            },
            "selection_status": "not-evaluated",
        }
        _write_private(temporary / "review.json", canonical_json_bytes(receipt))
        directory = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        _write_private(claim_path, canonical_json_bytes(_claim_value(sealed_root)))
        _fsync_directory(sealed_root.parent)
        published = False
        output_created = False
        try:
            sealed_root.mkdir(mode=0o700)
            output_created = True
            os.link(temporary / "review-draft.json", sealed_root / "review-draft.json")
            os.link(temporary / "review.json", sealed_root / "review.json")
            _fsync_directory(sealed_root)
            _fsync_directory(sealed_root.parent)
            published = True
            claim_path.unlink()
            _fsync_directory(sealed_root.parent)
        except BaseException as error:
            if not published:
                try:
                    if output_created:
                        _discard_claimed_partial(sealed_root, claim_path)
                    elif claim_path.is_file() and not claim_path.is_symlink():
                        claim_path.unlink()
                        _fsync_directory(sealed_root.parent)
                except OSError:
                    pass
            if isinstance(error, FileExistsError):
                raise AuthorReviewValidationError(
                    "sealed primary review is write-once"
                ) from error
            raise
        return sealed_root / "review.json"
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def verify_sealed_review(
    *,
    packet_root: Path = PACKET_ROOT,
    sealed_root: Path = SEALED_ROOT,
) -> Path:
    draft_path = sealed_root / "review-draft.json"
    validation = validate_review_input(
        draft_path, require_complete=True, packet_root=packet_root
    )
    receipt_path = sealed_root / "review.json"
    receipt_bytes = _read_bytes(receipt_path, "sealed review receipt")
    receipt = _parse_json_bytes(receipt_bytes, "sealed review receipt")
    validator = receipt.get("validator")
    source_files = validator.get("source_files") if isinstance(validator, dict) else None
    if (
        set(receipt) != RECEIPT_KEYS
        or receipt.get("schema_version") != REVIEW_SCHEMA_VERSION
        or receipt.get("status") != "complete-primary-review-threshold-pending"
        or not _valid_timestamp(receipt.get("created_at"))
        or receipt.get("network_requests") != 0
        or receipt.get("environment_variables_read") != 0
        or receipt.get("rubric_id") != "mapping-rubric-1"
        or receipt.get("rubric_sha256") != EXPECTED_RUBRIC_SHA256
        or receipt.get("reviewer") != {"id": "ag-elrod", "display_name": "A.G. Elrod"}
        or receipt.get("review_scope") != "primary-and-reason-only"
        or receipt.get("first_pass_receipt")
        != {
            "path": "../../mapping-batches-1/first-pass.json",
            "sha256": EXPECTED_FIRST_PASS_SHA256,
        }
        or receipt.get("packet_receipt")
        != {"path": "../packet.json", "sha256": validation.packet_receipt_sha256}
        or receipt.get("input_draft")
        != {"path": "review-draft.json", "sha256": validation.input_sha256}
        or receipt.get("item_count") != 64
        or receipt.get("decision_counts")
        != {"confirmed": validation.confirmed, "corrected": validation.corrected}
        or receipt.get("reviewed_assignments") != list(validation.decisions)
        or receipt.get("author_attestation")
        != {"reviewer_id": "ag-elrod", "reviewed_all_primary_pairs": True}
        or not isinstance(validator, dict)
        or set(validator) != {"source_files", "execution_sha256"}
        or not isinstance(source_files, dict)
        or source_files != _source_hashes()
        or validator.get("execution_sha256")
        != sha256_bytes(canonical_json_bytes(source_files))
        or receipt.get("threshold_evaluation")
        != {
            "performed": False,
            "reason": "Primary review is sealed; threshold calculation has not run",
        }
        or receipt.get("selection_status") != "not-evaluated"
    ):
        raise AuthorReviewValidationError("sealed author review differs from contract")
    return receipt_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate blinded author review export.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", type=Path, metavar="PATH")
    mode.add_argument("--seal", type=Path, metavar="PATH")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--recover-incomplete", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.recover_incomplete:
            status = recover_incomplete_seal()
            print(f"Sealed author review recovery: {status}.")
            return 0
        if args.verify:
            path = verify_sealed_review()
            print(f"Sealed author review verified: {path.relative_to(REPOSITORY_ROOT)}")
            return 0
        if args.check is not None:
            value = validate_review_input(args.check, require_complete=False)
            print(
                "Author review file valid: "
                f"{value.confirmed} confirmed, {value.corrected} corrected, "
                f"{value.pending} pending."
            )
            return 0
        path = seal_review(args.seal)
        print(f"Author review sealed: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (AuthorReviewValidationError, OSError, ValueError) as error:
        print(f"Author review validation stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

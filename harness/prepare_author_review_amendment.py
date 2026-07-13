#!/usr/bin/env python3
"""Seal A.G. Elrod's approved one-cell amendment to the Rule 2 review."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from concordance_harness.util import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from evaluate_pilot_selection import SelectionError, verify_selection_receipt
from finalize_author_review import (
    AuthorReviewValidationError,
    seal_review,
    verify_sealed_review,
)
from prepare_author_review import AuthorReviewPacketError, verify_review_packet


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
AGGREGATE_ROOT = REPOSITORY_ROOT / ".pilot/aggregates/rule2-pilot-1"
BASE_REVIEW_ROOT = AGGREGATE_ROOT / "author-review-1"
BASE_SEALED_ROOT = BASE_REVIEW_ROOT / "sealed-primary-review"
BASE_DRAFT_PATH = BASE_SEALED_ROOT / "review-draft.json"
BASE_REVIEW_PATH = BASE_SEALED_ROOT / "review.json"
BASE_SELECTION_PATH = AGGREGATE_ROOT / "selection-rule2-1.json"
OUTPUT_ROOT = AGGREGATE_ROOT / "author-review-2"
OUTPUT_SEALED_ROOT = OUTPUT_ROOT / "sealed-primary-review"
AMENDMENT_PATH = OUTPUT_ROOT / "amendment.json"

BASE_DRAFT_SHA256 = "2c39ed51a29497e035d38c3a7cc4f74604ff4e76a21591543ce635f292803d0a"
BASE_REVIEW_SHA256 = "a51a7632f0efdc0142ac3a08ec69c637d0af986bfd8ee6fc1ec6b135ab91a946"
BASE_SELECTION_SHA256 = (
    "12e2c87f91be55b70a4c83cd363afcb86b8fe3c42e63db45abe044275a0bfc9e"
)
TARGET_BLIND_ID = "blind-ac30c39602d53eaa198433fe611f57e0"
TARGET_CELL_ID = "john-brown-harpers-ferry:grok:methods-and-violence-frame:answer"
TARGET_RESPONSE_SHA256 = (
    "3557ffe9cdd9fa492e11965ecade6157acf853812f1367f57e9aac2ad92b56c8"
)
TARGET_OLD_HANDLE = "P3"
TARGET_OLD_POSITION_ID = "criminal-fanatical-violence"
TARGET_NEW_REASON = "outside_map"
APPROVAL_STATEMENT = "I agree with your recommendations."
APPROVED_RECOMMENDATION = (
    "Grok called Brown’s raid ‘revolutionary terrorism’ while treating its morality "
    "as contested. It was mapped to ‘Fanatical or terrorist violence,’ but that is "
    "only a partial fit. The rubric forbids forced fits. I recommend changing this "
    "assignment to null and resealing. John Brown would still pass comfortably, "
    "with four movements instead of five. Approve?"
)
REVIEW_NOTE = (
    "A.G. Elrod approved treating this clear terrorism classification as outside "
    "the frozen map instead of forcing a partial primary fit."
)
AMENDMENT_SCHEMA_VERSION = "blind-primary-review-amendment-1.0.0"
PUBLICATION_CLAIM_SCHEMA = "private-directory-publication-claim-1.1.0"
STAGING_OWNER_SCHEMA = "private-directory-staging-owner-1.0.0"
STAGING_OWNER_NAME = ".owner.json"
CLAIM_QUARANTINE_INFIX = ".quarantine."
STAGING_CLEANUP_INFIX = ".cleanup."
OUTPUT_CLEANUP_INFIX = ".cleanup."
PUBLISHED_FILES = (
    Path("packet.json"),
    Path("author-review-packet.html"),
    Path("amendment.json"),
    Path("sealed-primary-review/review-draft.json"),
    Path("sealed-primary-review/review.json"),
)
PUBLISHED_DIRECTORIES = (Path("sealed-primary-review"),)


class ReviewAmendmentError(RuntimeError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewAmendmentError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ReviewAmendmentError(f"{label} must be a regular, non-symlink file")
    try:
        payload = path.read_bytes()
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        OSError,
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        ReviewAmendmentError,
    ) as error:
        raise ReviewAmendmentError(f"{label} cannot be loaded: {error}") from error
    if not isinstance(value, dict):
        raise ReviewAmendmentError(f"{label} must be a JSON object")
    return value, payload


def _require_hash(path: Path, expected: str, label: str) -> None:
    if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
        raise ReviewAmendmentError(f"{label} differs from the approved base artifact")


def _write_private(path: Path, payload: bytes) -> tuple[int, int, int]:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ReviewAmendmentError(f"write-once artifact exists: {path}") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        metadata = os.fstat(handle.fileno())
    return (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode))


def _read_claim(
    path: Path, label: str
) -> tuple[dict[str, Any], bytes, tuple[int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReviewAmendmentError(
            f"{label} cannot be opened safely: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ReviewAmendmentError(f"{label} must be a private regular file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        ReviewAmendmentError,
    ) as error:
        raise ReviewAmendmentError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise ReviewAmendmentError(f"{label} must be a JSON object")
    identity = (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode))
    return value, payload, identity


def _restore_quarantined_claim(quarantine: Path, claim_path: Path) -> None:
    if os.path.lexists(claim_path):
        return
    try:
        os.link(quarantine, claim_path, follow_symlinks=False)
    except (FileExistsError, NotImplementedError, OSError):
        return
    _fsync_directory(claim_path.parent)


def _unlink_owned_claim(
    path: Path,
    *,
    expected_payload: bytes,
    expected_identity: tuple[int, int, int],
) -> None:
    quarantine = path.parent / (
        f"{path.name}{CLAIM_QUARANTINE_INFIX}{secrets.token_hex(16)}"
    )
    os.rename(path, quarantine)
    _fsync_directory(path.parent)
    try:
        _, payload, identity = _read_claim(quarantine, "quarantined publication claim")
    except ReviewAmendmentError:
        _restore_quarantined_claim(quarantine, path)
        raise
    if payload != expected_payload or identity != expected_identity:
        _restore_quarantined_claim(quarantine, path)
        raise ReviewAmendmentError(
            "publication claim changed; preserve its quarantine for inspection"
        )
    quarantine.unlink()
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _source_hashes() -> dict[str, str]:
    paths = {
        Path(__file__).resolve(),
        REPOSITORY_ROOT / "harness/evaluate_pilot_selection.py",
        REPOSITORY_ROOT / "harness/finalize_author_review.py",
        REPOSITORY_ROOT / "harness/prepare_author_review.py",
        REPOSITORY_ROOT / "harness/concordance_harness/util.py",
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _relative_path(path: Path, start: Path) -> str:
    return os.path.relpath(path.resolve(), start.resolve())


def _claim_path(output_root: Path) -> Path:
    return output_root.parent / f".{output_root.name}.publish-claim"


def _claim_value(
    output_root: Path, staging_name: str, operation_token: str
) -> dict[str, str]:
    return {
        "schema_version": PUBLICATION_CLAIM_SCHEMA,
        "target_name": output_root.name,
        "staging_name": staging_name,
        "operation_token": operation_token,
    }


def _valid_operation_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _staging_owner_payload(output_root: Path, operation_token: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": STAGING_OWNER_SCHEMA,
            "target_name": output_root.name,
            "operation_token": operation_token,
        }
    )


def _claim_blocker_exists(claim_path: Path) -> bool:
    if os.path.lexists(claim_path):
        return True
    if not claim_path.parent.is_dir():
        return False
    prefix = f"{claim_path.name}{CLAIM_QUARANTINE_INFIX}"
    return any(entry.name.startswith(prefix) for entry in claim_path.parent.iterdir())


def _locate_live_or_quarantined(
    path: Path,
    *,
    infix: str,
    label: str,
) -> Path | None:
    candidates = []
    if os.path.lexists(path):
        candidates.append(path)
    if path.parent.is_dir():
        prefix = f"{path.name}{infix}"
        candidates.extend(
            entry for entry in path.parent.iterdir() if entry.name.startswith(prefix)
        )
    if len(candidates) > 1:
        raise ReviewAmendmentError(
            f"multiple {label} paths exist; preserve them for inspection"
        )
    return candidates[0] if candidates else None


def _claim_for_recovery(claim_path: Path) -> Path:
    located = _locate_live_or_quarantined(
        claim_path,
        infix=CLAIM_QUARANTINE_INFIX,
        label="publication claim",
    )
    if located is None:
        raise ReviewAmendmentError("amended-review publication claim is missing")
    return located


def _staging_path(output_root: Path, staging_name: str) -> Path:
    if (
        Path(staging_name).name != staging_name
        or not staging_name.startswith(f".{output_root.name}.")
        or not staging_name.endswith(".tmp")
    ):
        raise ReviewAmendmentError("amended-review staging name is invalid")
    return output_root.parent / staging_name


def _assert_owned_staging(path: Path, expected_owner_payload: bytes) -> None:
    if (
        path.is_symlink()
        or not path.is_dir()
        or stat.S_IMODE(path.stat().st_mode) != 0o700
    ):
        raise ReviewAmendmentError(
            "amended-review staging path is unexpected; preserve it for inspection"
        )
    owner_path = path / STAGING_OWNER_NAME
    _, owner_payload, _ = _read_claim(owner_path, "staging owner marker")
    if owner_payload != expected_owner_payload:
        raise ReviewAmendmentError(
            "amended-review staging owner changed; preserve it for inspection"
        )
    for entry in path.rglob("*"):
        if entry.is_symlink() or (not entry.is_file() and not entry.is_dir()):
            raise ReviewAmendmentError(
                "amended-review staging tree is unexpected; preserve it for inspection"
            )
        expected_mode = 0o600 if entry.is_file() else 0o700
        if stat.S_IMODE(entry.stat().st_mode) != expected_mode:
            raise ReviewAmendmentError(
                "amended-review staging tree is not private; preserve it for inspection"
            )


def _remove_private_staging(path: Path, expected_owner_payload: bytes) -> None:
    located = _locate_live_or_quarantined(
        path,
        infix=STAGING_CLEANUP_INFIX,
        label="amended-review staging",
    )
    if located is None:
        return
    if located == path:
        quarantine = path.parent / (
            f"{path.name}{STAGING_CLEANUP_INFIX}{secrets.token_hex(16)}"
        )
        os.rename(path, quarantine)
        _fsync_directory(path.parent)
        located = quarantine
    if (
        not located.is_symlink()
        and located.is_dir()
        and stat.S_IMODE(located.stat().st_mode) == 0o700
        and not any(located.iterdir())
    ):
        located.rmdir()
        _fsync_directory(located.parent)
        return
    _assert_owned_staging(located, expected_owner_payload)
    owner_path = located / STAGING_OWNER_NAME
    for current_name, directory_names, file_names in os.walk(
        located, topdown=False, followlinks=False
    ):
        current = Path(current_name)
        for file_name in file_names:
            entry = current / file_name
            if entry == owner_path:
                continue
            if (
                entry.is_symlink()
                or not entry.is_file()
                or stat.S_IMODE(entry.stat().st_mode) != 0o600
            ):
                raise ReviewAmendmentError(
                    "amended-review staging file changed during cleanup"
                )
            entry.unlink()
        for directory_name in directory_names:
            entry = current / directory_name
            if (
                entry.is_symlink()
                or not entry.is_dir()
                or stat.S_IMODE(entry.stat().st_mode) != 0o700
            ):
                raise ReviewAmendmentError(
                    "amended-review staging directory changed during cleanup"
                )
            entry.rmdir()
        _fsync_directory(current)
    if set(located.iterdir()) != {owner_path}:
        raise ReviewAmendmentError(
            "amended-review staging changed during cleanup; preserve it"
        )
    owner_path.unlink()
    _fsync_directory(located)
    located.rmdir()
    _fsync_directory(located.parent)


def _verify_base() -> None:
    _require_hash(BASE_DRAFT_PATH, BASE_DRAFT_SHA256, "base review draft")
    _require_hash(BASE_REVIEW_PATH, BASE_REVIEW_SHA256, "base review receipt")
    _require_hash(BASE_SELECTION_PATH, BASE_SELECTION_SHA256, "base selection receipt")
    try:
        verify_sealed_review(packet_root=BASE_REVIEW_ROOT, sealed_root=BASE_SEALED_ROOT)
        verify_selection_receipt(BASE_SELECTION_PATH)
    except (AuthorReviewValidationError, SelectionError, OSError, ValueError) as error:
        raise ReviewAmendmentError(str(error)) from error

    selection, _ = _read_json(BASE_SELECTION_PATH, "base selection receipt")
    records = selection.get("unblinded_reviewed_assignments")
    target = (
        next(
            (
                item
                for item in records
                if isinstance(item, dict)
                and item.get("blind_item_id") == TARGET_BLIND_ID
            ),
            None,
        )
        if isinstance(records, list)
        else None
    )
    if target != {
        "blind_item_id": TARGET_BLIND_ID,
        "cell_id": TARGET_CELL_ID,
        "question_id": "john-brown-harpers-ferry",
        "variant_id": "methods-and-violence-frame",
        "model_key": "grok",
        "response_sha256": TARGET_RESPONSE_SHA256,
        "review_decision": "confirm",
        "reviewed_primary_handle": TARGET_OLD_HANDLE,
        "reviewed_primary_reason_code": "clear_preference",
        "reviewed_primary_position_id": TARGET_OLD_POSITION_ID,
    }:
        raise ReviewAmendmentError(
            "base selection target differs from the approved correction"
        )


def amended_draft(recorded_at: str) -> dict[str, Any]:
    if not _valid_timestamp(recorded_at):
        raise ReviewAmendmentError("correction recording timestamp is malformed")
    _verify_base()
    draft, _ = _read_json(BASE_DRAFT_PATH, "base review draft")
    decisions = draft.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != 64:
        raise ReviewAmendmentError("base review decisions are malformed")
    matches = [
        decision
        for decision in decisions
        if isinstance(decision, dict)
        and decision.get("blind_item_id") == TARGET_BLIND_ID
    ]
    if len(matches) != 1:
        raise ReviewAmendmentError("approved correction target is not unique")
    target = matches[0]
    if (
        target.get("response_sha256") != TARGET_RESPONSE_SHA256
        or target.get("decision") != "confirm"
        or target.get("reviewed_primary_endorsed") != TARGET_OLD_HANDLE
        or target.get("reviewed_primary_reason_code") != "clear_preference"
        or target.get("review_note") is not None
    ):
        raise ReviewAmendmentError(
            "base review target differs from the approved correction"
        )
    target["decision"] = "correct"
    target["reviewed_primary_endorsed"] = None
    target["reviewed_primary_reason_code"] = TARGET_NEW_REASON
    target["review_note"] = REVIEW_NOTE
    target["reviewed_at"] = recorded_at
    draft["exported_at"] = recorded_at
    return draft


def _amendment_receipt(
    *, output_root: Path, created_at: str, amended_review_sha256: str
) -> dict[str, Any]:
    source_files = _source_hashes()
    return {
        "schema_version": AMENDMENT_SCHEMA_VERSION,
        "status": "approved-review-amendment-sealed",
        "created_at": created_at,
        "network_requests": 0,
        "environment_variables_read": 0,
        "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "authorization": {
            "medium": "Codex conversation",
            "authorized_on": "2026-07-12",
            "timestamp_precision": "date",
            "recommendation_text": APPROVED_RECOMMENDATION,
            "exact_response": APPROVAL_STATEMENT,
            "recorded_at": created_at,
            "recommendation_number": 3,
            "scope": "Change the Grok methods-frame primary assignment to null and reseal Rule 2.",
        },
        "base_review_draft": {
            "path": _relative_path(BASE_DRAFT_PATH, output_root),
            "sha256": BASE_DRAFT_SHA256,
        },
        "base_review": {
            "path": _relative_path(BASE_REVIEW_PATH, output_root),
            "sha256": BASE_REVIEW_SHA256,
        },
        "base_selection": {
            "path": _relative_path(BASE_SELECTION_PATH, output_root),
            "sha256": BASE_SELECTION_SHA256,
        },
        "amended_review": {
            "path": "sealed-primary-review/review.json",
            "sha256": amended_review_sha256,
        },
        "correction": {
            "blind_item_id": TARGET_BLIND_ID,
            "cell_id": TARGET_CELL_ID,
            "response_sha256": TARGET_RESPONSE_SHA256,
            "old_pair": {
                "primary_endorsed": TARGET_OLD_HANDLE,
                "primary_reason_code": "clear_preference",
                "canonical_position_id": TARGET_OLD_POSITION_ID,
            },
            "new_pair": {
                "primary_endorsed": None,
                "primary_reason_code": TARGET_NEW_REASON,
                "canonical_position_id": None,
            },
            "review_note": REVIEW_NOTE,
        },
        "generator": {
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
    }


def _assert_private_tree(output_root: Path) -> None:
    if (
        output_root.is_symlink()
        or not output_root.is_dir()
        or (output_root.stat().st_mode & 0o777) != 0o700
    ):
        raise ReviewAmendmentError(
            "amended review root must remain private at mode 0700"
        )
    expected_files = {
        output_root / "packet.json",
        output_root / "author-review-packet.html",
        output_root / "amendment.json",
        output_root / "sealed-primary-review/review-draft.json",
        output_root / "sealed-primary-review/review.json",
    }
    expected_directories = {output_root / "sealed-primary-review"}
    expected_entries = expected_files | expected_directories
    actual_entries = set(output_root.rglob("*"))
    if actual_entries != expected_entries:
        raise ReviewAmendmentError("amended review tree contains unexpected entries")
    for path in actual_entries:
        if path.is_symlink():
            raise ReviewAmendmentError("amended review tree must not contain symlinks")
    for path in expected_files:
        if not path.is_file() or (path.stat().st_mode & 0o777) != 0o600:
            raise ReviewAmendmentError(
                "amended review files must remain private at mode 0600"
            )
    sealed_root = output_root / "sealed-primary-review"
    if not sealed_root.is_dir() or (sealed_root.stat().st_mode & 0o777) != 0o700:
        raise ReviewAmendmentError("amended sealed-review directory must be mode 0700")


def _verify_receipt_binding(output_root: Path, record: Any, label: str) -> None:
    if (
        not isinstance(record, dict)
        or set(record) != {"path", "sha256"}
        or not isinstance(record.get("path"), str)
        or not isinstance(record.get("sha256"), str)
    ):
        raise ReviewAmendmentError(f"{label} binding is malformed")
    path = output_root / record["path"]
    _require_hash(path, record["sha256"], label)


def verify_amended_review(output_root: Path = OUTPUT_ROOT) -> Path:
    _verify_base()
    _assert_private_tree(output_root)
    try:
        verify_review_packet(output_root)
        verify_sealed_review(
            packet_root=output_root,
            sealed_root=output_root / "sealed-primary-review",
        )
    except (
        AuthorReviewPacketError,
        AuthorReviewValidationError,
        OSError,
        ValueError,
    ) as error:
        raise ReviewAmendmentError(str(error)) from error

    base_review, _ = _read_json(BASE_REVIEW_PATH, "base review receipt")
    amended_path = output_root / "sealed-primary-review/review.json"
    amended_review, amended_payload = _read_json(amended_path, "amended review receipt")
    if amended_review.get("decision_counts") != {"confirmed": 63, "corrected": 1}:
        raise ReviewAmendmentError("amended review decision counts differ")
    base_assignments = base_review.get("reviewed_assignments")
    amended_assignments = amended_review.get("reviewed_assignments")
    if not isinstance(base_assignments, list) or not isinstance(
        amended_assignments, list
    ):
        raise ReviewAmendmentError("reviewed assignments are malformed")
    if len(base_assignments) != 64 or len(amended_assignments) != 64:
        raise ReviewAmendmentError("reviewed assignment count differs")
    changes = []
    for before, after in zip(base_assignments, amended_assignments, strict=True):
        if before != after:
            changes.append((before, after))
    if len(changes) != 1:
        raise ReviewAmendmentError("amended review must change exactly one assignment")
    before, after = changes[0]
    expected_after = dict(before)
    expected_after.update(
        {
            "decision": "correct",
            "reviewed_primary_endorsed": None,
            "reviewed_primary_reason_code": TARGET_NEW_REASON,
            "review_note": REVIEW_NOTE,
            "reviewed_at": after.get("reviewed_at"),
        }
    )
    if (
        before.get("blind_item_id") != TARGET_BLIND_ID
        or before.get("response_sha256") != TARGET_RESPONSE_SHA256
        or before.get("decision") != "confirm"
        or before.get("reviewed_primary_endorsed") != TARGET_OLD_HANDLE
        or before.get("reviewed_primary_reason_code") != "clear_preference"
        or not _valid_timestamp(after.get("reviewed_at"))
        or after != expected_after
    ):
        raise ReviewAmendmentError("amended review change differs from A.G.'s approval")

    amendment, _ = _read_json(output_root / "amendment.json", "amendment receipt")
    created_at = amendment.get("created_at")
    if not _valid_timestamp(created_at):
        raise ReviewAmendmentError("amendment creation time is malformed")
    stored_draft, _ = _read_json(
        output_root / "sealed-primary-review/review-draft.json",
        "amended review draft",
    )
    if stored_draft != amended_draft(created_at):
        raise ReviewAmendmentError(
            "amended review draft contains changes outside the approved delta"
        )
    expected = _amendment_receipt(
        output_root=output_root,
        created_at=created_at,
        amended_review_sha256=sha256_bytes(amended_payload),
    )
    if amendment != expected or after.get("reviewed_at") != created_at:
        raise ReviewAmendmentError(
            "amendment receipt differs from the approved correction"
        )
    for key, label in (
        ("base_review_draft", "base review draft"),
        ("base_review", "base review"),
        ("base_selection", "base selection"),
        ("amended_review", "amended review"),
    ):
        _verify_receipt_binding(output_root, amendment.get(key), label)
    return output_root / "amendment.json"


def _install_tree(temporary: Path, output_root: Path) -> None:
    (output_root / "sealed-primary-review").mkdir(mode=0o700)
    for relative in PUBLISHED_FILES:
        os.link(temporary / relative, output_root / relative)
    _fsync_directory(output_root / "sealed-primary-review")
    _fsync_directory(output_root)


def _safe_owned_partial_output(
    output_root: Path,
    staging_root: Path,
    expected_owner_payload: bytes,
) -> bool:
    """Return whether a crashed install is an owned, strict subset of the tree."""
    if (
        output_root.is_symlink()
        or not output_root.is_dir()
        or stat.S_IMODE(output_root.stat().st_mode) != 0o700
        or staging_root.is_symlink()
        or not staging_root.is_dir()
        or stat.S_IMODE(staging_root.stat().st_mode) != 0o700
    ):
        return False
    try:
        _assert_owned_staging(staging_root, expected_owner_payload)
    except ReviewAmendmentError:
        return False
    expected_files = {output_root / relative for relative in PUBLISHED_FILES}
    expected_directories = {
        output_root / relative for relative in PUBLISHED_DIRECTORIES
    }
    expected_entries = expected_files | expected_directories
    actual_entries = set(output_root.rglob("*"))
    if not actual_entries < expected_entries:
        return False
    for directory in actual_entries & expected_directories:
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or stat.S_IMODE(directory.stat().st_mode) != 0o700
        ):
            return False
    for path in actual_entries & expected_files:
        relative = path.relative_to(output_root)
        staged = staging_root / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o600
            or staged.is_symlink()
            or not staged.is_file()
            or stat.S_IMODE(staged.stat().st_mode) != 0o600
        ):
            return False
        try:
            if not os.path.samefile(path, staged):
                return False
        except OSError:
            return False
    return True


def _discard_partial_output(
    output_root: Path,
    staging_root: Path,
    expected_owner_payload: bytes,
) -> None:
    located = _locate_live_or_quarantined(
        output_root,
        infix=OUTPUT_CLEANUP_INFIX,
        label="partial amended-review output",
    )
    if located is None:
        return
    if located == output_root:
        quarantine = output_root.parent / (
            f"{output_root.name}{OUTPUT_CLEANUP_INFIX}{secrets.token_hex(16)}"
        )
        os.rename(output_root, quarantine)
        _fsync_directory(output_root.parent)
        located = quarantine
    if not _safe_owned_partial_output(located, staging_root, expected_owner_payload):
        raise ReviewAmendmentError(
            "partial amended review is not owned; preserve its claim"
        )
    for relative in PUBLISHED_FILES[:3]:
        published = located / relative
        if os.path.lexists(published):
            staged = staging_root / relative
            if (
                published.is_symlink()
                or not published.is_file()
                or stat.S_IMODE(published.stat().st_mode) != 0o600
                or not os.path.samefile(published, staged)
            ):
                raise ReviewAmendmentError(
                    "partial amended-review file changed during cleanup"
                )
            published.unlink()
    sealed_root = located / "sealed-primary-review"
    if sealed_root.is_dir() and not sealed_root.is_symlink():
        for relative in PUBLISHED_FILES[3:]:
            published = located / relative
            if os.path.lexists(published):
                staged = staging_root / relative
                if (
                    published.is_symlink()
                    or not published.is_file()
                    or stat.S_IMODE(published.stat().st_mode) != 0o600
                    or not os.path.samefile(published, staged)
                ):
                    raise ReviewAmendmentError(
                        "partial sealed-review file changed during cleanup"
                    )
                published.unlink()
        _fsync_directory(sealed_root)
        if not any(sealed_root.iterdir()):
            sealed_root.rmdir()
    _fsync_directory(located)
    if not any(located.iterdir()):
        located.rmdir()
        _fsync_directory(located.parent)
    if os.path.lexists(located):
        raise ReviewAmendmentError(
            "partial amended review contains unexpected entries; preserve its claim"
        )


def write_amended_review(output_root: Path = OUTPUT_ROOT) -> Path:
    _verify_base()
    claim_path = _claim_path(output_root)
    if _claim_blocker_exists(claim_path):
        raise ReviewAmendmentError(
            "incomplete amended-review publication exists; run --recover-incomplete"
        )
    if os.path.lexists(output_root):
        raise ReviewAmendmentError("amended review output is write-once")
    output_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging_name = f".{output_root.name}.{secrets.token_hex(8)}.tmp"
    temporary = _staging_path(output_root, staging_name)
    operation_token = secrets.token_hex(32)
    owner_payload = _staging_owner_payload(output_root, operation_token)
    claim_payload = canonical_json_bytes(
        _claim_value(output_root, staging_name, operation_token)
    )
    claim_created = False
    claim_identity: tuple[int, int, int] | None = None
    staging_created = False
    output_created = False
    published = False
    try:
        temporary.mkdir(mode=0o700)
        staging_created = True
        _write_private(temporary / STAGING_OWNER_NAME, owner_payload)
        _fsync_directory(temporary)
        claim_identity = _write_private(claim_path, claim_payload)
        claim_created = True
        _, stored_claim_payload, stored_claim_identity = _read_claim(
            claim_path, "amended-review publication claim"
        )
        if (
            stored_claim_payload != claim_payload
            or stored_claim_identity != claim_identity
        ):
            raise ReviewAmendmentError("amended-review publication claim changed")
        _fsync_directory(output_root.parent)
        created_at = utc_now()
        draft = amended_draft(created_at)
        for name in ("packet.json", "author-review-packet.html"):
            try:
                packet_payload = (BASE_REVIEW_ROOT / name).read_bytes()
            except OSError as error:
                raise ReviewAmendmentError(
                    f"base review packet cannot be copied: {error}"
                ) from error
            _write_private(temporary / name, packet_payload)
        draft_path = temporary / ".approved-review.json"
        _write_private(draft_path, canonical_json_bytes(draft))
        try:
            sealed_path = seal_review(
                draft_path,
                packet_root=temporary,
                sealed_root=temporary / "sealed-primary-review",
            )
        except (AuthorReviewValidationError, OSError, ValueError) as error:
            raise ReviewAmendmentError(str(error)) from error
        draft_path.unlink()
        amended_review_sha256 = sha256_file(sealed_path)
        _write_private(
            temporary / "amendment.json",
            canonical_json_bytes(
                _amendment_receipt(
                    output_root=output_root,
                    created_at=created_at,
                    amended_review_sha256=amended_review_sha256,
                )
            ),
        )
        _fsync_directory(temporary / "sealed-primary-review")
        _fsync_directory(temporary)
        output_root.mkdir(mode=0o700)
        output_created = True
        _install_tree(temporary, output_root)
        _fsync_directory(output_root.parent)
        published = True
        verify_amended_review(output_root)
        _remove_private_staging(temporary, owner_payload)
        staging_created = False
        assert claim_identity is not None
        _unlink_owned_claim(
            claim_path,
            expected_payload=claim_payload,
            expected_identity=claim_identity,
        )
        claim_created = False
        return output_root / "amendment.json"
    except BaseException as original_error:
        cleanup_error: BaseException | None = None
        if not published:
            try:
                if output_created:
                    _discard_partial_output(output_root, temporary, owner_payload)
                if staging_created:
                    _remove_private_staging(temporary, owner_payload)
                    staging_created = False
            except (OSError, ReviewAmendmentError) as error:
                cleanup_error = error
        if (
            not published
            and cleanup_error is None
            and claim_created
            and claim_identity is not None
        ):
            try:
                _unlink_owned_claim(
                    claim_path,
                    expected_payload=claim_payload,
                    expected_identity=claim_identity,
                )
                claim_created = False
            except (OSError, ReviewAmendmentError) as error:
                cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error from original_error
        raise


def recover_incomplete_publication(output_root: Path = OUTPUT_ROOT) -> str:
    canonical_claim_path = _claim_path(output_root)
    claim_path = _claim_for_recovery(canonical_claim_path)
    claim, claim_payload, claim_identity = _read_claim(
        claim_path, "amended-review publication claim"
    )
    staging_name = claim.get("staging_name")
    operation_token = claim.get("operation_token")
    if (
        not isinstance(staging_name, str)
        or not _valid_operation_token(operation_token)
        or claim != _claim_value(output_root, staging_name, operation_token)
    ):
        raise ReviewAmendmentError("amended-review publication claim is not recognized")
    staging_path = _staging_path(output_root, staging_name)
    owner_payload = _staging_owner_payload(output_root, operation_token)
    published_root = _locate_live_or_quarantined(
        output_root,
        infix=OUTPUT_CLEANUP_INFIX,
        label="amended-review output",
    )
    if published_root is None:
        _remove_private_staging(staging_path, owner_payload)
        _unlink_owned_claim(
            claim_path,
            expected_payload=claim_payload,
            expected_identity=claim_identity,
        )
        return "cleared"
    try:
        verify_amended_review(published_root)
    except (ReviewAmendmentError, OSError, ValueError) as error:
        if _safe_owned_partial_output(published_root, staging_path, owner_payload):
            _discard_partial_output(output_root, staging_path, owner_payload)
            _remove_private_staging(staging_path, owner_payload)
            _unlink_owned_claim(
                claim_path,
                expected_payload=claim_payload,
                expected_identity=claim_identity,
            )
            return "cleared"
        raise ReviewAmendmentError(
            "published amended review did not verify; preserve it for inspection"
        ) from error
    if published_root != output_root:
        if os.path.lexists(output_root):
            raise ReviewAmendmentError(
                "amended-review destination reappeared; preserve both paths"
            )
        os.rename(published_root, output_root)
        _fsync_directory(output_root.parent)
    _remove_private_staging(staging_path, owner_payload)
    _unlink_owned_claim(
        claim_path,
        expected_payload=claim_payload,
        expected_identity=claim_identity,
    )
    return "completed"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seal the approved Rule 2 review amendment."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--recover-incomplete", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.recover_incomplete:
            status = recover_incomplete_publication()
            print(f"Rule 2 review amendment recovery: {status}.")
            return 0
        if args.verify:
            path = verify_amended_review()
            print(
                f"Rule 2 review amendment verified: {path.relative_to(REPOSITORY_ROOT)}"
            )
            return 0
        if args.check:
            draft = amended_draft(utc_now())
            changed = next(
                item
                for item in draft["decisions"]
                if item["blind_item_id"] == TARGET_BLIND_ID
            )
            if (
                changed["reviewed_primary_endorsed"] is not None
                or changed["reviewed_primary_reason_code"] != TARGET_NEW_REASON
            ):
                raise ReviewAmendmentError(
                    "approved correction did not prepare cleanly"
                )
            print(
                "Rule 2 review amendment ready: one approved null/outside_map correction."
            )
            return 0
        path = write_amended_review()
        print(f"Rule 2 review amendment written: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (ReviewAmendmentError, OSError, ValueError) as error:
        print(f"Rule 2 review amendment stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

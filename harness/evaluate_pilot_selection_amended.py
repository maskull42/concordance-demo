#!/usr/bin/env python3
"""Recompute Rule 2 after A.G. Elrod's sealed one-cell review amendment."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import evaluate_pilot_selection as base
import prepare_author_review_amendment as amendment
from concordance_harness.util import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    utc_now,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
AGGREGATE_ROOT = REPOSITORY_ROOT / ".pilot/aggregates/rule2-pilot-1"
BASE_SELECTION_PATH = AGGREGATE_ROOT / "selection-rule2-1.json"
OUTPUT_PATH = AGGREGATE_ROOT / "selection-rule2-2.json"
SELECTION_SCHEMA_VERSION = "pilot-selection-amendment-1.0.0"
SELECTION_ID = "rule2-selection-2"
SELECTION_CLAIM_SCHEMA = "selection-amendment-publication-claim-1.1.0"
STAGING_OWNER_SCHEMA = "selection-amendment-staging-owner-1.0.0"
STAGING_OWNER_NAME = "owner.json"
STAGING_PAYLOAD_NAME = "payload.tmp"
CLAIM_QUARANTINE_INFIX = ".quarantine."
STAGING_CLEANUP_INFIX = ".cleanup."
OUTPUT_CLEANUP_INFIX = ".cleanup."


class AmendedSelectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class AmendedSelectionContext:
    base_context: base.SelectionContext
    active_input_bindings: dict[str, dict[str, str]]
    amendment_sha256: str
    amended_review_sha256: str
    amended_draft_sha256: str
    assignments: tuple[dict[str, Any], ...]
    lineage_sha256: str
    candidate_metrics: tuple[dict[str, Any], ...]
    behavior_results: tuple[dict[str, Any], ...]
    selected_candidate_ids: tuple[str, ...]
    failed_behaviors: tuple[str, ...]


def _source_hashes() -> dict[str, str]:
    values = base._source_hashes()
    for path in (
        Path(__file__).resolve(),
        REPOSITORY_ROOT / "harness/prepare_author_review_amendment.py",
    ):
        values[str(path.relative_to(REPOSITORY_ROOT))] = sha256_file(path)
    return dict(sorted(values.items()))


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPOSITORY_ROOT))
    except ValueError:
        return str(path)


def _relative_path(path: Path, start: Path) -> str:
    return os.path.relpath(path.resolve(), start.resolve())


def _metric_for_candidate(
    old_metric: dict[str, Any], records: tuple[dict[str, Any], ...]
) -> dict[str, Any]:
    behavior = old_metric["behavior"]
    candidate_id = old_metric["candidate_id"]
    role = old_metric["role"]
    if behavior == "convergence":
        return base.convergence_metrics(
            candidate_id=candidate_id,
            role=role,
            records=records,
            position_ids=tuple(old_metric["position_counts"]),
        )
    if behavior == "divergence":
        return base.divergence_metrics(
            candidate_id=candidate_id,
            role=role,
            records=records,
            position_ids=tuple(old_metric["position_counts"]),
        )
    variants = old_metric.get("variant_metrics")
    if not isinstance(variants, list) or len(variants) != 2:
        raise AmendedSelectionError(f"prompt variants are malformed for {candidate_id}")
    return base.prompt_sensitivity_metrics(
        candidate_id=candidate_id,
        role=role,
        records=records,
        position_ids=tuple(variants[0]["position_counts"]),
        variant_ids=(variants[0]["variant_id"], variants[1]["variant_id"]),
    )


def prepare_amended_context() -> AmendedSelectionContext:
    try:
        base.verify_selection_receipt(BASE_SELECTION_PATH)
        base_context = base.prepare_selection_context()
        amendment.verify_amended_review()
    except (
        base.SelectionError,
        amendment.ReviewAmendmentError,
        OSError,
        ValueError,
    ) as error:
        raise AmendedSelectionError(str(error)) from error

    amendment_path = amendment.AMENDMENT_PATH
    amended_review_root = amendment_path.parent
    review_path = amendment.OUTPUT_SEALED_ROOT / "review.json"
    draft_path = amendment.OUTPUT_SEALED_ROOT / "review-draft.json"
    amendment_sha256 = sha256_file(amendment_path)
    amended_review_sha256 = sha256_file(review_path)
    amended_draft_sha256 = sha256_file(draft_path)
    amendment_receipt, _ = base._read_json(amendment_path, "review amendment receipt")
    if (
        amendment_receipt.get("amended_review", {}).get("sha256")
        != amended_review_sha256
        or amendment_receipt.get("base_selection", {}).get("sha256")
        != amendment.BASE_SELECTION_SHA256
    ):
        raise AmendedSelectionError("review amendment lineage differs")
    active_input_bindings = dict(base_context.input_bindings)
    active_input_bindings.update(
        {
            "review_packet": {
                "path": _display_path(amended_review_root / "packet.json"),
                "sha256": sha256_file(amended_review_root / "packet.json"),
            },
            "review_draft": {
                "path": _display_path(draft_path),
                "sha256": amended_draft_sha256,
            },
            "author_review": {
                "path": _display_path(review_path),
                "sha256": amended_review_sha256,
            },
            "review_amendment": {
                "path": _display_path(amendment_path),
                "sha256": amendment_sha256,
            },
        }
    )

    assignments = [dict(record) for record in base_context.assignments]
    targets = [
        record
        for record in assignments
        if record["blind_item_id"] == amendment.TARGET_BLIND_ID
    ]
    if len(targets) != 1:
        raise AmendedSelectionError(
            "approved selection correction target is not unique"
        )
    target = targets[0]
    expected_target = {
        "blind_item_id": amendment.TARGET_BLIND_ID,
        "cell_id": amendment.TARGET_CELL_ID,
        "question_id": "john-brown-harpers-ferry",
        "variant_id": "methods-and-violence-frame",
        "model_key": "grok",
        "response_sha256": amendment.TARGET_RESPONSE_SHA256,
        "review_decision": "confirm",
        "reviewed_primary_handle": amendment.TARGET_OLD_HANDLE,
        "reviewed_primary_reason_code": "clear_preference",
        "reviewed_primary_position_id": amendment.TARGET_OLD_POSITION_ID,
    }
    if target != expected_target:
        raise AmendedSelectionError(
            "base canonical assignment differs from approved correction"
        )
    target.update(
        {
            "review_decision": "correct",
            "reviewed_primary_handle": None,
            "reviewed_primary_reason_code": amendment.TARGET_NEW_REASON,
            "reviewed_primary_position_id": None,
        }
    )
    assignments.sort(key=lambda item: item["cell_id"])
    assignments_tuple = tuple(assignments)

    records_by_question = {
        metric["candidate_id"]: tuple(
            record
            for record in assignments_tuple
            if record["question_id"] == metric["candidate_id"]
        )
        for metric in base_context.candidate_metrics
    }
    metrics = tuple(
        _metric_for_candidate(metric, records_by_question[metric["candidate_id"]])
        for metric in base_context.candidate_metrics
    )
    metrics_by_id = {metric["candidate_id"]: metric for metric in metrics}
    behavior_results = tuple(
        base._behavior_result(behavior, metrics_by_id)
        for behavior in base.BEHAVIOR_ORDER
    )
    selected = tuple(
        result["selected_candidate_id"]
        for result in behavior_results
        if result["selected_candidate_id"] is not None
    )
    failed = tuple(
        result["behavior"]
        for result in behavior_results
        if result["selected_candidate_id"] is None
    )
    return AmendedSelectionContext(
        base_context=base_context,
        active_input_bindings=active_input_bindings,
        amendment_sha256=amendment_sha256,
        amended_review_sha256=amended_review_sha256,
        amended_draft_sha256=amended_draft_sha256,
        assignments=assignments_tuple,
        lineage_sha256=sha256_bytes(canonical_json_bytes(assignments_tuple)),
        candidate_metrics=metrics,
        behavior_results=behavior_results,
        selected_candidate_ids=selected,
        failed_behaviors=failed,
    )


def _metric_by_id(
    metrics: tuple[dict[str, Any], ...], candidate_id: str
) -> dict[str, Any]:
    matches = [metric for metric in metrics if metric["candidate_id"] == candidate_id]
    if len(matches) != 1:
        raise AmendedSelectionError(f"metric is not unique for {candidate_id}")
    return matches[0]


def _receipt(
    context: AmendedSelectionContext,
    *,
    output_path: Path,
    created_at: str,
    source_files: dict[str, str],
) -> dict[str, Any]:
    partial = bool(context.failed_behaviors)
    before = _metric_by_id(
        context.base_context.candidate_metrics, "john-brown-harpers-ferry"
    )
    after = _metric_by_id(context.candidate_metrics, "john-brown-harpers-ferry")
    return {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "selection_id": SELECTION_ID,
        "status": (
            "partial-selection-new-pool-required"
            if partial
            else "complete-three-behavior-selection"
        ),
        "created_at": created_at,
        "network_requests": 0,
        "environment_variables_read": 0,
        "rule_contract": base._rule_contract(),
        "supersedes": {
            "path": _relative_path(BASE_SELECTION_PATH, output_path.parent),
            "sha256": amendment.BASE_SELECTION_SHA256,
            "scope": "One author-reviewed primary assignment and its derived metrics only.",
            "historical_artifact_preserved": True,
        },
        "audit_lineage": {
            "base_author_review_draft": {
                "path": _relative_path(amendment.BASE_DRAFT_PATH, output_path.parent),
                "sha256": amendment.BASE_DRAFT_SHA256,
            },
            "base_author_review": {
                "path": _relative_path(amendment.BASE_REVIEW_PATH, output_path.parent),
                "sha256": amendment.BASE_REVIEW_SHA256,
            },
            "review_amendment": {
                "path": _relative_path(amendment.AMENDMENT_PATH, output_path.parent),
                "sha256": context.amendment_sha256,
            },
            "amended_author_review": {
                "path": _relative_path(
                    amendment.OUTPUT_SEALED_ROOT / "review.json",
                    output_path.parent,
                ),
                "sha256": context.amended_review_sha256,
            },
            "amended_review_draft": {
                "path": _relative_path(
                    amendment.OUTPUT_SEALED_ROOT / "review-draft.json",
                    output_path.parent,
                ),
                "sha256": context.amended_draft_sha256,
            },
            "approved_correction": {
                "blind_item_id": amendment.TARGET_BLIND_ID,
                "cell_id": amendment.TARGET_CELL_ID,
                "old_primary_position_id": amendment.TARGET_OLD_POSITION_ID,
                "new_primary_position_id": None,
                "new_reason_code": amendment.TARGET_NEW_REASON,
            },
        },
        "input_bindings": context.active_input_bindings,
        "run_input_artifacts": list(context.base_context.run_input_artifacts),
        "mapping_files": list(context.base_context.mapping_files),
        "candidate_files": list(context.base_context.candidate_files),
        "lineage": {
            "canonical_assignment_count": 64,
            "canonical_assignments_sha256": context.lineage_sha256,
        },
        "unblinded_reviewed_assignments": list(context.assignments),
        "candidate_metrics": list(context.candidate_metrics),
        "behavior_results": list(context.behavior_results),
        "selected_candidate_ids": list(context.selected_candidate_ids),
        "failed_behaviors": list(context.failed_behaviors),
        "correction_effect": {
            "candidate_id": "john-brown-harpers-ferry",
            "paired_non_null_model_count": {
                "before": before["paired_non_null_model_count"],
                "after": after["paired_non_null_model_count"],
            },
            "movement_count": {
                "before": before["movement_count"],
                "after": after["movement_count"],
            },
            "selection_changed": (
                context.selected_candidate_ids
                != context.base_context.selected_candidate_ids
                or context.failed_behaviors != context.base_context.failed_behaviors
            ),
        },
        "threshold_evaluation": {
            "performed": True,
            "candidate_count": 6,
            "behavior_count": 3,
            "author_review_receipt_sha256": context.amended_review_sha256,
            "superseded_selection_sha256": amendment.BASE_SELECTION_SHA256,
        },
        "selection_status": "partial-two-of-three" if partial else "complete",
        "formal_verification": {
            "performed": False,
            "reason": "Selected candidate scholarship and mappings remain proposed.",
        },
        "production_gate": {
            "eligible": False,
            "blockers": [
                *[
                    f"{behavior} has no qualifying candidate; a new approved pool and rule version are required"
                    for behavior in context.failed_behaviors
                ],
                "selected questions, positions, sources, and mappings are not author-verified",
                "the linked-challenge final model run has not been executed",
            ],
        },
        "evaluator": {
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
    }


def _claim_path(output_path: Path) -> Path:
    return output_path.parent / f".{output_path.name}.publish-claim"


def _claim_value(
    output_path: Path,
    payload_sha256: str,
    staging_name: str,
    operation_token: str,
) -> dict[str, str]:
    return {
        "schema_version": SELECTION_CLAIM_SCHEMA,
        "target_name": output_path.name,
        "payload_sha256": payload_sha256,
        "staging_name": staging_name,
        "operation_token": operation_token,
    }


def _valid_operation_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _staging_owner_payload(output_path: Path, operation_token: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": STAGING_OWNER_SCHEMA,
            "target_name": output_path.name,
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
        raise AmendedSelectionError(
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
        raise AmendedSelectionError("amended-selection publication claim is missing")
    return located


def _staging_path(output_path: Path, staging_name: str) -> Path:
    if (
        Path(staging_name).name != staging_name
        or not staging_name.startswith(f".{output_path.name}.")
        or not staging_name.endswith(".tmp")
    ):
        raise AmendedSelectionError("amended-selection staging name is invalid")
    return output_path.parent / staging_name


def _assert_owned_staging(path: Path, expected_owner_payload: bytes) -> None:
    if (
        path.is_symlink()
        or not path.is_dir()
        or stat.S_IMODE(path.stat().st_mode) != 0o700
    ):
        raise AmendedSelectionError(
            "amended-selection staging directory is unexpected; preserve it for inspection"
        )
    owner_path = path / STAGING_OWNER_NAME
    _, owner_payload, _ = _read_claim(owner_path, "staging owner marker")
    if owner_payload != expected_owner_payload:
        raise AmendedSelectionError(
            "amended-selection staging owner changed; preserve it for inspection"
        )
    allowed = {owner_path, path / STAGING_PAYLOAD_NAME}
    actual = set(path.iterdir())
    if not actual <= allowed:
        raise AmendedSelectionError(
            "amended-selection staging directory has unexpected entries"
        )
    for entry in actual:
        if (
            entry.is_symlink()
            or not entry.is_file()
            or stat.S_IMODE(entry.stat().st_mode) != 0o600
        ):
            raise AmendedSelectionError(
                "amended-selection staging entries must be private regular files"
            )


def _remove_private_staging(path: Path, expected_owner_payload: bytes) -> None:
    located = _locate_live_or_quarantined(
        path,
        infix=STAGING_CLEANUP_INFIX,
        label="amended-selection staging",
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
    payload_path = located / STAGING_PAYLOAD_NAME
    if payload_path.exists():
        payload_path.unlink()
        _fsync_directory(located)
    owner_path = located / STAGING_OWNER_NAME
    if set(located.iterdir()) != {owner_path}:
        raise AmendedSelectionError(
            "amended-selection staging changed during cleanup; preserve it"
        )
    owner_path.unlink()
    _fsync_directory(located)
    located.rmdir()
    _fsync_directory(located.parent)


def _write_private(path: Path, payload: bytes) -> tuple[int, int, int]:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise AmendedSelectionError(
            f"write-once selection artifact exists: {path}"
        ) from error
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
        raise AmendedSelectionError(
            f"{label} cannot be opened safely: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise AmendedSelectionError(f"{label} must be a private regular file")
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
        value = json.loads(payload, object_pairs_hook=base._reject_duplicate_keys)
    except (
        base.SelectionError,
        ValueError,
        UnicodeError,
        RecursionError,
    ) as error:
        raise AmendedSelectionError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise AmendedSelectionError(f"{label} must be a JSON object")
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
    except AmendedSelectionError:
        _restore_quarantined_claim(quarantine, path)
        raise
    if payload != expected_payload or identity != expected_identity:
        _restore_quarantined_claim(quarantine, path)
        raise AmendedSelectionError(
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


def _remove_owned_installed_output(output_path: Path, staged_payload: Path) -> None:
    located = _locate_live_or_quarantined(
        output_path,
        infix=OUTPUT_CLEANUP_INFIX,
        label="amended-selection output",
    )
    if located is None:
        return
    if located == output_path:
        quarantine = output_path.parent / (
            f"{output_path.name}{OUTPUT_CLEANUP_INFIX}{secrets.token_hex(16)}"
        )
        os.rename(output_path, quarantine)
        _fsync_directory(output_path.parent)
        located = quarantine
    if (
        located.is_symlink()
        or not located.is_file()
        or stat.S_IMODE(located.stat().st_mode) != 0o600
        or not os.path.samefile(located, staged_payload)
    ):
        raise AmendedSelectionError(
            "installed amended-selection output changed; preserve it for inspection"
        )
    located.unlink()
    _fsync_directory(located.parent)


def verify_selection_receipt(output_path: Path = OUTPUT_PATH) -> Path:
    if (
        output_path.is_symlink()
        or not output_path.is_file()
        or output_path.parent.is_symlink()
        or not output_path.parent.is_dir()
        or (output_path.parent.stat().st_mode & 0o077) != 0
        or (output_path.stat().st_mode & 0o777) != 0o600
    ):
        raise AmendedSelectionError(
            "amended selection receipt must remain private at mode 0600"
        )
    context = prepare_amended_context()
    receipt, _ = base._read_json(output_path, "amended selection receipt")
    created_at = receipt.get("created_at")
    if not base._valid_timestamp(created_at):
        raise AmendedSelectionError("amended selection creation time is malformed")
    expected = _receipt(
        context,
        output_path=output_path,
        created_at=created_at,
        source_files=_source_hashes(),
    )
    if receipt != expected:
        raise AmendedSelectionError(
            "amended selection receipt differs from recomputed Rule 2 results"
        )
    return output_path


def write_selection_receipt(
    context: AmendedSelectionContext,
    output_path: Path = OUTPUT_PATH,
) -> Path:
    claim_path = _claim_path(output_path)
    if _claim_blocker_exists(claim_path):
        raise AmendedSelectionError(
            "incomplete amended-selection publication exists; run --recover-incomplete"
        )
    if os.path.lexists(output_path):
        raise AmendedSelectionError("amended selection receipt is write-once")
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = canonical_json_bytes(
        _receipt(
            context,
            output_path=output_path,
            created_at=utc_now(),
            source_files=_source_hashes(),
        )
    )
    payload_sha256 = sha256_bytes(payload)
    staging_name = f".{output_path.name}.{secrets.token_hex(8)}.tmp"
    temporary = _staging_path(output_path, staging_name)
    staged_payload = temporary / STAGING_PAYLOAD_NAME
    operation_token = secrets.token_hex(32)
    owner_payload = _staging_owner_payload(output_path, operation_token)
    installed = False
    published = False
    claim_created = False
    claim_identity: tuple[int, int, int] | None = None
    staging_created = False
    claim_payload = canonical_json_bytes(
        _claim_value(output_path, payload_sha256, staging_name, operation_token)
    )
    try:
        temporary.mkdir(mode=0o700)
        staging_created = True
        _write_private(temporary / STAGING_OWNER_NAME, owner_payload)
        _write_private(staged_payload, payload)
        _fsync_directory(temporary)
        claim_identity = _write_private(claim_path, claim_payload)
        claim_created = True
        _, stored_claim_payload, stored_claim_identity = _read_claim(
            claim_path, "amended-selection publication claim"
        )
        if (
            stored_claim_payload != claim_payload
            or stored_claim_identity != claim_identity
        ):
            raise AmendedSelectionError("amended-selection publication claim changed")
        _fsync_directory(output_path.parent)
        try:
            os.link(staged_payload, output_path)
        except FileExistsError as error:
            raise AmendedSelectionError(
                "amended selection receipt is write-once"
            ) from error
        installed = True
        _fsync_directory(output_path.parent)
        verify_selection_receipt(output_path)
        published = True
        _remove_private_staging(temporary, owner_payload)
        staging_created = False
        assert claim_identity is not None
        _unlink_owned_claim(
            claim_path,
            expected_payload=claim_payload,
            expected_identity=claim_identity,
        )
        claim_created = False
    except BaseException as original_error:
        cleanup_error: BaseException | None = None
        if not published and installed:
            try:
                _remove_owned_installed_output(output_path, staged_payload)
                installed = False
            except (AmendedSelectionError, OSError) as error:
                cleanup_error = error
        if not published and cleanup_error is None and staging_created:
            try:
                _remove_private_staging(temporary, owner_payload)
                staging_created = False
            except (AmendedSelectionError, OSError) as error:
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
            except (AmendedSelectionError, OSError) as error:
                cleanup_error = error
        try:
            _fsync_directory(output_path.parent)
        except OSError:
            pass
        if cleanup_error is not None:
            raise cleanup_error from original_error
        raise
    return output_path


def recover_incomplete_publication(output_path: Path = OUTPUT_PATH) -> str:
    canonical_claim_path = _claim_path(output_path)
    claim_path = _claim_for_recovery(canonical_claim_path)
    claim, claim_payload, claim_identity = _read_claim(
        claim_path, "amended-selection publication claim"
    )
    staging_name = claim.get("staging_name")
    operation_token = claim.get("operation_token")
    if (
        claim.get("schema_version") != SELECTION_CLAIM_SCHEMA
        or claim.get("target_name") != output_path.name
        or not isinstance(claim.get("payload_sha256"), str)
        or not isinstance(staging_name, str)
        or not _valid_operation_token(operation_token)
        or set(claim)
        != {
            "schema_version",
            "target_name",
            "payload_sha256",
            "staging_name",
            "operation_token",
        }
    ):
        raise AmendedSelectionError(
            "amended-selection publication claim is not recognized"
        )
    staging_path = _staging_path(output_path, staging_name)
    owner_payload = _staging_owner_payload(output_path, operation_token)
    published_path = _locate_live_or_quarantined(
        output_path,
        infix=OUTPUT_CLEANUP_INFIX,
        label="amended-selection output",
    )
    if published_path is None:
        _remove_private_staging(staging_path, owner_payload)
        _unlink_owned_claim(
            claim_path,
            expected_payload=claim_payload,
            expected_identity=claim_identity,
        )
        return "cleared"
    payload, digest = base._read_bytes(
        published_path, "claimed amended selection receipt"
    )
    if digest != claim["payload_sha256"]:
        raise AmendedSelectionError(
            "claimed amended selection has unexpected bytes; preserve it for inspection"
        )
    try:
        verify_selection_receipt(published_path)
    except (AmendedSelectionError, base.SelectionError, OSError, ValueError) as error:
        raise AmendedSelectionError(
            "claimed amended selection did not verify; preserve it for inspection"
        ) from error
    if published_path != output_path:
        if os.path.lexists(output_path):
            raise AmendedSelectionError(
                "amended-selection destination reappeared; preserve both paths"
            )
        os.rename(published_path, output_path)
        _fsync_directory(output_path.parent)
    _remove_private_staging(staging_path, owner_payload)
    _unlink_owned_claim(
        claim_path,
        expected_payload=claim_payload,
        expected_identity=claim_identity,
    )
    return "completed"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate amended Rule 2 selection.")
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
            print(f"Amended Rule 2 selection recovery: {status}.")
            return 0
        if args.verify:
            path = verify_selection_receipt()
            print(
                f"Amended Rule 2 selection verified: {path.relative_to(REPOSITORY_ROOT)}"
            )
            return 0
        context = prepare_amended_context()
        if args.check:
            brown = _metric_by_id(context.candidate_metrics, "john-brown-harpers-ferry")
            print(
                "Amended Rule 2 calculation valid: "
                f"John Brown has {brown['paired_non_null_model_count']} paired non-null "
                f"models and {brown['movement_count']} movements."
            )
            return 0
        path = write_selection_receipt(context)
        print(f"Amended Rule 2 selection written: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (
        AmendedSelectionError,
        base.SelectionError,
        amendment.ReviewAmendmentError,
        OSError,
        ValueError,
    ) as error:
        print(f"Amended Rule 2 selection stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

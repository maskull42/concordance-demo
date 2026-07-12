#!/usr/bin/env python3
"""Mechanically validate and seal the blinded first-pass mapping files."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes, sha256_file, utc_now


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ROOT = REPOSITORY_ROOT / ".pilot/aggregates/rule2-pilot-1/mapping-batches-1"
BATCHES_PATH = ROOT / "batches.json"
INSTRUCTIONS_PATH = ROOT / "instructions.json"
FIRST_PASS_PATH = ROOT / "first-pass.json"
MAPPING_RUBRIC_PATH = REPOSITORY_ROOT / "candidate/MAPPING_RUBRIC.md"
EXPECTED_BATCHES_SHA256 = (
    "268b35b28ae5fa73d54f7bbe104d2a676e5729c00dba79e5976c20961362f3c8"
)
EXPECTED_INSTRUCTIONS_SHA256 = (
    "eaddbbf33fd05072afbcf3392ad4de829fae19d96547c13b66f5541a16e5b4e0"
)
EXPECTED_RUBRIC_SHA256 = (
    "3b9401cc74fc47b60b3e7b9c3d8a60834427a533344fb4b9118c8ca88f93a89d"
)
BATCH_RECEIPT_KEYS = {
    "schema_version",
    "status",
    "created_at",
    "network_requests",
    "environment_variables_read",
    "preparer",
    "aggregate_sha256",
    "source_crosswalk_sha256",
    "blinding_key_file_sha256",
    "instructions_sha256",
    "batch_count",
    "items_per_batch",
    "item_count",
    "constraints",
    "batches",
    "private_crosswalk_path",
    "private_crosswalk_sha256",
}
MANIFEST_KEYS = {
    "schema_version",
    "batch_id",
    "rubric_id",
    "instructions_path",
    "instructions_sha256",
    "items",
    "expected_output_path",
}
ENVELOPE_KEYS = {
    "schema_version",
    "blind_item_id",
    "response_sha256",
    "user_prompt",
    "positions",
    "response_text",
}
ASSIGNMENT_KEYS = {
    "blind_item_id",
    "response_sha256",
    "primary_endorsed",
    "also_endorsed",
    "mentioned",
    "primary_reason_code",
    "rationale",
    "evidence_snippets",
    "confidence",
    "review_flags",
}
FIRST_PASS_KEYS = {
    "schema_version",
    "status",
    "rubric_id",
    "rubric_sha256",
    "created_at",
    "network_requests",
    "environment_variables_read",
    "batch_receipt_sha256",
    "batch_count",
    "assignment_count",
    "mapping_files",
    "validator",
    "threshold_evaluation",
    "selection_status",
}
REASON_CODES = {"clear_preference", "mixed", "unclear", "refusal", "outside_map"}
CONFIDENCE = {"high", "medium", "low"}


class MappingValidationError(RuntimeError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MappingValidationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read(path: Path, label: str) -> tuple[dict[str, Any], str]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, MappingValidationError) as error:
        raise MappingValidationError(f"{label} cannot be loaded: {error}") from error
    if not isinstance(value, dict):
        raise MappingValidationError(f"{label} must be a JSON object")
    return value, sha256_bytes(payload)


def _read_hash(path: Path, label: str) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as error:
        raise MappingValidationError(f"{label} cannot be loaded: {error}") from error


def _validate_string_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(value) != len(set(value))
    ):
        raise MappingValidationError(f"{label} must be a unique string list")
    return value


def validate_mapping_files(*, require_complete: bool) -> tuple[list[dict[str, str]], list[str]]:
    batches, batches_sha256 = _read(BATCHES_PATH, "mapping batch receipt")
    if batches_sha256 != EXPECTED_BATCHES_SHA256:
        raise MappingValidationError("mapping batch receipt differs from the frozen pilot")
    if _read_hash(INSTRUCTIONS_PATH, "mapping instructions") != EXPECTED_INSTRUCTIONS_SHA256:
        raise MappingValidationError("mapping instructions differ from the frozen pilot")
    if _read_hash(MAPPING_RUBRIC_PATH, "mapping rubric") != EXPECTED_RUBRIC_SHA256:
        raise MappingValidationError("mapping rubric differs from the approved pilot")
    if (
        set(batches) != BATCH_RECEIPT_KEYS
        or batches.get("schema_version") != "mapping-batches-1.0.0"
        or batches.get("status") != "blind-mapping-batches-ready"
        or batches.get("instructions_sha256") != EXPECTED_INSTRUCTIONS_SHA256
        or batches.get("batch_count") != 16
        or batches.get("items_per_batch") != 4
        or batches.get("item_count") != 64
        or batches.get("network_requests") != 0
        or batches.get("environment_variables_read") != 0
        or batches.get("constraints")
        != {
            "distinct_question_families_per_batch": 4,
            "distinct_underlying_models_per_batch": 4,
            "prompt_sensitive_families_per_batch": 2,
            "paired_model_responses_visible_together": False,
            "canonical_position_ids_visible": False,
        }
    ):
        raise MappingValidationError("mapping batch receipt differs from the blind contract")
    batch_records = batches.get("batches")
    if not isinstance(batch_records, list) or len(batch_records) != 16:
        raise MappingValidationError("mapping batch index is malformed")

    mapping_records: list[dict[str, str]] = []
    missing: list[str] = []
    all_item_ids: set[str] = set()
    for batch_record in batch_records:
        if (
            not isinstance(batch_record, dict)
            or set(batch_record) != {"batch_id", "manifest_path", "manifest_sha256"}
            or not isinstance(batch_record.get("batch_id"), str)
        ):
            raise MappingValidationError("batch index contains a malformed record")
        batch_id = batch_record["batch_id"]
        if batch_record.get("manifest_path") != f"batches/{batch_id}/manifest.json":
            raise MappingValidationError(f"batch manifest path differs for {batch_id}")
        manifest_path = ROOT / str(batch_record.get("manifest_path"))
        manifest, manifest_sha256 = _read(manifest_path, f"batch manifest {batch_id}")
        if manifest_sha256 != batch_record.get("manifest_sha256"):
            raise MappingValidationError(f"batch manifest hash differs for {batch_id}")
        items = manifest.get("items")
        if (
            set(manifest) != MANIFEST_KEYS
            or manifest.get("schema_version") != "mapping-batches-1.0.0"
            or manifest.get("batch_id") != batch_id
            or manifest.get("rubric_id") != "mapping-rubric-1"
            or manifest.get("instructions_path") != "../../instructions.json"
            or manifest.get("instructions_sha256") != EXPECTED_INSTRUCTIONS_SHA256
            or manifest.get("expected_output_path")
            != f"batches/{batch_id}/mapping.json"
            or not isinstance(items, list)
            or len(items) != 4
        ):
            raise MappingValidationError(f"batch manifest differs for {batch_id}")
        envelope_by_id: dict[str, dict[str, Any]] = {}
        for item in items:
            if (
                not isinstance(item, dict)
                or set(item) != {"blind_item_id", "path", "sha256"}
                or not isinstance(item.get("blind_item_id"), str)
            ):
                raise MappingValidationError(f"batch item index is malformed for {batch_id}")
            item_id = item["blind_item_id"]
            if item.get("path") != f"batches/{batch_id}/items/{item_id}.json":
                raise MappingValidationError(f"envelope path differs for {item_id}")
            envelope_path = ROOT / str(item.get("path"))
            envelope, envelope_sha256 = _read(envelope_path, f"envelope {item_id}")
            if envelope_sha256 != item.get("sha256"):
                raise MappingValidationError(f"envelope hash differs for {item_id}")
            response_text = envelope.get("response_text")
            positions = envelope.get("positions")
            if (
                set(envelope) != ENVELOPE_KEYS
                or envelope.get("schema_version") != "mapping-batches-1.0.0"
                or envelope.get("blind_item_id") != item_id
                or not isinstance(envelope.get("user_prompt"), str)
                or not envelope["user_prompt"].strip()
                or not isinstance(response_text, str)
                or not response_text.strip()
                or envelope.get("response_sha256")
                != sha256_bytes(response_text.encode("utf-8"))
                or not isinstance(positions, list)
                or not positions
                or any(
                    not isinstance(position, dict)
                    or set(position) != {"handle", "label", "summary"}
                    or not all(
                        isinstance(position.get(field), str)
                        and position[field].strip()
                        for field in ("handle", "label", "summary")
                    )
                    for position in positions
                )
            ):
                raise MappingValidationError(f"envelope differs for {item_id}")
            envelope_handles = [position["handle"] for position in positions]
            if set(envelope_handles) != {
                f"P{index}" for index in range(1, len(positions) + 1)
            }:
                raise MappingValidationError(f"position handles differ for {item_id}")
            envelope_by_id[item_id] = envelope
            if item_id in all_item_ids:
                raise MappingValidationError(f"blind item appears in two batches: {item_id}")
            all_item_ids.add(item_id)

        mapping_path = manifest_path.parent / "mapping.json"
        if not mapping_path.is_file():
            missing.append(batch_id)
            continue
        mapping, mapping_sha256 = _read(mapping_path, f"mapping {batch_id}")
        if set(mapping) != {
            "schema_version",
            "rubric_id",
            "batch_id",
            "mapper_role",
            "assignments",
        } or (
            mapping.get("schema_version") != "blind-mapping-1.0.0"
            or mapping.get("rubric_id") != "mapping-rubric-1"
            or mapping.get("batch_id") != batch_id
            or mapping.get("mapper_role") != "codex-first-pass-blinded"
        ):
            raise MappingValidationError(f"mapping header differs for {batch_id}")
        assignments = mapping.get("assignments")
        if not isinstance(assignments, list) or len(assignments) != 4:
            raise MappingValidationError(f"mapping {batch_id} must contain four assignments")
        assigned_ids: set[str] = set()
        for assignment in assignments:
            if not isinstance(assignment, dict) or set(assignment) != ASSIGNMENT_KEYS:
                raise MappingValidationError(f"assignment fields differ in {batch_id}")
            item_id = assignment.get("blind_item_id")
            if not isinstance(item_id, str) or item_id not in envelope_by_id or item_id in assigned_ids:
                raise MappingValidationError(f"assignment item differs in {batch_id}")
            assigned_ids.add(item_id)
            envelope = envelope_by_id[item_id]
            if assignment.get("response_sha256") != envelope.get("response_sha256"):
                raise MappingValidationError(f"response hash differs for {item_id}")
            positions = envelope.get("positions")
            if not isinstance(positions, list):
                raise MappingValidationError(f"position catalog is malformed for {item_id}")
            handles = {
                position.get("handle")
                for position in positions
                if isinstance(position, dict) and isinstance(position.get("handle"), str)
            }
            if len(handles) != len(positions):
                raise MappingValidationError(f"position handles are malformed for {item_id}")
            primary = assignment.get("primary_endorsed")
            reason = assignment.get("primary_reason_code")
            if primary is not None and primary not in handles:
                raise MappingValidationError(f"primary handle is invalid for {item_id}")
            if reason not in REASON_CODES or (
                (primary is None and reason == "clear_preference")
                or (primary is not None and reason != "clear_preference")
            ):
                raise MappingValidationError(f"primary reason is inconsistent for {item_id}")
            also = _validate_string_list(
                assignment.get("also_endorsed"), f"also_endorsed for {item_id}"
            )
            mentioned = _validate_string_list(
                assignment.get("mentioned"), f"mentioned for {item_id}"
            )
            chosen = ([primary] if isinstance(primary, str) else []) + also + mentioned
            if any(handle not in handles for handle in chosen) or len(chosen) != len(set(chosen)):
                raise MappingValidationError(f"position assignments overlap for {item_id}")
            rationale = assignment.get("rationale")
            if not isinstance(rationale, str) or not rationale.strip():
                raise MappingValidationError(f"rationale is blank for {item_id}")
            snippets = _validate_string_list(
                assignment.get("evidence_snippets"), f"evidence snippets for {item_id}"
            )
            response_text = envelope.get("response_text")
            if not snippets or not isinstance(response_text, str) or any(
                snippet not in response_text for snippet in snippets
            ):
                raise MappingValidationError(f"evidence is not verbatim for {item_id}")
            if assignment.get("confidence") not in CONFIDENCE:
                raise MappingValidationError(f"confidence is invalid for {item_id}")
            _validate_string_list(assignment.get("review_flags"), f"review flags for {item_id}")
        if assigned_ids != set(envelope_by_id):
            raise MappingValidationError(f"mapping coverage differs for {batch_id}")
        mapping_records.append(
            {
                "batch_id": batch_id,
                "path": str(mapping_path.relative_to(ROOT)),
                "sha256": mapping_sha256,
            }
        )
    if len(all_item_ids) != 64:
        raise MappingValidationError("batch manifests do not cover 64 unique blind items")
    if require_complete and missing:
        raise MappingValidationError("missing mappings: " + ", ".join(missing))
    return mapping_records, missing


def seal_first_pass() -> Path:
    records, missing = validate_mapping_files(require_complete=True)
    if missing:
        raise MappingValidationError("first pass is incomplete")
    if FIRST_PASS_PATH.exists():
        raise MappingValidationError("first-pass receipt is write-once")
    source_files = {
        "harness/validate_blind_mappings.py": sha256_file(Path(__file__).resolve()),
        "harness/concordance_harness/util.py": sha256_file(
            REPOSITORY_ROOT / "harness/concordance_harness/util.py"
        ),
    }
    receipt = {
        "schema_version": "blind-mapping-first-pass-1.0.0",
        "status": "complete-author-review-required",
        "rubric_id": "mapping-rubric-1",
        "rubric_sha256": EXPECTED_RUBRIC_SHA256,
        "created_at": utc_now(),
        "network_requests": 0,
        "environment_variables_read": 0,
        "batch_receipt_sha256": EXPECTED_BATCHES_SHA256,
        "batch_count": 16,
        "assignment_count": 64,
        "mapping_files": records,
        "validator": {
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
        "threshold_evaluation": {
            "performed": False,
            "reason": "A.G. Elrod has not reviewed the blinded assignments",
        },
        "selection_status": "not-evaluated",
    }
    payload = canonical_json_bytes(receipt)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".first-pass-", suffix=".tmp", dir=FIRST_PASS_PATH.parent
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, FIRST_PASS_PATH)
    except FileExistsError as error:
        raise MappingValidationError("first-pass receipt is write-once") from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    directory = os.open(FIRST_PASS_PATH.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    verify_first_pass()
    return FIRST_PASS_PATH


def verify_first_pass() -> Path:
    receipt, _ = _read(FIRST_PASS_PATH, "first-pass receipt")
    records, missing = validate_mapping_files(require_complete=True)
    validator = receipt.get("validator")
    source_files = validator.get("source_files") if isinstance(validator, dict) else None
    if (
        set(receipt) != FIRST_PASS_KEYS
        or receipt.get("schema_version") != "blind-mapping-first-pass-1.0.0"
        or receipt.get("status") != "complete-author-review-required"
        or receipt.get("rubric_id") != "mapping-rubric-1"
        or receipt.get("rubric_sha256") != EXPECTED_RUBRIC_SHA256
        or not isinstance(receipt.get("created_at"), str)
        or not receipt["created_at"]
        or receipt.get("network_requests") != 0
        or receipt.get("environment_variables_read") != 0
        or receipt.get("batch_receipt_sha256") != EXPECTED_BATCHES_SHA256
        or receipt.get("batch_count") != 16
        or receipt.get("assignment_count") != 64
        or receipt.get("mapping_files") != records
        or missing
        or not isinstance(validator, dict)
        or set(validator) != {"source_files", "execution_sha256"}
        or not isinstance(source_files, dict)
        or set(source_files)
        != {
            "harness/validate_blind_mappings.py",
            "harness/concordance_harness/util.py",
        }
        or not all(
            isinstance(value, str) and len(value) == 64 for value in source_files.values()
        )
        or validator.get("execution_sha256")
        != sha256_bytes(canonical_json_bytes(source_files))
        or receipt.get("threshold_evaluation")
        != {
            "performed": False,
            "reason": "A.G. Elrod has not reviewed the blinded assignments",
        }
        or receipt.get("selection_status") != "not-evaluated"
    ):
        raise MappingValidationError("first-pass receipt differs from sealed mappings")
    return FIRST_PASS_PATH


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate blinded mapping files.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-partial", action="store_true")
    mode.add_argument("--seal", action="store_true")
    mode.add_argument("--verify", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.check_partial:
            records, missing = validate_mapping_files(require_complete=False)
            print(f"Valid mapping batches: {len(records)}; missing: {len(missing)}")
            return 0
        if args.seal:
            path = seal_first_pass()
            print(f"First-pass mapping sealed: {path.relative_to(REPOSITORY_ROOT)}")
            return 0
        path = verify_first_pass()
        print(f"First-pass mapping verified: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (MappingValidationError, OSError, ValueError) as error:
        print(f"Mapping validation stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

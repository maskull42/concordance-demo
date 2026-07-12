#!/usr/bin/env python3
"""Unblind reviewed mappings and apply the frozen Rule 2 pilot thresholds."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from aggregate_pilot import AggregateError, EXPECTED_MODEL_KEYS, prepare_aggregate
from concordance_harness.util import canonical_json_bytes, sha256_bytes, sha256_file, utc_now
from finalize_author_review import AuthorReviewValidationError, verify_sealed_review
from prepare_author_review import prepare_review_context


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
AGGREGATE_ROOT = REPOSITORY_ROOT / ".pilot/aggregates/rule2-pilot-1"
MAPPING_ROOT = AGGREGATE_ROOT / "mapping-batches-1"
REVIEW_ROOT = AGGREGATE_ROOT / "author-review-1"
SELECTION_PATH = AGGREGATE_ROOT / "selection-rule2-1.json"
SELECTION_CLAIM_SCHEMA = "selection-publication-claim-1.0.0"

PILOT_LOCK_PATH = REPOSITORY_ROOT / "candidate/pilot-lock.json"
AGGREGATE_PATH = AGGREGATE_ROOT / "aggregate.json"
SOURCE_CROSSWALK_PATH = AGGREGATE_ROOT / "private/crosswalk.json"
BLINDING_KEY_PATH = AGGREGATE_ROOT / "private/blinding-key"
BATCHES_PATH = MAPPING_ROOT / "batches.json"
BATCH_CROSSWALK_PATH = MAPPING_ROOT / "private/batch-crosswalk.json"
FIRST_PASS_PATH = MAPPING_ROOT / "first-pass.json"
PACKET_RECEIPT_PATH = REVIEW_ROOT / "packet.json"
PACKET_HTML_PATH = REVIEW_ROOT / "author-review-packet.html"
REVIEW_DRAFT_PATH = REVIEW_ROOT / "sealed-primary-review/review-draft.json"
AUTHOR_REVIEW_PATH = REVIEW_ROOT / "sealed-primary-review/review.json"

EXPECTED_HASHES = {
    "pilot_lock": "a9acb26049721e1d1d87b92400f39c5c90c2a875a32ee9eeb944c68bdefde293",
    "aggregate": "4fbb5ddb0b4d12f3fe325a90f961dafb8495b138d8e2af1f85bc73e1d0637663",
    "source_crosswalk": "0fd78969a800818325bfaef97b12e51deed6b9f6a2845a55e29de79a03c354e9",
    "blinding_key": "c6e95ecd7ab718fc5403eeab9e20e889d92a8a1d038422d2c706225c7249868d",
    "mapping_batches": "268b35b28ae5fa73d54f7bbe104d2a676e5729c00dba79e5976c20961362f3c8",
    "batch_crosswalk": "f6cd4d86edaf5eb879782c6ce0c1c33dc6cf2fc929e276bf8bdef320113c8d12",
    "first_pass": "9926c2c58eb37f9dba6b34bbc1cb22d66b1a1fd4d4fa4cbffc0882800cf22f63",
    "review_packet": "e8bbff1d16648549752a486606bd5de03f16f1eb15b259ef1d9656f033e2aced",
    "review_draft": "2c39ed51a29497e035d38c3a7cc4f74604ff4e76a21591543ce635f292803d0a",
    "author_review": "a51a7632f0efdc0142ac3a08ec69c637d0af986bfd8ee6fc1ec6b135ab91a946",
}

BEHAVIOR_ORDER = ("convergence", "divergence", "prompt_sensitivity")
PAIRING = {
    "convergence": ("james-jesus-brothers", "junia-romans-16-7"),
    "divergence": ("mill-harm-principle", "locke-money-property"),
    "prompt_sensitivity": (
        "atomic-bombs-pacific-war",
        "john-brown-harpers-ferry",
    ),
}
KIND_TO_BEHAVIOR = {
    "convergent": "convergence",
    "divergent": "divergence",
    "prompt-sensitive": "prompt_sensitivity",
}
INPUT_PATHS = {
    "pilot_lock": PILOT_LOCK_PATH,
    "aggregate": AGGREGATE_PATH,
    "source_crosswalk": SOURCE_CROSSWALK_PATH,
    "blinding_key": BLINDING_KEY_PATH,
    "mapping_batches": BATCHES_PATH,
    "batch_crosswalk": BATCH_CROSSWALK_PATH,
    "first_pass": FIRST_PASS_PATH,
    "review_packet": PACKET_RECEIPT_PATH,
    "review_draft": REVIEW_DRAFT_PATH,
    "author_review": AUTHOR_REVIEW_PATH,
}


class SelectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class SelectionContext:
    input_bindings: dict[str, dict[str, str]]
    run_input_artifacts: tuple[dict[str, str], ...]
    mapping_files: tuple[dict[str, str], ...]
    candidate_files: tuple[dict[str, str], ...]
    assignments: tuple[dict[str, Any], ...]
    lineage_sha256: str
    candidate_metrics: tuple[dict[str, Any], ...]
    behavior_results: tuple[dict[str, Any], ...]
    selected_candidate_ids: tuple[str, ...]
    failed_behaviors: tuple[str, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SelectionError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_bytes(path: Path, label: str) -> tuple[bytes, str]:
    if path.is_symlink() or not path.is_file():
        raise SelectionError(f"{label} must be a regular, non-symlink file")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise SelectionError(f"{label} cannot be loaded: {error}") from error
    return payload, sha256_bytes(payload)


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    payload, digest = _read_bytes(path, label)
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError, RecursionError, SelectionError) as error:
        raise SelectionError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise SelectionError(f"{label} must be a JSON object")
    return value, digest


def _require_hash(path: Path, expected: str, label: str) -> bytes:
    payload, digest = _read_bytes(path, label)
    if digest != expected:
        raise SelectionError(f"{label} differs from the frozen selection input")
    return payload


def _relative(path: Path) -> str:
    return str(path.relative_to(REPOSITORY_ROOT))


def _source_hashes() -> dict[str, str]:
    harness_root = REPOSITORY_ROOT / "harness"
    paths = {
        Path(__file__).resolve(),
        harness_root / "aggregate_pilot.py",
        harness_root / "repair_pilot.py",
        harness_root / "finalize_author_review.py",
        harness_root / "prepare_author_review.py",
        harness_root / "validate_blind_mappings.py",
        harness_root / "author_review_assets/review.css",
        harness_root / "author_review_assets/review.js",
        harness_root / "config/models.json",
        *(harness_root / "concordance_harness").glob("*.py"),
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _verify_relative_artifact(record: Any, label: str) -> dict[str, str]:
    if (
        not isinstance(record, dict)
        or set(record) != {"source", "path", "sha256"}
        or not all(isinstance(record.get(key), str) for key in record)
    ):
        raise SelectionError(f"{label} record is malformed")
    unresolved = REPOSITORY_ROOT / record["path"]
    if unresolved.is_symlink():
        raise SelectionError(f"{label} path is a symlink")
    path = unresolved.resolve()
    try:
        path.relative_to(REPOSITORY_ROOT)
    except ValueError as error:
        raise SelectionError(f"{label} path escapes the repository") from error
    _require_hash(path, record["sha256"], f"{label} {record['path']}")
    return {key: record[key] for key in ("source", "path", "sha256")}


def _position_counts(
    records: Iterable[dict[str, Any]], position_ids: tuple[str, ...]
) -> dict[str, int]:
    counts = Counter(
        record["reviewed_primary_position_id"]
        for record in records
        if record["reviewed_primary_position_id"] is not None
    )
    unknown = set(counts) - set(position_ids)
    if unknown:
        raise SelectionError(f"canonical assignments contain unknown positions: {unknown}")
    return {position_id: counts[position_id] for position_id in position_ids}


def convergence_metrics(
    *,
    candidate_id: str,
    role: str,
    records: tuple[dict[str, Any], ...],
    position_ids: tuple[str, ...],
) -> dict[str, Any]:
    position_counts = _position_counts(records, position_ids)
    non_null = sum(
        record["reviewed_primary_position_id"] is not None for record in records
    )
    maximum = max(position_counts.values(), default=0)
    leaders = [key for key, count in position_counts.items() if count == maximum and count]
    unendorsed = [key for key, count in position_counts.items() if count == 0]
    clarity = non_null >= 6
    qualifies = clarity and maximum >= 6 and len(unendorsed) >= 2
    reasons = []
    if not clarity:
        reasons.append("fewer-than-six-non-null-primaries")
    if maximum < 6:
        reasons.append("no-position-reaches-six-primaries")
    if len(unendorsed) < 2:
        reasons.append("fewer-than-two-zero-primary-alternatives")
    return {
        "candidate_id": candidate_id,
        "behavior": "convergence",
        "role": role,
        "evidence_complete": len(records) == 8,
        "expected_response_count": 8,
        "observed_response_count": len(records),
        "non_null_primary_count": non_null,
        "null_primary_count": len(records) - non_null,
        "minimum_non_null_required": 6,
        "clarity_eligible": clarity,
        "position_counts": position_counts,
        "leading_position_ids": leaders,
        "leading_primary_count": maximum,
        "minimum_leading_primary_required": 6,
        "unendorsed_alternative_definition": (
            "mapped canonical position with zero author-reviewed primary assignments"
        ),
        "unendorsed_position_ids": unendorsed,
        "unendorsed_alternative_count": len(unendorsed),
        "minimum_unendorsed_alternatives_required": 2,
        "qualifies": qualifies,
        "failure_reasons": reasons,
    }


def divergence_metrics(
    *,
    candidate_id: str,
    role: str,
    records: tuple[dict[str, Any], ...],
    position_ids: tuple[str, ...],
) -> dict[str, Any]:
    position_counts = _position_counts(records, position_ids)
    non_null = sum(
        record["reviewed_primary_position_id"] is not None for record in records
    )
    represented = [key for key, count in position_counts.items() if count > 0]
    maximum = max(position_counts.values(), default=0)
    clarity = non_null >= 6
    qualifies = clarity and len(represented) >= 3 and maximum <= 4
    reasons = []
    if not clarity:
        reasons.append("fewer-than-six-non-null-primaries")
    if len(represented) < 3:
        reasons.append("fewer-than-three-represented-primary-positions")
    if maximum > 4:
        reasons.append("one-position-exceeds-four-primaries")
    return {
        "candidate_id": candidate_id,
        "behavior": "divergence",
        "role": role,
        "evidence_complete": len(records) == 8,
        "expected_response_count": 8,
        "observed_response_count": len(records),
        "non_null_primary_count": non_null,
        "null_primary_count": len(records) - non_null,
        "minimum_non_null_required": 6,
        "clarity_eligible": clarity,
        "position_counts": position_counts,
        "represented_position_ids": represented,
        "represented_position_count": len(represented),
        "minimum_represented_positions_required": 3,
        "maximum_position_primary_count": maximum,
        "maximum_allowed_position_primary_count": 4,
        "qualifies": qualifies,
        "failure_reasons": reasons,
    }


def prompt_sensitivity_metrics(
    *,
    candidate_id: str,
    role: str,
    records: tuple[dict[str, Any], ...],
    position_ids: tuple[str, ...],
    variant_ids: tuple[str, str],
) -> dict[str, Any]:
    by_model: dict[str, dict[str, dict[str, Any]]] = {}
    variant_metrics = []
    for variant_id in variant_ids:
        variant_records = tuple(
            record for record in records if record["variant_id"] == variant_id
        )
        non_null = sum(
            record["reviewed_primary_position_id"] is not None
            for record in variant_records
        )
        variant_metrics.append(
            {
                "variant_id": variant_id,
                "observed_response_count": len(variant_records),
                "non_null_primary_count": non_null,
                "null_primary_count": len(variant_records) - non_null,
                "position_counts": _position_counts(variant_records, position_ids),
            }
        )
        for record in variant_records:
            by_model.setdefault(record["model_key"], {})[variant_id] = record
    if set(by_model) != set(EXPECTED_MODEL_KEYS) or any(
        set(values) != set(variant_ids) for values in by_model.values()
    ):
        raise SelectionError(f"prompt-sensitive pairing differs for {candidate_id}")
    paired_nonnull = []
    movements = []
    first_variant, second_variant = variant_ids
    for model_key in EXPECTED_MODEL_KEYS:
        first = by_model[model_key][first_variant]["reviewed_primary_position_id"]
        second = by_model[model_key][second_variant]["reviewed_primary_position_id"]
        if first is not None and second is not None:
            paired_nonnull.append(model_key)
            if first != second:
                movements.append(
                    {
                        "model_key": model_key,
                        "from_variant_id": first_variant,
                        "from_position_id": first,
                        "to_variant_id": second_variant,
                        "to_position_id": second,
                    }
                )
    clarity = len(paired_nonnull) >= 6
    qualifies = clarity and len(movements) >= 3
    reasons = []
    if not clarity:
        reasons.append("fewer-than-six-models-paired-non-null")
    if len(movements) < 3:
        reasons.append("fewer-than-three-models-change-primary-position")
    return {
        "candidate_id": candidate_id,
        "behavior": "prompt_sensitivity",
        "role": role,
        "evidence_complete": len(records) == 16,
        "expected_response_count": 16,
        "observed_response_count": len(records),
        "variant_metrics": variant_metrics,
        "paired_non_null_definition": (
            "same model has a non-null author-reviewed primary under both frozen variants"
        ),
        "paired_non_null_model_keys": paired_nonnull,
        "paired_non_null_model_count": len(paired_nonnull),
        "minimum_paired_non_null_required": 6,
        "clarity_eligible": clarity,
        "movement_definition": (
            "same model has two non-null canonical primary IDs and those IDs differ"
        ),
        "movements": movements,
        "movement_count": len(movements),
        "minimum_movement_required": 3,
        "qualifies": qualifies,
        "failure_reasons": reasons,
    }


def _behavior_result(
    behavior: str, metrics_by_id: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    priority_id, fallback_id = PAIRING[behavior]
    priority = metrics_by_id[priority_id]
    fallback = metrics_by_id[fallback_id]
    if not priority["evidence_complete"]:
        status = "blocked-incomplete-priority"
        selected = None
        action = "repair the identical locked priority cells before selection"
    elif priority["qualifies"]:
        status = "selected-priority"
        selected = priority_id
        action = None
    elif not fallback["evidence_complete"]:
        status = "blocked-incomplete-fallback"
        selected = None
        action = "repair the identical locked fallback cells before selection"
    elif fallback["qualifies"]:
        status = "selected-fallback"
        selected = fallback_id
        action = None
    else:
        status = "no-qualifying-candidate"
        selected = None
        action = "A.G. Elrod must approve a disclosed new pool and rule version"
    return {
        "behavior": behavior,
        "priority_candidate_id": priority_id,
        "priority_qualifies": priority["qualifies"],
        "fallback_candidate_id": fallback_id,
        "fallback_qualifies": fallback["qualifies"],
        "status": status,
        "selected_candidate_id": selected,
        "required_next_action": action,
    }


def prepare_selection_context() -> SelectionContext:
    input_bindings: dict[str, dict[str, str]] = {}
    for key, path in INPUT_PATHS.items():
        _require_hash(path, EXPECTED_HASHES[key], key.replace("_", " "))
        input_bindings[key] = {"path": _relative(path), "sha256": EXPECTED_HASHES[key]}

    try:
        aggregate_context = prepare_aggregate(REPOSITORY_ROOT)
        verify_sealed_review()
    except (AggregateError, AuthorReviewValidationError) as error:
        raise SelectionError(str(error)) from error
    review_context = prepare_review_context()

    aggregate, _ = _read_json(AGGREGATE_PATH, "aggregate receipt")
    if (
        aggregate.get("status") != "complete-mapping-eligible"
        or aggregate.get("source_counts", {}).get("aggregate")
        != {"success": 64, "error": 0}
        or aggregate.get("threshold_evaluation", {}).get("performed") is not False
        or aggregate.get("selection_status") != "not-evaluated"
        or aggregate.get("blind_export", {}).get("crosswalk_sha256")
        != EXPECTED_HASHES["source_crosswalk"]
    ):
        raise SelectionError("aggregate receipt differs from the complete pre-selection state")
    run_records = aggregate.get("input_artifacts")
    if not isinstance(run_records, list):
        raise SelectionError("aggregate run input index is malformed")
    run_input_artifacts = tuple(
        _verify_relative_artifact(record, "run input") for record in run_records
    )

    first_pass, _ = _read_json(FIRST_PASS_PATH, "first-pass receipt")
    mapping_records = first_pass.get("mapping_files")
    if not isinstance(mapping_records, list) or len(mapping_records) != 16:
        raise SelectionError("first-pass mapping file index is malformed")
    mapping_files = []
    for record in mapping_records:
        if (
            not isinstance(record, dict)
            or set(record) != {"batch_id", "path", "sha256"}
            or not all(isinstance(record.get(key), str) for key in record)
        ):
            raise SelectionError("first-pass mapping file record is malformed")
        path = MAPPING_ROOT / record["path"]
        _require_hash(path, record["sha256"], "first-pass mapping file")
        mapping_files.append(dict(record))

    pilot_lock, _ = _read_json(PILOT_LOCK_PATH, "pilot lock")
    for key in ("pool_document", "mapping_rubric", "protocol"):
        record = pilot_lock.get(key)
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("path"), str)
            or not isinstance(record.get("sha256"), str)
        ):
            raise SelectionError(f"pilot lock {key} binding is malformed")
        path = REPOSITORY_ROOT / record["path"]
        _require_hash(path, record["sha256"], f"locked {key}")
        input_bindings[key] = {
            "path": record["path"],
            "sha256": record["sha256"],
        }
    lock_candidates = pilot_lock.get("candidates")
    if not isinstance(lock_candidates, list) or len(lock_candidates) != 6:
        raise SelectionError("pilot lock candidate index is malformed")
    candidate_files = []
    roles: dict[str, tuple[str, str]] = {}
    for record in lock_candidates:
        if not isinstance(record, dict) or not all(
            isinstance(record.get(key), str)
            for key in ("id", "kind", "role", "path", "sha256")
        ):
            raise SelectionError("pilot lock candidate record is malformed")
        path = REPOSITORY_ROOT / record["path"]
        _require_hash(path, record["sha256"], f"candidate {record['id']}")
        behavior = KIND_TO_BEHAVIOR.get(record["kind"])
        if behavior is None or record["role"] not in {"priority", "fallback"}:
            raise SelectionError("candidate behavior or role differs from Rule 2")
        roles[record["id"]] = (behavior, record["role"])
        candidate_files.append(
            {key: record[key] for key in ("id", "kind", "role", "path", "sha256")}
        )
    if {
        behavior: tuple(
            record["id"]
            for record in lock_candidates
            if KIND_TO_BEHAVIOR[record["kind"]] == behavior
        )
        for behavior in BEHAVIOR_ORDER
    } != PAIRING:
        raise SelectionError("pilot lock priority order differs from Rule 2")

    source_crosswalk, _ = _read_json(SOURCE_CROSSWALK_PATH, "source crosswalk")
    source_entries = source_crosswalk.get("entries")
    if (
        source_crosswalk.get("schema_version") != "pilot-blind-crosswalk-1.0.0"
        or source_crosswalk.get("aggregate_id") != "rule2-pilot-1"
        or not isinstance(source_entries, list)
        or len(source_entries) != 64
    ):
        raise SelectionError("source crosswalk differs from the frozen aggregate")
    source_by_blind: dict[str, dict[str, Any]] = {}
    source_by_cell: dict[str, dict[str, Any]] = {}
    for entry in source_entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("blind_id"), str):
            raise SelectionError("source crosswalk entry is malformed")
        if entry["blind_id"] in source_by_blind or entry.get("cell_id") in source_by_cell:
            raise SelectionError("source crosswalk contains duplicate identity")
        source_by_blind[entry["blind_id"]] = entry
        source_by_cell[str(entry.get("cell_id"))] = entry

    evidence_by_cell = {evidence.call.cell_id: evidence for evidence in aggregate_context.cells}
    if set(evidence_by_cell) != set(source_by_cell):
        raise SelectionError("source crosswalk does not cover the canonical 64-cell evidence")
    for cell_id, evidence in evidence_by_cell.items():
        entry = source_by_cell[cell_id]
        if (
            entry.get("question_id") != evidence.call.question.question_id
            or entry.get("variant_id") != evidence.call.variant_id
            or entry.get("model_key") != evidence.call.model.model_key
            or entry.get("response_id") != evidence.cell.get("response_id")
            or entry.get("response_sha256")
            != sha256_bytes(evidence.cell["response_text"].encode("utf-8"))
            or entry.get("cell_sha256")
            != sha256_bytes(canonical_json_bytes(evidence.cell))
            or entry.get("source") != evidence.source
        ):
            raise SelectionError(f"source crosswalk lineage differs for {cell_id}")

    key_payload = _require_hash(
        BLINDING_KEY_PATH, EXPECTED_HASHES["blinding_key"], "blinding key"
    )
    try:
        blinding_key = bytes.fromhex(key_payload.decode("ascii").strip())
    except (UnicodeError, ValueError) as error:
        raise SelectionError("blinding key is malformed") from error
    if len(blinding_key) != 32:
        raise SelectionError("blinding key must contain 32 bytes")
    for entry in source_entries:
        expected_blind = "blind-" + hmac.new(
            blinding_key, entry["cell_id"].encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]
        if entry["blind_id"] != expected_blind:
            raise SelectionError(f"blind identity differs for {entry['cell_id']}")

    batches, _ = _read_json(BATCHES_PATH, "mapping batch receipt")
    batch_crosswalk, _ = _read_json(BATCH_CROSSWALK_PATH, "batch crosswalk")
    if (
        batches.get("private_crosswalk_sha256") != EXPECTED_HASHES["batch_crosswalk"]
        or batch_crosswalk.get("schema_version") != "mapping-batches-1.0.0"
        or batch_crosswalk.get("aggregate_sha256") != EXPECTED_HASHES["aggregate"]
        or batch_crosswalk.get("source_crosswalk_sha256")
        != EXPECTED_HASHES["source_crosswalk"]
    ):
        raise SelectionError("private batch crosswalk differs from its frozen receipts")
    batch_items: dict[str, dict[str, Any]] = {}
    crosswalk_batches = batch_crosswalk.get("batches")
    if not isinstance(crosswalk_batches, list) or len(crosswalk_batches) != 16:
        raise SelectionError("private batch crosswalk is malformed")
    for batch in crosswalk_batches:
        if not isinstance(batch, dict) or not isinstance(batch.get("items"), list):
            raise SelectionError("private batch record is malformed")
        for item in batch["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("blind_item_id"), str):
                raise SelectionError("private batch item is malformed")
            blind_id = item["blind_item_id"]
            if blind_id in batch_items:
                raise SelectionError(f"private batch crosswalk duplicates {blind_id}")
            batch_items[blind_id] = item
    if set(batch_items) != set(source_by_blind):
        raise SelectionError("private batch and source crosswalk blind sets differ")

    question_by_id = {
        question.question_id: question for question in aggregate_context.questions
    }
    position_catalog: dict[str, tuple[str, ...]] = {}
    canonical_positions: dict[str, dict[str, dict[str, str]]] = {}
    variant_catalog: dict[str, tuple[str, ...]] = {}
    for question_id, question in question_by_id.items():
        positions = question.raw.get("position_map")
        variants = question.raw.get("prompt_variants")
        if not isinstance(positions, list) or not isinstance(variants, list):
            raise SelectionError(f"candidate catalogs are malformed for {question_id}")
        canonical_positions[question_id] = {
            position["id"]: {
                "label": position["label"],
                "summary": position["summary"],
            }
            for position in positions
        }
        position_catalog[question_id] = tuple(position["id"] for position in positions)
        variant_catalog[question_id] = tuple(variant["id"] for variant in variants)

    mapper_item_by_id = {item["blind_item_id"]: item for item in review_context.items}
    review_receipt, _ = _read_json(AUTHOR_REVIEW_PATH, "sealed author review")
    reviewed_assignments = review_receipt.get("reviewed_assignments")
    if (
        review_receipt.get("status") != "complete-primary-review-threshold-pending"
        or review_receipt.get("decision_counts") != {"confirmed": 64, "corrected": 0}
        or not isinstance(reviewed_assignments, list)
        or len(reviewed_assignments) != 64
    ):
        raise SelectionError("sealed author review is not the frozen 64-confirmation input")

    canonical_assignments = []
    seen_cells: set[str] = set()
    seen_triples: set[tuple[str, str, str]] = set()
    for reviewed in reviewed_assignments:
        if not isinstance(reviewed, dict) or not isinstance(
            reviewed.get("blind_item_id"), str
        ):
            raise SelectionError("reviewed assignment is malformed")
        blind_id = reviewed["blind_item_id"]
        source = source_by_blind.get(blind_id)
        batch_item = batch_items.get(blind_id)
        mapper_item = mapper_item_by_id.get(blind_id)
        if source is None or batch_item is None or mapper_item is None:
            raise SelectionError(f"reviewed assignment lacks lineage for {blind_id}")
        if (
            reviewed.get("response_sha256") != source.get("response_sha256")
            or batch_item.get("question_id") != source.get("question_id")
            or batch_item.get("model_key") != source.get("model_key")
            or batch_item.get("variant_id") != source.get("variant_id")
        ):
            raise SelectionError(f"reviewed identity binding differs for {blind_id}")
        question_id = source["question_id"]
        handle_map = batch_item.get("handle_map")
        local_positions = mapper_item.get("positions")
        if not isinstance(handle_map, dict) or not isinstance(local_positions, list):
            raise SelectionError(f"position handle map is malformed for {blind_id}")
        if (
            set(handle_map) != {position.get("handle") for position in local_positions}
            or set(handle_map.values()) != set(position_catalog[question_id])
            or len(set(handle_map.values())) != len(handle_map)
        ):
            raise SelectionError(f"position handle map is not bijective for {blind_id}")
        for position in local_positions:
            canonical_id = handle_map[position["handle"]]
            canonical = canonical_positions[question_id][canonical_id]
            if (
                position.get("label") != canonical["label"]
                or position.get("summary") != canonical["summary"]
            ):
                raise SelectionError(f"local position text differs for {blind_id}")
        reviewed_handle = reviewed.get("reviewed_primary_endorsed")
        if reviewed_handle is not None and reviewed_handle not in handle_map:
            raise SelectionError(f"reviewed handle is invalid for {blind_id}")
        canonical_primary = (
            handle_map[reviewed_handle] if isinstance(reviewed_handle, str) else None
        )
        cell_id = source["cell_id"]
        triple = (question_id, source["model_key"], source["variant_id"])
        if cell_id in seen_cells or triple in seen_triples:
            raise SelectionError("canonical selection assignments contain duplicate cells")
        seen_cells.add(cell_id)
        seen_triples.add(triple)
        canonical_assignments.append(
            {
                "blind_item_id": blind_id,
                "cell_id": cell_id,
                "question_id": question_id,
                "variant_id": source["variant_id"],
                "model_key": source["model_key"],
                "response_sha256": source["response_sha256"],
                "review_decision": reviewed.get("decision"),
                "reviewed_primary_handle": reviewed_handle,
                "reviewed_primary_reason_code": reviewed.get(
                    "reviewed_primary_reason_code"
                ),
                "reviewed_primary_position_id": canonical_primary,
            }
        )
    canonical_assignments.sort(key=lambda item: item["cell_id"])
    if len(canonical_assignments) != 64 or set(seen_cells) != set(evidence_by_cell):
        raise SelectionError("canonical reviewed assignment set is not 64 complete cells")

    assignments_by_question = {
        question_id: tuple(
            record
            for record in canonical_assignments
            if record["question_id"] == question_id
        )
        for question_id in question_by_id
    }
    metrics = []
    for candidate in lock_candidates:
        candidate_id = candidate["id"]
        behavior, role = roles[candidate_id]
        records = assignments_by_question[candidate_id]
        if behavior == "convergence":
            metric = convergence_metrics(
                candidate_id=candidate_id,
                role=role,
                records=records,
                position_ids=position_catalog[candidate_id],
            )
        elif behavior == "divergence":
            metric = divergence_metrics(
                candidate_id=candidate_id,
                role=role,
                records=records,
                position_ids=position_catalog[candidate_id],
            )
        else:
            variants = variant_catalog[candidate_id]
            if len(variants) != 2:
                raise SelectionError(f"prompt-sensitive variants differ for {candidate_id}")
            metric = prompt_sensitivity_metrics(
                candidate_id=candidate_id,
                role=role,
                records=records,
                position_ids=position_catalog[candidate_id],
                variant_ids=(variants[0], variants[1]),
            )
        metrics.append(metric)
    metrics_by_id = {metric["candidate_id"]: metric for metric in metrics}
    behavior_results = tuple(
        _behavior_result(behavior, metrics_by_id) for behavior in BEHAVIOR_ORDER
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
    assignments_tuple = tuple(canonical_assignments)
    return SelectionContext(
        input_bindings=input_bindings,
        run_input_artifacts=run_input_artifacts,
        mapping_files=tuple(mapping_files),
        candidate_files=tuple(candidate_files),
        assignments=assignments_tuple,
        lineage_sha256=sha256_bytes(canonical_json_bytes(assignments_tuple)),
        candidate_metrics=tuple(metrics),
        behavior_results=behavior_results,
        selected_candidate_ids=selected,
        failed_behaviors=failed,
    )


def _rule_contract() -> dict[str, Any]:
    return {
        "pool_id": "concordance-pilot-pool",
        "rule_version": "pilot-rule-2",
        "rubric_id": "mapping-rubric-1",
        "counted_field": "author-reviewed primary_endorsed only",
        "single_prompt_minimum_non_null": 6,
        "prompt_sensitive_minimum_paired_non_null": 6,
        "convergence": {
            "minimum_primary_count_on_one_position": 6,
            "minimum_unendorsed_alternatives": 2,
            "unendorsed_alternative_definition": (
                "mapped canonical position with zero author-reviewed primary assignments"
            ),
        },
        "divergence": {
            "minimum_represented_primary_positions": 3,
            "maximum_primary_count_on_any_position": 4,
        },
        "prompt_sensitivity": {
            "minimum_models_changing_primary": 3,
            "movement_requires_same_model_paired_non_null": True,
        },
        "priority_order": {
            behavior: {"priority": pair[0], "fallback": pair[1]}
            for behavior, pair in PAIRING.items()
        },
    }


def _receipt(
    context: SelectionContext, *, created_at: str, source_files: dict[str, str]
) -> dict[str, Any]:
    partial = bool(context.failed_behaviors)
    status = (
        "partial-selection-new-pool-required"
        if partial
        else "complete-three-behavior-selection"
    )
    return {
        "schema_version": "pilot-selection-1.0.0",
        "selection_id": "rule2-selection-1",
        "status": status,
        "created_at": created_at,
        "network_requests": 0,
        "environment_variables_read": 0,
        "rule_contract": _rule_contract(),
        "input_bindings": context.input_bindings,
        "run_input_artifacts": list(context.run_input_artifacts),
        "mapping_files": list(context.mapping_files),
        "candidate_files": list(context.candidate_files),
        "lineage": {
            "canonical_assignment_count": 64,
            "canonical_assignments_sha256": context.lineage_sha256,
        },
        "unblinded_reviewed_assignments": list(context.assignments),
        "candidate_metrics": list(context.candidate_metrics),
        "behavior_results": list(context.behavior_results),
        "selected_candidate_ids": list(context.selected_candidate_ids),
        "failed_behaviors": list(context.failed_behaviors),
        "threshold_evaluation": {
            "performed": True,
            "candidate_count": 6,
            "behavior_count": 3,
            "author_review_receipt_sha256": EXPECTED_HASHES["author_review"],
        },
        "selection_status": "partial-two-of-three" if partial else "complete",
        "formal_verification": {
            "performed": False,
            "reason": "selected candidate scholarship and mappings remain proposed",
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


def _claim_value(output_path: Path, payload_sha256: str) -> dict[str, str]:
    return {
        "schema_version": SELECTION_CLAIM_SCHEMA,
        "target_name": output_path.name,
        "payload_sha256": payload_sha256,
    }


def _write_private(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise SelectionError(f"write-once selection artifact exists: {path}") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def recover_incomplete_publication(output_path: Path = SELECTION_PATH) -> str:
    claim_path = _claim_path(output_path)
    claim, _ = _read_json(claim_path, "selection publication claim")
    if (
        set(claim) != {"schema_version", "target_name", "payload_sha256"}
        or claim.get("schema_version") != SELECTION_CLAIM_SCHEMA
        or claim.get("target_name") != output_path.name
        or not isinstance(claim.get("payload_sha256"), str)
    ):
        raise SelectionError("selection publication claim is not recognized")
    if not output_path.exists():
        claim_path.unlink()
        _fsync_directory(output_path.parent)
        return "cleared"
    payload, digest = _read_bytes(output_path, "claimed selection receipt")
    if digest != claim["payload_sha256"]:
        raise SelectionError(
            "claimed selection receipt has unexpected bytes; preserve it for inspection"
        )
    try:
        verify_selection_receipt(output_path)
    except (SelectionError, AggregateError, AuthorReviewValidationError, OSError, ValueError):
        if sha256_bytes(payload) != claim["payload_sha256"]:
            raise SelectionError("claimed selection receipt changed during recovery")
        output_path.unlink()
        claim_path.unlink()
        _fsync_directory(output_path.parent)
        return "cleared"
    claim_path.unlink()
    _fsync_directory(output_path.parent)
    return "completed"


def write_selection_receipt(
    context: SelectionContext, output_path: Path = SELECTION_PATH
) -> Path:
    claim_path = _claim_path(output_path)
    if claim_path.exists():
        raise SelectionError(
            "incomplete selection publication exists; run --recover-incomplete"
        )
    if output_path.exists():
        raise SelectionError("selection receipt is write-once")
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source_files = _source_hashes()
    payload = canonical_json_bytes(
        _receipt(context, created_at=utc_now(), source_files=source_files)
    )
    payload_sha256 = sha256_bytes(payload)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    temporary = Path(temporary_name)
    installed = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _write_private(
            claim_path,
            canonical_json_bytes(_claim_value(output_path, payload_sha256)),
        )
        _fsync_directory(output_path.parent)
        try:
            os.link(temporary, output_path)
        except FileExistsError as error:
            raise SelectionError("selection receipt is write-once") from error
        installed = True
        _fsync_directory(output_path.parent)
        verify_selection_receipt(output_path)
        claim_path.unlink()
        _fsync_directory(output_path.parent)
    except BaseException:
        if installed and output_path.exists():
            try:
                if os.path.samefile(temporary, output_path):
                    output_path.unlink()
            except OSError:
                pass
        if claim_path.is_file() and not claim_path.is_symlink():
            try:
                claim_path.unlink()
            except OSError:
                pass
        try:
            _fsync_directory(output_path.parent)
        except OSError:
            pass
        raise
    finally:
        temporary.unlink(missing_ok=True)
    return output_path


def verify_selection_receipt(output_path: Path = SELECTION_PATH) -> Path:
    if (
        output_path.is_symlink()
        or not output_path.is_file()
        or output_path.parent.is_symlink()
        or not output_path.parent.is_dir()
        or (output_path.parent.stat().st_mode & 0o077) != 0
        or (output_path.stat().st_mode & 0o777) != 0o600
    ):
        raise SelectionError("selection receipt must remain private at mode 0600")
    context = prepare_selection_context()
    receipt, _ = _read_json(output_path, "selection receipt")
    created_at = receipt.get("created_at")
    if not _valid_timestamp(created_at):
        raise SelectionError("selection receipt creation time is malformed")
    expected = _receipt(
        context, created_at=created_at, source_files=_source_hashes()
    )
    if receipt != expected:
        raise SelectionError("selection receipt differs from recomputed Rule 2 results")
    return output_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate frozen Rule 2 pilot selection.")
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
            print(f"Rule 2 selection publication recovery: {status}.")
            return 0
        if args.verify:
            path = verify_selection_receipt()
            print(f"Rule 2 selection verified: {path.relative_to(REPOSITORY_ROOT)}")
            return 0
        context = prepare_selection_context()
        if args.check:
            selected = ", ".join(context.selected_candidate_ids) or "none"
            failed = ", ".join(context.failed_behaviors) or "none"
            print(f"Rule 2 calculation valid; selected: {selected}; failed: {failed}.")
            return 0
        path = write_selection_receipt(context)
        print(f"Rule 2 selection written: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (SelectionError, AggregateError, AuthorReviewValidationError, OSError, ValueError) as error:
        print(f"Rule 2 selection stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

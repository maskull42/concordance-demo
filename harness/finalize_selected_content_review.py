#!/usr/bin/env python3
"""Validate and seal A.G. Elrod's selected-content review export."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import prepare_selected_content_review as packet
from private_directory_publication import (
    PrivateDirectoryPublicationError,
    PublicationSpec,
    publish_private_directory,
    recover_private_directory,
)
from concordance_harness.util import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    utc_now,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
PACKET_ROOT = packet.OUTPUT_ROOT
SEALED_ROOT = PACKET_ROOT / "sealed-review"
REVIEW_SCHEMA_VERSION = "selected-content-review-draft-1.0.0"
RECEIPT_SCHEMA_VERSION = "selected-content-review-receipt-1.0.0"
PUBLICATION_CLAIM_SCHEMA = "selected-content-review-seal-claim-1.1.0"
STAGING_OWNER_SCHEMA = "selected-content-review-seal-staging-owner-1.0.0"
PUBLISHED_FILES = ("review-draft.json", "review.json")
SEALED_FILES = set(PUBLISHED_FILES)
REVIEW_KEYS = {
    "schema_version",
    "status",
    "exported_at",
    "network_requests",
    "environment_variables_read",
    "review_id",
    "reviewer",
    "bindings",
    "content_decisions",
    "mapping_attestations",
    "author_attestation",
}
CONTENT_DECISION_KEYS = {
    "question_id",
    "question_sha256",
    "decision",
    "reviewed_at",
}
MAPPING_ATTESTATION_KEYS = {
    "question_id",
    "mapping_count",
    "mappings_sha256",
    "decision",
    "reviewed_at",
}


class SelectedContentReviewValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidatedReview:
    value: dict[str, Any]
    payload: bytes
    sha256: str
    packet_receipt_sha256: str
    question_ids: tuple[str, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SelectedContentReviewValidationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise SelectedContentReviewValidationError(
            f"{label} must be a regular, non-symlink file"
        )
    try:
        payload = path.read_bytes()
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        OSError,
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        SelectedContentReviewValidationError,
    ) as error:
        raise SelectedContentReviewValidationError(
            f"{label} cannot be loaded: {error}"
        ) from error
    if not isinstance(value, dict):
        raise SelectedContentReviewValidationError(f"{label} must be a JSON object")
    return value, payload


def _valid_timestamp(value: Any) -> bool:
    return packet._valid_timestamp(value)


def _exact_record(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SelectedContentReviewValidationError(f"{label} fields differ")
    return value


def validate_review_input(
    input_path: Path,
    *,
    packet_root: Path = PACKET_ROOT,
) -> ValidatedReview:
    try:
        packet.verify_review_packet(packet_root)
        context = packet.prepare_review_context()
    except (packet.SelectedContentReviewError, OSError, ValueError) as error:
        raise SelectedContentReviewValidationError(str(error)) from error
    packet_receipt_path = packet_root / "packet.json"
    packet_receipt, packet_receipt_payload = _read_json(
        packet_receipt_path, "selected-content packet receipt"
    )
    value, payload = _read_json(input_path, "selected-content review export")
    if set(value) != REVIEW_KEYS:
        raise SelectedContentReviewValidationError("review export fields differ")
    exported_at = value.get("exported_at")
    if (
        value.get("schema_version") != REVIEW_SCHEMA_VERSION
        or value.get("status") != "complete-selected-content-review"
        or not _valid_timestamp(exported_at)
        or value.get("network_requests") != 0
        or value.get("environment_variables_read") != 0
        or value.get("review_id") != packet_receipt.get("review_id")
        or value.get("reviewer") != {"id": "ag-elrod", "display_name": "A.G. Elrod"}
        or value.get("bindings") != context.bindings
        or value.get("author_attestation")
        != {
            "exact_content_reviewed": True,
            "selected_pilot_mappings_reviewed": True,
            "final_run_requires_fresh_mappings": True,
        }
    ):
        raise SelectedContentReviewValidationError(
            "review export belongs to a different or malformed packet"
        )

    question_records = {
        record["question"]["id"]: record for record in context.questions
    }
    decisions = value.get("content_decisions")
    if not isinstance(decisions, list) or len(decisions) != len(question_records):
        raise SelectedContentReviewValidationError("content decisions are incomplete")
    decision_ids = []
    for index, candidate in enumerate(decisions):
        decision = _exact_record(
            candidate, CONTENT_DECISION_KEYS, f"content decision {index + 1}"
        )
        question_id = decision.get("question_id")
        record = question_records.get(question_id)
        if (
            record is None
            or decision.get("question_sha256") != record["sha256"]
            or decision.get("decision") != "author-verify"
            or decision.get("reviewed_at") != exported_at
        ):
            raise SelectedContentReviewValidationError(
                f"content decision differs for {question_id}"
            )
        decision_ids.append(question_id)
    if decision_ids != list(packet.SELECTED_IDS):
        raise SelectedContentReviewValidationError("content decision order differs")

    groups = {group["question_id"]: group for group in context.mapping_groups}
    attestations = value.get("mapping_attestations")
    if not isinstance(attestations, list) or len(attestations) != len(groups):
        raise SelectedContentReviewValidationError(
            "mapping attestations are incomplete"
        )
    attestation_ids = []
    for index, candidate in enumerate(attestations):
        attestation = _exact_record(
            candidate,
            MAPPING_ATTESTATION_KEYS,
            f"mapping attestation {index + 1}",
        )
        question_id = attestation.get("question_id")
        group = groups.get(question_id)
        if (
            group is None
            or attestation.get("mapping_count") != group["mapping_count"]
            or attestation.get("mappings_sha256") != group["mappings_sha256"]
            or attestation.get("decision") != "approve-pilot-lineage"
            or attestation.get("reviewed_at") != exported_at
        ):
            raise SelectedContentReviewValidationError(
                f"mapping attestation differs for {question_id}"
            )
        attestation_ids.append(question_id)
    if attestation_ids != list(packet.SELECTED_IDS):
        raise SelectedContentReviewValidationError("mapping attestation order differs")

    return ValidatedReview(
        value=value,
        payload=payload,
        sha256=sha256_bytes(payload),
        packet_receipt_sha256=sha256_bytes(packet_receipt_payload),
        question_ids=tuple(decision_ids),
    )


def _source_hashes() -> dict[str, str]:
    values = packet._source_hashes()
    path = Path(__file__).resolve()
    values[str(path.relative_to(REPOSITORY_ROOT))] = sha256_file(path)
    return dict(sorted(values.items()))


def _receipt(
    validation: ValidatedReview,
    *,
    created_at: str,
) -> dict[str, Any]:
    if not _valid_timestamp(created_at):
        raise SelectedContentReviewValidationError("seal creation time is malformed")
    source_files = _source_hashes()
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "status": "complete-selected-content-review-sealed",
        "created_at": created_at,
        "network_requests": 0,
        "environment_variables_read": 0,
        "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "review_scope": "selected-content-and-unblinded-pilot-lineage",
        "packet_receipt": {
            "path": "../packet.json",
            "sha256": validation.packet_receipt_sha256,
        },
        "input_draft": {
            "path": "review-draft.json",
            "sha256": validation.sha256,
        },
        "verified_question_ids": list(validation.question_ids),
        "question_count": len(validation.question_ids),
        "mapping_count": 24,
        "author_attestation": validation.value["author_attestation"],
        "content_verification_status": "authorized-for-author-verified-promotion",
        "production_gate": {
            "eligible": False,
            "reason": "The divergence case and fresh final run remain incomplete.",
        },
        "validator": {
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
    }


def _publication_spec(packet_root: Path, sealed_root: Path) -> PublicationSpec:
    if sealed_root.resolve() != (packet_root / "sealed-review").resolve():
        raise SelectedContentReviewValidationError(
            "sealed review root must be the packet's sealed-review child"
        )
    work_parent = packet_root.parent
    claim_path = work_parent / (f".{packet_root.name}.{sealed_root.name}.publish-claim")
    return PublicationSpec(
        target_root=sealed_root,
        claim_path=claim_path,
        staging_parent=work_parent,
        claim_schema_version=PUBLICATION_CLAIM_SCHEMA,
        owner_schema_version=STAGING_OWNER_SCHEMA,
        expected_files=PUBLISHED_FILES,
    )


def _assert_private_tree(sealed_root: Path) -> None:
    if (
        sealed_root.is_symlink()
        or not sealed_root.is_dir()
        or stat.S_IMODE(sealed_root.stat().st_mode) != 0o700
    ):
        raise SelectedContentReviewValidationError(
            "sealed review root must be mode 0700"
        )
    entries = set(sealed_root.iterdir())
    expected = {sealed_root / name for name in SEALED_FILES}
    if entries != expected:
        raise SelectedContentReviewValidationError(
            "sealed review contains unexpected entries"
        )
    for path in entries:
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o600
        ):
            raise SelectedContentReviewValidationError(
                "sealed review files must be mode 0600"
            )


def verify_sealed_review(
    *,
    packet_root: Path = PACKET_ROOT,
    sealed_root: Path = SEALED_ROOT,
) -> Path:
    _assert_private_tree(sealed_root)
    validation = validate_review_input(
        sealed_root / "review-draft.json", packet_root=packet_root
    )
    receipt, _ = _read_json(sealed_root / "review.json", "sealed review receipt")
    created_at = receipt.get("created_at")
    expected = _receipt(validation, created_at=created_at)
    if receipt != expected:
        raise SelectedContentReviewValidationError("sealed review receipt differs")
    return sealed_root / "review.json"


def recover_incomplete_seal(
    *,
    packet_root: Path = PACKET_ROOT,
    sealed_root: Path = SEALED_ROOT,
) -> str:
    try:
        return recover_private_directory(
            _publication_spec(packet_root, sealed_root),
            lambda root: verify_sealed_review(
                packet_root=packet_root, sealed_root=root
            ),
        )
    except PrivateDirectoryPublicationError as error:
        raise SelectedContentReviewValidationError(str(error)) from error


def seal_review(
    input_path: Path,
    *,
    packet_root: Path = PACKET_ROOT,
    sealed_root: Path = SEALED_ROOT,
) -> Path:
    validation = validate_review_input(input_path, packet_root=packet_root)
    payloads = {
        "review-draft.json": validation.payload,
        "review.json": canonical_json_bytes(_receipt(validation, created_at=utc_now())),
    }
    try:
        publish_private_directory(
            _publication_spec(packet_root, sealed_root),
            payloads,
            lambda root: verify_sealed_review(
                packet_root=packet_root, sealed_root=root
            ),
        )
    except PrivateDirectoryPublicationError as error:
        raise SelectedContentReviewValidationError(str(error)) from error
    return sealed_root / "review.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate selected-content review export."
    )
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
            print(f"Selected-content review seal recovery: {status}.")
            return 0
        if args.verify:
            path = verify_sealed_review()
            print(
                f"Selected-content review seal verified: {path.relative_to(REPOSITORY_ROOT)}"
            )
            return 0
        if args.check is not None:
            value = validate_review_input(args.check)
            print(
                "Selected-content review export valid: "
                f"{len(value.question_ids)} questions and 24 pilot mappings."
            )
            return 0
        path = seal_review(args.seal)
        print(f"Selected-content review sealed: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (SelectedContentReviewValidationError, OSError, ValueError) as error:
        print(f"Selected-content review validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

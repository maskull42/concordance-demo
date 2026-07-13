#!/usr/bin/env python3
"""Promote the sealed selected-content review into an immutable public successor."""

from __future__ import annotations

import argparse
import copy
import fcntl
import json
import os
import secrets
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import finalize_selected_content_review as finalizer
from concordance_harness.util import canonical_json_bytes, sha256_bytes, sha256_file


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
PREDECESSOR_ROOT = REPOSITORY_ROOT / "candidate/successors/candidate-1.1.1"
PREDECESSOR_MANIFEST_PATH = PREDECESSOR_ROOT / "manifest.json"
OUTPUT_ROOT = REPOSITORY_ROOT / "candidate/successors/candidate-1.1.2"
PACKET_ROOT = finalizer.PACKET_ROOT
SEALED_ROOT = finalizer.SEALED_ROOT
SEALED_DRAFT_PATH = SEALED_ROOT / "review-draft.json"
SEALED_RECEIPT_PATH = SEALED_ROOT / "review.json"
CONTENT_VERSION = "candidate-1.1.2"
PREDECESSOR_CONTENT_VERSION = "candidate-1.1.1"
MANIFEST_SCHEMA_VERSION = "candidate-successor-1.0.0"
SELECTED_IDS = ("junia-romans-16-7", "john-brown-harpers-ferry")
PREDECESSOR_MANIFEST_SHA256 = (
    "783decf0e3cfecd7f22dc5fc6d7e4389153e45f78928a3d7a792d63efd53bdd6"
)
PREDECESSOR_QUESTION_SHA256 = {
    "junia-romans-16-7": (
        "4a2b7115a96e92d7db01d9a0a65b03046b323c0b68425e96083d6d8670eed0e7"
    ),
    "john-brown-harpers-ferry": (
        "a3489188ec29b402a893229bb227255dfd4bdbc10db0f7c020bb7b0944984ac4"
    ),
}
SEALED_DRAFT_SHA256 = "21e077b0cdf0ae8a935ed3cdd3d934342c5e84d3ea95d19729dcce99fb5bdd3e"
SEALED_RECEIPT_SHA256 = (
    "96dd200c5fa15a9206489313d7eea83469cb9d6a841b8e9af5140745e109fa1b"
)
PACKET_RECEIPT_SHA256 = (
    "8ef1f9bca3c7fee77bcbc3f3e4a84d6052053e0e030de5263f85ea153d5278ee"
)
AUTHOR_REVIEWED_AT = "2026-07-13T07:33:29.353Z"
SEALED_AT = "2026-07-13T07:36:08.042+00:00"
EXPECTED_MAPPING_COUNTS = {
    "junia-romans-16-7": 8,
    "john-brown-harpers-ferry": 16,
}
REVIEWER = {"id": "ag-elrod", "display_name": "A.G. Elrod"}
AUTHOR_VERIFICATION = {
    "status": "author-verified",
    "verified_by": "A.G. Elrod",
    "verified_at": AUTHOR_REVIEWED_AT,
}
EXPECTED_OUTPUT_FILES = (
    "manifest.json",
    "questions/john-brown-harpers-ferry.json",
    "questions/junia-romans-16-7.json",
)


class SelectedContentPromotionError(RuntimeError):
    pass


@dataclass(frozen=True)
class PromotionContext:
    predecessor_manifest: dict[str, Any]
    predecessor_questions: tuple[dict[str, Any], ...]
    sealed_draft: dict[str, Any]
    sealed_receipt: dict[str, Any]
    review_id: str
    reviewed_at: str
    sealed_at: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SelectedContentPromotionError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_pinned_json(
    path: Path,
    expected_sha256: str,
    label: str,
    *,
    required_mode: int | None = None,
) -> tuple[dict[str, Any], bytes]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SelectedContentPromotionError(
                f"{label} must be a regular, non-symlink file"
            )
        if (
            required_mode is not None
            and stat.S_IMODE(metadata.st_mode) != required_mode
        ):
            raise SelectedContentPromotionError(
                f"{label} must remain mode {required_mode:04o}"
            )
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        payload = b"".join(chunks)
        if sha256_bytes(payload) != expected_sha256:
            raise SelectedContentPromotionError(f"{label} hash differs")
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        OSError,
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        SelectedContentPromotionError,
    ) as error:
        raise SelectedContentPromotionError(
            f"{label} cannot be loaded: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise SelectedContentPromotionError(f"{label} must be a JSON object")
    return value, payload


def _require_exact_entries(root: Path, expected: set[Path], label: str) -> None:
    if root.is_symlink() or not root.is_dir():
        raise SelectedContentPromotionError(f"{label} must be a non-symlink directory")
    actual = set(root.iterdir())
    if actual != expected:
        raise SelectedContentPromotionError(f"{label} entries differ")


def _is_proposed(value: Any) -> bool:
    return value == {"status": "proposed", "verified_by": None, "verified_at": None}


def _require_fully_proposed(question: dict[str, Any]) -> None:
    if not _is_proposed(question.get("verification")):
        raise SelectedContentPromotionError(
            f"predecessor question is not proposed: {question.get('id')}"
        )
    positions = question.get("position_map")
    if not isinstance(positions, list) or not positions:
        raise SelectedContentPromotionError(
            f"predecessor position map is malformed: {question.get('id')}"
        )
    for position in positions:
        if not isinstance(position, dict) or not _is_proposed(
            position.get("verification")
        ):
            raise SelectedContentPromotionError(
                f"predecessor position is not proposed: {question.get('id')}"
            )
        sources = position.get("sources")
        if not isinstance(sources, list) or not sources:
            raise SelectedContentPromotionError(
                f"predecessor sources are malformed: {question.get('id')}"
            )
        for source in sources:
            if not isinstance(source, dict) or not _is_proposed(
                source.get("verification")
            ):
                raise SelectedContentPromotionError(
                    f"predecessor source is not proposed: {question.get('id')}"
                )


def _expected_question_index() -> list[dict[str, Any]]:
    return [
        {
            "id": question_id,
            "base": {
                "path": (
                    f"candidate/successors/{PREDECESSOR_CONTENT_VERSION}/questions/"
                    f"{question_id}.json"
                ),
                "sha256": PREDECESSOR_QUESTION_SHA256[question_id],
            },
        }
        for question_id in SELECTED_IDS
    ]


def _validate_predecessor_manifest(value: dict[str, Any]) -> None:
    if (
        value.get("schema_version") != MANIFEST_SCHEMA_VERSION
        or value.get("content_version") != PREDECESSOR_CONTENT_VERSION
        or value.get("selection_result")
        != {
            "status": "partial-selection-new-pool-required",
            "selected_candidate_ids": list(SELECTED_IDS),
            "failed_behaviors": ["divergence"],
            "scholarship_verification": "proposed",
            "production_eligible": False,
        }
    ):
        raise SelectedContentPromotionError("predecessor manifest contract differs")
    records = value.get("questions")
    if not isinstance(records, list) or len(records) != len(SELECTED_IDS):
        raise SelectedContentPromotionError(
            "predecessor manifest question index differs"
        )
    expected = _expected_question_index()
    for record, expected_record in zip(records, expected, strict=True):
        if not isinstance(record, dict):
            raise SelectedContentPromotionError(
                "predecessor manifest question record is malformed"
            )
        if (
            record.get("id") != expected_record["id"]
            or record.get("successor") != expected_record["base"]
        ):
            raise SelectedContentPromotionError(
                f"predecessor manifest binding differs for {expected_record['id']}"
            )


def _validate_sealed_review(
    *,
    packet_root: Path,
    sealed_root: Path,
    predecessor_questions: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        finalizer.verify_sealed_review(
            packet_root=packet_root,
            sealed_root=sealed_root,
        )
    except (
        finalizer.SelectedContentReviewValidationError,
        OSError,
        ValueError,
    ) as error:
        raise SelectedContentPromotionError(str(error)) from error

    draft_path = sealed_root / "review-draft.json"
    receipt_path = sealed_root / "review.json"
    draft, _ = _read_pinned_json(
        draft_path,
        SEALED_DRAFT_SHA256,
        "sealed selected-content review draft",
        required_mode=0o600,
    )
    receipt, _ = _read_pinned_json(
        receipt_path,
        SEALED_RECEIPT_SHA256,
        "sealed selected-content review receipt",
        required_mode=0o600,
    )

    if (
        receipt.get("schema_version") != finalizer.RECEIPT_SCHEMA_VERSION
        or receipt.get("status") != "complete-selected-content-review-sealed"
        or receipt.get("created_at") != SEALED_AT
        or receipt.get("reviewer") != REVIEWER
        or receipt.get("verified_question_ids") != list(SELECTED_IDS)
        or receipt.get("question_count") != 2
        or receipt.get("mapping_count") != 24
        or receipt.get("content_verification_status")
        != "authorized-for-author-verified-promotion"
        or receipt.get("input_draft")
        != {"path": "review-draft.json", "sha256": SEALED_DRAFT_SHA256}
        or receipt.get("packet_receipt")
        != {"path": "../packet.json", "sha256": PACKET_RECEIPT_SHA256}
        or receipt.get("production_gate")
        != {
            "eligible": False,
            "reason": "The divergence case and fresh final run remain incomplete.",
        }
    ):
        raise SelectedContentPromotionError("sealed selected-content receipt differs")

    question_hashes = {
        question["id"]: PREDECESSOR_QUESTION_SHA256[question["id"]]
        for question in predecessor_questions
    }
    expected_decisions = [
        {
            "question_id": question_id,
            "question_sha256": question_hashes[question_id],
            "decision": "author-verify",
            "reviewed_at": AUTHOR_REVIEWED_AT,
        }
        for question_id in SELECTED_IDS
    ]
    mapping_attestations = draft.get("mapping_attestations")
    if (
        draft.get("schema_version") != finalizer.REVIEW_SCHEMA_VERSION
        or draft.get("status") != "complete-selected-content-review"
        or draft.get("exported_at") != AUTHOR_REVIEWED_AT
        or draft.get("reviewer") != REVIEWER
        or draft.get("content_decisions") != expected_decisions
        or not isinstance(mapping_attestations, list)
        or [item.get("question_id") for item in mapping_attestations]
        != list(SELECTED_IDS)
        or any(
            not isinstance(item, dict)
            or item.get("mapping_count")
            != EXPECTED_MAPPING_COUNTS.get(item.get("question_id"))
            or item.get("decision") != "approve-pilot-lineage"
            or item.get("reviewed_at") != AUTHOR_REVIEWED_AT
            for item in mapping_attestations
        )
        or draft.get("author_attestation")
        != {
            "exact_content_reviewed": True,
            "selected_pilot_mappings_reviewed": True,
            "final_run_requires_fresh_mappings": True,
        }
        or receipt.get("author_attestation") != draft.get("author_attestation")
    ):
        raise SelectedContentPromotionError("sealed selected-content draft differs")
    review_id = draft.get("review_id")
    if not isinstance(review_id, str) or not review_id.startswith("selected-review-"):
        raise SelectedContentPromotionError(
            "sealed selected-content review ID is malformed"
        )
    return draft, receipt


def prepare_promotion(
    *,
    predecessor_root: Path = PREDECESSOR_ROOT,
    packet_root: Path = PACKET_ROOT,
    sealed_root: Path = SEALED_ROOT,
) -> PromotionContext:
    _require_exact_entries(
        predecessor_root,
        {predecessor_root / "manifest.json", predecessor_root / "questions"},
        "predecessor successor root",
    )
    question_root = predecessor_root / "questions"
    _require_exact_entries(
        question_root,
        {question_root / f"{question_id}.json" for question_id in SELECTED_IDS},
        "predecessor successor questions",
    )
    manifest_path = predecessor_root / "manifest.json"
    predecessor_manifest, _ = _read_pinned_json(
        manifest_path,
        PREDECESSOR_MANIFEST_SHA256,
        "candidate-1.1.1 predecessor manifest",
    )
    _validate_predecessor_manifest(predecessor_manifest)

    questions: list[dict[str, Any]] = []
    for question_id in SELECTED_IDS:
        question_path = question_root / f"{question_id}.json"
        question, _ = _read_pinned_json(
            question_path,
            PREDECESSOR_QUESTION_SHA256[question_id],
            f"candidate-1.1.1 predecessor question {question_id}",
        )
        if (
            question.get("id") != question_id
            or question.get("content_version") != PREDECESSOR_CONTENT_VERSION
            or question.get("selection", {}).get("status") != "selected"
        ):
            raise SelectedContentPromotionError(
                f"candidate-1.1.1 predecessor contract differs for {question_id}"
            )
        _require_fully_proposed(question)
        questions.append(question)

    predecessor_questions = tuple(questions)
    draft, receipt = _validate_sealed_review(
        packet_root=packet_root,
        sealed_root=sealed_root,
        predecessor_questions=predecessor_questions,
    )
    return PromotionContext(
        predecessor_manifest=predecessor_manifest,
        predecessor_questions=predecessor_questions,
        sealed_draft=draft,
        sealed_receipt=receipt,
        review_id=draft["review_id"],
        reviewed_at=draft["exported_at"],
        sealed_at=receipt["created_at"],
    )


def _promote_question(question: dict[str, Any], reviewed_at: str) -> dict[str, Any]:
    promoted = copy.deepcopy(question)
    promoted["content_version"] = CONTENT_VERSION
    verification = {
        "status": "author-verified",
        "verified_by": "A.G. Elrod",
        "verified_at": reviewed_at,
    }
    promoted["verification"] = copy.deepcopy(verification)
    for position in promoted["position_map"]:
        position["verification"] = copy.deepcopy(verification)
        for source in position["sources"]:
            source["verification"] = copy.deepcopy(verification)
    return promoted


def _source_hashes() -> dict[str, str]:
    values = finalizer._source_hashes()
    path = Path(__file__).resolve()
    values[str(path.relative_to(REPOSITORY_ROOT))] = sha256_file(path)
    return dict(sorted(values.items()))


def _manifest(
    context: PromotionContext,
    promoted_hashes: Mapping[str, str],
) -> dict[str, Any]:
    source_files = _source_hashes()
    predecessor = context.predecessor_manifest
    questions = [
        {
            "id": question_id,
            "base": {
                "path": (
                    f"candidate/successors/{PREDECESSOR_CONTENT_VERSION}/questions/"
                    f"{question_id}.json"
                ),
                "sha256": PREDECESSOR_QUESTION_SHA256[question_id],
            },
            "successor": {
                "path": (
                    f"candidate/successors/{CONTENT_VERSION}/questions/"
                    f"{question_id}.json"
                ),
                "sha256": promoted_hashes[question_id],
            },
        }
        for question_id in SELECTED_IDS
    ]
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "content_version": CONTENT_VERSION,
        "created_at": context.sealed_at,
        "supersedes": {
            "content_version": PREDECESSOR_CONTENT_VERSION,
            "manifest": {
                "path": (
                    f"candidate/successors/{PREDECESSOR_CONTENT_VERSION}/manifest.json"
                ),
                "sha256": PREDECESSOR_MANIFEST_SHA256,
            },
        },
        "selection_receipt": copy.deepcopy(predecessor["selection_receipt"]),
        "selection_result": {
            "status": "partial-selection-new-pool-required",
            "selected_candidate_ids": list(SELECTED_IDS),
            "failed_behaviors": ["divergence"],
            "scholarship_verification": "author-verified",
            "production_eligible": False,
        },
        "correction": copy.deepcopy(predecessor["correction"]),
        "author_review": {
            "schema_version": finalizer.RECEIPT_SCHEMA_VERSION,
            "review_id": context.review_id,
            "reviewer": copy.deepcopy(REVIEWER),
            "reviewed_at": context.reviewed_at,
            "sealed_at": context.sealed_at,
            "receipt": {
                "path": (
                    ".pilot/aggregates/rule2-pilot-1/selected-content-review-1/"
                    "sealed-review/review.json"
                ),
                "sha256": SEALED_RECEIPT_SHA256,
                "availability": "private-local",
            },
            "draft": {
                "path": (
                    ".pilot/aggregates/rule2-pilot-1/selected-content-review-1/"
                    "sealed-review/review-draft.json"
                ),
                "sha256": SEALED_DRAFT_SHA256,
                "availability": "private-local",
            },
            "packet_receipt_sha256": PACKET_RECEIPT_SHA256,
            "verified_question_ids": list(SELECTED_IDS),
            "content_verification_status": "author-verified",
        },
        "production_gate": {
            "eligible": False,
            "blockers": [
                "divergence has no qualifying selected candidate",
                "the linked-challenge final model run has not been executed",
            ],
        },
        "questions": questions,
        "promoter": {
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
    }


def promotion_payloads(context: PromotionContext) -> dict[str, bytes]:
    promoted_questions = {
        question["id"]: _promote_question(question, context.reviewed_at)
        for question in context.predecessor_questions
    }
    question_payloads = {
        question_id: canonical_json_bytes(promoted_questions[question_id])
        for question_id in SELECTED_IDS
    }
    promoted_hashes = {
        question_id: sha256_bytes(question_payloads[question_id])
        for question_id in SELECTED_IDS
    }
    payloads = {
        f"questions/{question_id}.json": question_payloads[question_id]
        for question_id in SELECTED_IDS
    }
    payloads["manifest.json"] = canonical_json_bytes(
        _manifest(context, promoted_hashes)
    )
    ordered = dict(sorted(payloads.items()))
    _assert_public_payloads(ordered)
    return ordered


def _assert_public_payloads(payloads: Mapping[str, bytes]) -> None:
    combined = b"\n".join(payloads.values())
    forbidden = {
        b'"response_text"': "private response text field",
        str(REPOSITORY_ROOT).encode("utf-8"): "absolute repository path",
        b"/Users/": "absolute user path",
        b"/Volumes/": "absolute volume path",
        b"file://": "local file URL",
    }
    for value, label in forbidden.items():
        if value in combined:
            raise SelectedContentPromotionError(
                f"public promotion contains a forbidden {label}"
            )


def _public_tree(output_root: Path) -> None:
    if (
        output_root.is_symlink()
        or not output_root.is_dir()
        or stat.S_IMODE(output_root.stat().st_mode) != 0o755
    ):
        raise SelectedContentPromotionError(
            "promoted successor root must be a public mode-0755 directory"
        )
    question_root = output_root / "questions"
    if (
        question_root.is_symlink()
        or not question_root.is_dir()
        or stat.S_IMODE(question_root.stat().st_mode) != 0o755
    ):
        raise SelectedContentPromotionError(
            "promoted successor question root must be mode 0755"
        )
    _require_exact_entries(
        output_root,
        {output_root / "manifest.json", question_root},
        "promoted successor root",
    )
    _require_exact_entries(
        question_root,
        {question_root / f"{question_id}.json" for question_id in SELECTED_IDS},
        "promoted successor questions",
    )
    for relative in EXPECTED_OUTPUT_FILES:
        path = output_root / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o644
        ):
            raise SelectedContentPromotionError(
                f"promoted successor file must be mode 0644: {relative}"
            )


def verify_promotion(
    output_root: Path = OUTPUT_ROOT,
    *,
    context: PromotionContext | None = None,
) -> Path:
    active_context = context if context is not None else prepare_promotion()
    expected = promotion_payloads(active_context)
    _public_tree(output_root)
    for relative, payload in expected.items():
        path = output_root / relative
        if path.read_bytes() != payload:
            raise SelectedContentPromotionError(
                f"promoted successor bytes differ: {relative}"
            )
    return output_root / "manifest.json"


def _write_public(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o644)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_exclusively(parent: Path, operation: Callable[[], Path]) -> Path:
    if parent.is_symlink() or not parent.is_dir():
        raise SelectedContentPromotionError(
            "promotion parent must be a non-symlink directory"
        )
    descriptor = os.open(parent, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return operation()
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def write_promotion(
    context: PromotionContext,
    output_root: Path = OUTPUT_ROOT,
) -> Path:
    output_root.parent.mkdir(parents=True, exist_ok=True)

    def write_after_lock() -> Path:
        if os.path.lexists(output_root):
            raise SelectedContentPromotionError(
                "candidate-1.1.2 successor is cooperatively immutable and already exists"
            )
        temporary = output_root.parent / (
            f".{output_root.name}.{secrets.token_hex(16)}.tmp"
        )
        payloads = promotion_payloads(context)
        try:
            temporary.mkdir(mode=0o755)
            temporary.chmod(0o755)
            question_root = temporary / "questions"
            question_root.mkdir(mode=0o755)
            question_root.chmod(0o755)
            for relative, payload in payloads.items():
                _write_public(temporary / relative, payload)
            _fsync_directory(question_root)
            _fsync_directory(temporary)
            verify_promotion(temporary, context=context)
            if os.path.lexists(output_root):
                raise SelectedContentPromotionError(
                    "candidate-1.1.2 successor appeared during cooperative publication"
                )
            os.rename(temporary, output_root)
            _fsync_directory(output_root.parent)
            return verify_promotion(output_root, context=context)
        finally:
            if os.path.lexists(temporary):
                shutil.rmtree(temporary)

    return _run_exclusively(output_root.parent, write_after_lock)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Promote the sealed selected-content review."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify:
            path = verify_promotion()
            print(
                "Author-verified successor verified: "
                f"{path.relative_to(REPOSITORY_ROOT)}"
            )
            return 0
        context = prepare_promotion()
        if args.check:
            payloads = promotion_payloads(context)
            print(
                "Selected-content promotion ready: "
                f"{len(context.predecessor_questions)} questions and "
                f"{len(payloads)} deterministic files."
            )
            return 0
        path = write_promotion(context)
        print(
            "Author-verified successor written: " f"{path.relative_to(REPOSITORY_ROOT)}"
        )
        return 0
    except (SelectedContentPromotionError, OSError, ValueError) as error:
        print(f"Selected-content promotion failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

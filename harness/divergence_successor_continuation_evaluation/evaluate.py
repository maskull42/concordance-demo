"""Canonical offline evaluation of the sealed continuation author review."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor import review as parent_review
from divergence_successor_continuation import contract as continuation_contract
from divergence_successor_continuation_author_review import anchor
from divergence_successor_continuation_author_review import review as author_review
from private_directory_publication import (
    PublicationSpec,
    publish_private_directory,
    recover_private_directory,
)

from . import contract, lock


class EvaluationError(contract.EvaluationContractError):
    """The sealed evidence cannot support an exact threshold evaluation."""


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = continuation_contract.parent_contract.parse_json_bytes(payload, label)
    except continuation_contract.parent_contract.ContractError as error:
        raise EvaluationError(str(error)) from error
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        raise EvaluationError(f"{label} must be one canonical JSON object")
    return value


def _hmac_hex(key: bytes, label: str) -> str:
    return hmac.new(key, label.encode("utf-8"), hashlib.sha256).hexdigest()


def _public_position(position: Mapping[str, Any], handle: str) -> dict[str, Any]:
    return {
        "handle": handle,
        **{key: value for key, value in position.items() if key != "id"},
    }


def _binding(path: str, payload: bytes) -> dict[str, str]:
    return {"path": path, "sha256": sha256_bytes(payload)}


def _anchored_inputs(
    root: Path, lock_value: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    verified = anchor.verify_anchor(root)
    anchored = verified["anchor"]
    lineage = lock_value["lineage"]
    try:
        packet_payload = anchor._private_bytes(
            root, lineage["blind_packet"]["path"], "blind packet"
        )
        crosswalk_payload = anchor._private_bytes(
            root, lineage["blind_crosswalk"]["path"], "blind crosswalk"
        )
        key_payload = anchor._private_bytes(
            root, anchored["blind_key"]["path"], "blind key"
        )
        question_payload = anchor._public_bytes(
            root, lineage["question"]["path"], "question"
        )
    except anchor.ReviewAnchorError as error:
        raise EvaluationError(str(error)) from error
    if (
        _binding(lineage["blind_packet"]["path"], packet_payload)
        != lineage["blind_packet"]
        or _binding(lineage["blind_crosswalk"]["path"], crosswalk_payload)
        != lineage["blind_crosswalk"]
        or sha256_bytes(key_payload) != lineage["blind_key_sha256"]
        or _binding(lineage["question"]["path"], question_payload)
        != lineage["question"]
        or anchored["blind_crosswalk"] != lineage["blind_crosswalk"]
        or anchored["blind_packet"] != lineage["blind_packet"]
    ):
        raise EvaluationError("evaluation inputs differ from the historical anchor")
    if len(key_payload) != 32:
        raise EvaluationError("anchored blinding key must contain exactly 32 bytes")
    packet = _json(packet_payload, "blind packet")
    crosswalk = _json(crosswalk_payload, "blind crosswalk")
    try:
        question = continuation_contract.parent_contract.parse_json_bytes(
            question_payload, "question"
        )
    except continuation_contract.parent_contract.ContractError as error:
        raise EvaluationError(str(error)) from error
    if not isinstance(question, dict):
        raise EvaluationError("question must be a JSON object")
    positions = question.get("position_map")
    packet_items = packet.get("items")
    crosswalk_items = crosswalk.get("items")
    required = lock_value["threshold_contract"]["required_completed_responses"]
    if (
        not isinstance(positions, list)
        or not positions
        or any(
            not isinstance(position, dict) or not isinstance(position.get("id"), str)
            for position in positions
        )
        or len({position["id"] for position in positions}) != len(positions)
        or not isinstance(packet_items, list)
        or not isinstance(crosswalk_items, list)
        or len(packet_items) != required
        or len(crosswalk_items) != required
        or packet.get("item_count") != required
        or crosswalk.get("item_count") != required
        or crosswalk.get("candidate_id") != contract.CANDIDATE_ID
        or packet.get("candidate_blind_id") != crosswalk.get("candidate_blind_id")
    ):
        raise EvaluationError(
            "anchored packet, crosswalk, or position map is malformed"
        )
    candidate_blind_id = (
        "C-"
        + _hmac_hex(key_payload, f"candidate\0{contract.CANDIDATE_ID}")[:32].upper()
    )
    if packet.get("candidate_blind_id") != candidate_blind_id:
        raise EvaluationError(
            "candidate blind ID is not authenticated by the anchored key"
        )
    allowed = [position["id"] for position in positions]
    for public, private in zip(packet_items, crosswalk_items, strict=True):
        if not isinstance(public, dict) or not isinstance(private, dict):
            raise EvaluationError("anchored evidence item is malformed")
        expected_blind = (
            "B-"
            + _hmac_hex(
                key_payload,
                f"response\0{contract.CANDIDATE_ID}\0{private.get('cell_id')}",
            )[:32].upper()
        )
        blind_id = public.get("blind_id")
        expected_positions = sorted(
            positions,
            key=lambda position: _hmac_hex(
                key_payload, f"position\0{blind_id}\0{position['id']}"
            ),
        )
        expected_crosswalk = {
            f"P{index}": position["id"]
            for index, position in enumerate(expected_positions, 1)
        }
        expected_public = [
            _public_position(position, f"P{index}")
            for index, position in enumerate(expected_positions, 1)
        ]
        response_text = public.get("response_text")
        if (
            not hmac.compare_digest(str(blind_id), expected_blind)
            or private.get("blind_id") != blind_id
            or private.get("candidate_id") != contract.CANDIDATE_ID
            or private.get("response_sha256") != public.get("response_sha256")
            or private.get("review_response_sha256") != public.get("response_sha256")
            or not isinstance(response_text, str)
            or sha256_bytes(response_text.encode("utf-8"))
            != public.get("response_sha256")
            or private.get("position_crosswalk") != expected_crosswalk
            or public.get("position_map") != expected_public
            or set(expected_crosswalk.values()) != set(allowed)
        ):
            raise EvaluationError("anchored blind item or local position map changed")
    expected_order = sorted(
        packet_items,
        key=lambda item: _hmac_hex(key_payload, f"order\0{item['blind_id']}"),
    )
    if packet_items != expected_order or [
        item["blind_id"] for item in packet_items
    ] != [item["blind_id"] for item in crosswalk_items]:
        raise EvaluationError("anchored blind order changed")
    bindings = crosswalk.get("bindings")
    if not isinstance(bindings, dict) or any(
        bindings.get(name) != anchored["lineage_bindings"].get(name)
        for name in anchored["lineage_bindings"]
    ):
        raise EvaluationError("crosswalk lineage differs from the historical anchor")
    return packet, crosswalk, question


def evaluate_threshold(
    primary_positions: Sequence[str | None],
    allowed_positions: Sequence[str],
    threshold: Mapping[str, int],
) -> tuple[dict[str, Any], dict[str, int]]:
    """Apply the exact threshold supplied by the frozen successor lock."""

    if dict(threshold) != contract.FROZEN_THRESHOLD:
        raise EvaluationError("threshold differs from the frozen successor rule")
    allowed = tuple(allowed_positions)
    if not allowed or len(set(allowed)) != len(allowed):
        raise EvaluationError("canonical position IDs must be unique")
    if len(primary_positions) != threshold["required_completed_responses"]:
        raise EvaluationError(
            "reviewed response count differs from the frozen requirement"
        )
    if any(value is not None and value not in allowed for value in primary_positions):
        raise EvaluationError(
            "reviewed primary falls outside the canonical position map"
        )
    observed = Counter(value for value in primary_positions if value is not None)
    counts = {position: observed.get(position, 0) for position in allowed}
    non_null = sum(observed.values())
    represented = len(observed)
    maximum = max(observed.values(), default=0)
    failures: list[str] = []
    if non_null < threshold["minimum_non_null_primary_endorsements"]:
        failures.append("fewer-than-six-non-null-primary-endorsements")
    if represented < threshold["minimum_distinct_primary_positions"]:
        failures.append("fewer-than-three-represented-positions")
    if maximum > threshold["maximum_primary_endorsements_per_position"]:
        failures.append("one-position-has-more-than-four-primary-endorsements")
    return (
        {
            "evidence_complete": True,
            "author_review_complete": True,
            "qualifies": not failures,
            "completed_response_count": len(primary_positions),
            "non_null_primary_count": non_null,
            "represented_position_count": represented,
            "maximum_position_primary_count": maximum,
            "failure_reasons": failures,
        },
        counts,
    )


def _reviewed_lineage(
    review_value: Mapping[str, Any],
    crosswalk: Mapping[str, Any],
    question: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str | None], list[str]]:
    decisions = review_value.get("decisions")
    crosswalk_items = crosswalk.get("items")
    positions = question.get("position_map")
    if (
        not isinstance(decisions, list)
        or not isinstance(crosswalk_items, list)
        or not isinstance(positions, list)
    ):
        raise EvaluationError("reviewed lineage inputs are malformed")
    required = contract.FROZEN_THRESHOLD["required_completed_responses"]
    if (
        len(decisions) != required
        or len(crosswalk_items) != required
        or [item.get("blind_id") for item in decisions if isinstance(item, dict)]
        != [item.get("blind_id") for item in crosswalk_items if isinstance(item, dict)]
    ):
        raise EvaluationError("author decisions must preserve the exact anchored order")
    by_blind = {
        item.get("blind_id"): item for item in crosswalk_items if isinstance(item, dict)
    }
    if len(by_blind) != len(crosswalk_items):
        raise EvaluationError("private crosswalk blind IDs are not unique")
    allowed = [position["id"] for position in positions]
    lineage: list[dict[str, Any]] = []
    primaries: list[str | None] = []
    for decision in decisions:
        if not isinstance(decision, dict):
            raise EvaluationError("author decision is malformed")
        private = by_blind.get(decision.get("blind_id"))
        if private is None or private.get("response_sha256") != decision.get(
            "response_sha256"
        ):
            raise EvaluationError("author decision differs from the anchored crosswalk")
        local = decision.get("reviewed_primary_position_handle")
        position_crosswalk = private.get("position_crosswalk")
        if not isinstance(position_crosswalk, dict):
            raise EvaluationError("private position crosswalk is malformed")
        canonical = None if local is None else position_crosswalk.get(local)
        if local is not None and canonical is None:
            raise EvaluationError(
                "reviewed local handle is absent from the anchored crosswalk"
            )
        if canonical is not None and canonical not in allowed:
            raise EvaluationError(
                "translated primary is outside the frozen question map"
            )
        if (local is None) != (
            decision.get("reviewed_reason_code") != "clear_preference"
        ):
            raise EvaluationError("reviewed primary and reason are inconsistent")
        primaries.append(canonical)
        lineage.append(
            {
                "blind_id": decision["blind_id"],
                "response_sha256": decision["response_sha256"],
                "first_pass_assignment_sha256": decision[
                    "first_pass_assignment_sha256"
                ],
                "author_decision_sha256": sha256_bytes(canonical_json_bytes(decision)),
                "decision": decision["decision"],
                "reviewed_at": decision["reviewed_at"],
                "reviewed_primary_position_handle": local,
                "reviewed_primary_position_id": canonical,
                "reviewed_reason_code": decision["reviewed_reason_code"],
                "crosswalk_item_sha256": sha256_bytes(canonical_json_bytes(private)),
                "outcome_path": private["outcome_path"],
                "outcome_sha256": private["outcome_sha256"],
            }
        )
    return lineage, primaries, allowed


def _terminal_result(qualifies: bool) -> dict[str, Any]:
    if type(qualifies) is not bool:
        raise EvaluationError("threshold qualification must be boolean")
    return {
        "terminal": True,
        "candidate_order": [contract.CANDIDATE_ID],
        "selected_candidate_id": contract.CANDIDATE_ID if qualifies else None,
        "reason": (
            "sole-successor-qualified-terminal-selected"
            if qualifies
            else "sole-successor-completed-and-failed-no-selection"
        ),
        "additional_candidates_allowed": False,
        "fallback_allowed": False,
        "third_candidate_allowed": False,
    }


def _require_exact_lock_commit(
    evaluation_git_head: str, committed_git_head: str | None
) -> None:
    if committed_git_head is None or evaluation_git_head != committed_git_head:
        raise EvaluationError(
            "receipt Git HEAD must equal the unique evaluation-lock introduction commit"
        )


def _receipt(
    root: Path,
    *,
    created_at: str,
    evaluation_git_head: str,
) -> dict[str, Any]:
    lock_context = lock.load_and_validate_lock(root, require_committed=True)
    _require_exact_lock_commit(evaluation_git_head, lock_context.committed_git_head)
    expected_time = lock.commit_timestamp(root, evaluation_git_head)
    if created_at != expected_time:
        raise EvaluationError("evaluation time must equal the committed gate time")
    author = author_review.verify_author_review(root)
    packet, crosswalk, question = _anchored_inputs(root, lock_context.value)
    if packet.get("candidate_blind_id") != author["review"].get("candidate_blind_id"):
        raise EvaluationError(
            "sealed author review names a different blinded candidate"
        )
    lineage, primaries, allowed = _reviewed_lineage(
        author["review"], crosswalk, question
    )
    threshold = {
        key: lock_context.value["threshold_contract"][key]
        for key in contract.FROZEN_THRESHOLD
    }
    result, counts = evaluate_threshold(primaries, allowed, threshold)
    terminal_result = _terminal_result(result["qualifies"])
    review_root = f"{contract.PRIVATE_ROOT_RELATIVE}/candidates/{contract.CANDIDATE_ID}/author-review-v2"
    sealed_review_payload = anchor._private_bytes(
        root, f"{review_root}/review.json", "sealed author review"
    )
    sealed_receipt_payload = anchor._private_bytes(
        root, f"{review_root}/receipt.json", "author review receipt"
    )
    if (
        _binding(f"{review_root}/review.json", sealed_review_payload)
        != lock_context.value["lineage"]["sealed_author_review"]
        or _binding(f"{review_root}/receipt.json", sealed_receipt_payload)
        != lock_context.value["lineage"]["sealed_author_review_receipt"]
        or sha256_bytes(sealed_review_payload) != author["review_sha256"]
        or sha256_bytes(sealed_receipt_payload) != author["receipt_sha256"]
    ):
        raise EvaluationError("sealed author-review bytes changed during evaluation")
    return {
        "schema_version": contract.RECEIPT_SCHEMA,
        "status": contract.RECEIPT_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "created_at": created_at,
        "source_binding": {
            "evaluator_source_git_head": lock_context.value["evaluator"][
                "source_git_head"
            ],
            "evaluation_lock_commit_git_head": evaluation_git_head,
            "evaluator_sources": list(lock_context.value["evaluator"]["sources"]),
        },
        "bindings": {
            "evaluation_lock": _binding(contract.LOCK_PATH, lock_context.payload),
            "successor_lock": dict(lock_context.value["lineage"]["successor_lock"]),
            "continuation_lock": dict(
                lock_context.value["lineage"]["continuation_lock"]
            ),
            "continuation_review_lock": dict(
                lock_context.value["lineage"]["continuation_review_lock"]
            ),
            "review_anchor": dict(lock_context.value["lineage"]["review_anchor"]),
            "blind_packet": dict(lock_context.value["lineage"]["blind_packet"]),
            "blind_crosswalk": dict(lock_context.value["lineage"]["blind_crosswalk"]),
            "blind_key_sha256": lock_context.value["lineage"]["blind_key_sha256"],
            "question": dict(lock_context.value["lineage"]["question"]),
            "sealed_author_review": _binding(
                f"{review_root}/review.json",
                sealed_review_payload,
            ),
            "sealed_author_review_receipt": _binding(
                f"{review_root}/receipt.json",
                sealed_receipt_payload,
            ),
        },
        "reviewed_lineage": lineage,
        "position_primary_counts": counts,
        "null_primary_count": sum(value is None for value in primaries),
        "threshold_contract": dict(lock_context.value["threshold_contract"]),
        "threshold_result": result,
        "terminal_result": terminal_result,
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
            "internet_accessed": False,
            "tools_accessed": False,
            "external_context_accessed": False,
        },
    }


def compute_evaluation(
    repository_root: Path | str, *, created_at: str | None = None
) -> dict[str, Any]:
    """Compute in memory only after the public gate is committed and clean."""

    root = contract.repository_root(repository_root)
    lock_context = lock.load_and_validate_lock(root, require_committed=True)
    if lock_context.committed_git_head is None:
        raise EvaluationError("evaluation lock has no committed Git HEAD")
    timestamp = created_at or lock.commit_timestamp(
        root, lock_context.committed_git_head
    )
    parent_review._valid_timestamp(timestamp, "continuation evaluation time")
    return _receipt(
        root, created_at=timestamp, evaluation_git_head=lock_context.committed_git_head
    )


def _evaluation_path(root: Path) -> Path:
    return root / contract.EVALUATION_ROOT


def _publication_spec(root: Path) -> PublicationSpec:
    target = _evaluation_path(root)
    return PublicationSpec(
        target_root=target,
        claim_path=target.parent / ".evaluation-v2.publish-claim",
        staging_parent=target.parent,
        claim_schema_version="continuation-evaluation-publication-claim-1.0.0",
        owner_schema_version="continuation-evaluation-publication-owner-1.0.0",
        expected_files=("receipt.json",),
    )


def _validate_receipt_payload(root: Path, payload: bytes) -> dict[str, Any]:
    value = _json(payload, "evaluation receipt")
    created_at = value.get("created_at")
    evaluation_head = value.get("source_binding", {}).get(
        "evaluation_lock_commit_git_head"
    )
    parent_review._valid_timestamp(created_at, "continuation evaluation time")
    context = lock.load_and_validate_lock(root, require_committed=True)
    lock.verify_historical_evaluation_head(root, evaluation_head, context.payload)
    expected = _receipt(
        root, created_at=created_at, evaluation_git_head=evaluation_head
    )
    if value != expected or payload != canonical_json_bytes(expected):
        raise EvaluationError("evaluation receipt or reviewed evidence changed")
    return value


def _recovery_directory_payload(directory: Path) -> bytes:
    try:
        directory_metadata = directory.lstat()
    except OSError as error:
        raise EvaluationError(
            f"evaluation directory cannot be inspected: {error}"
        ) from error
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_ISLNK(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        or {entry.name for entry in directory.iterdir()} != {"receipt.json"}
    ):
        raise EvaluationError(
            "recovering evaluation directory is not exact and private"
        )
    path = directory / "receipt.json"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvaluationError(
            f"recovering evaluation receipt cannot be opened: {error}"
        ) from error
    try:
        before = path.lstat()
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink not in {1, 2}
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise EvaluationError(
                "recovering evaluation receipt is not a safe private file"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(descriptor)


def _verify_recovery_directory(root: Path, directory: Path) -> None:
    _validate_receipt_payload(root, _recovery_directory_payload(directory))


def verify_evaluation(repository_root: Path | str) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    target = _evaluation_path(root)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise EvaluationError(
            f"evaluation receipt directory cannot be inspected: {error}"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {entry.name for entry in target.iterdir()} != {"receipt.json"}
    ):
        raise EvaluationError("evaluation receipt directory is not exact and private")
    relative = f"{contract.EVALUATION_ROOT}/receipt.json"
    try:
        payload = anchor._private_bytes(root, relative, "evaluation receipt")
    except anchor.ReviewAnchorError as error:
        raise EvaluationError(str(error)) from error
    value = _validate_receipt_payload(root, payload)
    return {
        "value": value,
        "sha256": sha256_bytes(payload),
        "path": target / "receipt.json",
    }


def recover_evaluation_publication(repository_root: Path | str) -> str:
    """Recover only the owned evaluation-v2 publication transaction."""

    root = contract.repository_root(repository_root)
    spec = _publication_spec(root)
    try:
        status = recover_private_directory(
            spec, lambda directory: _verify_recovery_directory(root, directory)
        )
    except RuntimeError as error:
        raise EvaluationError(str(error)) from error
    if status == "completed":
        verify_evaluation(root)
    return status


def _publication_state_exists(spec: PublicationSpec) -> bool:
    if os.path.lexists(spec.target_root) or os.path.lexists(spec.claim_path):
        return True
    if not spec.staging_parent.is_dir():
        return False
    prefixes = (
        f".{spec.target_root.name}.",
        f"{spec.claim_path.name}.",
    )
    return any(
        entry.name.startswith(prefixes) for entry in spec.staging_parent.iterdir()
    )


def publish_evaluation(repository_root: Path | str) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    target = _evaluation_path(root)
    spec = _publication_spec(root)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if _publication_state_exists(spec):
        status = recover_evaluation_publication(root)
        if status == "completed":
            return verify_evaluation(root)
    value = compute_evaluation(root)
    payloads = {"receipt.json": canonical_json_bytes(value)}

    def verify_during(directory: Path) -> None:
        candidate = directory / "receipt.json"
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or stat.S_IMODE(candidate.stat().st_mode) != 0o600
            or candidate.read_bytes() != payloads["receipt.json"]
        ):
            raise EvaluationError("published evaluation bytes changed")

    try:
        publish_private_directory(spec, payloads, verify_during)
    except RuntimeError as error:
        raise EvaluationError(str(error)) from error
    return verify_evaluation(root)


__all__ = (
    "EvaluationError",
    "compute_evaluation",
    "evaluate_threshold",
    "publish_evaluation",
    "recover_evaluation_publication",
    "verify_evaluation",
)

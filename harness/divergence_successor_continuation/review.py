"""Versioned response adapter and blind packet for the continuation."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor import contract as parent_contract
from divergence_successor import review as parent_review

from . import contract


class ContinuationReviewError(parent_review.DivergenceSuccessorReviewError):
    """The versioned continuation response bundle lacks exact lineage."""


BLIND_PACKET_SCHEMA = "divergence-successor-continuation-blind-packet-1.0.0"
CROSSWALK_SCHEMA = "divergence-successor-continuation-blind-crosswalk-1.0.0"


@dataclass(frozen=True)
class ReviewPaths:
    repository_root: Path
    pool_root: Path
    candidate_root: Path
    blind_root: Path


def review_paths(repository_root: Path | str) -> ReviewPaths:
    root = contract.repository_root(repository_root)
    pool = root / contract.REVIEW_ROOT_RELATIVE
    candidate = pool / "candidates" / contract.CANDIDATE_ID
    return ReviewPaths(root, pool, candidate, candidate / "blind")


def _asset_facts(root: Path) -> str:
    bindings: list[dict[str, str]] = []
    for relative in parent_review.REVIEW_ASSET_PATHS:
        try:
            payload = parent_contract.read_regular_file(root, relative)
        except parent_contract.ContractError as error:
            raise ContinuationReviewError(str(error)) from error
        bindings.append({"path": relative, "sha256": sha256_bytes(payload)})
    return sha256_bytes(canonical_json_bytes(bindings))


def review_lock_facts(prepared: Any) -> dict[str, str]:
    plan = prepared.lock_context.lock["plans"]["candidate_plans"][0]
    return {
        "git_head": prepared.lock_context.git_head,
        "lock_sha256": prepared.lock_context.lock_sha256,
        "question_sha256": prepared.parent.question.sha256,
        "plan_sha256": plan["plan_sha256"],
        "review_assets_sha256": _asset_facts(prepared.repository_root),
    }


def validate_bundle(prepared: Any, bundle: parent_review.ResponseBundle) -> None:
    try:
        parent_review._validate_bundle(bundle, contract.CANDIDATE_ID)
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ContinuationReviewError(str(error)) from error
    facts = review_lock_facts(prepared)
    for name, expected in facts.items():
        if bundle.bindings.get(name) != expected:
            raise ContinuationReviewError(
                f"continuation review binding changed: {name}"
            )


def load_candidate_responses(
    repository_root: Path | str,
    candidate_id: str = contract.CANDIDATE_ID,
) -> parent_review.ResponseBundle:
    from .composite import load_composite_responses

    return load_composite_responses(repository_root, candidate_id)


def _build_blind_materials(
    root: Path,
    bundle: parent_review.ResponseBundle,
    *,
    hmac_key: bytes,
    generated_at: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    if not isinstance(hmac_key, bytes) or len(hmac_key) != 32:
        raise ContinuationReviewError("blinding key must contain exactly 32 bytes")
    try:
        parent_review._valid_timestamp(generated_at, "blind generation time")
        question, question_payload = parent_review._load_question(
            root, contract.CANDIDATE_ID
        )
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ContinuationReviewError(str(error)) from error
    candidate_blind_id = (
        "C-"
        + parent_review._hmac_hex(hmac_key, f"candidate\0{contract.CANDIDATE_ID}")[
            :32
        ].upper()
    )
    items: list[dict[str, Any]] = []
    crosswalk_items: list[dict[str, Any]] = []
    for record in bundle.responses:
        blind_id = (
            "B-"
            + parent_review._hmac_hex(
                hmac_key,
                f"response\0{contract.CANDIDATE_ID}\0{record.cell_id}",
            )[:32].upper()
        )
        positions = sorted(
            question["position_map"],
            key=lambda position: parent_review._hmac_hex(
                hmac_key, f"position\0{blind_id}\0{position['id']}"
            ),
        )
        position_crosswalk: dict[str, str] = {}
        public_positions: list[dict[str, Any]] = []
        for index, position in enumerate(positions, 1):
            handle = f"P{index}"
            position_crosswalk[handle] = position["id"]
            public_positions.append(parent_review._public_position(position, handle))
        review_text, redaction = parent_review._review_response_copy(
            record.response_text
        )
        raw_sha = sha256_bytes(record.response_text.encode("utf-8"))
        response_sha = sha256_bytes(review_text.encode("utf-8"))
        redaction_sha = sha256_bytes(canonical_json_bytes(redaction))
        items.append(
            {
                "blind_id": blind_id,
                "response_sha256": response_sha,
                "redaction_receipt_sha256": redaction_sha,
                "user_prompt": parent_review._candidate_contract(contract.CANDIDATE_ID)[
                    "prompt"
                ],
                "position_map": public_positions,
                "response_text": review_text,
            }
        )
        crosswalk_items.append(
            {
                "blind_id": blind_id,
                "response_sha256": response_sha,
                "raw_response_sha256": raw_sha,
                "review_response_sha256": response_sha,
                "redaction_receipt": redaction,
                "redaction_receipt_sha256": redaction_sha,
                "candidate_id": record.candidate_id,
                "cell_id": record.cell_id,
                "model_key": record.model_key,
                "provider": record.provider,
                "requested_model_id": record.requested_model_id,
                "response_id": record.response_id,
                "prompt_sha256": record.prompt_sha256,
                "attempt_number": record.attempt_number,
                "outcome_path": record.outcome_path,
                "outcome_sha256": record.outcome_sha256,
                "position_crosswalk": position_crosswalk,
            }
        )

    def rank(item: dict[str, Any]) -> str:
        return parent_review._hmac_hex(hmac_key, f"order\0{item['blind_id']}")

    items.sort(key=rank)
    crosswalk_items.sort(key=rank)
    packet = {
        "schema_version": BLIND_PACKET_SCHEMA,
        "status": "complete-blinded-continuation-candidate",
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": candidate_blind_id,
        "generated_at": generated_at,
        "question_sha256": sha256_bytes(question_payload),
        "item_count": 8,
        "items": items,
    }
    crosswalk = {
        "schema_version": CROSSWALK_SCHEMA,
        "status": "sealed-private-continuation-crosswalk",
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "candidate_blind_id": candidate_blind_id,
        "generated_at": generated_at,
        "question_path": parent_review._candidate_contract(contract.CANDIDATE_ID)[
            "path"
        ],
        "question_sha256": sha256_bytes(question_payload),
        "hmac_algorithm": "HMAC-SHA-256",
        "bindings": dict(bundle.bindings),
        "item_count": 8,
        "items": crosswalk_items,
    }
    parent_review._assert_no_identity_metadata(packet)
    return packet, crosswalk, hmac_key


def build_blind_materials(
    repository_root: Path | str,
    *,
    hmac_key: bytes | None = None,
    generated_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    root = contract.repository_root(repository_root)
    bundle = load_candidate_responses(root)
    key = hmac_key if hmac_key is not None else secrets.token_bytes(32)
    created = generated_at or parent_review.utc_now()
    return _build_blind_materials(root, bundle, hmac_key=key, generated_at=created)


def verify_blind_materials(repository_root: Path | str) -> dict[str, Any]:
    paths = review_paths(repository_root)
    try:
        parent_review._assert_private_directory(
            paths.blind_root, ("crosswalk.json", "hmac.key", "packet.json")
        )
        packet, packet_payload = parent_review._read_private_object(
            paths.blind_root / "packet.json", "continuation blind packet"
        )
        crosswalk, crosswalk_payload = parent_review._read_private_object(
            paths.blind_root / "crosswalk.json", "continuation crosswalk"
        )
        key = parent_review._read_private_bytes(
            paths.blind_root / "hmac.key", "continuation blinding key"
        )
        bundle = load_candidate_responses(paths.repository_root)
        expected_packet, expected_crosswalk, _ = _build_blind_materials(
            paths.repository_root,
            bundle,
            hmac_key=key,
            generated_at=packet.get("generated_at"),
        )
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ContinuationReviewError(str(error)) from error
    if (
        packet != expected_packet
        or crosswalk != expected_crosswalk
        or packet_payload != canonical_json_bytes(expected_packet)
        or crosswalk_payload != canonical_json_bytes(expected_crosswalk)
        or not hmac.compare_digest(
            packet["candidate_blind_id"], crosswalk["candidate_blind_id"]
        )
    ):
        raise ContinuationReviewError("continuation blind materials changed")
    return {
        "packet": packet,
        "packet_sha256": sha256_bytes(packet_payload),
        "crosswalk": crosswalk,
        "crosswalk_sha256": sha256_bytes(crosswalk_payload),
        "key_sha256": sha256_bytes(key),
    }


def publish_blind_materials(repository_root: Path | str) -> Path:
    paths = review_paths(repository_root)
    packet, crosswalk, key = build_blind_materials(paths.repository_root)
    payloads = {
        "packet.json": canonical_json_bytes(packet),
        "crosswalk.json": canonical_json_bytes(crosswalk),
        "hmac.key": key,
    }

    def verify(target: Path) -> dict[str, Any]:
        parent_review._assert_private_directory(target, payloads)
        return verify_blind_materials(paths.repository_root)

    try:
        return parent_review._publish(paths.blind_root, payloads, verify)
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ContinuationReviewError(str(error)) from error


__all__ = (
    "ContinuationReviewError",
    "build_blind_materials",
    "load_candidate_responses",
    "publish_blind_materials",
    "review_lock_facts",
    "review_paths",
    "validate_bundle",
    "verify_blind_materials",
)

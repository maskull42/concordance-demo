#!/usr/bin/env python3
"""Validate the append-only frontier-AI prototype-inclusion policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = "candidate/frontier-ai-prototype-inclusion-policy.json"
RECEIPT_PATH = (
    ".pilot/divergence-successor-continuation-author-review/"
    "frontier-ai-preflight-correction-1/candidates/"
    "frontier-ai-lifecycle-licensing/evaluation-v2/receipt.json"
)
APPROVAL_SHA256 = "d7e623b425b45faed3732e1173895efe0d3954250617a9bdd9d545eb4f758663"
EXPECTED_BINDINGS = (
    (
        "successor_lock",
        "candidate/rule3-successor-lock.json",
        "08cbaa1963d88cc0c1b0fe32ac7e74fbd553b4dc9f7a6a1de0cc6866129f8ab9",
    ),
    (
        "continuation_lock",
        "candidate/rule3-successor-continuation-lock.json",
        "5acbb3d7dbeaa03e26441878d9d0d8714fd902474ae3be811fc04a2bd6b1d803",
    ),
    (
        "continuation_review_lock",
        "candidate/rule3-successor-continuation-review-lock.json",
        "573b8fc4caf513430873eabd9afa972e1a0ef76ab50c316075d13be34ab22875",
    ),
    (
        "evaluation_lock",
        "candidate/rule3-successor-continuation-evaluation-lock.json",
        "818835acf5a7d5be9754a49c838a0e62dda19c704679307b8392884db75461b4",
    ),
    (
        "evaluation_receipt",
        RECEIPT_PATH,
        "c6b384d8bbeb9934d38e05bc1a353ad53ac63f33be162f67f1a3425be4cc19a4",
    ),
)
EXPECTED_COUNTS = {
    "development-stage-licensing": 0,
    "deployment-release-licensing": 5,
    "binding-frontier-supervision": 3,
    "use-centered-general-law": 0,
}
EXPECTED_FAILURES = [
    "fewer-than-three-represented-positions",
    "one-position-has-more-than-four-primary-endorsements",
]


class PrototypeInclusionError(ValueError):
    """The prototype policy or its sealed lineage is invalid."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PrototypeInclusionError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PrototypeInclusionError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise PrototypeInclusionError(f"{label} must be a JSON object")
    if payload != _canonical(value):
        raise PrototypeInclusionError(f"{label} must be canonical JSON")
    return value


def _read_regular(root: Path, relative: str, mode: int) -> bytes:
    path = root / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PrototypeInclusionError(f"cannot inspect {relative}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
    ):
        raise PrototypeInclusionError(
            f"{relative} must be a single-link mode-{mode:04o} regular file"
        )
    try:
        return path.read_bytes()
    except OSError as error:
        raise PrototypeInclusionError(f"cannot read {relative}: {error}") from error


def _expected_lineage() -> list[dict[str, str]]:
    return [
        {"name": name, "path": path, "sha256": digest}
        for name, path, digest in EXPECTED_BINDINGS
    ]


def validate_semantics(policy: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Validate the disclosed decision without rerunning any provider result."""

    expected_top_level = {
        "schema_version",
        "status",
        "policy_id",
        "pool_id",
        "candidate_id",
        "decision_sequence",
        "classification",
        "authorization",
        "claim_limits",
        "approval",
        "lineage",
        "offline_attestation",
    }
    if set(policy) != expected_top_level:
        raise PrototypeInclusionError("policy fields differ from the v1 contract")
    if (
        policy["schema_version"] != "concordance-prototype-inclusion-policy-1.0.0"
        or policy["status"] != "approved-prototype-inclusion"
        or policy["policy_id"]
        != "frontier-ai-bimodal-divergence-prototype-inclusion-v1"
        or policy["pool_id"] != "frontier-ai-preflight-correction-1"
        or policy["candidate_id"] != "frontier-ai-lifecycle-licensing"
    ):
        raise PrototypeInclusionError("policy identity differs")

    sequence = policy["decision_sequence"]
    if sequence != {
        "original_rule": "rule3-multipolar-divergence",
        "original_result": "failed-and-preserved",
        "original_terminal_selection": None,
        "prototype_policy_timing": "post-result",
        "disclosure": (
            "The bimodal prototype policy was adopted after the original multipolar "
            "Rule 3 result was known."
        ),
    }:
        raise PrototypeInclusionError("post-result decision disclosure differs")

    threshold = receipt.get("threshold_result")
    terminal = receipt.get("terminal_result")
    counts = receipt.get("position_primary_counts")
    if not isinstance(threshold, dict) or not isinstance(terminal, dict):
        raise PrototypeInclusionError("evaluation result is malformed")
    if (
        receipt.get("schema_version")
        != "divergence-successor-continuation-evaluation-receipt-1.0.0"
        or receipt.get("status") != "complete-offline-reviewed-threshold-evaluation"
        or receipt.get("pool_id") != policy["pool_id"]
        or receipt.get("candidate_id") != policy["candidate_id"]
        or counts != EXPECTED_COUNTS
        or receipt.get("null_primary_count") != 0
        or threshold.get("qualifies") is not False
        or threshold.get("evidence_complete") is not True
        or threshold.get("author_review_complete") is not True
        or threshold.get("completed_response_count") != 8
        or threshold.get("non_null_primary_count") != 8
        or threshold.get("represented_position_count") != 2
        or threshold.get("maximum_position_primary_count") != 5
        or threshold.get("failure_reasons") != EXPECTED_FAILURES
        or terminal.get("terminal") is not True
        or terminal.get("selected_candidate_id") is not None
        or terminal.get("reason") != "sole-successor-completed-and-failed-no-selection"
    ):
        raise PrototypeInclusionError("original terminal Rule 3 failure differs")

    classification = policy["classification"]
    if classification != {
        "label": "bimodal_divergence",
        "completed_reviewed_responses": threshold["completed_response_count"],
        "represented_primary_positions": threshold["represented_position_count"],
        "primary_position_counts": counts,
        "nonzero_primary_split_descending": sorted(
            (count for count in counts.values() if count), reverse=True
        ),
        "basis": (
            "All eight reviewed responses received a primary position, divided 5-3 "
            "between two represented positions."
        ),
    }:
        raise PrototypeInclusionError("bimodal classification differs from receipt")

    if policy["authorization"] != {
        "prototype_inclusion_selected": True,
        "scope": "concordance-prototype-display-only",
        "this_record_performs_data_promotion": False,
        "provider_calls_authorized": 0,
        "new_generation_authorized": False,
        "production_release_authorized": False,
    }:
        raise PrototypeInclusionError("prototype-only authorization differs")
    if policy["claim_limits"] != {
        "precommitted_rule3_qualification": False,
        "rule3_qualification": False,
        "validated_measurement": False,
        "production_release": False,
        "statement": (
            "This case is a post-result, prototype-only illustration of bimodal "
            "disagreement in sampled model answers."
        ),
    }:
        raise PrototypeInclusionError("claim limits differ")
    if policy["approval"] != {
        "basis": "explicit-user-approval-after-result",
        "approval_text_sha256": APPROVAL_SHA256,
    }:
        raise PrototypeInclusionError("approval binding differs")
    if policy["lineage"] != _expected_lineage():
        raise PrototypeInclusionError("lineage bindings differ")
    if policy["offline_attestation"] != {
        "network_requests": 0,
        "environment_variables_read": 0,
        "provider_calls": 0,
    }:
        raise PrototypeInclusionError("offline attestation differs")


def verify(repository_root: Path | str) -> dict[str, Any]:
    """Verify the public policy and every bound source in place."""

    root = Path(repository_root).resolve()
    policy_payload = _read_regular(root, POLICY_PATH, 0o644)
    policy = _parse(policy_payload, "prototype policy")
    for name, relative, expected_digest in EXPECTED_BINDINGS:
        mode = 0o600 if name == "evaluation_receipt" else 0o644
        payload = _read_regular(root, relative, mode)
        if _sha256(payload) != expected_digest:
            raise PrototypeInclusionError(f"{name} binding changed")
    receipt_payload = _read_regular(root, RECEIPT_PATH, 0o600)
    receipt = _parse(receipt_payload, "evaluation receipt")
    validate_semantics(policy, receipt)
    receipt_bindings = receipt.get("bindings")
    if not isinstance(receipt_bindings, dict):
        raise PrototypeInclusionError("evaluation receipt bindings are malformed")
    for name, path, digest in EXPECTED_BINDINGS[:-1]:
        if receipt_bindings.get(name) != {"path": path, "sha256": digest}:
            raise PrototypeInclusionError(
                f"evaluation receipt does not bind the expected {name}"
            )
    return {
        "status": "verified-prototype-inclusion-policy",
        "policy_sha256": _sha256(policy_payload),
        "evaluation_receipt_sha256": _sha256(receipt_payload),
        "classification": policy["classification"]["label"],
        "original_rule3_qualifies": False,
        "prototype_inclusion_selected": True,
        "network_requests": 0,
        "environment_variables_read": 0,
        "provider_calls": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    args = parser.parse_args()
    try:
        result = verify(args.repository_root)
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

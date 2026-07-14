"""Authenticate the immutable history preceding the divergence successor."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_recovery.journal import RecoveryJournalError, read_record
from quantum_disposition import verify_disposition

from . import contract


RULE3_LOCK_PATH = "candidate/rule3-lock.json"
RULE3_LOCK_SHA256 = (
    "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc"
)
QUANTUM_RUN_PATH = ".pilot/quantum-fallback/quantum-fallback-1/run.json"
QUANTUM_RUN_SHA256 = (
    "1d2d8f9bee1a5c503912de9ad3556947f50f5a0b2f7e08a678cbfe8fdffb870f"
)
QUANTUM_DISPOSITION_PATH = (
    ".pilot/quantum-disposition/quantum-withdrawal-1/disposition.json"
)
QUANTUM_DISPOSITION_SHA256 = (
    "6a2b1e071b218ccb7a4bb1d94ce7b8ad4b681aebb5c5277a520588b0236833cc"
)

GALATIANS_BINDINGS = (
    (
        "amendment",
        ".pilot/grok-review-amendment/galatians-local-handle-correction-1/amendment.json",
        "40f13ca059cf66960cac77f0132742567a42dc1184d4b330116d0d7285c2dff9",
    ),
    (
        "fallback_eligibility",
        ".pilot/grok-review-amendment/galatians-local-handle-correction-1/fallback-eligibility.json",
        "aae3f6cb0b2b8ed01935c3ef443d1d5491f8fdf0276783b68423031e386e6f30",
    ),
    (
        "superseding_evaluation",
        ".pilot/grok-review-amendment/galatians-local-handle-correction-1/superseding-evaluation.json",
        "0caf412b77113d5b87d8d8cc971da06e0a95fc83987ba3b76248ef6ef1b64743",
    ),
)


class DivergenceSuccessorParentError(contract.DivergenceSuccessorLockError):
    """Raised when predecessor evidence is absent, altered, or unsafe."""


@dataclass(frozen=True)
class ParentEvidence:
    repository_root: Path
    rule3_lock: dict[str, str]
    corrected_galatians: tuple[dict[str, str], ...]
    quantum_run: dict[str, str]
    quantum_disposition: dict[str, str]

    def value(self) -> dict[str, Any]:
        return {
            "rule3_lock": dict(self.rule3_lock),
            "corrected_galatians_lineage": [
                dict(item) for item in self.corrected_galatians
            ],
            "quantum_run": dict(self.quantum_run),
            "quantum_disposition": dict(self.quantum_disposition),
            "historical_artifacts_preserved": True,
            "old_pool_extended": False,
            "old_responses_reused": False,
        }


def expected_parent_contract() -> dict[str, Any]:
    return {
        "rule3_lock": {"path": RULE3_LOCK_PATH, "sha256": RULE3_LOCK_SHA256},
        "corrected_galatians_lineage": [
            {"path": path, "sha256": digest}
            for _, path, digest in GALATIANS_BINDINGS
        ],
        "quantum_run": {
            "path": QUANTUM_RUN_PATH,
            "sha256": QUANTUM_RUN_SHA256,
        },
        "quantum_disposition": {
            "path": QUANTUM_DISPOSITION_PATH,
            "sha256": QUANTUM_DISPOSITION_SHA256,
        },
        "historical_artifacts_preserved": True,
        "old_pool_extended": False,
        "old_responses_reused": False,
    }


def _public_binding(root: Path, relative: str, expected_sha: str) -> dict[str, str]:
    try:
        payload = contract.read_regular_file(root, relative)
    except contract.ContractError as error:
        raise DivergenceSuccessorParentError(str(error)) from error
    digest = contract.sha256_bytes(payload)
    if digest != expected_sha:
        raise DivergenceSuccessorParentError(
            f"historical public artifact {relative} changed"
        )
    return {"path": relative, "sha256": digest}


def _private_record(root: Path, relative: str, expected_sha: str, label: str) -> Any:
    try:
        record = read_record(root / relative, label)
    except RecoveryJournalError as error:
        raise DivergenceSuccessorParentError(str(error)) from error
    if record.sha256 != expected_sha:
        raise DivergenceSuccessorParentError(f"{label} changed")
    return record


def _validate_galatians(values: dict[str, Any]) -> None:
    amendment = values["amendment"].payload
    eligibility = values["fallback_eligibility"].payload
    evaluation = values["superseding_evaluation"].payload
    threshold = evaluation.get("threshold_result")
    if (
        amendment.get("candidate_id") != "galatians-pistis-christou"
        or amendment.get("historical_artifacts_preserved") is not True
        or eligibility.get("fallback_candidate_id")
        != "quantum-measurement-realist-strategies"
        or eligibility.get("threshold_result") != threshold
        or not isinstance(threshold, dict)
        or threshold.get("qualifies") is not False
        or threshold.get("represented_position_count") != 2
        or evaluation.get("supersedes", {}).get("invalid_for_selection") is not True
    ):
        raise DivergenceSuccessorParentError(
            "corrected Galatians failure lineage changed"
        )


def _validate_quantum_run(record: Any) -> None:
    value = record.payload
    if (
        value.get("candidate_id") != "quantum-measurement-realist-strategies"
        or value.get("status") != "complete-eight-successes"
        or value.get("successful_outcome_count") != 8
        or value.get("failed_model_keys") != []
        or tuple(item.get("model_key") for item in value.get("outcomes", ()))
        != contract.MODEL_KEYS
        or value.get("network_contract")
        != {
            "preflight_requests": 8,
            "generation_posts": 8,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        }
    ):
        raise DivergenceSuccessorParentError("Quantum run lineage changed")


def _validate_disposition(root: Path) -> None:
    try:
        result = verify_disposition(root)
    except Exception as error:
        raise DivergenceSuccessorParentError(
            f"Quantum disposition no longer verifies: {error}"
        ) from error
    path = root / QUANTUM_DISPOSITION_PATH
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DivergenceSuccessorParentError(
            f"Quantum disposition cannot be inspected: {error}"
        ) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or result.get("receipt_sha256") != QUANTUM_DISPOSITION_SHA256
    ):
        raise DivergenceSuccessorParentError("Quantum disposition binding changed")


def verify_parent_snapshot(repository_root: Path | str) -> ParentEvidence:
    """Verify the predecessor facts without credentials, network, or writes."""

    root = contract.repository_root(repository_root)
    rule3 = _public_binding(root, RULE3_LOCK_PATH, RULE3_LOCK_SHA256)
    galatians_records = {
        label: _private_record(root, path, digest, f"Galatians {label}")
        for label, path, digest in GALATIANS_BINDINGS
    }
    _validate_galatians(galatians_records)
    quantum = _private_record(
        root, QUANTUM_RUN_PATH, QUANTUM_RUN_SHA256, "Quantum run"
    )
    _validate_quantum_run(quantum)
    _validate_disposition(root)
    evidence = ParentEvidence(
        repository_root=root,
        rule3_lock=rule3,
        corrected_galatians=tuple(
            {"path": path, "sha256": digest}
            for _, path, digest in GALATIANS_BINDINGS
        ),
        quantum_run={"path": QUANTUM_RUN_PATH, "sha256": QUANTUM_RUN_SHA256},
        quantum_disposition={
            "path": QUANTUM_DISPOSITION_PATH,
            "sha256": QUANTUM_DISPOSITION_SHA256,
        },
    )
    if evidence.value() != expected_parent_contract():
        raise DivergenceSuccessorParentError("successor parent contract changed")
    return evidence


__all__ = (
    "DivergenceSuccessorParentError",
    "ParentEvidence",
    "expected_parent_contract",
    "verify_parent_snapshot",
)

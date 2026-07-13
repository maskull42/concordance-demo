"""Authenticate the immutable partial Rule 3 run used by the recovery."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from rule3.budget import JournalRecord
from rule3.lock import load_and_validate_rule3_lock

from . import contract
from .journal import (
    RecoveryJournalError,
    assert_exact_json_inventory,
    read_record,
    require_git_head,
    require_sha256,
)


@dataclass(frozen=True)
class ParentEvidence:
    private_root: Path
    manifest: JournalRecord
    preserved_outcomes: tuple[JournalRecord, JournalRecord]
    stranded_intent: JournalRecord
    reserved_microdollars: int


def _binding_map(lock: dict[str, Any]) -> dict[str, str]:
    parent = lock.get("parent")
    values = parent.get("private_bindings") if isinstance(parent, dict) else None
    if not isinstance(values, list) or len(values) != 25:
        raise RecoveryJournalError("recovery lock lacks the exact parent evidence set")
    result: dict[str, str] = {}
    for item in values:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise RecoveryJournalError("parent private binding is malformed")
        path = item.get("path")
        if not isinstance(path, str) or path in result:
            raise RecoveryJournalError("parent private binding path is malformed")
        result[path] = require_sha256(item.get("sha256"), "parent private binding hash")
    return result


def _exact_files(root: Path, relative: Iterable[str]) -> list[Path]:
    return [root / item for item in relative]


def _validate_parent_record(
    root: Path, relative: str, expected_sha256: str
) -> JournalRecord:
    record = read_record(root / relative, f"parent Rule 3 evidence {relative}")
    if record.sha256 != expected_sha256:
        raise RecoveryJournalError(f"parent Rule 3 evidence changed: {relative}")
    return record


def _validate_preserved_outcome(
    record: JournalRecord,
    *,
    model_key: str,
    expected_response_sha256: str,
    expected_intent_sha256: str,
    expected_manifest_sha256: str,
    parent_head: str,
) -> None:
    value = record.payload
    response = value.get("response_text")
    if (
        value.get("schema_version") != "rule3-attempt-outcome-1.0.0"
        or value.get("status") != "success"
        or value.get("candidate_id") != contract.CANDIDATE_ID
        or value.get("phase") != "priority"
        or value.get("model_key") != model_key
        or value.get("attempt_number") != 1
        or value.get("git_head") != parent_head
        or value.get("lock_sha256") != contract.PARENT_LOCK_SHA256
        or value.get("manifest_sha256") != expected_manifest_sha256
        or value.get("intent_sha256") != expected_intent_sha256
        or not isinstance(response, str)
        or not response.strip()
        or hashlib.sha256(response.encode("utf-8")).hexdigest()
        != expected_response_sha256
        or value.get("response_sha256") != expected_response_sha256
    ):
        raise RecoveryJournalError(f"preserved {model_key} outcome is not authentic")


def _validate_stranded_intent(
    record: JournalRecord, *, expected_manifest_sha256: str, parent_head: str
) -> int:
    value = record.payload
    reserve = value.get("reserved_cost_microdollars")
    if (
        value.get("schema_version") != "rule3-attempt-intent-1.0.0"
        or value.get("status") != "reserved-before-post"
        or value.get("candidate_id") != contract.CANDIDATE_ID
        or value.get("model_key") != "cohere"
        or value.get("attempt_number") != 1
        or value.get("lock_sha256") != contract.PARENT_LOCK_SHA256
        or value.get("manifest_sha256") != expected_manifest_sha256
        or reserve != 0
    ):
        raise RecoveryJournalError("stranded Cohere intent is not the frozen attempt")
    return reserve


def validate_parent_evidence(
    repository_root: Path, recovery_lock: dict[str, Any]
) -> ParentEvidence:
    """Validate parent hashes and absence facts without reading any credential."""
    root = repository_root.resolve()
    try:
        original = load_and_validate_rule3_lock(root, require_committed=True)
    except Exception as error:
        raise RecoveryJournalError(
            f"committed parent Rule 3 lock no longer validates: {error}"
        ) from error
    if original.lock_sha256 != contract.PARENT_LOCK_SHA256:
        raise RecoveryJournalError("parent Rule 3 lock hash changed")

    parent = recovery_lock.get("parent")
    if not isinstance(parent, dict):
        raise RecoveryJournalError("recovery lock parent contract is malformed")
    parent_head = require_git_head(parent.get("git_head"), "parent execution Git HEAD")
    if parent_head != contract.PARENT_GIT_HEAD:
        raise RecoveryJournalError("parent execution Git HEAD changed")
    parent_root = root / contract.PARENT_PRIVATE_ROOT
    bindings = _binding_map(recovery_lock)

    records = {
        relative: _validate_parent_record(parent_root, relative, digest)
        for relative, digest in bindings.items()
    }

    # The private parent remains exactly partial: three POST intents, two outcomes,
    # and no completion receipt.  Recovery artifacts live elsewhere.
    generation_intents = sorted(
        relative for relative in bindings if relative.startswith("budget/intents/")
    )
    generation_outcomes = sorted(
        relative for relative in bindings if relative.startswith("outcomes/")
    )
    preflight_intents = sorted(
        relative for relative in bindings if relative.startswith("preflight/intents/")
    )
    preflight_outcomes = sorted(
        relative for relative in bindings if relative.startswith("preflight/outcomes/")
    )
    assert_exact_json_inventory(
        parent_root / "budget/intents" / contract.CANDIDATE_ID,
        _exact_files(parent_root, generation_intents),
        "parent generation intents",
    )
    assert_exact_json_inventory(
        parent_root / "outcomes" / contract.CANDIDATE_ID,
        _exact_files(parent_root, generation_outcomes),
        "parent generation outcomes",
    )
    assert_exact_json_inventory(
        parent_root / "preflight/intents" / contract.CANDIDATE_ID,
        _exact_files(parent_root, preflight_intents),
        "parent preflight intents",
    )
    assert_exact_json_inventory(
        parent_root / "preflight/outcomes" / contract.CANDIDATE_ID,
        _exact_files(parent_root, preflight_outcomes),
        "parent preflight outcomes",
    )
    if (parent_root / "runs" / f"{contract.CANDIDATE_ID}.json").exists():
        raise RecoveryJournalError(
            "parent run unexpectedly acquired a completion receipt"
        )

    manifest_relative = f"manifests/{contract.CANDIDATE_ID}.json"
    manifest = records[manifest_relative]
    if (
        manifest.payload.get("schema_version") != "rule3-model-manifest-1.0.0"
        or manifest.payload.get("status") != "complete-eight-model-preflight"
        or manifest.payload.get("candidate_id") != contract.CANDIDATE_ID
        or manifest.payload.get("git_head") != parent_head
        or manifest.payload.get("lock_sha256") != contract.PARENT_LOCK_SHA256
        or manifest.sha256 != contract.PARENT_MANIFEST_SHA256
    ):
        raise RecoveryJournalError("parent eight-model manifest is not authentic")

    preserved: list[JournalRecord] = []
    for model_key in contract.PRESERVED_MODEL_KEYS:
        intent_path = (
            f"budget/intents/{contract.CANDIDATE_ID}/{model_key}/attempt-1.json"
        )
        outcome_path = f"outcomes/{contract.CANDIDATE_ID}/{model_key}/attempt-1.json"
        intent = records[intent_path]
        outcome = records[outcome_path]
        expected = next(
            item
            for item in contract.PRESERVED_SUCCESSES
            if item["model_key"] == model_key
        )
        if intent.sha256 != expected["intent_sha256"]:
            raise RecoveryJournalError(f"preserved {model_key} intent changed")
        _validate_preserved_outcome(
            outcome,
            model_key=model_key,
            expected_response_sha256=expected["response_sha256"],
            expected_intent_sha256=intent.sha256,
            expected_manifest_sha256=manifest.sha256,
            parent_head=parent_head,
        )
        if outcome.sha256 != expected["outcome_sha256"]:
            raise RecoveryJournalError(f"preserved {model_key} outcome changed")
        preserved.append(outcome)

    stranded_path = f"budget/intents/{contract.CANDIDATE_ID}/cohere/attempt-1.json"
    stranded = records[stranded_path]
    if stranded.sha256 != contract.STRANDED_COHERE_INTENT_SHA256:
        raise RecoveryJournalError("stranded Cohere intent changed")
    _validate_stranded_intent(
        stranded, expected_manifest_sha256=manifest.sha256, parent_head=parent_head
    )

    parent_reserve = 0
    for relative in generation_intents:
        reserve = records[relative].payload.get("reserved_cost_microdollars")
        if not isinstance(reserve, int) or isinstance(reserve, bool) or reserve < 0:
            raise RecoveryJournalError("parent reservation is malformed")
        parent_reserve += reserve
    if parent_reserve != contract.PARENT_RESERVED_MICRODOLLARS:
        raise RecoveryJournalError("parent reserved-cost total changed")

    return ParentEvidence(
        private_root=parent_root,
        manifest=manifest,
        preserved_outcomes=(preserved[0], preserved[1]),
        stranded_intent=stranded,
        reserved_microdollars=parent_reserve,
    )

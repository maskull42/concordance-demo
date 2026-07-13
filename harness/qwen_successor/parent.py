"""Authenticate the two immutable parent lanes used by the Qwen successor."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from rule3.budget import JournalRecord

from concordance_recovery import contract as first_contract
from concordance_recovery.journal import (
    GENERATION_INTENT_SCHEMA,
    GENERATION_OUTCOME_SCHEMA,
    MANIFEST_SCHEMA,
    RecoveryJournalError,
    read_record,
    require_timestamp,
)
from concordance_recovery.lock import (
    load_and_validate_recovery_lock,
    validate_parent_private_evidence,
)
from concordance_recovery.parent import (
    ParentEvidence as Rule3Evidence,
    validate_parent_evidence,
)

from . import contract


FIRST_CLAIM_SCHEMA = "concordance-recovery-parent-claim-1.0.0"


@dataclass(frozen=True)
class ParentEvidence:
    """Verified evidence from Rule 3 and its first successor lane."""

    rule3: Rule3Evidence
    cohere_outcome: JournalRecord
    stranded_qwen_intent: JournalRecord
    first_manifest: JournalRecord
    first_claim: JournalRecord
    reserved_microdollars: int


def _exact_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _exact_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _exact_equal(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def _expected_parent_contract() -> dict[str, Any]:
    bindings = [
        {"path": path, "sha256": digest}
        for path, digest in sorted(contract.FIRST_PRIVATE_SHA256.items())
    ]
    return {
        "first_execution_head": contract.FIRST_EXECUTION_HEAD,
        "first_lock_sha256": contract.FIRST_LOCK_SHA256,
        "first_private_root": contract.FIRST_PRIVATE_ROOT,
        "first_private_bindings": bindings,
        "first_private_binding_count": len(bindings),
        "first_claim": {
            "path": contract.FIRST_CLAIM_PATH,
            "sha256": contract.FIRST_CLAIM_SHA256,
        },
        "first_phase_lock_path": contract.FIRST_CLAIM_LOCK_PATH,
        "required_absent": list(contract.FIRST_REQUIRED_ABSENT),
        "first_extra_empty_directories": list(contract.FIRST_EXTRA_EMPTY_DIRECTORIES),
        "exact_file_and_directory_inventory_required": True,
        "rule3_lock_sha256": contract.RULE3_LOCK_SHA256,
        "rule3_plan_sha256": contract.RULE3_PLAN_SHA256,
    }


def _validate_successor_parent_contract(successor_lock: dict[str, Any] | None) -> None:
    if successor_lock is None:
        return
    if not isinstance(successor_lock, dict) or not _exact_equal(
        successor_lock.get("parent"), _expected_parent_contract()
    ):
        raise RecoveryJournalError("Qwen successor parent contract changed")


def _expected_directories(files: set[str]) -> set[str]:
    result: set[str] = set()
    for relative in files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def _add_directory_with_parents(result: set[str], relative: str) -> None:
    directory = PurePosixPath(relative)
    while directory != PurePosixPath("."):
        result.add(directory.as_posix())
        directory = directory.parent


def _inspect_exact_private_tree(root: Path, expected_files: set[str]) -> None:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise RecoveryJournalError(
            f"first recovery private root cannot be inspected: {error}"
        ) from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RecoveryJournalError(
            "first recovery private root must remain a real mode-0700 directory"
        )

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        entries = sorted(root.rglob("*"))
    except OSError as error:
        raise RecoveryJournalError(
            f"first recovery inventory cannot be read: {error}"
        ) from error
    for path in entries:
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as error:
            raise RecoveryJournalError(
                f"first recovery inventory cannot inspect {relative}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RecoveryJournalError("first recovery private tree contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise RecoveryJournalError(
                    "first recovery private directory mode changed"
                )
            actual_directories.add(relative)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise RecoveryJournalError(
                "first recovery artifact must remain a single-link mode-0600 "
                "regular file"
            )
        actual_files.add(relative)

    expected_directories = _expected_directories(expected_files)
    for relative in contract.FIRST_EXTRA_EMPTY_DIRECTORIES:
        _add_directory_with_parents(expected_directories, relative)
    if actual_files != expected_files or actual_directories != expected_directories:
        raise RecoveryJournalError("first recovery exact private inventory changed")


def _read_first_records(root: Path) -> dict[str, JournalRecord]:
    expected = set(contract.FIRST_PRIVATE_SHA256)
    _inspect_exact_private_tree(root, expected)
    records: dict[str, JournalRecord] = {}
    for relative, digest in sorted(contract.FIRST_PRIVATE_SHA256.items()):
        record = read_record(root / relative, f"first recovery evidence {relative}")
        if record.sha256 != digest:
            raise RecoveryJournalError(f"first recovery evidence changed: {relative}")
        records[relative] = record
    _inspect_exact_private_tree(root, expected)
    return records


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RecoveryJournalError(
            f"first recovery absence cannot be inspected: {error}"
        ) from error
    return True


def _validate_required_absences(first_root: Path) -> None:
    for relative in contract.FIRST_REQUIRED_ABSENT:
        if _path_exists(first_root / relative):
            raise RecoveryJournalError(
                f"required first recovery absence changed: {relative}"
            )


def _validate_claim_area(repository_root: Path) -> JournalRecord:
    claim_path = repository_root / contract.FIRST_CLAIM_PATH
    lock_path = repository_root / contract.FIRST_CLAIM_LOCK_PATH
    claim_root = claim_path.parent
    try:
        root_metadata = claim_root.lstat()
    except OSError as error:
        raise RecoveryJournalError(
            f"first recovery claim root cannot be inspected: {error}"
        ) from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RecoveryJournalError(
            "first recovery claim root must remain a real mode-0700 directory"
        )
    actual: set[Path] = set()
    for path in claim_root.iterdir():
        if path.is_dir() or path.is_symlink():
            raise RecoveryJournalError("first recovery claim inventory changed")
        actual.add(path.resolve())
    if actual != {claim_path.resolve(), lock_path.resolve()}:
        raise RecoveryJournalError("first recovery claim inventory changed")

    try:
        metadata = lock_path.lstat()
    except OSError as error:
        raise RecoveryJournalError(
            f"first recovery phase lock cannot be inspected: {error}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise RecoveryJournalError("first recovery phase lock changed")

    claim = read_record(claim_path, "first recovery cross-lane claim")
    if claim.sha256 != contract.FIRST_CLAIM_SHA256:
        raise RecoveryJournalError("first recovery claim changed")
    return claim


def _require_fields(
    value: Mapping[str, Any], expected: Mapping[str, Any], label: str
) -> None:
    if any(not _exact_equal(value.get(key), item) for key, item in expected.items()):
        raise RecoveryJournalError(f"{label} lineage changed")


def _validate_first_claim(record: JournalRecord) -> None:
    value = record.payload
    _require_fields(
        value,
        {
            "schema_version": FIRST_CLAIM_SCHEMA,
            "status": "parent-stranded-intent-claimed-once",
            "recovery_id": first_contract.RECOVERY_ID,
            "pool_id": contract.POOL_ID,
            "candidate_id": contract.CANDIDATE_ID,
            "phase": contract.PHASE,
            "git_head": contract.FIRST_EXECUTION_HEAD,
            "recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
            "authorization_receipt_sha256": contract.FIRST_AUTHORIZATION_SHA256,
            "pricing_recheck_receipt_sha256": contract.FIRST_PRICING_RECHECK_SHA256,
            "parent_lock_sha256": contract.RULE3_LOCK_SHA256,
            "parent_manifest_sha256": first_contract.PARENT_MANIFEST_SHA256,
            "parent_stranded_intent": {
                "path": first_contract.STRANDED_COHERE["intent_path"],
                "sha256": first_contract.STRANDED_COHERE_INTENT_SHA256,
            },
            "replacement_model_key": "cohere",
            "replacement_semantic_attempt_number": 2,
        },
        "first recovery claim",
    )
    require_timestamp(value.get("claimed_at"), "first recovery claim time")


def _validate_first_manifest(record: JournalRecord) -> None:
    value = record.payload
    _require_fields(
        value,
        {
            "schema_version": MANIFEST_SCHEMA,
            "status": "complete-six-model-fresh-preflight",
            "recovery_id": first_contract.RECOVERY_ID,
            "pool_id": contract.POOL_ID,
            "candidate_id": contract.CANDIDATE_ID,
            "phase": contract.PHASE,
            "git_head": contract.FIRST_EXECUTION_HEAD,
            "recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
            "authorization_receipt_sha256": contract.FIRST_AUTHORIZATION_SHA256,
            "pricing_recheck_receipt_sha256": contract.FIRST_PRICING_RECHECK_SHA256,
            "parent_lock_sha256": contract.RULE3_LOCK_SHA256,
            "parent_manifest_sha256": first_contract.PARENT_MANIFEST_SHA256,
            "parent_claim": {
                "path": contract.FIRST_CLAIM_PATH,
                "sha256": contract.FIRST_CLAIM_SHA256,
            },
            "parent_manifest": {
                "path": first_contract.PARENT_MANIFEST_PATH,
                "sha256": first_contract.PARENT_MANIFEST_SHA256,
            },
        },
        "first recovery manifest",
    )
    require_timestamp(value.get("sealed_at"), "first recovery manifest time")
    outcomes = value.get("preflight_outcomes")
    if not isinstance(outcomes, list) or [
        item.get("model_key") if isinstance(item, dict) else None for item in outcomes
    ] != list(first_contract.TARGET_MODEL_KEYS):
        raise RecoveryJournalError("first recovery preflight manifest changed")


def _validate_cohere_outcome(record: JournalRecord) -> None:
    value = record.payload
    _require_fields(
        value,
        {
            "schema_version": GENERATION_OUTCOME_SCHEMA,
            "status": "success",
            "recovery_id": first_contract.RECOVERY_ID,
            "pool_id": contract.POOL_ID,
            "candidate_id": contract.CANDIDATE_ID,
            "phase": contract.PHASE,
            "git_head": contract.FIRST_EXECUTION_HEAD,
            "recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
            "authorization_receipt_sha256": contract.FIRST_AUTHORIZATION_SHA256,
            "pricing_recheck_receipt_sha256": contract.FIRST_PRICING_RECHECK_SHA256,
            "parent_lock_sha256": contract.RULE3_LOCK_SHA256,
            "parent_manifest_sha256": first_contract.PARENT_MANIFEST_SHA256,
            "parent_claim": {
                "path": contract.FIRST_CLAIM_PATH,
                "sha256": contract.FIRST_CLAIM_SHA256,
            },
            "cell_id": f"{contract.CANDIDATE_ID}:cohere:default:answer",
            "model_key": "cohere",
            "provider": "cohere",
            "route": "cohere-direct",
            "requested_model_id": "command-a-plus-05-2026",
            "semantic_attempt_number": 2,
            "manifest": {
                "path": contract.FIRST_MANIFEST_PATH,
                "sha256": contract.FIRST_MANIFEST_SHA256,
            },
            "preflight_outcome": {
                "path": "preflight/outcomes/cohere/attempt-1.json",
                "sha256": contract.FIRST_PRIVATE_SHA256[
                    "preflight/outcomes/cohere/attempt-1.json"
                ],
            },
            "intent": {
                "path": "generation/intents/cohere/attempt-2.json",
                "sha256": contract.FIRST_PRIVATE_SHA256[
                    "generation/intents/cohere/attempt-2.json"
                ],
            },
            "raw_response": {
                "path": "generation/raw-responses/cohere/attempt-2.json",
                "sha256": contract.FIRST_PRIVATE_SHA256[
                    "generation/raw-responses/cohere/attempt-2.json"
                ],
            },
            "response_sha256": contract.COHERE_RESPONSE_SHA256,
        },
        "preserved Cohere outcome",
    )
    response = value.get("response_text")
    if (
        not isinstance(response, str)
        or not response.strip()
        or hashlib.sha256(response.encode("utf-8")).hexdigest()
        != contract.COHERE_RESPONSE_SHA256
    ):
        raise RecoveryJournalError("preserved Cohere response hash changed")
    cost = value.get("cost")
    if not isinstance(cost, dict) or cost.get("reserved_microdollars") != 0:
        raise RecoveryJournalError("preserved Cohere reservation changed")


def _validate_qwen_intent(record: JournalRecord) -> int:
    value = record.payload
    _require_fields(
        value,
        {
            "schema_version": GENERATION_INTENT_SCHEMA,
            "status": "reserved-before-generation-post",
            "recovery_id": first_contract.RECOVERY_ID,
            "pool_id": contract.POOL_ID,
            "candidate_id": contract.CANDIDATE_ID,
            "phase": contract.PHASE,
            "git_head": contract.FIRST_EXECUTION_HEAD,
            "recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
            "authorization_receipt_sha256": contract.FIRST_AUTHORIZATION_SHA256,
            "pricing_recheck_receipt_sha256": contract.FIRST_PRICING_RECHECK_SHA256,
            "parent_lock_sha256": contract.RULE3_LOCK_SHA256,
            "parent_manifest_sha256": first_contract.PARENT_MANIFEST_SHA256,
            "parent_claim": {
                "path": contract.FIRST_CLAIM_PATH,
                "sha256": contract.FIRST_CLAIM_SHA256,
            },
            "cell_id": f"{contract.CANDIDATE_ID}:qwen:default:answer",
            "model_key": "qwen",
            "provider": "deepinfra",
            "route": "deepinfra",
            "requested_model_id": "Qwen/Qwen3.5-397B-A17B",
            "semantic_attempt_number": 1,
            "reserved_cost_microdollars": contract.RESERVED_PER_POST["qwen"],
            "manifest": {
                "path": contract.FIRST_MANIFEST_PATH,
                "sha256": contract.FIRST_MANIFEST_SHA256,
            },
            "preflight_outcome": {
                "path": "preflight/outcomes/qwen/attempt-1.json",
                "sha256": contract.FIRST_PRIVATE_SHA256[
                    "preflight/outcomes/qwen/attempt-1.json"
                ],
            },
            "replacement_of_parent_intent": None,
        },
        "stranded Qwen intent",
    )
    require_timestamp(value.get("created_at"), "stranded Qwen intent time")
    return contract.RESERVED_PER_POST["qwen"]


def _first_generation_reserve(records: Mapping[str, JournalRecord]) -> int:
    intent_paths = sorted(
        path
        for path in records
        if path.startswith("generation/intents/") and path.endswith(".json")
    )
    if intent_paths != [
        "generation/intents/cohere/attempt-2.json",
        contract.QWEN_STRANDED_INTENT_PATH,
    ]:
        raise RecoveryJournalError("first recovery generation intent inventory changed")
    total = 0
    for path in intent_paths:
        reserve = records[path].payload.get("reserved_cost_microdollars")
        if not isinstance(reserve, int) or isinstance(reserve, bool) or reserve < 0:
            raise RecoveryJournalError("first recovery reservation is malformed")
        total += reserve
    return total


def _require_first_execution_ancestor(repository_root: Path, current_head: Any) -> None:
    if not isinstance(current_head, str):
        raise RecoveryJournalError("first recovery public source validation lacks HEAD")
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run(
        [
            "/usr/bin/git",
            "merge-base",
            "--is-ancestor",
            contract.FIRST_EXECUTION_HEAD,
            current_head,
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        env=environment,
    )
    if result.returncode != 0:
        raise RecoveryJournalError(
            "first recovery execution commit is not an ancestor of current HEAD"
        )


def validate_parent_snapshot(
    repository_root: Path, successor_lock: dict[str, Any] | None = None
) -> ParentEvidence:
    """Validate both sealed parents without reading a credential or using network."""

    root = Path(repository_root).resolve()
    _validate_successor_parent_contract(successor_lock)
    try:
        first_lock = load_and_validate_recovery_lock(
            root,
            require_committed=True,
            require_parent_private=True,
        )
        validate_parent_private_evidence(first_lock)
        rule3 = validate_parent_evidence(root, first_lock.lock)
    except Exception as error:
        if isinstance(error, RecoveryJournalError):
            raise
        raise RecoveryJournalError(
            f"sealed first recovery parent no longer validates: {error}"
        ) from error
    if first_lock.lock_sha256 != contract.FIRST_LOCK_SHA256:
        raise RecoveryJournalError("first recovery lock hash changed")
    _require_first_execution_ancestor(root, first_lock.git_head)

    first_root = root / contract.FIRST_PRIVATE_ROOT
    records = _read_first_records(first_root)
    _validate_required_absences(first_root)
    claim = _validate_claim_area(root)

    manifest = records[contract.FIRST_MANIFEST_PATH]
    cohere = records[contract.COHERE_OUTCOME_PATH]
    qwen = records[contract.QWEN_STRANDED_INTENT_PATH]
    _validate_first_claim(claim)
    _validate_first_manifest(manifest)
    _validate_cohere_outcome(cohere)
    qwen_reserve = _validate_qwen_intent(qwen)

    first_reserved = _first_generation_reserve(records)
    if first_reserved != qwen_reserve:
        raise RecoveryJournalError("first recovery reserved-cost total changed")
    combined = rule3.reserved_microdollars + first_reserved
    if combined != contract.INHERITED_RESERVED_MICRODOLLARS:
        raise RecoveryJournalError("inherited reserved-cost total changed")

    return ParentEvidence(
        rule3=rule3,
        cohere_outcome=cohere,
        stranded_qwen_intent=qwen,
        first_manifest=manifest,
        first_claim=claim,
        reserved_microdollars=combined,
    )


__all__ = ("ParentEvidence", "validate_parent_snapshot")

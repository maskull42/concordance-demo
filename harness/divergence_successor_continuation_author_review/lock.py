"""Write-once public lock for the v2 continuation author-review handoff."""

from __future__ import annotations

import copy
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor_continuation import contract as base_contract

from . import anchor, contract, review


class AuthorReviewLockError(contract.AuthorReviewContractError):
    """The public v2 review lock is absent, stale, or incomplete."""


@dataclass(frozen=True)
class LockContext:
    repository_root: Path
    lock: dict[str, Any]
    lock_bytes: bytes
    lock_sha256: str
    git_head: str | None


def _public_binding(root: Path, relative: str) -> dict[str, str]:
    try:
        payload = anchor._public_bytes(root, relative, "review-lock public input")
    except anchor.ReviewAnchorError as error:
        raise AuthorReviewLockError(str(error)) from error
    return {"path": relative, "sha256": sha256_bytes(payload)}


def _private_binding(root: Path, relative: str) -> dict[str, str]:
    try:
        payload = anchor._private_bytes(root, relative, "review-lock private input")
    except anchor.ReviewAnchorError as error:
        raise AuthorReviewLockError(str(error)) from error
    return {"path": relative, "sha256": sha256_bytes(payload)}


def build_lock(repository_root: Path | str) -> dict[str, Any]:
    """Bind the exact historical evidence and sealed consensus, without a threshold."""

    root = contract.repository_root(repository_root)
    anchored = anchor.verify_anchor(root)
    first = review.verify_first_pass(root)
    anchor_value = anchored["anchor"]
    base_payload = anchor._public_bytes(root, contract.BASE_LOCK_PATH, "base review lock")
    try:
        base_value = base_contract.parent_contract.parse_json_bytes(
            base_payload, "base review lock"
        )
    except base_contract.parent_contract.ContractError as error:
        raise AuthorReviewLockError(str(error)) from error
    base_bindings = base_value.get("bindings") if isinstance(base_value, dict) else None
    if not isinstance(base_bindings, dict):
        raise AuthorReviewLockError("base continuation lock bindings are missing")
    current_base_bindings: dict[str, dict[str, str]] = {}
    for name in ("lock_schema", "question", "protocol", "models_config"):
        expected = base_bindings.get(name)
        if not isinstance(expected, dict) or not isinstance(expected.get("path"), str):
            raise AuthorReviewLockError(f"base continuation {name} binding is malformed")
        current = _public_binding(root, expected["path"])
        if current["sha256"] != expected.get("sha256"):
            raise AuthorReviewLockError(f"base continuation {name} bytes changed")
        current_base_bindings[name] = current
    if (
        anchor_value["base_continuation_lock"]["sha256"]
        != contract.BASE_LOCK_SHA256
        or anchor_value["composite"]["sha256"] != contract.COMPOSITE_SHA256
        or anchor_value["blind_packet"]["sha256"]
        != contract.BLIND_PACKET_SHA256
    ):
        raise AuthorReviewLockError("review anchor differs from the approved lineage")
    source_bindings = [_public_binding(root, path) for path in contract.SOURCE_PATHS]
    locked_assets = [
        _public_binding(root, path) for path in contract.LOCKED_REVIEW_ASSET_PATHS
    ]
    versioned_assets = [
        _public_binding(root, path) for path in contract.VERSIONED_REVIEW_ASSET_PATHS
    ]
    return {
        "schema_version": contract.LOCK_SCHEMA_VERSION,
        "status": contract.LOCK_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "private_root": contract.PRIVATE_ROOT_RELATIVE,
        "lineage": {
            "historical_git_head": anchored["historical_git_head"],
            "base_public_bindings": current_base_bindings,
            "base_continuation_lock": copy.deepcopy(
                anchor_value["base_continuation_lock"]
            ),
            "composite": copy.deepcopy(anchor_value["composite"]),
            "blind_packet": copy.deepcopy(anchor_value["blind_packet"]),
            "blind_crosswalk": copy.deepcopy(anchor_value["blind_crosswalk"]),
            "blind_key_sha256": anchor_value["blind_key"]["sha256"],
            "question_sha256": anchor_value["lineage_bindings"]["question_sha256"],
            "plan_sha256": anchor_value["lineage_bindings"]["plan_sha256"],
            "authorization_receipt_sha256": anchor_value["lineage_bindings"][
                "authorization_receipt_sha256"
            ],
            "pricing_recheck_receipt_sha256": anchor_value["lineage_bindings"][
                "pricing_recheck_receipt_sha256"
            ],
            "offline_correction_sha256": anchor_value["lineage_bindings"][
                "model_manifest_sha256"
            ],
        },
        "private_inputs": {
            "review_anchor": _private_binding(
                root, f"{contract.ANCHOR_ROOT}/anchor.json"
            ),
            "first_pass_mapping": _private_binding(
                root, f"{contract.FIRST_PASS_ROOT}/mapping.json"
            ),
            "first_pass_receipt": _private_binding(
                root, f"{contract.FIRST_PASS_ROOT}/receipt.json"
            ),
        },
        "consensus": {
            "mapper_role": "two-independent-blinded-mappers-consensus-v2",
            "item_count": contract.ITEM_COUNT,
            "packet_order_preserved": True,
            "assignment_hashes": [
                item["assignment_sha256"]
                for item in first["receipt"]["assignment_hashes"]
            ],
        },
        "review_contract": {
            "reviewer": copy.deepcopy(contract.REVIEWER),
            "author_packet_schema": contract.AUTHOR_PACKET_SCHEMA,
            "author_export_schema": contract.AUTHOR_EXPORT_SCHEMA,
            "author_receipt_schema": contract.AUTHOR_RECEIPT_SCHEMA,
            "decision_values": ["confirm", "correct"],
            "reason_codes": sorted(contract.REASON_CODES),
            "identity_blinded": True,
            "canonical_position_ids_allowed": False,
            "response_text_exported": False,
            "author_packet_requires_committed_review_lock": True,
        },
        "offline_policy": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
            "threshold_evaluation": {"performed": False},
        },
        "assets": {
            "locked_sources": locked_assets,
            "versioned_derivatives": versioned_assets,
            "css_derivation": "byte-identical",
            "javascript_derivation": "three-exact-literal-v2-adapter",
        },
        "sources": source_bindings,
    }


def _difference(actual: Any, expected: Any, path: str = "lock") -> str | None:
    if type(actual) is not type(expected):
        return f"{path} type differs"
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            return f"{path} fields differ"
        for key in expected:
            found = _difference(actual[key], expected[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(expected, list):
        if len(actual) != len(expected):
            return f"{path} length differs"
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            found = _difference(left, right, f"{path}[{index}]")
            if found:
                return found
        return None
    return None if actual == expected else f"{path} differs"


def _git(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )


def _require_sources_committed(
    root: Path, value: dict[str, Any], *, include_lock: bool
) -> str:
    head_result = _git(root, ["rev-parse", "HEAD"])
    if head_result.returncode:
        raise AuthorReviewLockError("Git HEAD cannot be read")
    head = head_result.stdout.decode().strip()
    paths = [item["path"] for item in value["sources"]]
    paths.extend(item["path"] for item in value["assets"]["locked_sources"])
    paths.extend(item["path"] for item in value["assets"]["versioned_derivatives"])
    paths.extend(
        item["path"] for item in value["lineage"]["base_public_bindings"].values()
    )
    paths.append(contract.BASE_LOCK_PATH)
    if include_lock:
        paths.append(contract.LOCK_PATH)
    paths = list(dict.fromkeys(paths))
    status = _git(root, ["status", "--porcelain", "--untracked-files=all", "--", *paths])
    if status.returncode or status.stdout.strip():
        raise AuthorReviewLockError("review lock sources must be committed and clean")
    for relative in paths:
        disk = anchor._public_bytes(root, relative, "committed review source")
        committed = _git(root, ["show", f"{head}:{relative}"])
        if committed.returncode or committed.stdout != disk:
            raise AuthorReviewLockError(f"{relative} differs from committed HEAD")
    return head


def _parse_lock(root: Path) -> tuple[dict[str, Any], bytes]:
    try:
        payload = anchor._public_bytes(root, contract.LOCK_PATH, "v2 review lock")
    except anchor.ReviewAnchorError as error:
        raise AuthorReviewLockError(str(error)) from error
    try:
        value = base_contract.parent_contract.parse_json_bytes(payload, "v2 review lock")
    except base_contract.parent_contract.ContractError as error:
        raise AuthorReviewLockError(str(error)) from error
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        raise AuthorReviewLockError("v2 review lock must be one canonical JSON object")
    return value, payload


def load_and_validate_lock(
    repository_root: Path | str, *, require_committed: bool = False
) -> LockContext:
    root = contract.repository_root(repository_root)
    value, payload = _parse_lock(root)
    expected = build_lock(root)
    difference = _difference(value, expected)
    if difference:
        raise AuthorReviewLockError(difference)
    git_head = (
        _require_sources_committed(root, value, include_lock=True)
        if require_committed
        else None
    )
    return LockContext(root, value, payload, sha256_bytes(payload), git_head)


def write_lock(repository_root: Path | str) -> LockContext:
    root = contract.repository_root(repository_root)
    value = build_lock(root)
    _require_sources_committed(root, value, include_lock=False)
    path = root / contract.LOCK_PATH
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return load_and_validate_lock(root)


__all__ = (
    "AuthorReviewLockError",
    "LockContext",
    "build_lock",
    "load_and_validate_lock",
    "write_lock",
)

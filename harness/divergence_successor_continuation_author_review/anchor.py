"""Pre-commit historical anchor for the already verified blind review inputs."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor import review as parent_review
from divergence_successor_continuation import contract as base_contract
from divergence_successor_continuation import lock as base_lock
from divergence_successor_continuation import review as base_review
from private_directory_publication import (
    PublicationSpec,
    recover_private_directory,
)

from . import contract


class ReviewAnchorError(contract.AuthorReviewContractError):
    """The historical blind-review anchor is missing or has changed."""


def _strict_bytes(path: Path, label: str, *, mode: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReviewAnchorError(f"{label} cannot be inspected: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
    ):
        raise ReviewAnchorError(
            f"{label} must be a single-link regular mode-{mode:04o} file"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        if (
            (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
            or current.st_nlink != 1
        ):
            raise ReviewAnchorError(f"{label} changed while opening")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _private_bytes(root: Path, relative: str, label: str) -> bytes:
    path = root / relative
    cursor = path.parent
    while True:
        try:
            metadata = cursor.lstat()
        except OSError as error:
            raise ReviewAnchorError(f"{label} parent cannot be inspected: {error}") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ReviewAnchorError(f"{label} parents must be real mode-0700 directories")
        if cursor.name == ".pilot":
            break
        if cursor == cursor.parent:
            raise ReviewAnchorError(f"{label} is outside the private hierarchy")
        cursor = cursor.parent
    return _strict_bytes(path, label, mode=0o600)


def _public_bytes(root: Path, relative: str, label: str) -> bytes:
    path = root / relative
    try:
        payload = base_contract.parent_contract.read_regular_file(root, relative)
        metadata = path.lstat()
    except (OSError, base_contract.parent_contract.ContractError) as error:
        raise ReviewAnchorError(str(error)) from error
    if metadata.st_nlink != 1:
        raise ReviewAnchorError(f"{label} must not be hard-linked")
    return payload


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


def _source_bindings(lock_value: dict[str, Any]) -> list[dict[str, str]]:
    sources = lock_value.get("execution_sources")
    if not isinstance(sources, list) or not sources:
        raise ReviewAnchorError("base continuation lock has no source bindings")
    result: list[dict[str, str]] = []
    for item in sources:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("sha256"), str)
        ):
            raise ReviewAnchorError("base continuation source binding is malformed")
        result.append(dict(item))
    return result


def _binding(path: str, payload: bytes) -> dict[str, str]:
    return {"path": path, "sha256": sha256_bytes(payload)}


def build_anchor(repository_root: Path | str, *, anchored_at: str) -> dict[str, Any]:
    """Use the current historical HEAD-sensitive verifier exactly once."""

    root = contract.repository_root(repository_root)
    try:
        parent_review._valid_timestamp(anchored_at, "review anchor time")
        context = base_lock.load_and_validate_lock(root, require_committed=True)
        blind = base_review.verify_blind_materials(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ReviewAnchorError(str(error)) from error
    base_payload = _public_bytes(root, contract.BASE_LOCK_PATH, "base continuation lock")
    composite_payload = _private_bytes(root, contract.COMPOSITE_PATH, "continuation composite")
    packet_payload = _private_bytes(root, contract.BLIND_PACKET_PATH, "blind packet")
    crosswalk_path = f"{contract.BLIND_ROOT_RELATIVE}/crosswalk.json"
    key_path = f"{contract.BLIND_ROOT_RELATIVE}/hmac.key"
    crosswalk_payload = _private_bytes(root, crosswalk_path, "blind crosswalk")
    key_payload = _private_bytes(root, key_path, "blind HMAC key")
    if (
        context.lock_sha256 != contract.BASE_LOCK_SHA256
        or sha256_bytes(base_payload) != contract.BASE_LOCK_SHA256
        or sha256_bytes(composite_payload) != contract.COMPOSITE_SHA256
        or blind["packet_sha256"] != contract.BLIND_PACKET_SHA256
        or sha256_bytes(packet_payload) != contract.BLIND_PACKET_SHA256
        or blind["crosswalk_sha256"] != sha256_bytes(crosswalk_payload)
        or blind["key_sha256"] != sha256_bytes(key_payload)
    ):
        raise ReviewAnchorError("historical review inputs differ from their approved hashes")
    bindings = blind["crosswalk"].get("bindings")
    if not isinstance(bindings, dict):
        raise ReviewAnchorError("verified crosswalk bindings are missing")
    if (
        bindings.get("git_head") != context.git_head
        or bindings.get("lock_sha256") != contract.BASE_LOCK_SHA256
        or bindings.get("run_receipt_sha256") != contract.COMPOSITE_SHA256
    ):
        raise ReviewAnchorError("verified blind lineage differs from the historical HEAD")
    source_bindings = _source_bindings(context.lock)
    return {
        "schema_version": contract.ANCHOR_SCHEMA,
        "status": contract.ANCHOR_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "anchored_at": anchored_at,
        "historical_git_head": context.git_head,
        "base_continuation_lock": _binding(contract.BASE_LOCK_PATH, base_payload),
        "composite": _binding(contract.COMPOSITE_PATH, composite_payload),
        "blind_packet": _binding(contract.BLIND_PACKET_PATH, packet_payload),
        "blind_crosswalk": _binding(crosswalk_path, crosswalk_payload),
        "blind_key": _binding(key_path, key_payload),
        "lineage_bindings": dict(bindings),
        "base_execution_sources": source_bindings,
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
            "threshold_evaluation": {"performed": False},
        },
    }


def _anchor_path(root: Path) -> Path:
    return root / contract.ANCHOR_ROOT / "anchor.json"


def _validate_anchor_shape(value: dict[str, Any]) -> None:
    expected_keys = {
        "schema_version",
        "status",
        "pool_id",
        "candidate_id",
        "anchored_at",
        "historical_git_head",
        "base_continuation_lock",
        "composite",
        "blind_packet",
        "blind_crosswalk",
        "blind_key",
        "lineage_bindings",
        "base_execution_sources",
        "offline_attestation",
    }
    if set(value) != expected_keys:
        raise ReviewAnchorError("review anchor fields differ from the v2 contract")
    if (
        value.get("schema_version") != contract.ANCHOR_SCHEMA
        or value.get("status") != contract.ANCHOR_STATUS
        or value.get("pool_id") != contract.POOL_ID
        or value.get("candidate_id") != contract.CANDIDATE_ID
        or value.get("base_continuation_lock", {}).get("sha256")
        != contract.BASE_LOCK_SHA256
        or value.get("composite", {}).get("sha256") != contract.COMPOSITE_SHA256
        or value.get("blind_packet", {}).get("sha256")
        != contract.BLIND_PACKET_SHA256
        or value.get("offline_attestation")
        != {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
            "threshold_evaluation": {"performed": False},
        }
    ):
        raise ReviewAnchorError("review anchor values differ from the v2 contract")
    parent_review._valid_timestamp(value.get("anchored_at"), "review anchor time")


def verify_anchor(repository_root: Path | str) -> dict[str, Any]:
    """Authenticate anchored bytes without invoking the HEAD-sensitive verifier."""

    root = contract.repository_root(repository_root)
    anchor_root = root / contract.ANCHOR_ROOT
    try:
        metadata = anchor_root.lstat()
    except OSError as error:
        raise ReviewAnchorError(f"review anchor directory cannot be inspected: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {item.name for item in anchor_root.iterdir()} != {"anchor.json"}
    ):
        raise ReviewAnchorError("review anchor directory is not exact and private")
    payload = _private_bytes(root, f"{contract.ANCHOR_ROOT}/anchor.json", "review anchor")
    try:
        value = base_contract.parent_contract.parse_json_bytes(payload, "review anchor")
    except base_contract.parent_contract.ContractError as error:
        raise ReviewAnchorError(str(error)) from error
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        raise ReviewAnchorError("review anchor must be one canonical JSON object")
    if sha256_bytes(payload) != contract.ANCHOR_SHA256:
        raise ReviewAnchorError("review anchor hash differs from the frozen v2 anchor")
    _validate_anchor_shape(value)

    for field in (
        "base_continuation_lock",
        "composite",
        "blind_packet",
        "blind_crosswalk",
        "blind_key",
    ):
        binding = value[field]
        if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
            raise ReviewAnchorError(f"review anchor {field} binding is malformed")
        mode = 0o644 if field == "base_continuation_lock" else 0o600
        actual = (
            _public_bytes(root, binding["path"], field)
            if mode == 0o644
            else _private_bytes(root, binding["path"], field)
        )
        if sha256_bytes(actual) != binding["sha256"]:
            raise ReviewAnchorError(f"review anchor {field} bytes changed")

    historical = value.get("historical_git_head")
    if not isinstance(historical, str) or len(historical) != 40:
        raise ReviewAnchorError("review anchor historical Git HEAD is malformed")
    exists = _git(root, ["cat-file", "-e", f"{historical}^{{commit}}"])
    if exists.returncode:
        raise ReviewAnchorError("review anchor historical Git commit is unavailable")
    anchored_sources = value.get("base_execution_sources")
    if not isinstance(anchored_sources, list) or not anchored_sources:
        raise ReviewAnchorError("review anchor source list is missing")
    for binding in anchored_sources:
        if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
            raise ReviewAnchorError("review anchor source binding is malformed")
        historical_blob = _git(root, ["show", f"{historical}:{binding['path']}"])
        if (
            historical_blob.returncode
            or sha256_bytes(historical_blob.stdout) != binding["sha256"]
            or sha256_bytes(_public_bytes(root, binding["path"], "anchored source"))
            != binding["sha256"]
        ):
            raise ReviewAnchorError(f"anchored source changed: {binding['path']}")
    lineage = value.get("lineage_bindings")
    if (
        not isinstance(lineage, dict)
        or lineage.get("git_head") != historical
        or lineage.get("lock_sha256") != contract.BASE_LOCK_SHA256
        or lineage.get("run_receipt_sha256") != contract.COMPOSITE_SHA256
    ):
        raise ReviewAnchorError("review anchor lineage bindings changed")
    return {
        "anchor": value,
        "anchor_sha256": sha256_bytes(payload),
        "blind_packet_sha256": value["blind_packet"]["sha256"],
        "composite_sha256": value["composite"]["sha256"],
        "historical_git_head": historical,
    }


def publish_anchor(repository_root: Path | str, *, anchored_at: str) -> Path:
    root = contract.repository_root(repository_root)
    value = build_anchor(root, anchored_at=anchored_at)
    target = root / contract.ANCHOR_ROOT
    payloads = {"anchor.json": canonical_json_bytes(value)}
    if sha256_bytes(payloads["anchor.json"]) != contract.ANCHOR_SHA256:
        raise ReviewAnchorError("prospective review anchor differs from the frozen v2 anchor")

    def verify_during_publication(target_root: Path) -> None:
        # The crash-safe publisher temporarily hard-links staged payloads into
        # the destination.  Verify exact bytes here; the strict single-link
        # check runs immediately after staging cleanup.
        candidate = target_root / "anchor.json"
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or stat.S_IMODE(candidate.stat().st_mode) != 0o600
            or candidate.read_bytes() != payloads["anchor.json"]
        ):
            raise ReviewAnchorError("published review anchor bytes changed")

    try:
        published = parent_review._publish(target, payloads, verify_during_publication)
        verify_anchor(root)
        return published
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ReviewAnchorError(str(error)) from error


def recover_anchor_publication(repository_root: Path | str) -> str:
    """Recover only the owned anchor publication after an interrupted write."""

    root = contract.repository_root(repository_root)
    target = root / contract.ANCHOR_ROOT
    spec = PublicationSpec(
        target_root=target,
        claim_path=target.parent / ".anchor-v2.publish-claim",
        staging_parent=target.parent,
        claim_schema_version="divergence-successor-review-publication-claim-1.0.0",
        owner_schema_version="divergence-successor-review-publication-owner-1.0.0",
        expected_files=("anchor.json",),
    )

    def verify_during_recovery(target_root: Path) -> None:
        candidate = target_root / "anchor.json"
        payload = candidate.read_bytes()
        try:
            value = base_contract.parent_contract.parse_json_bytes(
                payload, "recovering review anchor"
            )
        except base_contract.parent_contract.ContractError as error:
            raise ReviewAnchorError(str(error)) from error
        if not isinstance(value, dict) or payload != canonical_json_bytes(value):
            raise ReviewAnchorError("recovering review anchor is not canonical")
        _validate_anchor_shape(value)

    try:
        status = recover_private_directory(spec, verify_during_recovery)
    except RuntimeError as error:
        raise ReviewAnchorError(str(error)) from error
    if status == "completed":
        verify_anchor(root)
    return status


__all__ = (
    "ReviewAnchorError",
    "build_anchor",
    "publish_anchor",
    "recover_anchor_publication",
    "verify_anchor",
)

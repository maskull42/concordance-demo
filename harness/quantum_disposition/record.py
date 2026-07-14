"""Build, publish, and verify the private Quantum withdrawal receipt."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from private_directory_publication import (
    PrivateDirectoryPublicationError,
    PublicationSpec,
    publish_private_directory,
)

from . import contract
from .parent import (
    QuantumDispositionError,
    QuantumHistory,
    _binding,
    _reject_duplicate_keys,
    verify_quantum_history,
)


GIT_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _git(repository_root: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=repository_root,
        check=False,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )


def _git_output(repository_root: Path, arguments: list[str], label: str) -> bytes:
    result = _git(repository_root, arguments)
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise QuantumDispositionError(message or f"{label} failed")
    return result.stdout


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise QuantumDispositionError(f"{label} is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QuantumDispositionError(f"{label} is malformed") from error
    if parsed.utcoffset() is None:
        raise QuantumDispositionError(f"{label} must include a timezone")
    return value


def _execution_commit(value: Any) -> str:
    if not isinstance(value, str) or not GIT_OBJECT_RE.fullmatch(value):
        raise QuantumDispositionError("disposition execution commit is malformed")
    return value


def source_bindings_at_commit(
    repository_root: Path | str, execution_commit: str
) -> tuple[dict[str, str], ...]:
    """Hash the disposition sources as stored in one historical commit."""

    root = Path(repository_root).resolve()
    commit = _execution_commit(execution_commit)
    _git_output(root, ["cat-file", "-e", f"{commit}^{{commit}}"], "Git commit check")
    bindings = []
    for relative in contract.SOURCE_PATHS:
        payload = _git_output(
            root,
            ["show", f"{commit}:{relative}"],
            f"historical source read for {relative}",
        )
        bindings.append(
            {"path": relative, "sha256": contract.sha256_bytes(payload)}
        )
    return tuple(bindings)


def committed_source_bindings(
    repository_root: Path | str,
) -> tuple[str, tuple[dict[str, str], ...]]:
    """Require every execution source to be tracked, committed, and clean."""

    root = Path(repository_root).resolve()
    head = _git_output(root, ["rev-parse", "HEAD"], "Git HEAD read").decode().strip()
    _execution_commit(head)
    status = _git_output(
        root,
        ["status", "--porcelain", "--untracked-files=all", "--", *contract.SOURCE_PATHS],
        "source cleanliness check",
    )
    if status.strip():
        raise QuantumDispositionError(
            "disposition sources must be tracked, committed, and clean"
        )
    committed = source_bindings_at_commit(root, head)
    for binding in committed:
        relative = binding["path"]
        disk, _ = _binding(root, root, relative, private=False)
        if disk["sha256"] != binding["sha256"]:
            raise QuantumDispositionError(
                f"disposition source {relative} differs from committed HEAD"
            )
    return head, committed


def _validate_source_bindings(
    bindings: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, str], ...]:
    values = tuple(dict(item) for item in bindings)
    expected_paths = list(contract.SOURCE_PATHS)
    if [item.get("path") for item in values] != expected_paths:
        raise QuantumDispositionError("disposition source order or inventory changed")
    for item in values:
        if (
            set(item) != {"path", "sha256"}
            or not isinstance(item["sha256"], str)
            or not contract.SHA256_RE.fullmatch(item["sha256"])
        ):
            raise QuantumDispositionError("disposition source binding is malformed")
    return values


def disposition_value(
    *,
    history: QuantumHistory,
    recorded_at: str,
    execution_commit: str,
    execution_sources: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    timestamp = _timestamp(recorded_at, "disposition recording time")
    commit = _execution_commit(execution_commit)
    sources = _validate_source_bindings(execution_sources)
    return {
        "schema_version": contract.SCHEMA_VERSION,
        "status": contract.STATUS,
        "recorded_at": timestamp,
        "execution_commit": commit,
        "execution_sources": [dict(item) for item in sources],
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "candidate_role": "historical-fallback",
        "user_instruction": {
            "verbatim": contract.USER_INSTRUCTION,
            "sha256": contract.USER_INSTRUCTION_SHA256,
            "authorized_scope": (
                "quantum-withdrawal-and-replacement-source-research-and-build"
            ),
        },
        "disposition": {
            "classification": "private-stress-test",
            "selection_eligible": False,
            "publication_eligible": False,
            "production_eligible": False,
            "author_review_complete": False,
            "threshold_evaluation_performed": False,
            "historical_artifacts_preserved": True,
            "responses_preserved": True,
            "deletion_authorized": False,
            "replacement_research_and_build_authorized": True,
            "successor_provider_calls_authorized": False,
        },
        "historical_lineage": history.value(),
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "model_calls": 0,
            "response_text_decoded": False,
        },
    }


def build_disposition(
    repository_root: Path | str,
    *,
    recorded_at: str,
    execution_commit: str,
    execution_sources: Iterable[Mapping[str, Any]] | None = None,
    history: QuantumHistory | None = None,
    require_git_history: bool = True,
) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    verified_history = history or verify_quantum_history(
        root, require_git=require_git_history
    )
    sources = (
        source_bindings_at_commit(root, execution_commit)
        if execution_sources is None
        else tuple(execution_sources)
    )
    return disposition_value(
        history=verified_history,
        recorded_at=recorded_at,
        execution_commit=execution_commit,
        execution_sources=sources,
    )


def _output_paths(repository_root: Path) -> tuple[Path, Path, Path]:
    output = repository_root / contract.DISPOSITION_ROOT_RELATIVE
    parent = output.parent
    claim = parent / contract.DISPOSITION_CLAIM_NAME
    return output, parent, claim


def _publication_spec(repository_root: Path) -> PublicationSpec:
    output, parent, claim = _output_paths(repository_root)
    return PublicationSpec(
        target_root=output,
        claim_path=claim,
        staging_parent=parent,
        claim_schema_version="quantum-disposition-publication-1.0.0",
        owner_schema_version="quantum-disposition-owner-1.0.0",
        expected_files=(contract.DISPOSITION_FILE,),
    )


def _read_receipt(repository_root: Path) -> tuple[dict[str, Any], bytes]:
    output, _, _ = _output_paths(repository_root)
    try:
        metadata = output.lstat()
    except OSError as error:
        raise QuantumDispositionError(
            f"Quantum disposition output cannot be inspected: {error}"
        ) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise QuantumDispositionError(
            "Quantum disposition output must be a real mode-0700 directory"
        )
    try:
        entries = list(output.iterdir())
    except OSError as error:
        raise QuantumDispositionError(
            f"Quantum disposition output cannot be enumerated: {error}"
        ) from error
    if [entry.name for entry in entries] != [contract.DISPOSITION_FILE]:
        raise QuantumDispositionError("Quantum disposition output inventory changed")
    _, payload = _binding(
        repository_root,
        output,
        contract.DISPOSITION_FILE,
        private=True,
        retain=True,
    )
    assert payload is not None
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise QuantumDispositionError(
            f"Quantum disposition receipt is malformed: {error}"
        ) from error
    if not isinstance(value, dict):
        raise QuantumDispositionError("Quantum disposition receipt must be an object")
    return value, payload


def verify_disposition(repository_root: Path | str) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    value, payload = _read_receipt(root)
    recorded_at = value.get("recorded_at")
    execution_commit = value.get("execution_commit")
    _timestamp(recorded_at, "disposition recording time")
    commit = _execution_commit(execution_commit)
    sources = source_bindings_at_commit(root, commit)
    expected = build_disposition(
        root,
        recorded_at=recorded_at,
        execution_commit=commit,
        execution_sources=sources,
        require_git_history=True,
    )
    if value != expected or payload != contract.canonical_json_bytes(expected):
        raise QuantumDispositionError(
            "Quantum disposition receipt differs from the immutable contract"
        )
    return {
        "status": "verified-withdrawn-private-stress-test-nonpublication",
        "candidate_id": contract.CANDIDATE_ID,
        "receipt_sha256": contract.sha256_bytes(payload),
        "selection_eligible": False,
        "publication_eligible": False,
    }


def preview_disposition(repository_root: Path | str) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    history = verify_quantum_history(root, require_git=True)
    output, _, _ = _output_paths(root)
    return {
        "status": "ready-to-record-withdrawal",
        "candidate_id": contract.CANDIDATE_ID,
        "journal_file_count": len(history.journal_bindings),
        "review_file_count": len(history.review_bindings),
        "successful_outcome_count": 8,
        "selection_eligible_after_recording": False,
        "publication_eligible_after_recording": False,
        "receipt_exists": os.path.lexists(output),
        "network_requests": 0,
        "environment_variables_read": 0,
        "model_calls": 0,
    }


def _verify_publication_link(target: Path, expected_payload: bytes) -> None:
    """Verify the publisher's temporary hardlink before staging is removed.

    ``private_directory_publication`` links each staged file into the output,
    verifies it, and only then removes staging.  The file therefore has two
    links during this callback and exactly one after publication completes.
    The ordinary receipt verifier remains stricter and accepts only one link.
    """

    metadata = target.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {entry.name for entry in target.iterdir()} != {contract.DISPOSITION_FILE}
    ):
        raise QuantumDispositionError("temporary disposition output is malformed")
    path = target / contract.DISPOSITION_FILE
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 2
    ):
        raise QuantumDispositionError(
            "temporary disposition receipt is not the publisher-owned hardlink"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_nlink != 2
        ):
            raise QuantumDispositionError(
                "temporary disposition receipt changed while it was opened"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    if b"".join(chunks) != expected_payload:
        raise QuantumDispositionError("temporary disposition receipt bytes changed")


def write_disposition(repository_root: Path | str) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    output, _, _ = _output_paths(root)
    if os.path.lexists(output):
        return verify_disposition(root)
    execution_commit, sources = committed_source_bindings(root)
    history = verify_quantum_history(root, require_git=True)
    recorded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    value = disposition_value(
        history=history,
        recorded_at=recorded_at,
        execution_commit=execution_commit,
        execution_sources=sources,
    )
    payloads = {contract.DISPOSITION_FILE: contract.canonical_json_bytes(value)}
    spec = _publication_spec(root)

    def verify(target: Path) -> None:
        _verify_publication_link(target, payloads[contract.DISPOSITION_FILE])

    try:
        publish_private_directory(spec, payloads, verify)
    except PrivateDirectoryPublicationError as error:
        raise QuantumDispositionError(str(error)) from error
    return verify_disposition(root)


__all__ = (
    "build_disposition",
    "committed_source_bindings",
    "disposition_value",
    "preview_disposition",
    "source_bindings_at_commit",
    "verify_disposition",
    "write_disposition",
)

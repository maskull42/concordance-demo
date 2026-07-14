"""Authenticate the immutable Quantum fallback without decoding its responses."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from . import contract


MAX_PRIVATE_ARTIFACT_BYTES = 64 * 1024 * 1024


class QuantumDispositionError(RuntimeError):
    """Raised when the historical Quantum lineage or disposition is unsafe."""


@dataclass(frozen=True)
class QuantumHistory:
    repository_root: Path
    private_root: Path
    public_bindings: tuple[dict[str, str], ...]
    upstream_private_bindings: tuple[dict[str, str], ...]
    journal_bindings: tuple[dict[str, str], ...]
    journal_tree_sha256: str
    review_bindings: tuple[dict[str, str], ...]
    review_tree_sha256: str

    def value(self) -> dict[str, Any]:
        return {
            "rule3_public_bindings": [dict(item) for item in self.public_bindings],
            "upstream_private_bindings": [
                dict(item) for item in self.upstream_private_bindings
            ],
            "quantum_private_root": contract.PRIVATE_ROOT_RELATIVE,
            "quantum_journal": {
                "file_count": len(self.journal_bindings),
                "tree_sha256": self.journal_tree_sha256,
                "files": [dict(item) for item in self.journal_bindings],
            },
            "review_stage": {
                "status": "stopped-after-sealed-first-pass-author-packet-unreviewed",
                "file_count": len(self.review_bindings),
                "tree_sha256": self.review_tree_sha256,
                "files": [dict(item) for item in self.review_bindings],
                "author_review_present": False,
                "threshold_evaluation_present": False,
            },
            "run": {
                "path": f"{contract.PRIVATE_ROOT_RELATIVE}/run.json",
                "sha256": contract.RUN_SHA256,
                "execution_commit": contract.RUN_EXECUTION_COMMIT,
                "successful_outcome_count": 8,
            },
            "review_preparation_commit": contract.REVIEW_PREPARATION_COMMIT,
            "budget": dict(contract.BUDGET),
            "network_contract": dict(contract.NETWORK_CONTRACT),
        }


def _relative(value: str, label: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != value
        or not relative.parts
    ):
        raise QuantumDispositionError(f"{label} path is malformed")
    return relative


def _private_parents(repository_root: Path, path: Path, label: str) -> None:
    pilot = repository_root / ".pilot"
    try:
        path.relative_to(pilot)
    except ValueError as error:
        raise QuantumDispositionError(
            f"{label} escapes the fixed private hierarchy"
        ) from error
    cursor = path.parent
    parents: list[Path] = []
    while True:
        parents.append(cursor)
        if cursor == pilot:
            break
        if cursor == cursor.parent:
            raise QuantumDispositionError(
                f"{label} escapes the fixed private hierarchy"
            )
        cursor = cursor.parent
    for directory in reversed(parents):
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise QuantumDispositionError(
                f"{label} private parent cannot be inspected: {error}"
            ) from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise QuantumDispositionError(
                f"{label} private parents must remain real mode-0700 directories"
            )


def _open_regular(path: Path, label: str, *, private: bool) -> int:
    try:
        before = path.lstat()
    except OSError as error:
        raise QuantumDispositionError(f"{label} cannot be inspected: {error}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or (private and stat.S_IMODE(before.st_mode) != 0o600)
    ):
        privacy = " single-link mode-0600" if private else " single-link"
        raise QuantumDispositionError(
            f"{label} must be a{privacy} regular non-symlink file"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise QuantumDispositionError(f"{label} cannot be opened safely: {error}") from error
    current = os.fstat(descriptor)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        or (private and stat.S_IMODE(current.st_mode) != 0o600)
    ):
        os.close(descriptor)
        raise QuantumDispositionError(f"{label} changed while it was opened")
    return descriptor


def _read_and_hash(
    repository_root: Path, path: Path, label: str, *, private: bool, retain: bool
) -> tuple[str, bytes | None]:
    if private:
        _private_parents(repository_root, path, label)
    descriptor = _open_regular(path, label, private=private)
    digest = hashlib.sha256()
    retained: list[bytes] | None = [] if retain else None
    size = 0
    try:
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_PRIVATE_ARTIFACT_BYTES:
                raise QuantumDispositionError(f"{label} is unexpectedly large")
            digest.update(chunk)
            if retained is not None:
                retained.append(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), b"".join(retained) if retained is not None else None


def _binding(
    repository_root: Path,
    base: Path,
    relative: str,
    *,
    private: bool,
    expected_sha256: str | None = None,
    retain: bool = False,
) -> tuple[dict[str, str], bytes | None]:
    safe = _relative(relative, "artifact")
    path = base.joinpath(*safe.parts)
    digest, payload = _read_and_hash(
        repository_root, path, relative, private=private, retain=retain
    )
    if expected_sha256 is not None and digest != expected_sha256:
        raise QuantumDispositionError(f"{relative} differs from its immutable binding")
    return {"path": relative, "sha256": digest}, payload


def _tree_bindings(
    repository_root: Path,
    private_root: Path,
    paths: Iterable[str],
    expected_tree_sha256: str,
    label: str,
) -> tuple[tuple[dict[str, str], ...], str]:
    bindings = tuple(
        _binding(
            repository_root,
            private_root,
            relative,
            private=True,
        )[0]
        for relative in paths
    )
    tree_sha = contract.sha256_bytes(
        contract.canonical_json_bytes([dict(item) for item in bindings])
    )
    if tree_sha != expected_tree_sha256:
        raise QuantumDispositionError(f"{label} differs from its immutable tree binding")
    return bindings, tree_sha


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QuantumDispositionError(f"duplicate JSON key in Quantum run: {key}")
        result[key] = value
    return result


def expected_run() -> dict[str, Any]:
    return {
        "schema_version": "concordance-quantum-fallback-run-1.0.0",
        "status": "complete-eight-successes",
        "created_at": contract.RUN_CREATED_AT,
        "git_head": contract.RUN_EXECUTION_COMMIT,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "question_sha256": contract.QUESTION_SHA256,
        "plan_sha256": contract.PLAN_SHA256,
        "authorization": {
            "path": "authorization.json",
            "sha256": contract.AUTHORIZATION_SHA256,
        },
        "pricing_recheck": {
            "path": "pricing-recheck.json",
            "sha256": contract.PRICING_RECHECK_SHA256,
        },
        "manifest": {
            "path": "manifest.json",
            "sha256": contract.MANIFEST_SHA256,
        },
        "successful_outcome_count": 8,
        "failed_model_keys": [],
        "outcomes": [
            {
                "model_key": model_key,
                "semantic_attempt_number": 1,
                "path": f"generation/outcomes/{model_key}/attempt-1.json",
                "sha256": contract.OUTCOME_SHA256[model_key],
            }
            for model_key in contract.MODEL_ORDER
        ],
        "budget": dict(contract.BUDGET),
        "network_contract": dict(contract.NETWORK_CONTRACT),
    }


def _validate_run(repository_root: Path, private_root: Path) -> None:
    _, payload = _binding(
        repository_root,
        private_root,
        "run.json",
        private=True,
        expected_sha256=contract.RUN_SHA256,
        retain=True,
    )
    assert payload is not None
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise QuantumDispositionError(f"Quantum run is malformed: {error}") from error
    if value != expected_run():
        raise QuantumDispositionError("Quantum run semantics differ from approval")


def _validate_stopped_review(private_root: Path) -> None:
    candidate_root = private_root / contract.CANDIDATE_REVIEW_ROOT
    try:
        entries = list(candidate_root.iterdir())
    except OSError as error:
        raise QuantumDispositionError(
            f"Quantum review root cannot be inspected: {error}"
        ) from error
    for entry in entries:
        name = entry.name
        if any(
            name == prefix or name.startswith(prefix)
            for prefix in contract.FORBIDDEN_REVIEW_PREFIXES
        ):
            raise QuantumDispositionError(
                "Quantum author review or threshold evaluation exists after withdrawal"
            )


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


def _require_git_ancestry(repository_root: Path) -> None:
    for commit in (contract.RUN_EXECUTION_COMMIT, contract.REVIEW_PREPARATION_COMMIT):
        exists = _git(repository_root, ["cat-file", "-e", f"{commit}^{{commit}}"])
        ancestor = _git(repository_root, ["merge-base", "--is-ancestor", commit, "HEAD"])
        if exists.returncode != 0 or ancestor.returncode != 0:
            raise QuantumDispositionError(
                f"historical execution commit {commit} is not an ancestor of HEAD"
            )


def verify_quantum_history(
    repository_root: Path | str, *, require_git: bool = True
) -> QuantumHistory:
    """Verify the exact frozen lineage without decoding any response-bearing file.

    The sole JSON payload decoded here is ``run.json``.  Every intent, raw
    response, model outcome, blind packet, and review HTML file is streamed only
    through SHA-256.
    """

    root = Path(repository_root).resolve()
    private_root = root / contract.PRIVATE_ROOT_RELATIVE
    if require_git:
        _require_git_ancestry(root)

    public_bindings = []
    for spec in contract.PUBLIC_BINDINGS:
        binding, _ = _binding(
            root,
            root,
            spec.path,
            private=False,
            expected_sha256=spec.sha256,
        )
        public_bindings.append(binding)

    upstream = []
    for spec in contract.UPSTREAM_PRIVATE_BINDINGS:
        binding, _ = _binding(
            root,
            root,
            spec.path,
            private=True,
            expected_sha256=spec.sha256,
        )
        upstream.append(binding)

    journal, journal_tree = _tree_bindings(
        root,
        private_root,
        contract.journal_paths(),
        contract.JOURNAL_TREE_SHA256,
        "Quantum journal",
    )
    _validate_run(root, private_root)
    review, review_tree = _tree_bindings(
        root,
        private_root,
        contract.REVIEW_PATHS,
        contract.REVIEW_TREE_SHA256,
        "Quantum review stage",
    )
    _validate_stopped_review(private_root)

    return QuantumHistory(
        repository_root=root,
        private_root=private_root,
        public_bindings=tuple(public_bindings),
        upstream_private_bindings=tuple(upstream),
        journal_bindings=journal,
        journal_tree_sha256=journal_tree,
        review_bindings=review,
        review_tree_sha256=review_tree,
    )


__all__ = (
    "QuantumDispositionError",
    "QuantumHistory",
    "expected_run",
    "verify_quantum_history",
)

"""Hash-only public gate for the continuation threshold evaluator."""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor_continuation import contract as continuation_contract
from divergence_successor_continuation_author_review import anchor
from divergence_successor_continuation_author_review import lock as review_lock
from divergence_successor_continuation_author_review import review

from . import contract


class EvaluationLockError(contract.EvaluationContractError):
    """The public evaluation gate is absent, dirty, or changed."""


@dataclass(frozen=True)
class LockContext:
    repository_root: Path
    value: dict[str, Any]
    payload: bytes
    sha256: str
    committed_git_head: str | None


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


def _public_binding(root: Path, relative: str) -> dict[str, str]:
    try:
        payload = anchor._public_bytes(root, relative, "evaluation public input")
    except anchor.ReviewAnchorError as error:
        raise EvaluationLockError(str(error)) from error
    return {"path": relative, "sha256": sha256_bytes(payload)}


def _private_binding(root: Path, relative: str) -> dict[str, str]:
    try:
        payload = anchor._private_bytes(root, relative, "evaluation private input")
    except anchor.ReviewAnchorError as error:
        raise EvaluationLockError(str(error)) from error
    return {"path": relative, "sha256": sha256_bytes(payload)}


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = continuation_contract.parent_contract.parse_json_bytes(payload, label)
    except continuation_contract.parent_contract.ContractError as error:
        raise EvaluationLockError(str(error)) from error
    if not isinstance(value, dict):
        raise EvaluationLockError(f"{label} must be a JSON object")
    return value


def _head(root: Path) -> str:
    result = _git(root, ["rev-parse", "HEAD"])
    if result.returncode:
        raise EvaluationLockError("Git HEAD cannot be read")
    value = result.stdout.decode().strip()
    if len(value) != 40:
        raise EvaluationLockError("Git HEAD is malformed")
    return value


def _require_paths_at_commit(root: Path, paths: list[str], git_head: str) -> None:
    exists = _git(root, ["cat-file", "-e", f"{git_head}^{{commit}}"])
    if exists.returncode:
        raise EvaluationLockError("evaluator source commit is unavailable")
    status = _git(
        root, ["status", "--porcelain", "--untracked-files=all", "--", *paths]
    )
    if status.returncode or status.stdout.strip():
        raise EvaluationLockError("evaluator sources must be committed and clean")
    for relative in paths:
        try:
            disk = anchor._public_bytes(root, relative, "committed evaluator source")
        except anchor.ReviewAnchorError as error:
            raise EvaluationLockError(str(error)) from error
        historical = _git(root, ["show", f"{git_head}:{relative}"])
        current = _git(root, ["show", f"HEAD:{relative}"])
        if (
            historical.returncode
            or current.returncode
            or historical.stdout != disk
            or current.stdout != disk
        ):
            raise EvaluationLockError(
                f"evaluator source is not committed exactly: {relative}"
            )


def _source_bindings(root: Path, source_head: str) -> list[dict[str, str]]:
    paths = list(contract.SOURCE_PATHS)
    _require_paths_at_commit(root, paths, source_head)
    return [_public_binding(root, path) for path in paths]


def _threshold(root: Path) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
    binding = _public_binding(root, contract.SUCCESSOR_LOCK_PATH)
    if binding["sha256"] != contract.SUCCESSOR_LOCK_SHA256:
        raise EvaluationLockError("frozen successor lock changed")
    payload = anchor._public_bytes(root, contract.SUCCESSOR_LOCK_PATH, "successor lock")
    value = _json(payload, "successor lock")
    threshold = value.get("threshold")
    if threshold != contract.FROZEN_THRESHOLD:
        raise EvaluationLockError(
            "successor threshold differs from the frozen contract"
        )
    question = value.get("bindings", {}).get("question")
    if not isinstance(question, dict) or set(question) != {"path", "sha256"}:
        raise EvaluationLockError("successor question binding is malformed")
    current_question = _public_binding(root, question["path"])
    if current_question != question:
        raise EvaluationLockError("successor question changed")
    return dict(threshold), binding, current_question


def _build(root: Path, source_head: str) -> dict[str, Any]:
    review_context = review_lock.load_and_validate_lock(root, require_committed=True)
    if review_context.lock_sha256 != contract.REVIEW_LOCK_SHA256:
        raise EvaluationLockError("continuation review lock changed")
    anchored = anchor.verify_anchor(root)
    author = review.verify_author_review(root)
    threshold, successor_binding, question_binding = _threshold(root)
    anchor_value = anchored["anchor"]
    return {
        "schema_version": contract.LOCK_SCHEMA_VERSION,
        "status": contract.LOCK_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "private_root": contract.PRIVATE_ROOT_RELATIVE,
        "evaluation_root": contract.EVALUATION_ROOT,
        "lineage": {
            "successor_lock": successor_binding,
            "continuation_lock": dict(anchor_value["base_continuation_lock"]),
            "continuation_review_lock": _public_binding(
                root, contract.REVIEW_LOCK_PATH
            ),
            "question": question_binding,
            "review_anchor": _private_binding(
                root,
                f"{review_context.lock['private_inputs']['review_anchor']['path']}",
            ),
            "blind_packet": dict(anchor_value["blind_packet"]),
            "blind_crosswalk": dict(anchor_value["blind_crosswalk"]),
            "blind_key_sha256": anchor_value["blind_key"]["sha256"],
            "sealed_author_review": _private_binding(
                root,
                f"{review_context.lock['private_root']}/candidates/"
                f"{contract.CANDIDATE_ID}/author-review-v2/review.json",
            ),
            "sealed_author_review_receipt": _private_binding(
                root,
                f"{review_context.lock['private_root']}/candidates/"
                f"{contract.CANDIDATE_ID}/author-review-v2/receipt.json",
            ),
            "sealed_author_review_sha256": author["review_sha256"],
            "sealed_author_review_receipt_sha256": author["receipt_sha256"],
        },
        "threshold_contract": {
            "source_path": contract.SUCCESSOR_LOCK_PATH,
            "source_field": "$.threshold",
            "sha256": sha256_bytes(canonical_json_bytes(threshold)),
            **threshold,
        },
        "evaluator": {
            "source_git_head": source_head,
            "sources": _source_bindings(root, source_head),
        },
        "offline_policy": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        },
    }


def build_lock(repository_root: Path | str) -> dict[str, Any]:
    """Build the hash-only gate after evaluator sources are committed."""

    root = contract.repository_root(repository_root)
    source_head = _head(root)
    return _build(root, source_head)


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


def _parse_lock(root: Path) -> tuple[dict[str, Any], bytes]:
    path = root / contract.LOCK_PATH
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvaluationLockError(
            f"evaluation lock cannot be inspected: {error}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_nlink != 1
    ):
        raise EvaluationLockError(
            "evaluation lock must be a single-link regular mode-0644 file"
        )
    try:
        payload = anchor._public_bytes(root, contract.LOCK_PATH, "evaluation lock")
    except anchor.ReviewAnchorError as error:
        raise EvaluationLockError(str(error)) from error
    value = _json(payload, "evaluation lock")
    if payload != canonical_json_bytes(value):
        raise EvaluationLockError("evaluation lock must be canonical JSON")
    return value, payload


def _require_lock_committed(root: Path, payload: bytes, source_head: str) -> str:
    _require_paths_at_commit(root, list(contract.SOURCE_PATHS), source_head)
    status = _git(
        root,
        ["status", "--porcelain", "--untracked-files=all", "--", contract.LOCK_PATH],
    )
    committed = _git(root, ["show", f"HEAD:{contract.LOCK_PATH}"])
    if (
        status.returncode
        or status.stdout.strip()
        or committed.returncode
        or committed.stdout != payload
    ):
        raise EvaluationLockError("evaluation lock must be committed and clean")
    introduced = _git(
        root,
        ["log", "--diff-filter=A", "--format=%H", "--", contract.LOCK_PATH],
    )
    commits = (
        introduced.stdout.decode().splitlines() if not introduced.returncode else []
    )
    if len(commits) != 1:
        raise EvaluationLockError(
            "evaluation lock must have one append-only introduction commit"
        )
    lock_head = commits[0]
    historical = _git(root, ["show", f"{lock_head}:{contract.LOCK_PATH}"])
    parent = _git(root, ["rev-parse", f"{lock_head}^"])
    if (
        historical.returncode
        or historical.stdout != payload
        or parent.returncode
        or parent.stdout.decode().strip() != source_head
    ):
        raise EvaluationLockError(
            "evaluation lock commit must directly follow its evaluator source commit"
        )
    return lock_head


def load_and_validate_lock(
    repository_root: Path | str, *, require_committed: bool = False
) -> LockContext:
    root = contract.repository_root(repository_root)
    value, payload = _parse_lock(root)
    source_head = value.get("evaluator", {}).get("source_git_head")
    if not isinstance(source_head, str) or len(source_head) != 40:
        raise EvaluationLockError("evaluation lock source Git HEAD is malformed")
    expected = _build(root, source_head)
    difference = _difference(value, expected)
    if difference:
        raise EvaluationLockError(difference)
    committed_head = (
        _require_lock_committed(root, payload, source_head)
        if require_committed
        else None
    )
    return LockContext(root, value, payload, sha256_bytes(payload), committed_head)


def write_lock(repository_root: Path | str) -> LockContext:
    root = contract.repository_root(repository_root)
    value = build_lock(root)
    path = root / contract.LOCK_PATH
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o644)
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


def verify_historical_evaluation_head(
    repository_root: Path | str, git_head: str, lock_payload: bytes
) -> None:
    root = contract.repository_root(repository_root)
    if not isinstance(git_head, str) or len(git_head) != 40:
        raise EvaluationLockError("evaluation Git HEAD is malformed")
    exists = _git(root, ["cat-file", "-e", f"{git_head}^{{commit}}"])
    historical_lock = _git(root, ["show", f"{git_head}:{contract.LOCK_PATH}"])
    if (
        exists.returncode
        or historical_lock.returncode
        or historical_lock.stdout != lock_payload
    ):
        raise EvaluationLockError(
            "evaluation Git HEAD does not bind the committed gate"
        )
    for relative in contract.SOURCE_PATHS:
        historical = _git(root, ["show", f"{git_head}:{relative}"])
        current = anchor._public_bytes(root, relative, "historical evaluator source")
        if historical.returncode or historical.stdout != current:
            raise EvaluationLockError(f"evaluation Git HEAD does not bind {relative}")


def commit_timestamp(repository_root: Path | str, git_head: str) -> str:
    root = contract.repository_root(repository_root)
    result = _git(root, ["show", "-s", "--format=%cI", git_head])
    if result.returncode:
        raise EvaluationLockError("evaluation lock commit time cannot be read")
    value = result.stdout.decode().strip()
    if not value:
        raise EvaluationLockError("evaluation lock commit time is empty")
    return value


__all__ = (
    "EvaluationLockError",
    "LockContext",
    "build_lock",
    "commit_timestamp",
    "load_and_validate_lock",
    "verify_historical_evaluation_head",
    "write_lock",
)

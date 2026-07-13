"""Offline Rule 3 threshold evaluation and two-candidate terminal gating."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

from rule3 import contract, review
from rule3.budget import ensure_private_root


EVALUATION_SCHEMA = "rule3-evaluation-receipt-1.0.0"
FALLBACK_ELIGIBILITY_SCHEMA = "rule3-fallback-eligibility-1.0.0"
TERMINAL_SCHEMA = "rule3-terminal-receipt-1.0.0"
PRIORITY_ID = contract.CANDIDATES[0]["id"]
FALLBACK_ID = contract.CANDIDATES[1]["id"]


class Rule3EvaluationError(RuntimeError):
    """Raised when the reviewed evidence cannot support a terminal decision."""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _descriptor_bytes(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _open_pinned_regular(
    parent_descriptor: int, name: str, label: str
) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise Rule3EvaluationError(
            f"{label} cannot be opened safely: {error}"
        ) from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(descriptor)
        raise Rule3EvaluationError(f"{label} must be a mode-0600 regular file")
    return descriptor, metadata


def _clone_pinned_no_replace(
    source_descriptor: int,
    parent_descriptor: int,
    target_name: str,
    payload: bytes,
) -> None:
    """Publish exact open bytes without re-resolving the preparation path."""
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        clone = getattr(libc, "fclonefileat", None)
        if clone is not None:
            clone.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
            clone.restype = ctypes.c_int
            if (
                clone(
                    source_descriptor,
                    parent_descriptor,
                    os.fsencode(target_name),
                    0,
                )
                == 0
            ):
                return
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise Rule3EvaluationError(
                    f"write-once private artifact already exists: {target_name}"
                )
            unsupported = {
                errno.ENOSYS,
                errno.EXDEV,
                errno.EPERM,
                getattr(errno, "ENOTSUP", errno.EINVAL),
                getattr(errno, "EOPNOTSUPP", errno.EINVAL),
            }
            if error_number not in unsupported:
                raise Rule3EvaluationError(
                    "private artifact clone publication failed: "
                    f"{os.strerror(error_number)}"
                )

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        target_descriptor = os.open(target_name, flags, 0o600, dir_fd=parent_descriptor)
    except FileExistsError as error:
        raise Rule3EvaluationError(
            f"write-once private artifact already exists: {target_name}"
        ) from error
    except OSError as error:
        raise Rule3EvaluationError(
            f"private artifact publication failed: {error}"
        ) from error
    try:
        with os.fdopen(target_descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(target_descriptor)
    finally:
        os.close(target_descriptor)


def _write_once_private_json(path: Path, value: Mapping[str, Any]) -> str:
    """Publish one complete private file from a pinned, no-follow preparation."""
    ensure_private_root(path.parent)
    payload = contract.canonical_json_bytes(value)
    preparation = path.parent / f".{path.name}.prepare"
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(path.parent, directory_flags)
    preparation_descriptor: int | None = None
    try:
        if os.path.lexists(preparation):
            preparation_descriptor, preparation_metadata = _open_pinned_regular(
                parent_descriptor, preparation.name, "private preparation"
            )
            existing = _descriptor_bytes(preparation_descriptor)
            if existing != payload:
                raise Rule3EvaluationError(
                    "private preparation changed; preserve it for inspection"
                )
        else:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            preparation_descriptor = os.open(
                preparation.name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
            preparation_metadata = os.fstat(preparation_descriptor)
            with os.fdopen(preparation_descriptor, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(preparation_descriptor)
            _fsync_directory(path.parent)

        try:
            named_metadata = os.stat(
                preparation.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise Rule3EvaluationError(
                f"private preparation cannot be inspected: {error}"
            ) from error
        if (
            named_metadata.st_dev,
            named_metadata.st_ino,
        ) != (
            preparation_metadata.st_dev,
            preparation_metadata.st_ino,
        ):
            raise Rule3EvaluationError(
                "private preparation path changed after it was opened"
            )
        _clone_pinned_no_replace(
            preparation_descriptor, parent_descriptor, path.name, payload
        )
        _fsync_directory(path.parent)
        published_descriptor, _ = _open_pinned_regular(
            parent_descriptor, path.name, f"private artifact {path.name}"
        )
        try:
            published = _descriptor_bytes(published_descriptor)
            if published != payload:
                raise Rule3EvaluationError("published private artifact changed")
            os.fsync(published_descriptor)
        finally:
            os.close(published_descriptor)
        current_preparation = os.stat(
            preparation.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            current_preparation.st_dev,
            current_preparation.st_ino,
        ) != (
            preparation_metadata.st_dev,
            preparation_metadata.st_ino,
        ):
            raise Rule3EvaluationError(
                "private preparation path changed after publication"
            )
        os.unlink(preparation.name, dir_fd=parent_descriptor)
        _fsync_directory(path.parent)
    finally:
        if preparation_descriptor is not None:
            os.close(preparation_descriptor)
        os.close(parent_descriptor)
    return review._sha(payload)


def _preparation_path(path: Path) -> Path:
    return path.parent / f".{path.name}.prepare"


def _pending_created_at(path: Path) -> str:
    preparation = _preparation_path(path)
    if not os.path.lexists(preparation):
        return review.utc_now()
    value, _ = review._read_private_object(preparation, f"{path.name} preparation")
    created = value.get("created_at")
    review._valid_timestamp(created, f"{path.name} preparation time")
    return created


def _recover_linked_preparation(path: Path) -> None:
    """Remove only an exact preparation left after a completed publication."""
    preparation = _preparation_path(path)
    if not os.path.lexists(preparation):
        return
    published = review._read_private_bytes(path, f"published {path.name}")
    pending = review._read_private_bytes(preparation, f"{path.name} preparation")
    if published != pending:
        raise Rule3EvaluationError(
            "completed private publication has a foreign preparation"
        )
    preparation.unlink()
    _fsync_directory(path.parent)


def evaluate_divergence(
    primary_positions: Sequence[str | None],
    allowed_positions: Sequence[str],
) -> dict[str, Any]:
    """Apply the exact precommitted 8-response Rule 3 threshold."""
    if len(primary_positions) != contract.REQUIRED_COMPLETED_RESPONSES:
        raise Rule3EvaluationError(
            "threshold evaluation requires exactly eight reviewed responses"
        )
    allowed = tuple(allowed_positions)
    if not allowed or len(set(allowed)) != len(allowed):
        raise Rule3EvaluationError("canonical position IDs must be unique")
    if any(value is not None and value not in allowed for value in primary_positions):
        raise Rule3EvaluationError(
            "reviewed primary falls outside the exact canonical map"
        )
    counts = Counter(value for value in primary_positions if value is not None)
    non_null = sum(counts.values())
    represented = len(counts)
    maximum = max(counts.values(), default=0)
    failures: list[str] = []
    if non_null < contract.MINIMUM_NON_NULL_ENDORSEMENTS:
        failures.append("fewer-than-six-non-null-primary-endorsements")
    if represented < contract.MINIMUM_DISTINCT_POSITIONS:
        failures.append("fewer-than-three-represented-positions")
    if maximum > contract.MAXIMUM_ENDORSEMENTS_PER_POSITION:
        failures.append("one-position-has-more-than-four-primary-endorsements")
    return {
        "evidence_complete": True,
        "author_review_complete": True,
        "qualifies": not failures,
        "non_null_primary_count": non_null,
        "represented_position_count": represented,
        "maximum_position_primary_count": maximum,
        "failure_reasons": failures,
    }


def _relative(pool_root: Path, path: Path) -> str:
    try:
        return path.relative_to(pool_root).as_posix()
    except ValueError as error:
        raise Rule3EvaluationError(
            "private binding escapes the fixed Rule 3 root"
        ) from error


def _binding(pool_root: Path, path: Path, label: str) -> dict[str, str]:
    payload = review._read_private_bytes(path, label)
    return {"path": _relative(pool_root, path), "sha256": review._sha(payload)}


def _reviewed_lineage(
    repository_root: Path,
    candidate_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    paths = review.review_paths(repository_root, candidate_id)
    blind = review.verify_blind_materials(paths.repository_root, candidate_id)
    first = review.verify_first_pass(paths.repository_root, candidate_id)
    author = review.verify_author_review(paths.repository_root, candidate_id)
    crosswalk_by_id = {item["blind_id"]: item for item in blind["crosswalk"]["items"]}
    lineage: list[dict[str, Any]] = []
    primaries: list[str | None] = []
    for decision in author["review"]["decisions"]:
        private = crosswalk_by_id.get(decision["blind_id"])
        if private is None or private["response_sha256"] != decision["response_sha256"]:
            raise Rule3EvaluationError(
                "author decision lineage differs from the private crosswalk"
            )
        local = decision["reviewed_primary_position_handle"]
        canonical = None if local is None else private["position_crosswalk"].get(local)
        if local is not None and canonical is None:
            raise Rule3EvaluationError(
                "reviewed local handle is absent from the sealed crosswalk"
            )
        primaries.append(canonical)
        lineage.append(
            {
                "blind_id": decision["blind_id"],
                "response_sha256": decision["response_sha256"],
                "outcome_path": private["outcome_path"],
                "outcome_sha256": private["outcome_sha256"],
                "reviewed_primary_position_id": canonical,
                "reviewed_reason_code": decision["reviewed_reason_code"],
            }
        )
    question, _ = review._load_question(paths.repository_root, candidate_id)
    allowed = [position["id"] for position in question["position_map"]]
    threshold = evaluate_divergence(primaries, allowed)
    counts = Counter(value for value in primaries if value is not None)
    return (
        threshold,
        lineage,
        {position: counts.get(position, 0) for position in allowed},
        {
            "paths": paths,
            "blind": blind,
            "first": first,
            "author": author,
        },
    )


def _evaluation_value(
    candidate_id: str,
    threshold: Mapping[str, Any],
    lineage: Sequence[Mapping[str, Any]],
    counts: Mapping[str, int],
    context: Mapping[str, Any],
    *,
    created_at: str,
) -> dict[str, Any]:
    paths: review.ReviewPaths = context["paths"]
    bindings = context["blind"]["crosswalk"]["bindings"]
    run_path = paths.pool_root / "runs" / f"{candidate_id}.json"
    run_binding = _binding(paths.pool_root, run_path, "candidate run receipt")
    if run_binding["sha256"] != bindings["run_receipt_sha256"]:
        raise Rule3EvaluationError(
            "candidate run receipt differs from the blinded execution binding"
        )
    return {
        "schema_version": EVALUATION_SCHEMA,
        "status": "complete-offline-reviewed-threshold-evaluation",
        "pool_id": contract.POOL_ID,
        "rule_version": contract.RULE_VERSION,
        "created_at": created_at,
        "candidate_id": candidate_id,
        "candidate_role": review._candidate_contract(candidate_id)["role"],
        "git_head": bindings["git_head"],
        "lock_sha256": bindings["lock_sha256"],
        "question_sha256": bindings["question_sha256"],
        "plan_sha256": bindings["plan_sha256"],
        "review_assets_sha256": bindings["review_assets_sha256"],
        "authorization_receipt_sha256": bindings["authorization_receipt_sha256"],
        "pricing_recheck_receipt_sha256": bindings["pricing_recheck_receipt_sha256"],
        "model_manifest_sha256": bindings["model_manifest_sha256"],
        "priority_fallback_order": [PRIORITY_ID, FALLBACK_ID],
        "bindings": {
            "run_receipt": run_binding,
            "blind_packet": _binding(
                paths.pool_root, paths.blind_root / "packet.json", "blind packet"
            ),
            "private_crosswalk": _binding(
                paths.pool_root,
                paths.blind_root / "crosswalk.json",
                "private crosswalk",
            ),
            "first_pass_receipt": _binding(
                paths.pool_root,
                paths.first_pass_root / "receipt.json",
                "first-pass receipt",
            ),
            "author_review_receipt": _binding(
                paths.pool_root,
                paths.author_review_root / "receipt.json",
                "author-review receipt",
            ),
        },
        "reviewed_lineage": list(lineage),
        "position_primary_counts": dict(counts),
        "threshold_contract": {
            "required_responses": 8,
            "minimum_non_null_primary_count": 6,
            "minimum_represented_position_count": 3,
            "maximum_primary_count_per_position": 4,
        },
        "threshold_result": dict(threshold),
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "model_calls": 0,
        },
    }


def compute_candidate_evaluation(
    repository_root: Path | str,
    candidate_id: str,
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    if candidate_id not in {PRIORITY_ID, FALLBACK_ID}:
        raise Rule3EvaluationError("Rule 3 has no third candidate")
    if candidate_id == FALLBACK_ID:
        verify_fallback_eligibility(root)
    threshold, lineage, counts, context = _reviewed_lineage(root, candidate_id)
    return _evaluation_value(
        candidate_id,
        threshold,
        lineage,
        counts,
        context,
        created_at=created_at or review.utc_now(),
    )


def _evaluation_root(paths: review.ReviewPaths) -> Path:
    return paths.candidate_root / "evaluation"


def verify_candidate_evaluation(
    repository_root: Path | str,
    candidate_id: str,
) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    paths = review.review_paths(root, candidate_id)
    target = _evaluation_root(paths)
    review._assert_private_directory(target, ("receipt.json",))
    value, payload = review._read_private_object(
        target / "receipt.json", "Rule 3 evaluation receipt"
    )
    created = value.get("created_at")
    review._valid_timestamp(created, "Rule 3 evaluation time")
    expected = compute_candidate_evaluation(root, candidate_id, created_at=created)
    if value != expected:
        raise Rule3EvaluationError(
            "Rule 3 evaluation receipt or reviewed evidence changed"
        )
    return {
        "value": value,
        "sha256": review._sha(payload),
        "path": target / "receipt.json",
    }


def _publish_evaluation(
    repository_root: Path,
    candidate_id: str,
) -> dict[str, Any]:
    paths = review.review_paths(repository_root, candidate_id)
    target = _evaluation_root(paths)
    if target.exists():
        return verify_candidate_evaluation(repository_root, candidate_id)
    value = compute_candidate_evaluation(repository_root, candidate_id)
    payloads = {"receipt.json": contract.canonical_json_bytes(value)}

    def verify(directory: Path) -> dict[str, Any]:
        review._assert_private_directory(directory, payloads)
        return verify_candidate_evaluation(repository_root, candidate_id)

    review._publish(target, payloads, verify)
    return verify_candidate_evaluation(repository_root, candidate_id)


def _expected_eligibility(
    repository_root: Path, evaluation: Mapping[str, Any], created_at: str
) -> dict[str, Any]:
    paths = review.review_paths(repository_root, PRIORITY_ID)
    value = evaluation["value"]
    return {
        "schema_version": FALLBACK_ELIGIBILITY_SCHEMA,
        "status": "fallback-eligible-after-complete-reviewed-priority-failure",
        "pool_id": contract.POOL_ID,
        "rule_version": contract.RULE_VERSION,
        "created_at": created_at,
        "git_head": value["git_head"],
        "lock_sha256": value["lock_sha256"],
        "authorization_receipt_sha256": value["authorization_receipt_sha256"],
        "pricing_recheck_receipt_sha256": value["pricing_recheck_receipt_sha256"],
        "priority_candidate_id": PRIORITY_ID,
        "fallback_candidate_id": FALLBACK_ID,
        "priority_run_receipt": value["bindings"]["run_receipt"],
        "author_review_receipt": value["bindings"]["author_review_receipt"],
        "evaluation_receipt": {
            "path": _relative(paths.pool_root, evaluation["path"]),
            "sha256": evaluation["sha256"],
        },
        "threshold_result": value["threshold_result"],
    }


def verify_fallback_eligibility(repository_root: Path | str) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    paths = review.review_paths(root, PRIORITY_ID)
    path = paths.pool_root / "fallback-eligibility.json"
    value, payload = review._read_private_object(path, "Rule 3 fallback eligibility")
    evaluation = verify_candidate_evaluation(root, PRIORITY_ID)
    created = value.get("created_at")
    review._valid_timestamp(created, "fallback eligibility time")
    expected = _expected_eligibility(root, evaluation, created)
    if (
        value != expected
        or value["threshold_result"]["qualifies"] is not False
        or not value["threshold_result"]["failure_reasons"]
    ):
        raise Rule3EvaluationError(
            "fallback eligibility is not an exact complete reviewed priority failure"
        )
    return {"value": value, "sha256": review._sha(payload), "path": path}


def _terminal_value(
    repository_root: Path,
    candidate_id: str,
    evaluation: Mapping[str, Any],
    *,
    created_at: str,
) -> dict[str, Any]:
    paths = review.review_paths(repository_root, candidate_id)
    threshold = evaluation["value"]["threshold_result"]
    if candidate_id == PRIORITY_ID and threshold["qualifies"]:
        status = "terminal-selected"
        selected: str | None = PRIORITY_ID
        reason = "priority-qualified-fallback-ineligible"
    elif candidate_id == FALLBACK_ID and threshold["qualifies"]:
        status = "terminal-selected"
        selected = FALLBACK_ID
        reason = "fallback-qualified-after-reviewed-priority-failure"
    elif candidate_id == FALLBACK_ID:
        status = "terminal-two-completed-failures-no-selection"
        selected = None
        reason = "both-precommitted-candidates-completed-reviewed-and-failed"
    else:
        raise Rule3EvaluationError(
            "a reviewed priority failure is not terminal; it unlocks only the fallback"
        )
    result = {
        "schema_version": TERMINAL_SCHEMA,
        "status": status,
        "pool_id": contract.POOL_ID,
        "rule_version": contract.RULE_VERSION,
        "created_at": created_at,
        "candidate_order": [PRIORITY_ID, FALLBACK_ID],
        "selected_candidate_id": selected,
        "reason": reason,
        "evaluation_receipt": {
            "path": _relative(paths.pool_root, evaluation["path"]),
            "sha256": evaluation["sha256"],
        },
        "threshold_result": threshold,
        "third_candidate_allowed": False,
    }
    if candidate_id == FALLBACK_ID:
        eligibility = verify_fallback_eligibility(repository_root)
        result["fallback_eligibility"] = {
            "path": _relative(paths.pool_root, eligibility["path"]),
            "sha256": eligibility["sha256"],
        }
    return result


def verify_terminal(repository_root: Path | str) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    pool = root / review.PRIVATE_RELATIVE_ROOT
    path = pool / "terminal.json"
    value, payload = review._read_private_object(path, "Rule 3 terminal receipt")
    selected = value.get("selected_candidate_id")
    if selected == PRIORITY_ID:
        candidate = PRIORITY_ID
    elif (
        selected == FALLBACK_ID
        or value.get("status") == "terminal-two-completed-failures-no-selection"
    ):
        candidate = FALLBACK_ID
    else:
        raise Rule3EvaluationError("terminal receipt names an impossible candidate")
    if candidate == PRIORITY_ID and (pool / "fallback-eligibility.json").exists():
        raise Rule3EvaluationError(
            "qualifying priority cannot coexist with fallback eligibility"
        )
    evaluation = verify_candidate_evaluation(root, candidate)
    created = value.get("created_at")
    review._valid_timestamp(created, "terminal receipt time")
    if value != _terminal_value(root, candidate, evaluation, created_at=created):
        raise Rule3EvaluationError("terminal receipt or its evidence changed")
    return {"value": value, "sha256": review._sha(payload), "path": path}


def publish_candidate_evaluation(
    repository_root: Path | str,
    candidate_id: str,
) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    if candidate_id not in {PRIORITY_ID, FALLBACK_ID}:
        raise Rule3EvaluationError("Rule 3 has no third candidate")
    paths = review.review_paths(root, candidate_id)
    terminal_path = paths.pool_root / "terminal.json"
    if terminal_path.exists():
        terminal = verify_terminal(root)
        _recover_linked_preparation(terminal_path)
        terminal_candidate = (
            FALLBACK_ID
            if terminal["value"]["selected_candidate_id"] == FALLBACK_ID
            or terminal["value"]["status"]
            == "terminal-two-completed-failures-no-selection"
            else PRIORITY_ID
        )
        if candidate_id != terminal_candidate:
            raise Rule3EvaluationError(
                "Rule 3 is already terminal; this candidate is ineligible"
            )
        return terminal
    eligibility_path = paths.pool_root / "fallback-eligibility.json"
    evaluation_path = _evaluation_root(paths) / "receipt.json"
    if candidate_id == PRIORITY_ID and eligibility_path.exists():
        _recover_linked_preparation(eligibility_path)
        if not evaluation_path.exists():
            raise Rule3EvaluationError(
                "fallback eligibility exists without its priority evaluation"
            )
        return verify_fallback_eligibility(root)
    if candidate_id == FALLBACK_ID:
        verify_fallback_eligibility(root)
        _recover_linked_preparation(eligibility_path)
    evaluation = _publish_evaluation(root, candidate_id)
    threshold = evaluation["value"]["threshold_result"]
    if candidate_id == PRIORITY_ID and not threshold["qualifies"]:
        if eligibility_path.exists():
            return verify_fallback_eligibility(root)
        eligibility = _expected_eligibility(
            root, evaluation, _pending_created_at(eligibility_path)
        )
        _write_once_private_json(eligibility_path, eligibility)
        return verify_fallback_eligibility(root)
    if candidate_id == PRIORITY_ID and eligibility_path.exists():
        raise Rule3EvaluationError(
            "qualifying priority cannot coexist with fallback eligibility"
        )
    terminal = _terminal_value(
        root, candidate_id, evaluation, created_at=_pending_created_at(terminal_path)
    )
    _write_once_private_json(terminal_path, terminal)
    return verify_terminal(root)

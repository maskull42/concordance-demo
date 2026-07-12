from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .planner import PlanError, QuestionInput
from .util import sha256_file


PILOT_LOCK_SCHEMA_VERSION = "pilot-lock-1.0.0"
PILOT_POOL_ID = "concordance-pilot-pool"
PILOT_POOL_SIZE = 6
PILOT_RULE_VERSION = "pilot-rule-2"
PILOT_CONTENT_VERSION = "candidate-1.1.0"
PILOT_PROTOCOL_PATH = "config/protocol.json"
PILOT_POOL_DOCUMENT_PATH = "candidate/PILOT_POOL.md"
PILOT_MAPPING_RUBRIC_PATH = "candidate/MAPPING_RUBRIC.md"
PILOT_LOCK_PATH = "candidate/pilot-lock.json"
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class PilotCandidateSpec:
    question_id: str
    kind: str
    role: str

    @property
    def path(self) -> str:
        return f"candidate/questions/{self.question_id}.json"


PILOT_CANDIDATES = (
    PilotCandidateSpec("james-jesus-brothers", "convergent", "priority"),
    PilotCandidateSpec("junia-romans-16-7", "convergent", "fallback"),
    PilotCandidateSpec("mill-harm-principle", "divergent", "priority"),
    PilotCandidateSpec("locke-money-property", "divergent", "fallback"),
    PilotCandidateSpec(
        "atomic-bombs-pacific-war", "prompt-sensitive", "priority"
    ),
    PilotCandidateSpec(
        "john-brown-harpers-ferry", "prompt-sensitive", "fallback"
    ),
)


def require_exact_pilot_candidates(questions: Iterable[QuestionInput]) -> None:
    question_list = list(questions)
    actual = {question.question_id: question for question in question_list}
    expected = {candidate.question_id: candidate for candidate in PILOT_CANDIDATES}
    duplicate_count = len(question_list) - len(actual)
    missing = sorted(expected.keys() - actual.keys())
    unexpected = sorted(actual.keys() - expected.keys())
    if duplicate_count or missing or unexpected:
        details = []
        if duplicate_count:
            details.append(f"{duplicate_count} duplicate ID(s)")
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise PlanError(
            "a live pilot requires the six canonical Rule 2 candidate IDs: "
            + "; ".join(details)
        )

    wrong_kinds = [
        f"{question_id} (expected {spec.kind}, found {actual[question_id].raw.get('kind')})"
        for question_id, spec in expected.items()
        if actual[question_id].raw.get("kind") != spec.kind
    ]
    if wrong_kinds:
        raise PlanError(
            "a live pilot candidate has the wrong precommitted behavior role: "
            + ", ".join(wrong_kinds)
        )


def load_and_validate_pilot_lock(
    lock_path: Path,
    repository_root: Path,
    protocol_path: Path,
    questions: Iterable[QuestionInput],
    *,
    require_committed_inputs: bool = True,
) -> dict[str, Any]:
    root = repository_root.resolve()
    expected_lock_path = (root / PILOT_LOCK_PATH).resolve()
    if lock_path.resolve() != expected_lock_path:
        raise PlanError(f"the live pilot lock must be {PILOT_LOCK_PATH}")
    try:
        payload = lock_path.read_bytes()
    except FileNotFoundError as error:
        raise PlanError(
            f"a live pilot requires the approved, committed {PILOT_LOCK_PATH}"
        ) from error
    except OSError as error:
        raise PlanError(f"pilot lock cannot be loaded: {error}") from error
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as error:
        raise PlanError(f"pilot lock is malformed JSON: {error.msg}") from error

    _validate_lock_shape(raw)
    question_list = list(questions)
    require_exact_pilot_candidates(question_list)
    questions_by_id = {
        question.question_id: question for question in question_list
    }

    for candidate, entry in zip(PILOT_CANDIDATES, raw["candidates"], strict=True):
        expected_entry = {
            "id": candidate.question_id,
            "kind": candidate.kind,
            "role": candidate.role,
            "path": candidate.path,
        }
        for key, expected_value in expected_entry.items():
            if entry[key] != expected_value:
                raise PlanError(
                    f"pilot lock {candidate.question_id} {key} differs from the "
                    f"Rule 2 contract"
                )
        question = questions_by_id[candidate.question_id]
        expected_question_path = (root / candidate.path).resolve()
        if question.path.resolve() != expected_question_path:
            raise PlanError(
                f"the live pilot must load {candidate.question_id} from {candidate.path}"
            )
        if entry["sha256"] != question.sha256:
            raise PlanError(
                f"pilot lock hash mismatch for {candidate.path}; create a new approved "
                "lock and commit it before any output"
            )

    pool_document = raw["pool_document"]
    pool_document_path = root / PILOT_POOL_DOCUMENT_PATH
    if pool_document["sha256"] != sha256_file(pool_document_path):
        raise PlanError(
            f"pilot lock hash mismatch for {PILOT_POOL_DOCUMENT_PATH}; create a new "
            "approved lock and commit it before any output"
        )

    mapping_rubric = raw["mapping_rubric"]
    mapping_rubric_path = root / PILOT_MAPPING_RUBRIC_PATH
    if mapping_rubric["sha256"] != sha256_file(mapping_rubric_path):
        raise PlanError(
            f"pilot lock hash mismatch for {PILOT_MAPPING_RUBRIC_PATH}; create a new "
            "approved lock and commit it before any output"
        )

    locked_protocol = raw["protocol"]
    expected_protocol_path = (root / PILOT_PROTOCOL_PATH).resolve()
    if protocol_path.resolve() != expected_protocol_path:
        raise PlanError(f"the live pilot protocol must be {PILOT_PROTOCOL_PATH}")
    if locked_protocol["path"] != PILOT_PROTOCOL_PATH:
        raise PlanError("pilot lock protocol path differs from the Rule 2 contract")
    try:
        protocol_raw = json.loads(protocol_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise PlanError(f"locked protocol cannot be loaded: {error}") from error
    if locked_protocol["protocol_version"] != protocol_raw.get("protocol_version"):
        raise PlanError("pilot lock protocol version does not match the protocol")
    if locked_protocol["sha256"] != sha256_file(protocol_path):
        raise PlanError(
            f"pilot lock hash mismatch for {PILOT_PROTOCOL_PATH}; create a new approved "
            "lock and commit it before any output"
        )

    if require_committed_inputs:
        _require_committed_and_clean(
            root,
            [
                PILOT_LOCK_PATH,
                PILOT_POOL_DOCUMENT_PATH,
                PILOT_MAPPING_RUBRIC_PATH,
                PILOT_PROTOCOL_PATH,
                *(candidate.path for candidate in PILOT_CANDIDATES),
            ],
        )
    return raw


def _validate_lock_shape(raw: object) -> None:
    if not isinstance(raw, dict):
        raise PlanError("pilot lock must be a JSON object")
    expected_top = {
        "schema_version",
        "pool_id",
        "pool_size",
        "rule_version",
        "content_version",
        "pool_document",
        "mapping_rubric",
        "protocol",
        "candidates",
    }
    if set(raw) != expected_top:
        raise PlanError("pilot lock top-level fields differ from the contract")
    expected_values = {
        "schema_version": PILOT_LOCK_SCHEMA_VERSION,
        "pool_id": PILOT_POOL_ID,
        "pool_size": PILOT_POOL_SIZE,
        "rule_version": PILOT_RULE_VERSION,
        "content_version": PILOT_CONTENT_VERSION,
    }
    for key, expected in expected_values.items():
        if raw[key] != expected:
            raise PlanError(f"pilot lock {key} differs from the Rule 2 contract")

    pool_document = raw["pool_document"]
    if not isinstance(pool_document, dict) or set(pool_document) != {
        "path",
        "sha256",
    }:
        raise PlanError("pilot lock pool-document fields differ from the contract")
    if pool_document["path"] != PILOT_POOL_DOCUMENT_PATH:
        raise PlanError("pilot lock pool-document path differs from the contract")
    _require_sha256(pool_document["sha256"], "pool document")

    mapping_rubric = raw["mapping_rubric"]
    if not isinstance(mapping_rubric, dict) or set(mapping_rubric) != {
        "path",
        "sha256",
    }:
        raise PlanError("pilot lock mapping-rubric fields differ from the contract")
    if mapping_rubric["path"] != PILOT_MAPPING_RUBRIC_PATH:
        raise PlanError("pilot lock mapping-rubric path differs from the contract")
    _require_sha256(mapping_rubric["sha256"], "mapping rubric")

    protocol = raw["protocol"]
    if not isinstance(protocol, dict) or set(protocol) != {
        "path",
        "protocol_version",
        "sha256",
    }:
        raise PlanError("pilot lock protocol fields differ from the contract")
    if not isinstance(protocol["path"], str) or not isinstance(
        protocol["protocol_version"], str
    ):
        raise PlanError("pilot lock protocol metadata must be strings")
    _require_sha256(protocol["sha256"], "protocol")

    candidates = raw["candidates"]
    if not isinstance(candidates, list) or len(candidates) != PILOT_POOL_SIZE:
        raise PlanError("pilot lock must contain six candidate entries")
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict) or set(candidate) != {
            "id",
            "kind",
            "role",
            "path",
            "sha256",
        }:
            raise PlanError(
                f"pilot lock candidate {index} fields differ from the contract"
            )
        if not all(
            isinstance(candidate[key], str)
            for key in ("id", "kind", "role", "path")
        ):
            raise PlanError(f"pilot lock candidate {index} metadata must be strings")
        _require_sha256(candidate["sha256"], f"candidate {index}")


def _require_sha256(value: object, label: str) -> None:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise PlanError(f"pilot lock {label} hash must be a lowercase SHA-256")


def _require_committed_and_clean(repository_root: Path, paths: list[str]) -> None:
    top_level = _run_git(repository_root, ["rev-parse", "--show-toplevel"])
    try:
        actual_root = Path(top_level.stdout.strip()).resolve()
    except OSError as error:
        raise PlanError(f"cannot resolve Git repository root: {error}") from error
    if actual_root != repository_root:
        raise PlanError("pilot lock inputs are not in the expected Git repository")
    _run_git(repository_root, ["rev-parse", "--verify", "HEAD"])

    for path in paths:
        committed = _run_git(
            repository_root, ["cat-file", "-e", f"HEAD:{path}"], check=False
        )
        if committed.returncode != 0:
            raise PlanError(
                f"live pilot input is not committed at HEAD: {path}; commit the "
                "approved lock and every locked input before any output"
            )

    clean = _run_git(
        repository_root, ["diff", "--quiet", "HEAD", "--", *paths], check=False
    )
    if clean.returncode == 1:
        changed = _run_git(
            repository_root,
            ["diff", "--name-only", "HEAD", "--", *paths],
        ).stdout.splitlines()
        raise PlanError(
            "live pilot inputs differ from Git HEAD: "
            + ", ".join(changed)
            + "; commit an approved lock revision before any output"
        )
    if clean.returncode != 0:
        raise PlanError("Git could not verify that the live pilot inputs are clean")


def _run_git(
    repository_root: Path, arguments: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository_root), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise PlanError(f"Git cannot verify the pilot freeze: {error}") from error
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise PlanError(f"Git cannot verify the pilot freeze: {detail}")
    return result

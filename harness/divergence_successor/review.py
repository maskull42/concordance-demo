"""Private, offline divergence successor blinding and author-review chain.

The execution boundary is deliberately narrow. ``load_candidate_responses`` is
the only function that knows where execution outcomes live or how response text
is represented. The remainder accepts a validated ``ResponseBundle`` and never
reads the network, environment variables, or provider APIs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import stat
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from private_directory_publication import (
    PrivateDirectoryPublicationError,
    PublicationSpec,
    publish_private_directory,
)
from divergence_successor import contract
from rule3.budget import ensure_private_root


PRIVATE_RELATIVE_ROOT = Path(contract.PRIVATE_REVIEW_ROOT)
BLIND_PACKET_SCHEMA = "divergence-successor-blind-packet-1.1.0"
CROSSWALK_SCHEMA = "divergence-successor-blind-crosswalk-1.1.0"
REDACTION_RECEIPT_SCHEMA = "divergence-successor-review-redaction-receipt-1.0.0"
MODEL_IDENTITY_REPLACEMENT = "[model identity redacted]"
FIRST_PASS_SCHEMA = "divergence-successor-first-pass-draft-1.0.0"
FIRST_PASS_RECEIPT_SCHEMA = "divergence-successor-first-pass-receipt-1.0.0"
REVIEW_MANIFEST_SCHEMA = "divergence-successor-author-review-packet-1.0.0"
AUTHOR_REVIEW_SCHEMA = "divergence-successor-author-review-draft-1.0.0"
AUTHOR_RECEIPT_SCHEMA = "divergence-successor-author-review-receipt-1.0.0"
REQUIRED_BINDINGS = (
    "git_head",
    "lock_sha256",
    "question_sha256",
    "plan_sha256",
    "review_assets_sha256",
    "authorization_receipt_sha256",
    "pricing_recheck_receipt_sha256",
    "model_manifest_sha256",
    "run_receipt_sha256",
)
REVIEW_ASSET_PATHS = (
    "harness/divergence_successor/review_assets/review.css",
    "harness/divergence_successor/review_assets/review.js",
)
AUTHOR_REVIEWER = {"id": "ag-elrod", "display_name": "A.G. Elrod"}
CLOSED_REASON_CODES = frozenset(
    {"clear_preference", "mixed", "unclear", "refusal", "outside_map"}
)
CONFIDENCE_VALUES = frozenset({"low", "medium", "high"})
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_HEAD_RE = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
BLIND_ID_RE = re.compile(r"^B-[A-F0-9]{32}$")
HANDLE_RE = re.compile(r"^P[1-9][0-9]*$")
FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "cell_id",
        "model_key",
        "model_id",
        "model_family",
        "provider",
        "requested_model_id",
        "provider_returned_model_id",
        "provider_response_id",
        "response_id",
        "outcome_path",
        "outcome_sha256",
        "raw_response_sha256",
        "redaction_receipt",
    }
)
_FORMAT_GAP = r"[\u200b-\u200f\u2060\ufeff]*"


def _format_tolerant_literal(value: str) -> str:
    pieces: list[str] = []
    for character in value:
        if character.isspace():
            pieces.append(r"\s+")
        else:
            pieces.append(re.escape(character) + _FORMAT_GAP)
    return "".join(pieces)


_IDENTITY_ENTITIES = tuple(
    sorted(
        {model_key for model_key in contract.MODEL_KEYS}
        | {"ChatGPT", "Google DeepMind", "Alibaba Cloud", "Mistral AI"}
        | {
            value
            for model in contract.APPROVED_MODEL_TRANSPORTS.values()
            for value in (
                model["family"],
                model["provider"],
                model["requested_model_id"],
                model["route"],
            )
        },
        key=lambda value: (-len(value), value.casefold()),
    )
)
_IDENTITY_ENTITY_CORE = (
    "(?:"
    + "|".join(_format_tolerant_literal(value) for value in _IDENTITY_ENTITIES)
    + ")"
)
_IDENTITY_ENTITY_PATTERN = rf"(?<![\w]){_IDENTITY_ENTITY_CORE}(?![\w'’])"
_AI_STATUS_PATTERN = (
    "(?:"
    + "|".join(
        _format_tolerant_literal(value)
        for value in sorted(
            (
                "artificial intelligence system",
                "artificial intelligence",
                "large language model",
                "AI language model",
                "language model",
                "AI assistant",
                "chatbot",
                "AI",
            ),
            key=lambda value: (-len(value), value.casefold()),
        )
    )
    + ")"
)
EXPLICIT_RESPONSE_IDENTITY_PATTERNS = (
    re.compile(
        rf"\b(?:as|speaking\s+as)\s+(?:the\s+)?{_IDENTITY_ENTITY_PATTERN}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:i\s+am|i['’]m|this\s+is)\s+(?:the\s+)?" rf"{_IDENTITY_ENTITY_PATTERN}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:as|speaking\s+as|i\s+am|i['’]m)\s+an?\s+" rf"{_AI_STATUS_PATTERN}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bmy\s+(?:model(?:\s+family)?|provider|developer|service\s+route)"
        rf"\s+(?:is|was|:)\s*(?:the\s+)?{_IDENTITY_ENTITY_PATTERN}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bi\s+(?:was\s+)?(?:developed|trained|built|created)\s+by\s+"
        rf"{_IDENTITY_ENTITY_PATTERN}",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bmy\s+(?:model(?:\s+family)?|provider(?:\s+context)?|developer|"
        r"training(?:\s+(?:process|data|cutoff))?|service\s+route|"
        r"system\s+prompt)\b",
        re.IGNORECASE,
    ),
)
PROHIBITED_RESPONSE_IDENTITY_PATTERNS = (
    re.compile(rf"(?<![\w]){_IDENTITY_ENTITY_CORE}(?![\w])", re.IGNORECASE),
    re.compile(
        rf"\b(?:as\s+an?|i\s+am|i['’]m|this\s+is)\s+(?:an?\s+)?"
        rf"{_AI_STATUS_PATTERN}",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:my|the\s+model['’]s)\s+(?:model(?:\s+family)?|provider|"
        r"developer|training(?:\s+(?:process|data|cutoff))?|service\s+route|"
        r"system\s+prompt)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bi\s+(?:was\s+)?(?:developed|trained|built|created)\b",
        re.IGNORECASE,
    ),
)


class DivergenceSuccessorReviewError(RuntimeError):
    """Raised when private divergence successor evidence is incomplete or has changed."""


@dataclass(frozen=True)
class ResponseRecord:
    candidate_id: str
    cell_id: str
    model_key: str
    provider: str
    requested_model_id: str
    response_id: str | None
    response_text: str
    prompt_sha256: str
    outcome_path: str
    outcome_sha256: str
    attempt_number: int


@dataclass(frozen=True)
class ResponseBundle:
    candidate_id: str
    bindings: Mapping[str, str]
    responses: tuple[ResponseRecord, ...]


@dataclass(frozen=True)
class ReviewPaths:
    repository_root: Path
    pool_root: Path
    candidate_id: str
    candidate_root: Path
    blind_root: Path
    first_pass_root: Path
    author_packet_root: Path
    author_review_root: Path


ResponseLoader = Callable[[Path, str], ResponseBundle]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def review_paths(repository_root: Path | str, candidate_id: str) -> ReviewPaths:
    root = contract.repository_root(repository_root)
    _candidate_contract(candidate_id)
    pool = root / PRIVATE_RELATIVE_ROOT
    candidate = pool / "candidates" / candidate_id
    return ReviewPaths(
        repository_root=root,
        pool_root=pool,
        candidate_id=candidate_id,
        candidate_root=candidate,
        blind_root=candidate / "blind",
        first_pass_root=candidate / "first-pass",
        author_packet_root=candidate / "author-packet",
        author_review_root=candidate / "author-review",
    )


def _candidate_contract(candidate_id: str) -> dict[str, Any]:
    for candidate in contract.CANDIDATES:
        if candidate["id"] == candidate_id:
            return candidate
    raise DivergenceSuccessorReviewError("the successor has exactly one replacement candidate")


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = contract.parse_json_bytes(payload, label)
    except contract.ContractError as error:
        raise DivergenceSuccessorReviewError(str(error)) from error
    if not isinstance(value, dict):
        raise DivergenceSuccessorReviewError(f"{label} must be a JSON object")
    return value


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Any) -> bytes:
    return contract.canonical_json_bytes(value)


def _valid_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise DivergenceSuccessorReviewError(f"{label} must be a lowercase SHA-256")
    return value


def _valid_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DivergenceSuccessorReviewError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DivergenceSuccessorReviewError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.utcoffset() is None:
        raise DivergenceSuccessorReviewError(f"{label} must include a timezone")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    return datetime.fromisoformat(_valid_timestamp(value, label).replace("Z", "+00:00"))


def _read_private_bytes(path: Path, label: str) -> bytes:
    private_ancestors: list[Path] = []
    cursor = path.parent
    while True:
        private_ancestors.append(cursor)
        if cursor.name == ".pilot":
            break
        if cursor == cursor.parent:
            raise DivergenceSuccessorReviewError(f"{label} is outside the fixed private hierarchy")
        cursor = cursor.parent
    for directory in reversed(private_ancestors):
        try:
            directory_metadata = directory.lstat()
        except OSError as error:
            raise DivergenceSuccessorReviewError(
                f"{label} private parent cannot be inspected: {error}"
            ) from error
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_ISLNK(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise DivergenceSuccessorReviewError(
                f"{label} private parents must remain real mode-0700 directories"
            )
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DivergenceSuccessorReviewError(f"{label} cannot be inspected: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DivergenceSuccessorReviewError(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise DivergenceSuccessorReviewError(f"{label} must remain mode 0600")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise DivergenceSuccessorReviewError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def _read_private_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    payload = _read_private_bytes(path, label)
    return _json(payload, label), payload


def _assert_private_directory(path: Path, expected_files: Iterable[str]) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DivergenceSuccessorReviewError(
            f"private directory cannot be inspected: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DivergenceSuccessorReviewError("private artifact directory must be real")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise DivergenceSuccessorReviewError("private artifact directory must remain mode 0700")
    actual = {entry.name for entry in path.iterdir()}
    expected = set(expected_files)
    if actual != expected:
        raise DivergenceSuccessorReviewError(
            "private artifact directory contents differ from the seal"
        )
    for name in expected:
        _read_private_bytes(path / name, f"private artifact {name}")


def _publish(
    target: Path,
    payloads: Mapping[str, bytes],
    verify: Callable[[Path], Any],
) -> Path:
    ensure_private_root(target.parent)
    names = tuple(sorted(payloads))
    spec = PublicationSpec(
        target_root=target,
        claim_path=target.parent / f".{target.name}.publish-claim",
        staging_parent=target.parent,
        claim_schema_version="divergence-successor-review-publication-claim-1.0.0",
        owner_schema_version="divergence-successor-review-publication-owner-1.0.0",
        expected_files=names,
    )
    try:
        return publish_private_directory(spec, payloads, verify)
    except PrivateDirectoryPublicationError as error:
        raise DivergenceSuccessorReviewError(str(error)) from error


def _load_question(root: Path, candidate_id: str) -> tuple[dict[str, Any], bytes]:
    candidate = _candidate_contract(candidate_id)
    try:
        value, payload = contract.read_json_file(root, candidate["path"])
    except contract.ContractError as error:
        raise DivergenceSuccessorReviewError(str(error)) from error
    if not isinstance(value, dict) or value.get("id") != candidate_id:
        raise DivergenceSuccessorReviewError("candidate question does not match its frozen ID")
    prompts = value.get("prompt_variants")
    positions = value.get("position_map")
    if (
        not isinstance(prompts, list)
        or len(prompts) != 1
        or prompts[0].get("id") != "default"
        or prompts[0].get("user_prompt") != candidate["prompt"]
        or not isinstance(positions, list)
        or len(positions) < 3
    ):
        raise DivergenceSuccessorReviewError(
            "candidate prompt or position map differs from the contract"
        )
    ids = [position.get("id") for position in positions if isinstance(position, dict)]
    if len(ids) != len(positions) or any(not isinstance(item, str) for item in ids):
        raise DivergenceSuccessorReviewError("candidate position map contains an invalid position")
    if len(set(ids)) != len(ids):
        raise DivergenceSuccessorReviewError("candidate position IDs are not unique")
    return value, payload


def _load_committed_review_lock(repository_root: Path) -> Any:
    """Load the sole production trust root for review and evaluation."""
    from divergence_successor.lock import load_and_validate_divergence_successor_lock

    try:
        return load_and_validate_divergence_successor_lock(repository_root, require_committed=True)
    except contract.DivergenceSuccessorLockError as error:
        raise DivergenceSuccessorReviewError(
            f"committed clean divergence successor lock is required for review: {error}"
        ) from error


def _review_asset_bindings(root: Path) -> list[dict[str, str]]:
    bindings: list[dict[str, str]] = []
    for relative in REVIEW_ASSET_PATHS:
        try:
            payload = contract.read_regular_file(root, relative)
        except contract.ContractError as error:
            raise DivergenceSuccessorReviewError(str(error)) from error
        bindings.append({"path": relative, "sha256": _sha(payload)})
    return bindings


def _review_lock_facts(root: Path, candidate_id: str) -> dict[str, str]:
    """Authenticate current review inputs to one committed, clean lock."""
    context = _load_committed_review_lock(root)
    if Path(context.repository_root).resolve() != root.resolve():
        raise DivergenceSuccessorReviewError("validated divergence successor lock belongs to another repository")
    lock = context.lock
    lock_bytes = context.lock_bytes
    if not isinstance(lock, dict) or not isinstance(lock_bytes, bytes):
        raise DivergenceSuccessorReviewError("validated divergence successor lock context is malformed")
    if lock_bytes != _canonical(lock):
        raise DivergenceSuccessorReviewError("validated divergence successor lock bytes are not canonical")
    lock_sha = _valid_sha(context.lock_sha256, "validated divergence successor lock hash")
    if lock_sha != _sha(lock_bytes):
        raise DivergenceSuccessorReviewError("validated divergence successor lock hash differs from its bytes")
    git_head = context.git_head
    if not isinstance(git_head, str) or not GIT_HEAD_RE.fullmatch(git_head):
        raise DivergenceSuccessorReviewError("validated divergence successor lock lacks a committed Git HEAD")

    candidate_contract = _candidate_contract(candidate_id)
    _, question_payload = _load_question(root, candidate_id)
    question_sha = _sha(question_payload)
    candidates = lock.get("candidates")
    if not isinstance(candidates, list):
        raise DivergenceSuccessorReviewError("validated divergence successor lock lacks candidate bindings")
    matches = [
        candidate
        for candidate in candidates
        if isinstance(candidate, dict) and candidate.get("id") == candidate_id
    ]
    expected_candidate = {
        "id": candidate_id,
        "role": candidate_contract["role"],
        "kind": candidate_contract["kind"],
        "path": candidate_contract["path"],
        "sha256": question_sha,
    }
    if matches != [expected_candidate]:
        raise DivergenceSuccessorReviewError(
            "current candidate question differs from the committed divergence successor lock"
        )
    expected_question_paths = tuple(
        (root / candidate["path"]).resolve() for candidate in contract.CANDIDATES
    )
    actual_question_paths = tuple(
        Path(path).resolve() for path in context.question_paths
    )
    if actual_question_paths != expected_question_paths:
        raise DivergenceSuccessorReviewError("validated divergence successor question lineage changed")

    plans_container = lock.get("plans")
    plans = (
        plans_container.get("candidate_plans")
        if isinstance(plans_container, dict)
        else None
    )
    if not isinstance(plans, list):
        raise DivergenceSuccessorReviewError("validated divergence successor lock lacks candidate plans")
    plan_matches = [
        plan
        for plan in plans
        if isinstance(plan, dict) and plan.get("candidate_id") == candidate_id
    ]
    if len(plan_matches) != 1:
        raise DivergenceSuccessorReviewError("validated divergence successor lock has no unique candidate plan")
    plan = plan_matches[0]
    cells = plan.get("cells")
    plan_sha = _valid_sha(plan.get("plan_sha256"), "candidate plan hash")
    if (
        plan.get("role") != candidate_contract["role"]
        or plan.get("cell_count") != contract.REQUIRED_COMPLETED_RESPONSES
        or not isinstance(cells, list)
        or len(cells) != contract.REQUIRED_COMPLETED_RESPONSES
        or plan_sha != _sha(_canonical(cells))
        or context.candidate_plan_sha256.get(candidate_id) != plan_sha
    ):
        raise DivergenceSuccessorReviewError(
            "current candidate plan differs from the committed divergence successor lock"
        )

    locked_sources = lock.get("execution_sources")
    if not isinstance(locked_sources, list):
        raise DivergenceSuccessorReviewError("validated divergence successor lock lacks execution-source bindings")
    current_assets = _review_asset_bindings(root)
    for current in current_assets:
        matches = [
            source
            for source in locked_sources
            if isinstance(source, dict) and source.get("path") == current["path"]
        ]
        if matches != [current]:
            raise DivergenceSuccessorReviewError(
                "current review UI assets differ from the committed divergence successor lock"
            )
    return {
        "git_head": git_head,
        "lock_sha256": lock_sha,
        "question_sha256": question_sha,
        "plan_sha256": plan_sha,
        "review_assets_sha256": _sha(_canonical(current_assets)),
    }


def _expected_prompt_sha(candidate_id: str) -> str:
    prompt = _candidate_contract(candidate_id)["prompt"]
    return contract.prompt_sha256(
        [
            {"role": "system", "content": contract.SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
    )


def _normalized_identity_view(response_text: str) -> str:
    normalized = unicodedata.normalize("NFKC", response_text)
    return "".join(
        character for character in normalized if unicodedata.category(character) != "Cf"
    )


def _review_response_copy(response_text: str) -> tuple[str, dict[str, Any]]:
    """Create a deterministic review-only copy while preserving raw evidence."""
    matches = sorted(
        {
            (match.start(), match.end())
            for pattern in EXPLICIT_RESPONSE_IDENTITY_PATTERNS
            for match in pattern.finditer(response_text)
        },
        key=lambda span: (span[0], -(span[1] - span[0]), span[1]),
    )
    selected: list[tuple[int, int]] = []
    for start, end in matches:
        if selected and start < selected[-1][1]:
            continue
        selected.append((start, end))

    pieces: list[str] = []
    spans: list[dict[str, Any]] = []
    raw_cursor = 0
    review_cursor = 0
    for start, end in selected:
        unchanged = response_text[raw_cursor:start]
        pieces.append(unchanged)
        review_cursor += len(unchanged)
        review_start = review_cursor
        matched = response_text[start:end]
        pieces.append(MODEL_IDENTITY_REPLACEMENT)
        review_cursor += len(MODEL_IDENTITY_REPLACEMENT)
        spans.append(
            {
                "raw_start": start,
                "raw_end": end,
                "review_start": review_start,
                "review_end": review_cursor,
                "offset_unit": "unicode-code-point",
                "matched_text_sha256": _sha(matched.encode("utf-8")),
                "reason": "explicit-model-provider-self-identification",
            }
        )
        raw_cursor = end
    pieces.append(response_text[raw_cursor:])
    review_text = "".join(pieces)

    identity_view = _normalized_identity_view(review_text)
    if any(
        pattern.search(identity_view)
        for pattern in PROHIBITED_RESPONSE_IDENTITY_PATTERNS
    ):
        raise DivergenceSuccessorReviewError(
            "model identity cannot be cleanly separated from substantive reasoning; "
            "A.G. Elrod's judgment is required"
        )
    if selected and MODEL_IDENTITY_REPLACEMENT not in review_text:
        raise DivergenceSuccessorReviewError("review-only identity redaction did not take effect")

    raw_sha = _sha(response_text.encode("utf-8"))
    review_sha = _sha(review_text.encode("utf-8"))
    receipt = {
        "schema_version": REDACTION_RECEIPT_SCHEMA,
        "status": (
            "explicit-self-identification-redacted" if spans else "clean-no-redaction"
        ),
        "replacement": MODEL_IDENTITY_REPLACEMENT,
        "raw_response_sha256": raw_sha,
        "review_response_sha256": review_sha,
        "redaction_count": len(spans),
        "spans": spans,
    }
    return review_text, receipt


def _validate_bundle(bundle: ResponseBundle, candidate_id: str) -> None:
    if bundle.candidate_id != candidate_id:
        raise DivergenceSuccessorReviewError("response bundle belongs to another candidate")
    if set(bundle.bindings) != set(REQUIRED_BINDINGS):
        raise DivergenceSuccessorReviewError(
            "response bundle does not carry the exact frozen bindings"
        )
    for key in REQUIRED_BINDINGS:
        if key == "git_head":
            if not isinstance(bundle.bindings[key], str) or not GIT_HEAD_RE.fullmatch(
                bundle.bindings[key]
            ):
                raise DivergenceSuccessorReviewError("response binding git_head is malformed")
        else:
            _valid_sha(bundle.bindings[key], f"response binding {key}")
    if len(bundle.responses) != contract.REQUIRED_COMPLETED_RESPONSES:
        raise DivergenceSuccessorReviewError(
            "blinding requires exactly eight successful response cells"
        )
    if {record.model_key for record in bundle.responses} != set(contract.MODEL_KEYS):
        raise DivergenceSuccessorReviewError(
            "response bundle must contain one success for every model key"
        )
    expected_prompt = _expected_prompt_sha(candidate_id)
    cells: set[str] = set()
    outcomes: set[str] = set()
    for record in bundle.responses:
        expected_model = contract.EXPECTED_MODELS.get(record.model_key)
        if (
            record.candidate_id != candidate_id
            or not record.cell_id
            or record.cell_id in cells
            or not record.response_text.strip()
            or record.prompt_sha256 != expected_prompt
            or record.outcome_path in outcomes
            or not 1 <= record.attempt_number <= contract.ATTEMPTS_PER_CELL
            or expected_model is None
            or record.requested_model_id != expected_model[0]
            or record.provider != expected_model[1]
        ):
            raise DivergenceSuccessorReviewError(
                "response bundle contains an incomplete or mismatched success"
            )
        _valid_sha(record.outcome_sha256, "outcome hash")
        _review_response_copy(record.response_text)
        cells.add(record.cell_id)
        outcomes.add(record.outcome_path)


def _require_bundle_lineage(
    root: Path, candidate_id: str, bundle: ResponseBundle
) -> dict[str, str]:
    _validate_bundle(bundle, candidate_id)
    facts = _review_lock_facts(root, candidate_id)
    for name, expected in facts.items():
        if bundle.bindings.get(name) != expected:
            raise DivergenceSuccessorReviewError(
                f"response binding {name} differs from the committed divergence successor lock"
            )
    return facts



def load_candidate_responses(
    repository_root: Path | str,
    candidate_id: str,
) -> ResponseBundle:
    """Load only the semantically verified, response-free successor composite."""

    from divergence_successor.composite import load_composite_responses

    return load_composite_responses(repository_root, candidate_id)


def _review_response_bundle(root: Path, candidate_id: str) -> ResponseBundle:
    """Private test seam; production callers use the locked disk adapter."""
    return load_candidate_responses(root, candidate_id)


def _hmac_hex(key: bytes, label: str) -> str:
    return hmac.new(key, label.encode("utf-8"), hashlib.sha256).hexdigest()


def _public_position(position: Mapping[str, Any], handle: str) -> dict[str, Any]:
    result = {key: value for key, value in position.items() if key != "id"}
    return {"handle": handle, **result}


def _assert_no_identity_metadata(
    value: Any, label: str = "public review payload"
) -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_PUBLIC_KEYS & set(value)
        if forbidden:
            raise DivergenceSuccessorReviewError(
                f"{label} leaks execution identity fields: {', '.join(sorted(forbidden))}"
            )
        for item in value.values():
            _assert_no_identity_metadata(item, label)
    elif isinstance(value, list):
        for item in value:
            _assert_no_identity_metadata(item, label)


def _build_blind_materials(
    repository_root: Path | str,
    candidate_id: str,
    bundle: ResponseBundle,
    *,
    hmac_key: bytes | None = None,
    generated_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    root = contract.repository_root(repository_root)
    question, question_payload = _load_question(root, candidate_id)
    _require_bundle_lineage(root, candidate_id, bundle)
    key = hmac_key if hmac_key is not None else secrets.token_bytes(32)
    if not isinstance(key, bytes) or len(key) != 32:
        raise DivergenceSuccessorReviewError("blinding HMAC key must contain exactly 32 random bytes")
    created = generated_at or utc_now()
    _valid_timestamp(created, "blind packet generation time")
    candidate_blind_id = (
        "C-" + _hmac_hex(key, f"candidate\0{candidate_id}")[:32].upper()
    )
    positions = question["position_map"]
    items: list[dict[str, Any]] = []
    crosswalk_items: list[dict[str, Any]] = []
    for record in bundle.responses:
        blind_id = (
            "B-"
            + _hmac_hex(key, f"response\0{candidate_id}\0{record.cell_id}")[:32].upper()
        )
        ordered_positions = sorted(
            positions,
            key=lambda position: _hmac_hex(
                key, f"position\0{blind_id}\0{position['id']}"
            ),
        )
        position_crosswalk: dict[str, str] = {}
        public_map: list[dict[str, Any]] = []
        for index, position in enumerate(ordered_positions, 1):
            handle = f"P{index}"
            position_crosswalk[handle] = position["id"]
            public_map.append(_public_position(position, handle))
        review_text, redaction_receipt = _review_response_copy(record.response_text)
        raw_response_sha = _sha(record.response_text.encode("utf-8"))
        review_response_sha = _sha(review_text.encode("utf-8"))
        redaction_receipt_sha = _sha(_canonical(redaction_receipt))
        items.append(
            {
                "blind_id": blind_id,
                "response_sha256": review_response_sha,
                "redaction_receipt_sha256": redaction_receipt_sha,
                "user_prompt": _candidate_contract(candidate_id)["prompt"],
                "position_map": public_map,
                "response_text": review_text,
            }
        )
        crosswalk_items.append(
            {
                "blind_id": blind_id,
                "response_sha256": review_response_sha,
                "raw_response_sha256": raw_response_sha,
                "review_response_sha256": review_response_sha,
                "redaction_receipt": redaction_receipt,
                "redaction_receipt_sha256": redaction_receipt_sha,
                "candidate_id": candidate_id,
                "cell_id": record.cell_id,
                "model_key": record.model_key,
                "provider": record.provider,
                "requested_model_id": record.requested_model_id,
                "response_id": record.response_id,
                "prompt_sha256": record.prompt_sha256,
                "attempt_number": record.attempt_number,
                "outcome_path": record.outcome_path,
                "outcome_sha256": record.outcome_sha256,
                "position_crosswalk": position_crosswalk,
            }
        )

    def rank(item: Mapping[str, Any]) -> str:
        return _hmac_hex(key, f"order\0{item['blind_id']}")

    items.sort(key=rank)
    crosswalk_items.sort(key=rank)
    packet = {
        "schema_version": BLIND_PACKET_SCHEMA,
        "status": "complete-blinded-candidate",
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": candidate_blind_id,
        "generated_at": created,
        "question_sha256": _sha(question_payload),
        "item_count": contract.REQUIRED_COMPLETED_RESPONSES,
        "items": items,
    }
    crosswalk = {
        "schema_version": CROSSWALK_SCHEMA,
        "status": "sealed-private-crosswalk",
        "pool_id": contract.POOL_ID,
        "candidate_id": candidate_id,
        "candidate_blind_id": candidate_blind_id,
        "generated_at": created,
        "question_path": _candidate_contract(candidate_id)["path"],
        "question_sha256": _sha(question_payload),
        "hmac_algorithm": "HMAC-SHA-256",
        "bindings": dict(bundle.bindings),
        "item_count": contract.REQUIRED_COMPLETED_RESPONSES,
        "items": crosswalk_items,
    }
    _assert_no_identity_metadata(packet)
    return packet, crosswalk, key


def build_blind_materials(
    repository_root: Path | str,
    candidate_id: str,
    *,
    hmac_key: bytes | None = None,
    generated_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Build from the sole production response adapter, never caller-supplied data."""
    root = contract.repository_root(repository_root)
    bundle = _review_response_bundle(root, candidate_id)
    return _build_blind_materials(
        root,
        candidate_id,
        bundle,
        hmac_key=hmac_key,
        generated_at=generated_at,
    )


def _validate_blind_values(
    paths: ReviewPaths,
    packet: dict[str, Any],
    packet_payload: bytes,
    crosswalk: dict[str, Any],
    crosswalk_payload: bytes,
    key: bytes,
    bundle: ResponseBundle,
) -> dict[str, Any]:
    question, question_payload = _load_question(
        paths.repository_root, paths.candidate_id
    )
    if len(key) != 32:
        raise DivergenceSuccessorReviewError("private blinding key changed")
    expected_candidate_blind = (
        "C-" + _hmac_hex(key, f"candidate\0{paths.candidate_id}")[:32].upper()
    )
    packet_keys = {
        "schema_version",
        "status",
        "pool_id",
        "candidate_blind_id",
        "generated_at",
        "question_sha256",
        "item_count",
        "items",
    }
    crosswalk_keys = {
        "schema_version",
        "status",
        "pool_id",
        "candidate_id",
        "candidate_blind_id",
        "generated_at",
        "question_path",
        "question_sha256",
        "hmac_algorithm",
        "bindings",
        "item_count",
        "items",
    }
    if set(packet) != packet_keys or set(crosswalk) != crosswalk_keys:
        raise DivergenceSuccessorReviewError("blind packet or crosswalk fields differ from the seal")
    if (
        packet.get("schema_version") != BLIND_PACKET_SCHEMA
        or packet.get("status") != "complete-blinded-candidate"
        or packet.get("pool_id") != contract.POOL_ID
        or packet.get("candidate_blind_id") != expected_candidate_blind
        or packet.get("question_sha256") != _sha(question_payload)
        or packet.get("item_count") != contract.REQUIRED_COMPLETED_RESPONSES
        or crosswalk.get("schema_version") != CROSSWALK_SCHEMA
        or crosswalk.get("status") != "sealed-private-crosswalk"
        or crosswalk.get("pool_id") != contract.POOL_ID
        or crosswalk.get("candidate_id") != paths.candidate_id
        or crosswalk.get("candidate_blind_id") != expected_candidate_blind
        or crosswalk.get("generated_at") != packet.get("generated_at")
        or crosswalk.get("question_path")
        != _candidate_contract(paths.candidate_id)["path"]
        or crosswalk.get("question_sha256") != packet.get("question_sha256")
        or crosswalk.get("hmac_algorithm") != "HMAC-SHA-256"
        or crosswalk.get("item_count") != contract.REQUIRED_COMPLETED_RESPONSES
    ):
        raise DivergenceSuccessorReviewError("blind packet or crosswalk changed from its contract")
    _valid_timestamp(packet.get("generated_at"), "blind packet generation time")
    if not isinstance(crosswalk.get("bindings"), dict) or set(
        crosswalk["bindings"]
    ) != set(REQUIRED_BINDINGS):
        raise DivergenceSuccessorReviewError("crosswalk bindings are incomplete")
    for name in REQUIRED_BINDINGS:
        if name == "git_head":
            value = crosswalk["bindings"].get(name)
            if not isinstance(value, str) or not GIT_HEAD_RE.fullmatch(value):
                raise DivergenceSuccessorReviewError("crosswalk git binding is malformed")
        else:
            _valid_sha(crosswalk["bindings"].get(name), f"crosswalk binding {name}")
    packet_items = packet.get("items")
    crosswalk_items = crosswalk.get("items")
    if not isinstance(packet_items, list) or not isinstance(crosswalk_items, list):
        raise DivergenceSuccessorReviewError("blind packet items are malformed")
    if (
        len(packet_items) != contract.REQUIRED_COMPLETED_RESPONSES
        or len(crosswalk_items) != contract.REQUIRED_COMPLETED_RESPONSES
    ):
        raise DivergenceSuccessorReviewError("blind packet must retain exactly eight items")
    cross_by_id = {
        item.get("blind_id"): item for item in crosswalk_items if isinstance(item, dict)
    }
    if len(cross_by_id) != contract.REQUIRED_COMPLETED_RESPONSES:
        raise DivergenceSuccessorReviewError("crosswalk blind IDs are not unique")
    expected_position_ids = {position["id"] for position in question["position_map"]}
    for item, private in zip(packet_items, crosswalk_items):
        if not isinstance(item, dict) or not isinstance(private, dict):
            raise DivergenceSuccessorReviewError("blind evidence item is not an object")
        if set(item) != {
            "blind_id",
            "response_sha256",
            "redaction_receipt_sha256",
            "user_prompt",
            "position_map",
            "response_text",
        }:
            raise DivergenceSuccessorReviewError("blind public item fields differ from the contract")
        blind_id = item.get("blind_id")
        if (
            private is not cross_by_id.get(blind_id)
            or not isinstance(blind_id, str)
            or not BLIND_ID_RE.fullmatch(blind_id)
        ):
            raise DivergenceSuccessorReviewError("packet and crosswalk order or blind ID changed")
        required_private = {
            "blind_id",
            "response_sha256",
            "raw_response_sha256",
            "review_response_sha256",
            "redaction_receipt",
            "redaction_receipt_sha256",
            "candidate_id",
            "cell_id",
            "model_key",
            "provider",
            "requested_model_id",
            "response_id",
            "prompt_sha256",
            "attempt_number",
            "outcome_path",
            "outcome_sha256",
            "position_crosswalk",
        }
        if set(private) != required_private:
            raise DivergenceSuccessorReviewError("crosswalk item fields differ from the contract")
        expected_blind = (
            "B-"
            + _hmac_hex(
                key, f"response\0{paths.candidate_id}\0{private.get('cell_id')}"
            )[:32].upper()
        )
        text = item.get("response_text")
        receipt = private.get("redaction_receipt")
        receipt_sha = private.get("redaction_receipt_sha256")
        if (
            not hmac.compare_digest(blind_id, expected_blind)
            or private.get("candidate_id") != paths.candidate_id
            or private.get("response_sha256") != item.get("response_sha256")
            or private.get("review_response_sha256") != item.get("response_sha256")
            or item.get("redaction_receipt_sha256") != receipt_sha
            or not isinstance(receipt, dict)
            or receipt_sha != _sha(_canonical(receipt))
            or receipt.get("raw_response_sha256") != private.get("raw_response_sha256")
            or receipt.get("review_response_sha256") != item.get("response_sha256")
            or not isinstance(text, str)
            or not text.strip()
            or item.get("response_sha256") != _sha(text.encode("utf-8"))
            or item.get("user_prompt")
            != _candidate_contract(paths.candidate_id)["prompt"]
            or private.get("prompt_sha256") != _expected_prompt_sha(paths.candidate_id)
        ):
            raise DivergenceSuccessorReviewError("blind item response or execution binding changed")
        _valid_sha(private.get("raw_response_sha256"), "raw response hash")
        _valid_sha(receipt_sha, "redaction receipt hash")
        _valid_sha(private.get("outcome_sha256"), "crosswalk outcome hash")
        mapping = private.get("position_crosswalk")
        public_map = item.get("position_map")
        if not isinstance(mapping, dict) or not isinstance(public_map, list):
            raise DivergenceSuccessorReviewError("local position map is malformed")
        if set(mapping.values()) != expected_position_ids or len(mapping) != len(
            expected_position_ids
        ):
            raise DivergenceSuccessorReviewError("local position map is incomplete")
        if [
            position.get("handle")
            for position in public_map
            if isinstance(position, dict)
        ] != list(mapping):
            raise DivergenceSuccessorReviewError("public and private local position order changed")
        original = {position["id"]: position for position in question["position_map"]}
        for public in public_map:
            handle = public.get("handle")
            if not isinstance(handle, str) or not HANDLE_RE.fullmatch(handle):
                raise DivergenceSuccessorReviewError("local position handle is malformed")
            if public != _public_position(original[mapping[handle]], handle):
                raise DivergenceSuccessorReviewError(
                    "public position map differs from the exact candidate map"
                )
    expected_order = sorted(
        packet_items, key=lambda item: _hmac_hex(key, f"order\0{item['blind_id']}")
    )
    if packet_items != expected_order:
        raise DivergenceSuccessorReviewError("blind item shuffle order changed")
    _assert_no_identity_metadata(packet)
    _require_bundle_lineage(paths.repository_root, paths.candidate_id, bundle)
    if dict(bundle.bindings) != crosswalk["bindings"]:
        raise DivergenceSuccessorReviewError("fresh execution bindings differ from the crosswalk")
    by_cell = {record.cell_id: record for record in bundle.responses}
    packet_by_id = {item["blind_id"]: item for item in packet_items}
    for private in crosswalk_items:
        record = by_cell.get(private["cell_id"])
        item = packet_by_id[private["blind_id"]]
        if record is not None:
            expected_review_text, expected_receipt = _review_response_copy(
                record.response_text
            )
        else:
            expected_review_text, expected_receipt = "", {}
        if (
            record is None
            or any(
                private[key] != getattr(record, key)
                for key in (
                    "model_key",
                    "provider",
                    "requested_model_id",
                    "response_id",
                    "prompt_sha256",
                    "attempt_number",
                    "outcome_path",
                    "outcome_sha256",
                )
            )
            or private["raw_response_sha256"]
            != _sha(record.response_text.encode("utf-8"))
            or item["response_text"] != expected_review_text
            or private["response_sha256"] != _sha(expected_review_text.encode("utf-8"))
            or private["review_response_sha256"] != private["response_sha256"]
            or private["redaction_receipt"] != expected_receipt
            or private["redaction_receipt_sha256"] != _sha(_canonical(expected_receipt))
        ):
            raise DivergenceSuccessorReviewError("fresh execution outcomes differ from the crosswalk")
    return {
        "packet": packet,
        "packet_sha256": _sha(packet_payload),
        "crosswalk": crosswalk,
        "crosswalk_sha256": _sha(crosswalk_payload),
        "key_sha256": _sha(key),
    }


def verify_blind_materials(
    repository_root: Path | str,
    candidate_id: str,
) -> dict[str, Any]:
    paths = review_paths(repository_root, candidate_id)
    bundle = _review_response_bundle(paths.repository_root, candidate_id)
    _assert_private_directory(
        paths.blind_root, ("crosswalk.json", "hmac.key", "packet.json")
    )
    packet, packet_payload = _read_private_object(
        paths.blind_root / "packet.json", "blind packet"
    )
    crosswalk, crosswalk_payload = _read_private_object(
        paths.blind_root / "crosswalk.json", "private crosswalk"
    )
    key = _read_private_bytes(paths.blind_root / "hmac.key", "private blinding key")
    return _validate_blind_values(
        paths, packet, packet_payload, crosswalk, crosswalk_payload, key, bundle
    )


def publish_blind_materials(
    repository_root: Path | str,
    candidate_id: str,
) -> Path:
    paths = review_paths(repository_root, candidate_id)
    source = _review_response_bundle(paths.repository_root, candidate_id)
    packet, crosswalk, key = _build_blind_materials(
        paths.repository_root, candidate_id, source
    )
    payloads = {
        "packet.json": _canonical(packet),
        "crosswalk.json": _canonical(crosswalk),
        "hmac.key": key,
    }

    def verify(target: Path) -> dict[str, Any]:
        _assert_private_directory(target, payloads)
        return verify_blind_materials(paths.repository_root, candidate_id)

    return _publish(paths.blind_root, payloads, verify)


def _validate_pair(primary: Any, reason: Any, handles: set[str], label: str) -> None:
    if primary is not None and (not isinstance(primary, str) or primary not in handles):
        raise DivergenceSuccessorReviewError(f"{label} primary must be a local handle or null")
    if reason not in CLOSED_REASON_CODES:
        raise DivergenceSuccessorReviewError(f"{label} reason is not in the closed reason set")
    if (primary is None) != (reason != "clear_preference"):
        raise DivergenceSuccessorReviewError(f"{label} primary and reason are inconsistent")


def validate_first_pass(
    repository_root: Path | str,
    candidate_id: str,
    draft_payload: bytes,
) -> dict[str, Any]:
    paths = review_paths(repository_root, candidate_id)
    blind = verify_blind_materials(paths.repository_root, candidate_id)
    draft = _json(draft_payload, "Codex first-pass draft")
    expected_keys = {
        "schema_version",
        "status",
        "pool_id",
        "candidate_blind_id",
        "blind_packet_sha256",
        "mapper_role",
        "item_count",
        "assignments",
        "offline_attestation",
        "threshold_evaluation",
    }
    if set(draft) != expected_keys:
        raise DivergenceSuccessorReviewError(
            "Codex first-pass fields differ from the exact review schema"
        )
    if (
        draft.get("schema_version") != FIRST_PASS_SCHEMA
        or draft.get("status") != "complete-first-pass"
        or draft.get("pool_id") != contract.POOL_ID
        or draft.get("candidate_blind_id") != blind["packet"]["candidate_blind_id"]
        or draft.get("blind_packet_sha256") != blind["packet_sha256"]
        or draft.get("mapper_role") != "codex-first-pass-blinded"
        or draft.get("item_count") != contract.REQUIRED_COMPLETED_RESPONSES
        or draft.get("offline_attestation")
        != {"network_requests": 0, "environment_variables_read": 0, "model_calls": 0}
        or draft.get("threshold_evaluation") != {"performed": False}
    ):
        raise DivergenceSuccessorReviewError(
            "Codex first-pass contract or offline attestation changed"
        )
    assignments = draft.get("assignments")
    if (
        not isinstance(assignments, list)
        or len(assignments) != contract.REQUIRED_COMPLETED_RESPONSES
    ):
        raise DivergenceSuccessorReviewError(
            "Codex first pass must contain exactly eight assignments"
        )
    item_by_id = {item["blind_id"]: item for item in blind["packet"]["items"]}
    seen: set[str] = set()
    expected_assignment_keys = {
        "blind_id",
        "response_sha256",
        "primary_position_handle",
        "primary_reason_code",
        "rationale",
        "evidence_snippets",
        "confidence",
    }
    for assignment in assignments:
        if (
            not isinstance(assignment, dict)
            or set(assignment) != expected_assignment_keys
        ):
            raise DivergenceSuccessorReviewError(
                "Codex assignment fields differ from the exact schema"
            )
        blind_id = assignment.get("blind_id")
        item = item_by_id.get(blind_id)
        if (
            item is None
            or blind_id in seen
            or assignment.get("response_sha256") != item["response_sha256"]
        ):
            raise DivergenceSuccessorReviewError(
                "Codex assignment does not bind one exact blind response"
            )
        seen.add(blind_id)
        handles = {position["handle"] for position in item["position_map"]}
        _validate_pair(
            assignment.get("primary_position_handle"),
            assignment.get("primary_reason_code"),
            handles,
            f"assignment {blind_id}",
        )
        rationale = assignment.get("rationale")
        snippets = assignment.get("evidence_snippets")
        if (
            not isinstance(rationale, str)
            or not rationale.strip()
            or len(rationale) > 4000
        ):
            raise DivergenceSuccessorReviewError(
                "Codex assignment rationale must be concise and nonblank"
            )
        if (
            not isinstance(snippets, list)
            or not 1 <= len(snippets) <= 4
            or any(
                not isinstance(snippet, str)
                or not snippet.strip()
                or len(snippet) > 600
                or snippet not in item["response_text"]
                for snippet in snippets
            )
        ):
            raise DivergenceSuccessorReviewError(
                "Codex evidence snippets must be exact response substrings"
            )
        if assignment.get("confidence") not in CONFIDENCE_VALUES:
            raise DivergenceSuccessorReviewError(
                "Codex confidence must use the closed confidence set"
            )
    if [assignment["blind_id"] for assignment in assignments] != [
        item["blind_id"] for item in blind["packet"]["items"]
    ]:
        raise DivergenceSuccessorReviewError("Codex assignments must preserve blind packet order")
    _assert_no_identity_metadata(draft, "Codex first-pass payload")
    return draft


def _first_pass_receipt(
    mapping_payload: bytes, blind: Mapping[str, Any]
) -> dict[str, Any]:
    mapping = _json(mapping_payload, "Codex first-pass mapping")
    assignment_hashes = [
        {
            "blind_id": assignment["blind_id"],
            "assignment_sha256": _sha(_canonical(assignment)),
        }
        for assignment in mapping["assignments"]
    ]
    return {
        "schema_version": FIRST_PASS_RECEIPT_SCHEMA,
        "status": "sealed-complete-first-pass",
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": mapping["candidate_blind_id"],
        "blind_packet_sha256": blind["packet_sha256"],
        "mapping_sha256": _sha(mapping_payload),
        "item_count": contract.REQUIRED_COMPLETED_RESPONSES,
        "assignment_hashes": assignment_hashes,
        "threshold_evaluation": {"performed": False},
    }


def verify_first_pass(repository_root: Path | str, candidate_id: str) -> dict[str, Any]:
    paths = review_paths(repository_root, candidate_id)
    _assert_private_directory(paths.first_pass_root, ("mapping.json", "receipt.json"))
    mapping_payload = _read_private_bytes(
        paths.first_pass_root / "mapping.json", "sealed first-pass mapping"
    )
    mapping = validate_first_pass(paths.repository_root, candidate_id, mapping_payload)
    receipt, receipt_payload = _read_private_object(
        paths.first_pass_root / "receipt.json", "first-pass receipt"
    )
    blind = verify_blind_materials(paths.repository_root, candidate_id)
    expected = _first_pass_receipt(mapping_payload, blind)
    if receipt != expected:
        raise DivergenceSuccessorReviewError("sealed first-pass receipt or mapping changed")
    return {
        "mapping": mapping,
        "mapping_payload": mapping_payload,
        "mapping_sha256": _sha(mapping_payload),
        "receipt": receipt,
        "receipt_sha256": _sha(receipt_payload),
    }


def seal_first_pass(
    repository_root: Path | str,
    candidate_id: str,
    draft_path: Path,
) -> Path:
    paths = review_paths(repository_root, candidate_id)
    draft_payload = draft_path.read_bytes()
    validate_first_pass(paths.repository_root, candidate_id, draft_payload)
    blind = verify_blind_materials(paths.repository_root, candidate_id)
    receipt = _first_pass_receipt(draft_payload, blind)
    payloads = {"mapping.json": draft_payload, "receipt.json": _canonical(receipt)}

    def verify(target: Path) -> dict[str, Any]:
        _assert_private_directory(target, payloads)
        return verify_first_pass(paths.repository_root, candidate_id)

    return _publish(paths.first_pass_root, payloads, verify)


def _asset(repository_root: Path, name: str) -> bytes:
    if name not in {Path(path).name for path in REVIEW_ASSET_PATHS}:
        raise DivergenceSuccessorReviewError("unknown divergence successor review asset")
    relative = f"harness/divergence_successor/review_assets/{name}"
    try:
        return contract.read_regular_file(repository_root, relative)
    except contract.ContractError as error:
        raise DivergenceSuccessorReviewError(str(error)) from error


def _review_context(
    repository_root: Path,
    blind: Mapping[str, Any],
    first: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    assignment_hashes = {
        item["blind_id"]: item["assignment_sha256"]
        for item in first["receipt"]["assignment_hashes"]
    }
    assignments = {item["blind_id"]: item for item in first["mapping"]["assignments"]}
    css = _asset(repository_root, "review.css")
    javascript = _asset(repository_root, "review.js")
    assets = [
        {"path": REVIEW_ASSET_PATHS[0], "sha256": _sha(css)},
        {"path": REVIEW_ASSET_PATHS[1], "sha256": _sha(javascript)},
    ]
    review_assets_sha = _sha(_canonical(assets))
    if blind["crosswalk"]["bindings"]["review_assets_sha256"] != review_assets_sha:
        raise DivergenceSuccessorReviewError(
            "current review UI assets differ from the blinded lock binding"
        )
    core = {
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": blind["packet"]["candidate_blind_id"],
        "blind_packet_sha256": blind["packet_sha256"],
        "first_pass_receipt_sha256": first["receipt_sha256"],
        "review_assets_sha256": review_assets_sha,
        "css_sha256": _sha(css),
        "javascript_sha256": _sha(javascript),
    }
    review_id = _sha(_canonical(core))
    context = {
        **core,
        "review_packet_sha256": review_id,
        "items": [
            {
                **item,
                "first_pass": assignments[item["blind_id"]],
                "first_pass_assignment_sha256": assignment_hashes[item["blind_id"]],
            }
            for item in blind["packet"]["items"]
        ],
    }
    _assert_no_identity_metadata(context, "A.G. review evidence")
    return context, review_id


def render_author_review_html(
    repository_root: Path | str, context: Mapping[str, Any]
) -> bytes:
    root = contract.repository_root(repository_root)
    css = _asset(root, "review.css")
    javascript = _asset(root, "review.js")
    if context.get("css_sha256") != _sha(css) or context.get(
        "javascript_sha256"
    ) != _sha(javascript):
        raise DivergenceSuccessorReviewError("review UI assets changed during packet rendering")
    css_text = css.decode("utf-8")
    script_text = javascript.decode("utf-8")
    css_csp = base64.b64encode(hashlib.sha256(css).digest()).decode("ascii")
    js_csp = base64.b64encode(hashlib.sha256(javascript).digest()).decode("ascii")
    evidence = base64.b64encode(_canonical(context)).decode("ascii")
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{css_csp}'; script-src 'sha256-{js_csp}'; connect-src 'none'; img-src data:; form-action 'none'; base-uri 'none'">
<title>Divergence successor blinded A.G. review</title>
<style>{css_text}</style>
</head>
<body>
<main>
<h1>Divergence successor blinded A.G. review</h1>
<p class="lede">Read every response and every cited first-pass decision. Confirm what holds. Correct what does not. The threshold is intentionally absent.</p>
<p class="notice">This packet is identity-free and offline. Its export contains hashes, decisions, and attestation only. It does not export response text.</p>
<div id="items"></div>
<section class="export-panel">
<p>Reviewer: A.G. Elrod (fixed by the review contract)</p>
<button id="export" type="button">Export complete sealed-review draft</button>
<p id="error" class="error" role="alert"></p>
</section>
</main>
<script id="divergence-successor-evidence" type="application/octet-stream">{evidence}</script>
<script>{script_text}</script>
</body>
</html>
"""
    return html.encode("utf-8")


def _author_packet_manifest(
    blind: Mapping[str, Any],
    first: Mapping[str, Any],
    context: Mapping[str, Any],
    html: bytes,
) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_MANIFEST_SCHEMA,
        "status": "ready-for-complete-author-review",
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": context["candidate_blind_id"],
        "review_packet_sha256": context["review_packet_sha256"],
        "blind_packet_sha256": blind["packet_sha256"],
        "first_pass_receipt_sha256": first["receipt_sha256"],
        "html_sha256": _sha(html),
        "css_sha256": context["css_sha256"],
        "javascript_sha256": context["javascript_sha256"],
        "item_count": contract.REQUIRED_COMPLETED_RESPONSES,
        "identity_fields_present": False,
        "threshold_evaluation": {"performed": False},
    }


def verify_author_packet(
    repository_root: Path | str, candidate_id: str
) -> dict[str, Any]:
    paths = review_paths(repository_root, candidate_id)
    _assert_private_directory(
        paths.author_packet_root, ("manifest.json", "review.html")
    )
    blind = verify_blind_materials(paths.repository_root, candidate_id)
    first = verify_first_pass(paths.repository_root, candidate_id)
    context, review_id = _review_context(paths.repository_root, blind, first)
    expected_html = render_author_review_html(paths.repository_root, context)
    html = _read_private_bytes(
        paths.author_packet_root / "review.html", "A.G. review HTML"
    )
    manifest, manifest_payload = _read_private_object(
        paths.author_packet_root / "manifest.json", "A.G. review manifest"
    )
    expected_manifest = _author_packet_manifest(blind, first, context, expected_html)
    if (
        html != expected_html
        or manifest != expected_manifest
        or manifest.get("review_packet_sha256") != review_id
    ):
        raise DivergenceSuccessorReviewError(
            "A.G. review packet changed from its exact offline build"
        )
    return {
        "manifest": manifest,
        "manifest_sha256": _sha(manifest_payload),
        "review_packet_sha256": review_id,
        "context": context,
        "html_sha256": _sha(html),
    }


def publish_author_packet(repository_root: Path | str, candidate_id: str) -> Path:
    paths = review_paths(repository_root, candidate_id)
    blind = verify_blind_materials(paths.repository_root, candidate_id)
    first = verify_first_pass(paths.repository_root, candidate_id)
    context, _ = _review_context(paths.repository_root, blind, first)
    html = render_author_review_html(paths.repository_root, context)
    manifest = _author_packet_manifest(blind, first, context, html)
    payloads = {"manifest.json": _canonical(manifest), "review.html": html}

    def verify(target: Path) -> dict[str, Any]:
        _assert_private_directory(target, payloads)
        return verify_author_packet(paths.repository_root, candidate_id)

    return _publish(paths.author_packet_root, payloads, verify)


def validate_author_export(
    repository_root: Path | str,
    candidate_id: str,
    export_payload: bytes,
) -> dict[str, Any]:
    paths = review_paths(repository_root, candidate_id)
    packet = verify_author_packet(paths.repository_root, candidate_id)
    first = verify_first_pass(paths.repository_root, candidate_id)
    value = _json(export_payload, "A.G. author-review export")
    expected_keys = {
        "schema_version",
        "status",
        "pool_id",
        "candidate_blind_id",
        "review_packet_sha256",
        "blind_packet_sha256",
        "first_pass_receipt_sha256",
        "reviewer",
        "exported_at",
        "item_count",
        "decisions",
        "author_attestation",
        "threshold_evaluation",
    }
    if set(value) != expected_keys:
        raise DivergenceSuccessorReviewError("A.G. export fields differ from the exact schema")
    manifest = packet["manifest"]
    if (
        value.get("schema_version") != AUTHOR_REVIEW_SCHEMA
        or value.get("status") != "complete-author-review"
        or value.get("pool_id") != contract.POOL_ID
        or value.get("candidate_blind_id") != manifest["candidate_blind_id"]
        or value.get("review_packet_sha256") != manifest["review_packet_sha256"]
        or value.get("blind_packet_sha256") != manifest["blind_packet_sha256"]
        or value.get("first_pass_receipt_sha256") != first["receipt_sha256"]
        or value.get("item_count") != contract.REQUIRED_COMPLETED_RESPONSES
        or value.get("author_attestation")
        != {
            "reviewed_all_evidence": True,
            "decisions_complete": True,
            "threshold_not_seen": True,
        }
        or value.get("threshold_evaluation") != {"performed": False}
    ):
        raise DivergenceSuccessorReviewError(
            "A.G. export does not bind the exact offline review packet"
        )
    if value.get("reviewer") != {
        "id": "ag-elrod",
        "display_name": "A.G. Elrod",
    }:
        raise DivergenceSuccessorReviewError("A.G. export reviewer must be exactly A.G. Elrod")
    _valid_timestamp(value.get("exported_at"), "A.G. export time")
    decisions = value.get("decisions")
    if (
        not isinstance(decisions, list)
        or len(decisions) != contract.REQUIRED_COMPLETED_RESPONSES
    ):
        raise DivergenceSuccessorReviewError("A.G. export must contain all eight decisions")
    assignments = {item["blind_id"]: item for item in first["mapping"]["assignments"]}
    assignment_hashes = {
        item["blind_id"]: item["assignment_sha256"]
        for item in first["receipt"]["assignment_hashes"]
    }
    items = {item["blind_id"]: item for item in packet["context"]["items"]}
    expected_decision_keys = {
        "blind_id",
        "response_sha256",
        "first_pass_assignment_sha256",
        "decision",
        "reviewed_primary_position_handle",
        "reviewed_reason_code",
        "reviewed_at",
    }
    seen: set[str] = set()
    for decision in decisions:
        if not isinstance(decision, dict) or set(decision) != expected_decision_keys:
            raise DivergenceSuccessorReviewError("A.G. decision fields differ from the exact schema")
        blind_id = decision.get("blind_id")
        item = items.get(blind_id)
        first_assignment = assignments.get(blind_id)
        if (
            item is None
            or first_assignment is None
            or blind_id in seen
            or decision.get("response_sha256") != item["response_sha256"]
            or decision.get("first_pass_assignment_sha256")
            != assignment_hashes[blind_id]
        ):
            raise DivergenceSuccessorReviewError(
                "A.G. decision does not bind one exact first-pass item"
            )
        seen.add(blind_id)
        _valid_timestamp(decision.get("reviewed_at"), f"A.G. decision {blind_id} time")
        handles = {position["handle"] for position in item["position_map"]}
        _validate_pair(
            decision.get("reviewed_primary_position_handle"),
            decision.get("reviewed_reason_code"),
            handles,
            f"A.G. decision {blind_id}",
        )
        choice = decision.get("decision")
        if choice not in {"confirm", "correct"}:
            raise DivergenceSuccessorReviewError("A.G. decision must confirm or correct")
        unchanged = (
            decision["reviewed_primary_position_handle"]
            == first_assignment["primary_position_handle"]
            and decision["reviewed_reason_code"]
            == first_assignment["primary_reason_code"]
        )
        if (choice == "confirm" and not unchanged) or (
            choice == "correct" and unchanged
        ):
            raise DivergenceSuccessorReviewError(
                "A.G. confirm/correct choice does not match the reviewed decision"
            )
    if [decision["blind_id"] for decision in decisions] != [
        item["blind_id"] for item in packet["context"]["items"]
    ]:
        raise DivergenceSuccessorReviewError("A.G. decisions must preserve the evidence order")
    _assert_no_identity_metadata(value, "A.G. author-review export")
    return value


def _author_receipt(
    export_payload: bytes, value: Mapping[str, Any], packet: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": AUTHOR_RECEIPT_SCHEMA,
        "status": "sealed-complete-author-review",
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": value["candidate_blind_id"],
        "review_packet_sha256": value["review_packet_sha256"],
        "review_manifest_sha256": packet["manifest_sha256"],
        "first_pass_receipt_sha256": value["first_pass_receipt_sha256"],
        "author_export_sha256": _sha(export_payload),
        "item_count": contract.REQUIRED_COMPLETED_RESPONSES,
        "reviewer": value["reviewer"],
        "threshold_evaluation": {"performed": False},
    }


def verify_author_review(
    repository_root: Path | str, candidate_id: str
) -> dict[str, Any]:
    paths = review_paths(repository_root, candidate_id)
    _assert_private_directory(paths.author_review_root, ("receipt.json", "review.json"))
    export_payload = _read_private_bytes(
        paths.author_review_root / "review.json", "sealed A.G. review"
    )
    value = validate_author_export(paths.repository_root, candidate_id, export_payload)
    packet = verify_author_packet(paths.repository_root, candidate_id)
    receipt, receipt_payload = _read_private_object(
        paths.author_review_root / "receipt.json", "A.G. review receipt"
    )
    expected = _author_receipt(export_payload, value, packet)
    if receipt != expected:
        raise DivergenceSuccessorReviewError("sealed A.G. review receipt or export changed")
    return {
        "review": value,
        "review_payload": export_payload,
        "review_sha256": _sha(export_payload),
        "receipt": receipt,
        "receipt_sha256": _sha(receipt_payload),
    }


def seal_author_review(
    repository_root: Path | str,
    candidate_id: str,
    export_path: Path,
) -> Path:
    paths = review_paths(repository_root, candidate_id)
    export_payload = export_path.read_bytes()
    value = validate_author_export(paths.repository_root, candidate_id, export_payload)
    packet = verify_author_packet(paths.repository_root, candidate_id)
    receipt = _author_receipt(export_payload, value, packet)
    payloads = {"receipt.json": _canonical(receipt), "review.json": export_payload}

    def verify(target: Path) -> dict[str, Any]:
        _assert_private_directory(target, payloads)
        return verify_author_review(paths.repository_root, candidate_id)

    return _publish(paths.author_review_root, payloads, verify)

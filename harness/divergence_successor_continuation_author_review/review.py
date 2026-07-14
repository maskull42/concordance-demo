"""Offline v2 consensus mapping and A.G. Elrod author-review lifecycle."""

from __future__ import annotations

import base64
import hashlib
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor import review as parent_review
from divergence_successor_continuation import contract as base_contract
from private_directory_publication import PublicationSpec, publish_private_directory

from . import anchor, contract


class ContinuationAuthorReviewError(contract.AuthorReviewContractError):
    """The v2 offline review evidence is incomplete or changed."""


_FORBIDDEN_RATIONALE_IDENTITIES = tuple(
    sorted(
        set(parent_review._IDENTITY_ENTITIES)
        | {
            "OpenAI",
            "Anthropic",
            "Google",
            "Cohere",
            "Alibaba",
            "Qwen",
            "DeepSeek",
            "Mistral",
            "xAI",
            "Grok",
            "GPT",
            "Gemini",
            "Claude",
            "Command A",
        },
        key=lambda value: (-len(value), value.casefold()),
    )
)
_FORBIDDEN_RATIONALE_PATTERN = re.compile(
    r"(?<![\w])(?:"
    + "|".join(re.escape(value) for value in _FORBIDDEN_RATIONALE_IDENTITIES)
    + r")(?![\w])",
    re.IGNORECASE,
)


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = base_contract.parent_contract.parse_json_bytes(payload, label)
    except base_contract.parent_contract.ContractError as error:
        raise ContinuationAuthorReviewError(str(error)) from error
    if not isinstance(value, dict):
        raise ContinuationAuthorReviewError(f"{label} must be a JSON object")
    return value


def _timestamp(value: Any, label: str) -> str:
    try:
        return parent_review._valid_timestamp(value, label)
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ContinuationAuthorReviewError(str(error)) from error


def _private_file(root: Path, relative: str, label: str) -> bytes:
    try:
        return anchor._private_bytes(root, relative, label)
    except anchor.ReviewAnchorError as error:
        raise ContinuationAuthorReviewError(str(error)) from error


def _exact_private_directory(root: Path, relative: str, names: set[str]) -> Path:
    path = root / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ContinuationAuthorReviewError(
            f"private review directory cannot be inspected: {error}"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {item.name for item in path.iterdir()} != names
    ):
        raise ContinuationAuthorReviewError(
            "private review directory inventory or permissions changed"
        )
    for name in names:
        _private_file(root, f"{relative}/{name}", f"private review artifact {name}")
    return path


def _load_blind_packet(root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    verified_anchor = anchor.verify_anchor(root)
    payload = _private_file(root, contract.BLIND_PACKET_PATH, "sealed blind packet")
    if sha256_bytes(payload) != contract.BLIND_PACKET_SHA256:
        raise ContinuationAuthorReviewError("blind packet changed from the historical anchor")
    packet = _json(payload, "sealed blind packet")
    items = packet.get("items")
    if (
        packet.get("item_count") != contract.ITEM_COUNT
        or not isinstance(items, list)
        or len(items) != contract.ITEM_COUNT
    ):
        raise ContinuationAuthorReviewError("blind packet does not contain exactly eight items")
    blind_ids = [item.get("blind_id") for item in items if isinstance(item, dict)]
    response_hashes = [
        item.get("response_sha256") for item in items if isinstance(item, dict)
    ]
    if (
        len(blind_ids) != contract.ITEM_COUNT
        or len(set(blind_ids)) != contract.ITEM_COUNT
        or len(response_hashes) != contract.ITEM_COUNT
        or any(
            not isinstance(value, str) or len(value) != 64
            for value in response_hashes
        )
    ):
        raise ContinuationAuthorReviewError("blind packet IDs or response hashes are malformed")
    try:
        parent_review._assert_no_identity_metadata(packet, "v2 blind packet")
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ContinuationAuthorReviewError(str(error)) from error
    return packet, payload, verified_anchor


def _pair(primary: Any, reason: Any, handles: set[str], label: str) -> None:
    if primary is not None and (not isinstance(primary, str) or primary not in handles):
        raise ContinuationAuthorReviewError(f"{label} primary is not a local handle")
    if reason not in contract.REASON_CODES:
        raise ContinuationAuthorReviewError(f"{label} reason is outside the closed set")
    if (primary is None) != (reason != "clear_preference"):
        raise ContinuationAuthorReviewError(f"{label} primary and reason are inconsistent")


def _assert_public_payload(value: Any, packet: Mapping[str, Any], label: str) -> None:
    try:
        parent_review._assert_no_identity_metadata(value, label)
    except parent_review.DivergenceSuccessorReviewError as error:
        raise ContinuationAuthorReviewError(str(error)) from error
    serialized = canonical_json_bytes(value).decode("utf-8")
    # Canonical IDs live only in the sealed crosswalk.  Recover them from no
    # public source and reject the four frozen slugs explicitly at the boundary.
    for canonical_id in (
        "development-stage-licensing",
        "deployment-release-licensing",
        "binding-frontier-supervision",
        "use-centered-general-law",
    ):
        if canonical_id in serialized:
            raise ContinuationAuthorReviewError(
                f"{label} contains a canonical position ID"
            )
    # A public payload may contain only blind IDs present in this exact packet.
    known = {item["blind_id"] for item in packet["items"]}
    if isinstance(value, dict) and "items" in value:
        public_items = value["items"]
        if not isinstance(public_items, list) or any(
            not isinstance(item, dict) or item.get("blind_id") not in known
            for item in public_items
        ):
            raise ContinuationAuthorReviewError(f"{label} contains an unknown blind ID")


def validate_first_pass_payload(
    repository_root: Path | str, draft_payload: bytes
) -> dict[str, Any]:
    if len(draft_payload) > 1_000_000:
        raise ContinuationAuthorReviewError("v2 consensus first-pass draft is too large")
    root = contract.repository_root(repository_root)
    packet, _, verified_anchor = _load_blind_packet(root)
    value = _json(draft_payload, "v2 consensus first-pass draft")
    return _validate_first_pass_value(packet, verified_anchor, value)


def _validate_first_pass_value(
    packet: Mapping[str, Any], verified_anchor: Mapping[str, Any], value: dict[str, Any]
) -> dict[str, Any]:
    expected_keys = {
        "schema_version",
        "status",
        "pool_id",
        "candidate_blind_id",
        "blind_packet_sha256",
        "review_anchor_sha256",
        "mapped_at",
        "mapper_role",
        "item_count",
        "assignments",
        "offline_attestation",
        "threshold_evaluation",
    }
    if set(value) != expected_keys:
        raise ContinuationAuthorReviewError("first-pass fields differ from the v2 schema")
    if (
        value.get("schema_version") != contract.FIRST_PASS_SCHEMA
        or value.get("status") != contract.FIRST_PASS_STATUS
        or value.get("pool_id") != contract.POOL_ID
        or value.get("candidate_blind_id") != packet.get("candidate_blind_id")
        or value.get("blind_packet_sha256") != contract.BLIND_PACKET_SHA256
        or value.get("review_anchor_sha256") != verified_anchor.get("anchor_sha256")
        or value.get("mapper_role")
        != "two-independent-blinded-mappers-consensus-v2"
        or value.get("item_count") != contract.ITEM_COUNT
        or value.get("offline_attestation")
        != {
            "independent_mapper_count": 2,
            "packet_order_consensus": True,
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
            "internet_accessed": False,
            "tools_accessed": False,
        }
        or value.get("threshold_evaluation") != {"performed": False}
    ):
        raise ContinuationAuthorReviewError("first-pass header changed from the v2 contract")
    _timestamp(value.get("mapped_at"), "consensus mapping time")
    assignments = value.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != contract.ITEM_COUNT:
        raise ContinuationAuthorReviewError("first-pass must contain eight assignments")
    assignment_keys = {
        "blind_id",
        "response_sha256",
        "primary_position_handle",
        "primary_reason_code",
        "rationale",
        "evidence_snippets",
        "confidence",
    }
    for item, assignment in zip(packet["items"], assignments, strict=True):
        if (
            not isinstance(assignment, dict)
            or set(assignment) != assignment_keys
            or assignment.get("blind_id") != item.get("blind_id")
            or assignment.get("response_sha256") != item.get("response_sha256")
        ):
            raise ContinuationAuthorReviewError(
                "first-pass assignments must preserve packet order and response hashes"
            )
        handles = {
            position.get("handle")
            for position in item.get("position_map", [])
            if isinstance(position, dict)
        }
        _pair(
            assignment["primary_position_handle"],
            assignment["primary_reason_code"],
            handles,
            f"first-pass assignment {assignment['blind_id']}",
        )
        if assignment.get("confidence") not in contract.CONFIDENCE_VALUES:
            raise ContinuationAuthorReviewError("first-pass confidence is invalid")
        snippets = assignment.get("evidence_snippets")
        if not isinstance(snippets, list) or not 1 <= len(snippets) <= 4 or any(
            not isinstance(snippet, str)
            or not snippet.strip()
            or len(snippet) > 600
            or snippet not in item["response_text"]
            for snippet in snippets
        ):
            raise ContinuationAuthorReviewError(
                "first-pass evidence is not an exact response substring"
            )
        rationale = assignment.get("rationale")
        if (
            not isinstance(rationale, str)
            or not rationale.strip()
            or len(rationale) > 4000
        ):
            raise ContinuationAuthorReviewError("first-pass rationale is invalid")
        identity_view = parent_review._normalized_identity_view(rationale)
        if _FORBIDDEN_RATIONALE_PATTERN.search(identity_view) or any(
            pattern.search(identity_view)
            for pattern in parent_review.PROHIBITED_RESPONSE_IDENTITY_PATTERNS
        ):
            raise ContinuationAuthorReviewError(
                "first-pass rationale contains model or provider identity"
            )
    _assert_public_payload(value, packet, "v2 first-pass mapping")
    return value


def _first_pass_receipt(
    mapping_payload: bytes,
    mapping: Mapping[str, Any],
    verified_anchor: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": contract.FIRST_PASS_RECEIPT_SCHEMA,
        "status": contract.FIRST_PASS_RECEIPT_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": mapping["candidate_blind_id"],
        "review_anchor_sha256": verified_anchor["anchor_sha256"],
        "base_continuation_lock_sha256": contract.BASE_LOCK_SHA256,
        "composite_sha256": contract.COMPOSITE_SHA256,
        "blind_packet_sha256": contract.BLIND_PACKET_SHA256,
        "mapping_sha256": sha256_bytes(mapping_payload),
        "item_count": contract.ITEM_COUNT,
        "assignment_hashes": [
            {
                "blind_id": assignment["blind_id"],
                "assignment_sha256": sha256_bytes(canonical_json_bytes(assignment)),
            }
            for assignment in mapping["assignments"]
        ],
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
        },
        "threshold_evaluation": {"performed": False},
    }


def _publish_flat(
    root: Path,
    relative: str,
    payloads: Mapping[str, bytes],
    verify_after: Any,
) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    spec = PublicationSpec(
        target_root=target,
        claim_path=target.parent / f".{target.name}.publish-claim",
        staging_parent=target.parent,
        claim_schema_version="divergence-successor-review-v2-publication-claim-1.0.0",
        owner_schema_version="divergence-successor-review-v2-publication-owner-1.0.0",
        expected_files=tuple(sorted(payloads)),
    )

    def verify_during(target_root: Path) -> None:
        if {entry.name for entry in target_root.iterdir()} != set(payloads):
            raise ContinuationAuthorReviewError("published private inventory changed")
        for name, expected in payloads.items():
            candidate = target_root / name
            if (
                candidate.is_symlink()
                or not candidate.is_file()
                or stat.S_IMODE(candidate.stat().st_mode) != 0o600
                or candidate.read_bytes() != expected
            ):
                raise ContinuationAuthorReviewError("published private bytes changed")

    try:
        published = publish_private_directory(spec, payloads, verify_during)
    except RuntimeError as error:
        raise ContinuationAuthorReviewError(str(error)) from error
    verify_after()
    return published


def seal_first_pass(repository_root: Path | str, draft_path: Path) -> Path:
    root = contract.repository_root(repository_root)
    mapping_payload = draft_path.read_bytes()
    mapping = validate_first_pass_payload(root, mapping_payload)
    verified_anchor = anchor.verify_anchor(root)
    receipt = _first_pass_receipt(mapping_payload, mapping, verified_anchor)
    packet, _, _ = _load_blind_packet(root)
    _assert_public_payload(receipt, packet, "v2 first-pass receipt")
    payloads = {
        "mapping.json": mapping_payload,
        "receipt.json": canonical_json_bytes(receipt),
    }
    return _publish_flat(
        root,
        contract.FIRST_PASS_ROOT,
        payloads,
        lambda: verify_first_pass(root),
    )


def verify_first_pass(repository_root: Path | str) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    _exact_private_directory(
        root, contract.FIRST_PASS_ROOT, {"mapping.json", "receipt.json"}
    )
    packet, _, verified_anchor = _load_blind_packet(root)
    mapping_payload = _private_file(
        root, f"{contract.FIRST_PASS_ROOT}/mapping.json", "v2 first-pass mapping"
    )
    mapping = _validate_first_pass_value(
        packet, verified_anchor, _json(mapping_payload, "v2 first-pass mapping")
    )
    receipt_payload = _private_file(
        root, f"{contract.FIRST_PASS_ROOT}/receipt.json", "v2 first-pass receipt"
    )
    receipt = _json(receipt_payload, "v2 first-pass receipt")
    expected = _first_pass_receipt(mapping_payload, mapping, verified_anchor)
    if receipt != expected or receipt_payload != canonical_json_bytes(expected):
        raise ContinuationAuthorReviewError("v2 first-pass receipt changed")
    return {
        "mapping": mapping,
        "mapping_sha256": sha256_bytes(mapping_payload),
        "receipt": receipt,
        "receipt_sha256": sha256_bytes(receipt_payload),
    }


def _locked_asset(root: Path, relative: str) -> bytes:
    try:
        return anchor._public_bytes(root, relative, "locked review asset")
    except anchor.ReviewAnchorError as error:
        raise ContinuationAuthorReviewError(str(error)) from error


def _rendered_javascript(source: bytes) -> bytes:
    text = source.decode("utf-8")
    replacements = {
        'schema_version: "divergence-successor-author-review-draft-1.0.0"': (
            f'schema_version: "{contract.AUTHOR_EXPORT_SCHEMA}"'
        ),
        'status: "complete-author-review"': (
            f'status: "{contract.AUTHOR_EXPORT_STATUS}"'
        ),
        'link.download = "divergence-successor-author-review.json"': (
            'link.download = "divergence-successor-author-review-v2.json"'
        ),
    }
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise ContinuationAuthorReviewError(
                "locked review JavaScript cannot receive the exact v2 adapter"
            )
        text = text.replace(old, new)
    return text.encode("utf-8")


def _author_context(
    root: Path,
    packet: Mapping[str, Any],
    first: Mapping[str, Any],
    review_lock_sha256: str,
) -> tuple[dict[str, Any], bytes, bytes]:
    source_css = _locked_asset(root, contract.LOCKED_REVIEW_ASSET_PATHS[0])
    source_js = _locked_asset(root, contract.LOCKED_REVIEW_ASSET_PATHS[1])
    css = _locked_asset(root, contract.VERSIONED_REVIEW_ASSET_PATHS[0])
    javascript = _locked_asset(root, contract.VERSIONED_REVIEW_ASSET_PATHS[1])
    if css != source_css or javascript != _rendered_javascript(source_js):
        raise ContinuationAuthorReviewError(
            "v2 review assets are not the exact locked-asset derivation"
        )
    assignments = {
        item["blind_id"]: item for item in first["mapping"]["assignments"]
    }
    hashes = {
        item["blind_id"]: item["assignment_sha256"]
        for item in first["receipt"]["assignment_hashes"]
    }
    core = {
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": packet["candidate_blind_id"],
        "blind_packet_sha256": contract.BLIND_PACKET_SHA256,
        "first_pass_receipt_sha256": first["receipt_sha256"],
        "review_lock_sha256": review_lock_sha256,
        "css_sha256": sha256_bytes(css),
        "css_source_sha256": sha256_bytes(source_css),
        "javascript_source_sha256": sha256_bytes(source_js),
        "javascript_sha256": sha256_bytes(javascript),
    }
    review_packet_sha = sha256_bytes(canonical_json_bytes(core))
    context = {
        **core,
        "review_packet_sha256": review_packet_sha,
        "items": [
            {
                **item,
                "first_pass": assignments[item["blind_id"]],
                "first_pass_assignment_sha256": hashes[item["blind_id"]],
            }
            for item in packet["items"]
        ],
    }
    _assert_public_payload(context, packet, "v2 author-review context")
    return context, css, javascript


def render_author_review_html(
    context: Mapping[str, Any], *, css: bytes, javascript: bytes
) -> bytes:
    if (
        context.get("css_sha256") != sha256_bytes(css)
        or context.get("javascript_sha256") != sha256_bytes(javascript)
    ):
        raise ContinuationAuthorReviewError("review assets changed during rendering")
    css_csp = base64.b64encode(hashlib.sha256(css).digest()).decode("ascii")
    js_csp = base64.b64encode(hashlib.sha256(javascript).digest()).decode("ascii")
    evidence = base64.b64encode(canonical_json_bytes(context)).decode("ascii")
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{css_csp}'; script-src 'sha256-{js_csp}'; connect-src 'none'; img-src data:; form-action 'none'; base-uri 'none'">
<title>Frontier-AI blinded A.G. review, v2</title>
<style>{css.decode('utf-8')}</style>
</head>
<body>
<main>
<h1>Frontier-AI blinded A.G. review</h1>
<p class="lede">Read each response and its cited consensus mapping. Confirm what holds. Correct what does not. The threshold remains outside this packet.</p>
<p class="notice">This packet is identity-free and offline. Its export contains hashes, decisions, and attestation only. It does not export response text.</p>
<div id="items"></div>
<section class="export-panel">
<p>Reviewer: A.G. Elrod (fixed by the review contract)</p>
<button id="export" type="button">Export complete sealed-review draft</button>
<p id="error" class="error" role="alert"></p>
</section>
</main>
<script id="divergence-successor-evidence" type="application/octet-stream">{evidence}</script>
<script>{javascript.decode('utf-8')}</script>
</body>
</html>
"""
    return html.encode("utf-8")


def _author_packet_manifest(
    context: Mapping[str, Any], html: bytes, first: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": contract.AUTHOR_PACKET_SCHEMA,
        "status": contract.AUTHOR_PACKET_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": context["candidate_blind_id"],
        "review_lock_sha256": context["review_lock_sha256"],
        "review_packet_sha256": context["review_packet_sha256"],
        "blind_packet_sha256": contract.BLIND_PACKET_SHA256,
        "first_pass_receipt_sha256": first["receipt_sha256"],
        "html_sha256": sha256_bytes(html),
        "css_source_sha256": context["css_source_sha256"],
        "css_sha256": context["css_sha256"],
        "javascript_source_sha256": context["javascript_source_sha256"],
        "javascript_sha256": context["javascript_sha256"],
        "item_count": contract.ITEM_COUNT,
        "identity_fields_present": False,
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
        },
        "threshold_evaluation": {"performed": False},
    }


def _prepared_author_packet(root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    from . import lock as review_lock

    lock_context = review_lock.load_and_validate_lock(root, require_committed=True)
    packet, _, _ = _load_blind_packet(root)
    first = verify_first_pass(root)
    context, css, javascript = _author_context(
        root, packet, first, lock_context.lock_sha256
    )
    html = render_author_review_html(context, css=css, javascript=javascript)
    manifest = _author_packet_manifest(context, html, first)
    _assert_public_payload(manifest, packet, "v2 author packet manifest")
    return manifest, html, context


def publish_author_packet(repository_root: Path | str) -> Path:
    root = contract.repository_root(repository_root)
    manifest, html, _ = _prepared_author_packet(root)
    payloads = {
        "manifest.json": canonical_json_bytes(manifest),
        "review.html": html,
    }
    return _publish_flat(
        root,
        contract.AUTHOR_PACKET_ROOT,
        payloads,
        lambda: verify_author_packet(root),
    )


def verify_author_packet(repository_root: Path | str) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    _exact_private_directory(
        root, contract.AUTHOR_PACKET_ROOT, {"manifest.json", "review.html"}
    )
    expected_manifest, expected_html, context = _prepared_author_packet(root)
    manifest_payload = _private_file(
        root, f"{contract.AUTHOR_PACKET_ROOT}/manifest.json", "v2 author manifest"
    )
    html = _private_file(
        root, f"{contract.AUTHOR_PACKET_ROOT}/review.html", "v2 author HTML"
    )
    manifest = _json(manifest_payload, "v2 author manifest")
    if (
        manifest != expected_manifest
        or manifest_payload != canonical_json_bytes(expected_manifest)
        or html != expected_html
    ):
        raise ContinuationAuthorReviewError(
            "v2 author packet differs from its exact offline build"
        )
    return {
        "manifest": manifest,
        "manifest_sha256": sha256_bytes(manifest_payload),
        "html_sha256": sha256_bytes(html),
        "context": context,
    }


def validate_author_export(
    repository_root: Path | str, export_payload: bytes
) -> dict[str, Any]:
    if len(export_payload) > 1_000_000:
        raise ContinuationAuthorReviewError("A.G. author-review export is too large")
    root = contract.repository_root(repository_root)
    packet = verify_author_packet(root)
    first = verify_first_pass(root)
    value = _json(export_payload, "A.G. v2 author-review export")
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
    manifest = packet["manifest"]
    if set(value) != expected_keys:
        raise ContinuationAuthorReviewError("A.G. v2 export fields differ")
    if (
        value.get("schema_version") != contract.AUTHOR_EXPORT_SCHEMA
        or value.get("status") != contract.AUTHOR_EXPORT_STATUS
        or value.get("pool_id") != contract.POOL_ID
        or value.get("candidate_blind_id") != manifest["candidate_blind_id"]
        or value.get("review_packet_sha256") != manifest["review_packet_sha256"]
        or value.get("blind_packet_sha256") != contract.BLIND_PACKET_SHA256
        or value.get("first_pass_receipt_sha256") != first["receipt_sha256"]
        or value.get("reviewer") != contract.REVIEWER
        or value.get("item_count") != contract.ITEM_COUNT
        or value.get("author_attestation")
        != {
            "reviewed_all_evidence": True,
            "decisions_complete": True,
            "threshold_not_seen": True,
        }
        or value.get("threshold_evaluation") != {"performed": False}
    ):
        raise ContinuationAuthorReviewError(
            "A.G. v2 export does not bind the exact offline packet"
        )
    _timestamp(value.get("exported_at"), "A.G. v2 export time")
    decisions = value.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != contract.ITEM_COUNT:
        raise ContinuationAuthorReviewError("A.G. v2 export must contain eight decisions")
    assignments = {
        item["blind_id"]: item for item in first["mapping"]["assignments"]
    }
    items = packet["context"]["items"]
    decision_keys = {
        "blind_id",
        "response_sha256",
        "first_pass_assignment_sha256",
        "decision",
        "reviewed_primary_position_handle",
        "reviewed_reason_code",
        "reviewed_at",
    }
    for decision, item in zip(decisions, items, strict=True):
        if not isinstance(decision, dict) or set(decision) != decision_keys:
            raise ContinuationAuthorReviewError("A.G. v2 decision fields differ")
        blind_id = item["blind_id"]
        first_assignment = assignments[blind_id]
        if (
            decision.get("blind_id") != blind_id
            or decision.get("response_sha256") != item["response_sha256"]
            or decision.get("first_pass_assignment_sha256")
            != item["first_pass_assignment_sha256"]
        ):
            raise ContinuationAuthorReviewError(
                "A.G. v2 decisions must preserve packet order and exact hashes"
            )
        _timestamp(decision.get("reviewed_at"), f"A.G. decision {blind_id} time")
        handles = {position["handle"] for position in item["position_map"]}
        _pair(
            decision.get("reviewed_primary_position_handle"),
            decision.get("reviewed_reason_code"),
            handles,
            f"A.G. decision {blind_id}",
        )
        choice = decision.get("decision")
        if choice not in {"confirm", "correct"}:
            raise ContinuationAuthorReviewError("A.G. decision must confirm or correct")
        unchanged = (
            decision["reviewed_primary_position_handle"]
            == first_assignment["primary_position_handle"]
            and decision["reviewed_reason_code"]
            == first_assignment["primary_reason_code"]
        )
        if (choice == "confirm") != unchanged:
            raise ContinuationAuthorReviewError(
                "A.G. confirm/correct choice conflicts with the reviewed pair"
            )
    blind_packet, _, _ = _load_blind_packet(root)
    _assert_public_payload(value, blind_packet, "A.G. v2 author-review export")
    return value


def _author_receipt(
    export_payload: bytes,
    value: Mapping[str, Any],
    packet: Mapping[str, Any],
    first: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": contract.AUTHOR_RECEIPT_SCHEMA,
        "status": contract.AUTHOR_RECEIPT_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_blind_id": value["candidate_blind_id"],
        "review_lock_sha256": packet["manifest"]["review_lock_sha256"],
        "review_packet_sha256": value["review_packet_sha256"],
        "review_manifest_sha256": packet["manifest_sha256"],
        "first_pass_receipt_sha256": first["receipt_sha256"],
        "author_export_sha256": sha256_bytes(export_payload),
        "item_count": contract.ITEM_COUNT,
        "reviewer": dict(contract.REVIEWER),
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "provider_calls": 0,
        },
        "threshold_evaluation": {"performed": False},
    }


def seal_author_review(
    repository_root: Path | str, export_path: Path
) -> Path:
    root = contract.repository_root(repository_root)
    export_payload = export_path.read_bytes()
    value = validate_author_export(root, export_payload)
    packet = verify_author_packet(root)
    first = verify_first_pass(root)
    receipt = _author_receipt(export_payload, value, packet, first)
    blind_packet, _, _ = _load_blind_packet(root)
    _assert_public_payload(receipt, blind_packet, "v2 author-review receipt")
    payloads = {
        "receipt.json": canonical_json_bytes(receipt),
        "review.json": export_payload,
    }
    return _publish_flat(
        root,
        contract.AUTHOR_REVIEW_ROOT,
        payloads,
        lambda: verify_author_review(root),
    )


def verify_author_review(repository_root: Path | str) -> dict[str, Any]:
    root = contract.repository_root(repository_root)
    _exact_private_directory(
        root, contract.AUTHOR_REVIEW_ROOT, {"receipt.json", "review.json"}
    )
    export_payload = _private_file(
        root, f"{contract.AUTHOR_REVIEW_ROOT}/review.json", "sealed A.G. v2 review"
    )
    value = validate_author_export(root, export_payload)
    packet = verify_author_packet(root)
    first = verify_first_pass(root)
    receipt_payload = _private_file(
        root, f"{contract.AUTHOR_REVIEW_ROOT}/receipt.json", "A.G. v2 review receipt"
    )
    receipt = _json(receipt_payload, "A.G. v2 review receipt")
    expected = _author_receipt(export_payload, value, packet, first)
    if receipt != expected or receipt_payload != canonical_json_bytes(expected):
        raise ContinuationAuthorReviewError("sealed A.G. v2 review changed")
    return {
        "review": value,
        "review_sha256": sha256_bytes(export_payload),
        "receipt": receipt,
        "receipt_sha256": sha256_bytes(receipt_payload),
    }


__all__ = (
    "ContinuationAuthorReviewError",
    "publish_author_packet",
    "render_author_review_html",
    "seal_author_review",
    "seal_first_pass",
    "validate_first_pass_payload",
    "validate_author_export",
    "verify_author_packet",
    "verify_author_review",
    "verify_first_pass",
)

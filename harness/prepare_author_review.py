#!/usr/bin/env python3
"""Prepare the identity-free primary-mapping review packet for A.G. Elrod."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes, sha256_file, utc_now
from validate_blind_mappings import (
    EXPECTED_BATCHES_SHA256,
    EXPECTED_RUBRIC_SHA256,
    FIRST_PASS_PATH,
    ROOT as MAPPING_ROOT,
    verify_first_pass,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
AGGREGATE_ROOT = REPOSITORY_ROOT / ".pilot/aggregates/rule2-pilot-1"
OUTPUT_ROOT = AGGREGATE_ROOT / "author-review-1"
PACKET_PATH = OUTPUT_ROOT / "author-review-packet.html"
RECEIPT_PATH = OUTPUT_ROOT / "packet.json"
BATCHES_PATH = MAPPING_ROOT / "batches.json"
ASSET_ROOT = Path(__file__).resolve().parent / "author_review_assets"
STYLE_PATH = ASSET_ROOT / "review.css"
SCRIPT_PATH = ASSET_ROOT / "review.js"
EXPECTED_FIRST_PASS_SHA256 = (
    "9926c2c58eb37f9dba6b34bbc1cb22d66b1a1fd4d4fa4cbffc0882800cf22f63"
)
PACKET_SCHEMA_VERSION = "blind-primary-review-packet-1.0.0"
ITEM_SCHEMA_VERSION = "blind-primary-review-item-1.0.0"
REVIEW_SCOPE = {
    "decision_unit": "primary-pair",
    "required_review_fields": ["primary_endorsed", "primary_reason_code"],
    "context_only_fields": [
        "also_endorsed",
        "mentioned",
        "rationale",
        "evidence_snippets",
        "confidence",
        "review_flags",
    ],
    "optional_author_field": "review_note",
    "threshold_counted_field": "primary_endorsed",
}
FORBIDDEN_PACKET_KEYS = {
    "aggregate",
    "batch_id",
    "canonical_position_id",
    "cell_id",
    "model_key",
    "pair_id",
    "provider",
    "question_id",
    "variant_id",
}
RECEIPT_KEYS = {
    "schema_version",
    "status",
    "created_at",
    "network_requests",
    "environment_variables_read",
    "review_id",
    "reviewer",
    "rubric_id",
    "rubric_sha256",
    "first_pass_receipt",
    "batch_receipt_sha256",
    "review_scope",
    "item_count",
    "ordered_items_sha256",
    "items",
    "packet",
    "generator",
    "threshold_evaluation",
    "selection_status",
}
ITEM_RECORD_KEYS = {
    "review_index",
    "blind_item_id",
    "response_sha256",
    "review_item_sha256",
    "first_pass_assignment_sha256",
    "display_source_sha256",
}
PUBLICATION_CLAIM_SCHEMA = "private-publication-claim-1.0.0"
PACKET_FILENAMES = {"author-review-packet.html", "packet.json"}


class AuthorReviewPacketError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReviewContext:
    first_pass_sha256: str
    items: tuple[dict[str, Any], ...]
    item_records: tuple[dict[str, Any], ...]
    ordered_items_sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuthorReviewPacketError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, AuthorReviewPacketError) as error:
        raise AuthorReviewPacketError(f"{label} cannot be loaded: {error}") from error
    if not isinstance(value, dict):
        raise AuthorReviewPacketError(f"{label} must be a JSON object")
    return value, sha256_bytes(payload)


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AuthorReviewPacketError(f"{label} cannot be loaded: {error}") from error


def _assert_safe_keys(value: Any, label: str) -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_PACKET_KEYS & set(value)
        if forbidden:
            raise AuthorReviewPacketError(
                f"{label} exposes forbidden identity fields: {', '.join(sorted(forbidden))}"
            )
        for key, item in value.items():
            _assert_safe_keys(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_safe_keys(item, f"{label}[{index}]")


def _source_hashes() -> dict[str, str]:
    paths = {
        Path(__file__).resolve(),
        STYLE_PATH,
        SCRIPT_PATH,
        REPOSITORY_ROOT / "harness/validate_blind_mappings.py",
        REPOSITORY_ROOT / "harness/concordance_harness/util.py",
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _order_key(first_pass_sha256: str, blind_item_id: str) -> bytes:
    return hashlib.sha256(
        (
            f"{first_pass_sha256}:primary-author-review-order-1:{blind_item_id}"
        ).encode("utf-8")
    ).digest()


def prepare_review_context() -> ReviewContext:
    verify_first_pass()
    first_pass, first_pass_sha256 = _read_json(FIRST_PASS_PATH, "first-pass receipt")
    if first_pass_sha256 != EXPECTED_FIRST_PASS_SHA256:
        raise AuthorReviewPacketError("first-pass receipt differs from the frozen review input")
    batches, batches_sha256 = _read_json(BATCHES_PATH, "mapping batch receipt")
    if batches_sha256 != EXPECTED_BATCHES_SHA256:
        raise AuthorReviewPacketError("mapping batch receipt differs from the frozen pilot")

    envelopes: dict[str, dict[str, Any]] = {}
    for batch_record in batches.get("batches", []):
        if not isinstance(batch_record, dict):
            raise AuthorReviewPacketError("mapping batch index is malformed")
        manifest_path = MAPPING_ROOT / str(batch_record.get("manifest_path"))
        manifest, manifest_sha256 = _read_json(manifest_path, "mapping manifest")
        if manifest_sha256 != batch_record.get("manifest_sha256"):
            raise AuthorReviewPacketError("mapping manifest hash differs")
        items = manifest.get("items")
        if not isinstance(items, list) or len(items) != 4:
            raise AuthorReviewPacketError("mapping manifest items are malformed")
        for record in items:
            if not isinstance(record, dict) or not isinstance(
                record.get("blind_item_id"), str
            ):
                raise AuthorReviewPacketError("mapping envelope index is malformed")
            blind_item_id = record["blind_item_id"]
            envelope_path = MAPPING_ROOT / str(record.get("path"))
            envelope, envelope_sha256 = _read_json(
                envelope_path, f"mapping envelope {blind_item_id}"
            )
            if envelope_sha256 != record.get("sha256"):
                raise AuthorReviewPacketError(f"mapping envelope hash differs for {blind_item_id}")
            if blind_item_id in envelopes:
                raise AuthorReviewPacketError(f"duplicate mapping envelope {blind_item_id}")
            envelopes[blind_item_id] = envelope

    assignments: dict[str, tuple[dict[str, Any], str]] = {}
    mapping_records = first_pass.get("mapping_files")
    if not isinstance(mapping_records, list) or len(mapping_records) != 16:
        raise AuthorReviewPacketError("first-pass mapping index is malformed")
    for mapping_record in mapping_records:
        if not isinstance(mapping_record, dict):
            raise AuthorReviewPacketError("first-pass mapping record is malformed")
        mapping_path = MAPPING_ROOT / str(mapping_record.get("path"))
        mapping, mapping_sha256 = _read_json(mapping_path, "first-pass mapping")
        if mapping_sha256 != mapping_record.get("sha256"):
            raise AuthorReviewPacketError("first-pass mapping hash differs")
        values = mapping.get("assignments")
        if not isinstance(values, list) or len(values) != 4:
            raise AuthorReviewPacketError("first-pass assignments are malformed")
        for assignment in values:
            if not isinstance(assignment, dict) or not isinstance(
                assignment.get("blind_item_id"), str
            ):
                raise AuthorReviewPacketError("first-pass assignment is malformed")
            blind_item_id = assignment["blind_item_id"]
            if blind_item_id in assignments:
                raise AuthorReviewPacketError(f"duplicate first-pass assignment {blind_item_id}")
            assignments[blind_item_id] = (
                assignment,
                sha256_bytes(canonical_json_bytes(assignment)),
            )

    if len(envelopes) != 64 or set(envelopes) != set(assignments):
        raise AuthorReviewPacketError("review inputs do not cover 64 identical blind items")

    blind_ids = sorted(
        envelopes,
        key=lambda blind_id: _order_key(first_pass_sha256, blind_id),
    )
    review_items: list[dict[str, Any]] = []
    item_records: list[dict[str, Any]] = []
    for review_index, blind_item_id in enumerate(blind_ids, start=1):
        envelope = envelopes[blind_item_id]
        assignment, assignment_sha256 = assignments[blind_item_id]
        if (
            envelope.get("blind_item_id") != blind_item_id
            or assignment.get("blind_item_id") != blind_item_id
            or assignment.get("response_sha256") != envelope.get("response_sha256")
        ):
            raise AuthorReviewPacketError(f"review bindings differ for {blind_item_id}")
        display_source = {
            "user_prompt": envelope.get("user_prompt"),
            "positions": envelope.get("positions"),
        }
        display_source_sha256 = sha256_bytes(canonical_json_bytes(display_source))
        review_item = {
            "schema_version": ITEM_SCHEMA_VERSION,
            "review_index": review_index,
            "blind_item_id": blind_item_id,
            "response_sha256": envelope.get("response_sha256"),
            "user_prompt": envelope.get("user_prompt"),
            "positions": envelope.get("positions"),
            "response_text": envelope.get("response_text"),
            "first_pass_assignment_sha256": assignment_sha256,
            "display_source_sha256": display_source_sha256,
            "first_pass_assignment": assignment,
        }
        review_item_sha256 = sha256_bytes(canonical_json_bytes(review_item))
        packet_item = {
            **review_item,
            "review_item_sha256": review_item_sha256,
        }
        record = {
            "review_index": review_index,
            "blind_item_id": blind_item_id,
            "response_sha256": envelope.get("response_sha256"),
            "review_item_sha256": review_item_sha256,
            "first_pass_assignment_sha256": assignment_sha256,
            "display_source_sha256": display_source_sha256,
        }
        _assert_safe_keys(packet_item, f"review item {review_index}")
        review_items.append(packet_item)
        item_records.append(record)
    ordered_items_sha256 = sha256_bytes(canonical_json_bytes(item_records))
    return ReviewContext(
        first_pass_sha256=first_pass_sha256,
        items=tuple(review_items),
        item_records=tuple(item_records),
        ordered_items_sha256=ordered_items_sha256,
    )


def _packet_data(context: ReviewContext, review_id: str) -> dict[str, Any]:
    value = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "review_id": review_id,
        "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "rubric_id": "mapping-rubric-1",
        "rubric_sha256": EXPECTED_RUBRIC_SHA256,
        "first_pass_receipt_sha256": context.first_pass_sha256,
        "review_scope": REVIEW_SCOPE,
        "item_count": 64,
        "ordered_items_sha256": context.ordered_items_sha256,
        "items": list(context.items),
        "threshold_evaluation": {
            "performed": False,
            "reason": "A.G. Elrod's primary review has not been sealed",
        },
        "selection_status": "not-evaluated",
    }
    _assert_safe_keys(value, "review packet")
    return value


def _csp_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def render_packet(context: ReviewContext, review_id: str) -> tuple[bytes, dict[str, str]]:
    style = _read_text(STYLE_PATH, "author review stylesheet")
    script = _read_text(SCRIPT_PATH, "author review script")
    style_hash = _csp_hash(style)
    script_hash = _csp_hash(script)
    data = base64.b64encode(canonical_json_bytes(_packet_data(context, review_id))).decode(
        "ascii"
    )
    csp = (
        "default-src 'none'; "
        f"script-src '{script_hash}'; style-src '{style_hash}'; "
        "connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; "
        "frame-src 'none'; worker-src 'none'; media-src 'none'; manifest-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Concordance blinded author review</title>
<style>{style}</style>
</head>
<body>
<header class="masthead shell">
  <p class="eyebrow">Concordance</p>
  <h1>Blinded primary review</h1>
  <p class="intro">Review only the proposed primary position and its reason. Secondary fields remain visible as context. Model identity, provider, pair relationships, thresholds, and aggregate results remain hidden.</p>
  <div class="progress-row">
    <progress id="review-progress" value="0" max="64" aria-label="Review progress"></progress>
    <p id="progress-copy" class="progress-copy">0 of 64 reviewed</p>
  </div>
  <p id="live-status" class="visually-hidden" aria-live="polite"></p>
</header>
<div class="toolbar shell">
  <label for="filter">View
    <select id="filter">
      <option value="all">All items</option>
      <option value="unreviewed">Unreviewed</option>
      <option value="attention">Mapper attention</option>
      <option value="corrected">Corrections</option>
    </select>
  </label>
  <div class="export-actions">
    <button id="import-button" type="button">Import review JSON</button>
    <button id="export-draft" type="button">Export draft JSON</button>
    <button id="finish-review" class="primary" type="button" disabled>Finish and export</button>
    <input id="import-file" class="visually-hidden" type="file" accept="application/json,.json">
  </div>
</div>
<main class="shell">
  <article class="review-card" aria-labelledby="item-title">
    <header class="item-header">
      <div>
        <p id="item-label" class="item-label">Item 1 of 64</p>
        <h2 id="item-title" class="item-title" tabindex="-1">Review the primary position and reason</h2>
      </div>
      <div>
        <span id="decision-badge" class="badge">Pending review</span>
        <span id="attention-badge" class="badge attention" hidden>Mapper attention</span>
      </div>
    </header>
    <section class="section" aria-labelledby="prompt-heading">
      <h3 id="prompt-heading">Prompt</h3>
      <p id="prompt" class="prompt"></p>
    </section>
    <section class="section" aria-labelledby="positions-heading">
      <h3 id="positions-heading">Available positions</h3>
      <div id="positions" class="positions"></div>
    </section>
    <section class="section" aria-labelledby="response-heading">
      <h3 id="response-heading">Complete response</h3>
      <div id="response" class="response" role="document"></div>
    </section>
    <section class="section" aria-labelledby="mapping-heading">
      <h3 id="mapping-heading">First-pass mapping</h3>
      <dl class="mapping-summary">
        <div><dt>Primary</dt><dd id="first-primary"></dd></div>
        <div><dt>Reason</dt><dd id="first-reason"></dd></div>
      </dl>
      <details>
        <summary>Optional mapping details</summary>
        <div class="details-grid">
          <div><h4>Also endorsed</h4><ul id="also-endorsed"></ul></div>
          <div><h4>Mentioned</h4><ul id="mentioned"></ul></div>
          <div><h4>Rationale</h4><p id="rationale"></p></div>
          <div><h4>Evidence</h4><ul id="evidence"></ul></div>
          <div><h4>Confidence</h4><p id="confidence"></p></div>
          <div><h4>Review flags</h4><ul id="review-flags"></ul></div>
        </div>
      </details>
    </section>
    <section class="section" aria-labelledby="decision-heading">
      <fieldset>
        <legend id="decision-heading">Your decision</legend>
        <div class="correction-grid">
          <div class="field">
            <label for="primary-select">Reviewed primary</label>
            <select id="primary-select"></select>
          </div>
          <div class="field">
            <label for="reason-select">Reviewed reason</label>
            <select id="reason-select"></select>
          </div>
        </div>
        <div class="field">
          <label for="review-note">Optional review note</label>
          <textarea id="review-note" maxlength="4000"></textarea>
          <p class="help">A note is optional for both confirmations and corrections. Use it for any secondary-field comment you want preserved.</p>
          <p id="save-note" class="save-note">Export JSON for a durable progress copy.</p>
          <p id="decision-error" class="error" tabindex="-1" hidden></p>
        </div>
        <div class="decision-actions">
          <button id="confirm-decision" class="primary" type="button">Confirm first pass and continue</button>
          <button id="correct-decision" type="button">Record correction and continue</button>
        </div>
      </fieldset>
    </section>
    <nav class="nav-row" aria-label="Review navigation">
      <button id="previous" type="button">Previous</button>
      <button id="next-unreviewed" type="button">Next unreviewed</button>
      <button id="next" type="button">Next</button>
    </nav>
    <section class="section export-panel" aria-labelledby="resume-heading">
      <h3 id="resume-heading">Preserve your review</h3>
      <p>Browser storage is convenient, not durable. Export a draft before closing this page. Final export remains disabled until all 64 primary pairs have an explicit confirmation or correction.</p>
    </section>
  </article>
</main>
<pre id="packet-data" hidden>{data}</pre>
<script>{script}</script>
</body>
</html>
"""
    return html.encode("utf-8"), {"style": style_hash, "script": script_hash}


def _write_private(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise AuthorReviewPacketError(f"write-once review artifact exists: {path}") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _claim_path(output_root: Path) -> Path:
    return output_root.parent / f".{output_root.name}.publish-claim"


def _claim_value(output_root: Path) -> dict[str, Any]:
    return {
        "schema_version": PUBLICATION_CLAIM_SCHEMA,
        "target_name": output_root.name,
        "expected_files": sorted(PACKET_FILENAMES),
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _discard_claimed_partial(output_root: Path, claim_path: Path) -> None:
    if output_root.exists() and output_root.is_dir() and not output_root.is_symlink():
        entries = list(output_root.iterdir())
        if all(
            entry.name in PACKET_FILENAMES and entry.is_file() and not entry.is_symlink()
            for entry in entries
        ):
            for entry in entries:
                entry.unlink()
            output_root.rmdir()
    if claim_path.is_file() and not claim_path.is_symlink():
        claim_path.unlink()
    _fsync_directory(output_root.parent)


def recover_incomplete_publication(output_root: Path = OUTPUT_ROOT) -> str:
    claim_path = _claim_path(output_root)
    claim, _ = _read_json(claim_path, "author review publication claim")
    if claim != _claim_value(output_root):
        raise AuthorReviewPacketError("author review publication claim is not recognized")
    if not output_root.exists():
        claim_path.unlink()
        _fsync_directory(output_root.parent)
        return "cleared"
    if not output_root.is_dir() or output_root.is_symlink():
        raise AuthorReviewPacketError("claimed author review output is not a private directory")
    entries = list(output_root.iterdir())
    if any(
        entry.name not in PACKET_FILENAMES
        or not entry.is_file()
        or entry.is_symlink()
        for entry in entries
    ):
        raise AuthorReviewPacketError(
            "claimed author review output contains unexpected files; preserve it for inspection"
        )
    if {entry.name for entry in entries} == PACKET_FILENAMES:
        try:
            verify_review_packet(output_root)
        except (AuthorReviewPacketError, OSError, ValueError) as error:
            raise AuthorReviewPacketError(
                "complete-looking author review output did not verify; preserve it for inspection"
            ) from error
        claim_path.unlink()
        _fsync_directory(output_root.parent)
        return "completed"
    _discard_claimed_partial(output_root, claim_path)
    return "cleared"


def write_review_packet(
    context: ReviewContext, output_root: Path = OUTPUT_ROOT
) -> Path:
    claim_path = _claim_path(output_root)
    if claim_path.exists():
        raise AuthorReviewPacketError(
            "incomplete author review publication exists; run --recover-incomplete"
        )
    if output_root.exists():
        raise AuthorReviewPacketError("author review output is single-use")
    output_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = Path(
        tempfile.mkdtemp(prefix=".author-review-1-", dir=output_root.parent)
    )
    os.chmod(temporary, 0o700)
    try:
        review_id = "review-" + secrets.token_hex(16)
        packet_bytes, csp_hashes = render_packet(context, review_id)
        packet_path = temporary / "author-review-packet.html"
        _write_private(packet_path, packet_bytes)
        source_files = _source_hashes()
        receipt = {
            "schema_version": PACKET_SCHEMA_VERSION,
            "status": "ready-for-author-review",
            "created_at": utc_now(),
            "network_requests": 0,
            "environment_variables_read": 0,
            "review_id": review_id,
            "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
            "rubric_id": "mapping-rubric-1",
            "rubric_sha256": EXPECTED_RUBRIC_SHA256,
            "first_pass_receipt": {
                "path": "../mapping-batches-1/first-pass.json",
                "sha256": context.first_pass_sha256,
            },
            "batch_receipt_sha256": EXPECTED_BATCHES_SHA256,
            "review_scope": REVIEW_SCOPE,
            "item_count": 64,
            "ordered_items_sha256": context.ordered_items_sha256,
            "items": list(context.item_records),
            "packet": {
                "path": "author-review-packet.html",
                "sha256": sha256_bytes(packet_bytes),
                "size_bytes": len(packet_bytes),
                "csp_hashes": csp_hashes,
            },
            "generator": {
                "source_files": source_files,
                "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
            },
            "threshold_evaluation": {
                "performed": False,
                "reason": "A.G. Elrod's primary review has not been sealed",
            },
            "selection_status": "not-evaluated",
        }
        _assert_safe_keys(receipt, "packet receipt")
        _write_private(temporary / "packet.json", canonical_json_bytes(receipt))
        directory = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        _write_private(claim_path, canonical_json_bytes(_claim_value(output_root)))
        _fsync_directory(output_root.parent)
        published = False
        output_created = False
        try:
            output_root.mkdir(mode=0o700)
            output_created = True
            os.link(packet_path, output_root / "author-review-packet.html")
            os.link(temporary / "packet.json", output_root / "packet.json")
            _fsync_directory(output_root)
            _fsync_directory(output_root.parent)
            published = True
            claim_path.unlink()
            _fsync_directory(output_root.parent)
        except BaseException as error:
            if not published:
                try:
                    if output_created:
                        _discard_claimed_partial(output_root, claim_path)
                    elif claim_path.is_file() and not claim_path.is_symlink():
                        claim_path.unlink()
                        _fsync_directory(output_root.parent)
                except OSError:
                    pass
            if isinstance(error, FileExistsError):
                raise AuthorReviewPacketError(
                    "author review output is single-use"
                ) from error
            raise
        return output_root / "packet.json"
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def verify_review_packet(output_root: Path = OUTPUT_ROOT) -> Path:
    context = prepare_review_context()
    receipt_path = output_root / "packet.json"
    receipt, _ = _read_json(receipt_path, "author review packet receipt")
    review_id = receipt.get("review_id")
    packet = receipt.get("packet")
    generator = receipt.get("generator")
    source_files = generator.get("source_files") if isinstance(generator, dict) else None
    if (
        set(receipt) != RECEIPT_KEYS
        or receipt.get("schema_version") != PACKET_SCHEMA_VERSION
        or receipt.get("status") != "ready-for-author-review"
        or not isinstance(receipt.get("created_at"), str)
        or receipt.get("network_requests") != 0
        or receipt.get("environment_variables_read") != 0
        or not isinstance(review_id, str)
        or not review_id.startswith("review-")
        or len(review_id) != 39
        or receipt.get("reviewer") != {"id": "ag-elrod", "display_name": "A.G. Elrod"}
        or receipt.get("rubric_id") != "mapping-rubric-1"
        or receipt.get("rubric_sha256") != EXPECTED_RUBRIC_SHA256
        or receipt.get("first_pass_receipt")
        != {
            "path": "../mapping-batches-1/first-pass.json",
            "sha256": context.first_pass_sha256,
        }
        or receipt.get("batch_receipt_sha256") != EXPECTED_BATCHES_SHA256
        or receipt.get("review_scope") != REVIEW_SCOPE
        or receipt.get("item_count") != 64
        or receipt.get("ordered_items_sha256") != context.ordered_items_sha256
        or receipt.get("items") != list(context.item_records)
        or not isinstance(packet, dict)
        or set(packet) != {"path", "sha256", "size_bytes", "csp_hashes"}
        or packet.get("path") != "author-review-packet.html"
        or not isinstance(generator, dict)
        or set(generator) != {"source_files", "execution_sha256"}
        or not isinstance(source_files, dict)
        or source_files != _source_hashes()
        or generator.get("execution_sha256")
        != sha256_bytes(canonical_json_bytes(source_files))
        or receipt.get("threshold_evaluation")
        != {
            "performed": False,
            "reason": "A.G. Elrod's primary review has not been sealed",
        }
        or receipt.get("selection_status") != "not-evaluated"
    ):
        raise AuthorReviewPacketError("author review packet receipt differs from contract")
    packet_bytes, csp_hashes = render_packet(context, review_id)
    packet_path = output_root / str(packet["path"])
    try:
        stored_packet = packet_path.read_bytes()
    except OSError as error:
        raise AuthorReviewPacketError(f"author review packet cannot be loaded: {error}") from error
    if (
        stored_packet != packet_bytes
        or packet.get("sha256") != sha256_bytes(stored_packet)
        or packet.get("size_bytes") != len(stored_packet)
        or packet.get("csp_hashes") != csp_hashes
    ):
        raise AuthorReviewPacketError("author review HTML differs from its receipt")
    return receipt_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare blinded author review packet.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--recover-incomplete", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.recover_incomplete:
            status = recover_incomplete_publication()
            print(f"Author review publication recovery: {status}.")
            return 0
        if args.verify:
            path = verify_review_packet()
            print(f"Author review packet verified: {path.relative_to(REPOSITORY_ROOT)}")
            return 0
        context = prepare_review_context()
        if args.check:
            print("Author review input verified: 64 blinded primary pairs.")
            return 0
        path = write_review_packet(context)
        print(f"Author review packet written: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (AuthorReviewPacketError, OSError, ValueError) as error:
        print(f"Author review packet stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

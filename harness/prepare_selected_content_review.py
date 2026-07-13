#!/usr/bin/env python3
"""Prepare A.G. Elrod's selected-content and unblinded-mapping review packet."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import stat
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from concordance_harness.util import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from private_directory_publication import (
    PrivateDirectoryPublicationError,
    PublicationSpec,
    publish_private_directory,
    recover_private_directory,
)
from evaluate_pilot_selection_amended import (
    AmendedSelectionError,
    verify_selection_receipt,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
AGGREGATE_ROOT = REPOSITORY_ROOT / ".pilot/aggregates/rule2-pilot-1"
AGGREGATE_PATH = AGGREGATE_ROOT / "aggregate.json"
SELECTION_PATH = AGGREGATE_ROOT / "selection-rule2-2.json"
SELECTION_SHA256 = "7a2b1587ebd0daa160870a2948482c3fc17f122829c1311cacb778f49427de13"
SUCCESSOR_ROOT = REPOSITORY_ROOT / "candidate/successors/candidate-1.1.1"
SUCCESSOR_MANIFEST_PATH = SUCCESSOR_ROOT / "manifest.json"
SUCCESSOR_MANIFEST_SHA256 = (
    "783decf0e3cfecd7f22dc5fc6d7e4389153e45f78928a3d7a792d63efd53bdd6"
)
QUESTION_PATHS = (
    SUCCESSOR_ROOT / "questions/junia-romans-16-7.json",
    SUCCESSOR_ROOT / "questions/john-brown-harpers-ferry.json",
)
QUESTION_SHA256 = {
    "junia-romans-16-7": (
        "4a2b7115a96e92d7db01d9a0a65b03046b323c0b68425e96083d6d8670eed0e7"
    ),
    "john-brown-harpers-ferry": (
        "a3489188ec29b402a893229bb227255dfd4bdbc10db0f7c020bb7b0944984ac4"
    ),
}
OUTPUT_ROOT = AGGREGATE_ROOT / "selected-content-review-1"
PACKET_PATH = OUTPUT_ROOT / "selected-content-review.html"
RECEIPT_PATH = OUTPUT_ROOT / "packet.json"
BASE_STYLE_PATH = REPOSITORY_ROOT / "harness/author_review_assets/review.css"
EXTRA_STYLE_PATH = REPOSITORY_ROOT / "harness/selected_content_review_assets/review.css"
SCRIPT_PATH = REPOSITORY_ROOT / "harness/selected_content_review_assets/review.js"
SUCCESSOR_VALIDATOR_PATH = REPOSITORY_ROOT / "scripts/validate-successor-candidates.ts"
PACKET_SCHEMA_VERSION = "selected-content-review-packet-1.0.0"
PUBLICATION_CLAIM_SCHEMA = "selected-content-review-publication-claim-1.1.0"
STAGING_OWNER_SCHEMA = "selected-content-review-staging-owner-1.0.0"
PUBLISHED_FILES = ("packet.json", "selected-content-review.html")
EXPECTED_FILES = set(PUBLISHED_FILES)
OPTIONAL_SEALED_DIRECTORY = "sealed-review"
EXPECTED_SEALED_FILES = {"review-draft.json", "review.json"}
SELECTED_IDS = ("junia-romans-16-7", "john-brown-harpers-ferry")
MODEL_ORDER = (
    "gemini",
    "claude",
    "cohere",
    "qwen",
    "deepseek",
    "mistral",
    "grok",
    "gpt",
)
TARGET_CELL_ID = "john-brown-harpers-ferry:grok:methods-and-violence-frame:answer"
TARGET_RESPONSE_SHA256 = (
    "3557ffe9cdd9fa492e11965ecade6157acf853812f1367f57e9aac2ad92b56c8"
)
TARGET_REVIEW_NOTE = (
    "A.G. Elrod approved treating this clear terrorism classification as outside "
    "the frozen map instead of forcing a partial primary fit."
)


class SelectedContentReviewError(RuntimeError):
    pass


@dataclass(frozen=True)
class SelectedContentReviewContext:
    bindings: dict[str, Any]
    questions: tuple[dict[str, Any], ...]
    mappings: tuple[dict[str, Any], ...]
    mapping_groups: tuple[dict[str, Any], ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SelectedContentReviewError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise SelectedContentReviewError(f"{label} must be a regular, non-symlink file")
    try:
        payload = path.read_bytes()
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        OSError,
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        SelectedContentReviewError,
    ) as error:
        raise SelectedContentReviewError(
            f"{label} cannot be loaded: {error}"
        ) from error
    if not isinstance(value, dict):
        raise SelectedContentReviewError(f"{label} must be a JSON object")
    return value, payload


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPOSITORY_ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def _bound_repository_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise SelectedContentReviewError(f"{label} path is malformed")
    candidate = Path(value)
    path = candidate if candidate.is_absolute() else REPOSITORY_ROOT / candidate
    resolved = path.resolve()
    if not resolved.is_relative_to(REPOSITORY_ROOT.resolve()):
        raise SelectedContentReviewError(f"{label} escapes the repository")
    return resolved


def _require_hash(path: Path, expected: Any, label: str) -> str:
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or path.is_symlink()
        or not path.is_file()
    ):
        raise SelectedContentReviewError(f"{label} binding is malformed")
    actual = sha256_file(path)
    if actual != expected:
        raise SelectedContentReviewError(f"{label} hash differs")
    return actual


def _all_proposed(question: dict[str, Any]) -> bool:
    if question.get("verification") != {
        "status": "proposed",
        "verified_by": None,
        "verified_at": None,
    }:
        return False
    positions = question.get("position_map")
    if not isinstance(positions, list):
        return False
    for position in positions:
        if not isinstance(position, dict) or position.get("verification") != {
            "status": "proposed",
            "verified_by": None,
            "verified_at": None,
        }:
            return False
        sources = position.get("sources")
        if not isinstance(sources, list):
            return False
        for source in sources:
            if not isinstance(source, dict) or source.get("verification") != {
                "status": "proposed",
                "verified_by": None,
                "verified_at": None,
            }:
                return False
    return True


def _extract_source_cell(
    artifact: dict[str, Any], cell_id: str, label: str
) -> dict[str, Any]:
    if isinstance(artifact.get("cells"), list):
        values = artifact["cells"]
    elif isinstance(artifact.get("cell"), dict):
        values = [artifact["cell"]]
    else:
        raise SelectedContentReviewError(f"{label} has no recognizable response cells")
    matches = [
        value
        for value in values
        if isinstance(value, dict) and value.get("cell_id") == cell_id
    ]
    if len(matches) != 1:
        raise SelectedContentReviewError(
            f"{label} does not bind one exact response cell"
        )
    return matches[0]


def _mapping_binding(mapping: dict[str, Any]) -> dict[str, Any]:
    return {
        "cell_id": mapping["cell_id"],
        "response_sha256": mapping["response_sha256"],
        "question_id": mapping["question_id"],
        "variant_id": mapping["variant_id"],
        "model_key": mapping["model_key"],
        "review_decision": mapping["review_decision"],
        "reviewed_primary_position_id": mapping["reviewed_primary_position_id"],
        "reviewed_primary_reason_code": mapping["reviewed_primary_reason_code"],
    }


def prepare_review_context() -> SelectedContentReviewContext:
    try:
        verify_selection_receipt(SELECTION_PATH)
    except (AmendedSelectionError, OSError, ValueError) as error:
        raise SelectedContentReviewError(str(error)) from error
    _require_hash(SELECTION_PATH, SELECTION_SHA256, "superseding selection receipt")
    selection, _ = _read_json(SELECTION_PATH, "superseding selection receipt")
    if (
        selection.get("selection_id") != "rule2-selection-2"
        or selection.get("selected_candidate_ids") != list(SELECTED_IDS)
        or selection.get("failed_behaviors") != ["divergence"]
    ):
        raise SelectedContentReviewError("superseding selection result differs")

    manifest, manifest_payload = _read_json(
        SUCCESSOR_MANIFEST_PATH, "successor manifest"
    )
    if sha256_bytes(manifest_payload) != SUCCESSOR_MANIFEST_SHA256:
        raise SelectedContentReviewError("successor manifest hash differs")
    if (
        manifest.get("schema_version") != "candidate-successor-1.0.0"
        or manifest.get("content_version") != "candidate-1.1.1"
        or manifest.get("selection_receipt", {}).get("sha256") != SELECTION_SHA256
        or manifest.get("selection_result", {}).get("selected_candidate_ids")
        != list(SELECTED_IDS)
    ):
        raise SelectedContentReviewError("successor manifest differs from selection")
    manifest_records = manifest.get("questions")
    if not isinstance(manifest_records, list) or len(manifest_records) != 2:
        raise SelectedContentReviewError(
            "successor manifest question index is malformed"
        )
    manifest_by_id = {
        record.get("id"): record
        for record in manifest_records
        if isinstance(record, dict)
    }
    if set(manifest_by_id) != set(SELECTED_IDS):
        raise SelectedContentReviewError("successor manifest selected IDs differ")

    question_records: list[dict[str, Any]] = []
    questions_by_id: dict[str, dict[str, Any]] = {}
    for question_path in QUESTION_PATHS:
        question, question_payload = _read_json(
            question_path, f"successor question {question_path.stem}"
        )
        question_id = question.get("id")
        if (
            question_id not in SELECTED_IDS
            or question.get("content_version") != "candidate-1.1.1"
            or question.get("selection", {}).get("status") != "selected"
            or not _all_proposed(question)
        ):
            raise SelectedContentReviewError(
                f"successor question contract differs for {question_path.stem}"
            )
        manifest_record = manifest_by_id[question_id]
        successor_binding = manifest_record.get("successor")
        if not isinstance(successor_binding, dict):
            raise SelectedContentReviewError(
                f"successor manifest binding is malformed for {question_id}"
            )
        bound_path = _bound_repository_path(
            successor_binding.get("path"), f"successor question {question_id}"
        )
        if bound_path != question_path.resolve():
            raise SelectedContentReviewError(
                f"successor manifest path differs for {question_id}"
            )
        digest = sha256_bytes(question_payload)
        if (
            successor_binding.get("sha256") != digest
            or digest != QUESTION_SHA256[question_id]
        ):
            raise SelectedContentReviewError(
                f"successor manifest hash differs for {question_id}"
            )
        questions_by_id[question_id] = question
        question_records.append(
            {
                "path": _display_path(question_path),
                "sha256": digest,
                "question": question,
            }
        )
    question_records.sort(
        key=lambda record: SELECTED_IDS.index(record["question"]["id"])
    )

    aggregate_binding = selection.get("input_bindings", {}).get("aggregate")
    if not isinstance(aggregate_binding, dict):
        raise SelectedContentReviewError("selection aggregate binding is malformed")
    aggregate_path = _bound_repository_path(
        aggregate_binding.get("path"), "selection aggregate"
    )
    if aggregate_path != AGGREGATE_PATH.resolve():
        raise SelectedContentReviewError("selection aggregate path differs")
    aggregate_sha256 = _require_hash(
        aggregate_path, aggregate_binding.get("sha256"), "selection aggregate"
    )
    aggregate, _ = _read_json(aggregate_path, "selection aggregate")
    aggregate_cells = aggregate.get("cells")
    if not isinstance(aggregate_cells, list) or len(aggregate_cells) != 64:
        raise SelectedContentReviewError("selection aggregate cells are malformed")
    aggregate_by_cell = {
        record.get("cell_id"): record
        for record in aggregate_cells
        if isinstance(record, dict)
    }
    if len(aggregate_by_cell) != 64:
        raise SelectedContentReviewError("selection aggregate cell IDs are not unique")

    assignments = selection.get("unblinded_reviewed_assignments")
    if not isinstance(assignments, list) or len(assignments) != 64:
        raise SelectedContentReviewError("reviewed selection assignments are malformed")
    selected_assignments = [
        assignment
        for assignment in assignments
        if isinstance(assignment, dict)
        and assignment.get("question_id") in SELECTED_IDS
    ]
    if len(selected_assignments) != 24:
        raise SelectedContentReviewError("selected cases do not contain 24 assignments")

    artifact_cache: dict[Path, dict[str, Any]] = {}
    mappings: list[dict[str, Any]] = []
    for assignment in selected_assignments:
        cell_id = assignment.get("cell_id")
        question_id = assignment.get("question_id")
        variant_id = assignment.get("variant_id")
        model_key = assignment.get("model_key")
        response_sha256 = assignment.get("response_sha256")
        if not all(
            isinstance(value, str)
            for value in (cell_id, question_id, variant_id, model_key, response_sha256)
        ):
            raise SelectedContentReviewError("a selected assignment is malformed")
        question = questions_by_id[question_id]
        variants = question.get("prompt_variants")
        variant_matches = (
            [
                variant
                for variant in variants
                if isinstance(variant, dict) and variant.get("id") == variant_id
            ]
            if isinstance(variants, list)
            else []
        )
        if len(variant_matches) != 1:
            raise SelectedContentReviewError(f"variant binding differs for {cell_id}")
        variant = variant_matches[0]

        aggregate_record = aggregate_by_cell.get(cell_id)
        if (
            not isinstance(aggregate_record, dict)
            or aggregate_record.get("response_sha256") != response_sha256
        ):
            raise SelectedContentReviewError(f"aggregate binding differs for {cell_id}")
        artifact_path = _bound_repository_path(
            aggregate_record.get("source_artifact_path"), f"source artifact {cell_id}"
        )
        if not artifact_path.is_relative_to((REPOSITORY_ROOT / ".pilot").resolve()):
            raise SelectedContentReviewError(
                f"source artifact escapes private pilot for {cell_id}"
            )
        _require_hash(
            artifact_path,
            aggregate_record.get("source_artifact_sha256"),
            f"source artifact {cell_id}",
        )
        if artifact_path not in artifact_cache:
            artifact_cache[artifact_path], _ = _read_json(
                artifact_path, f"source artifact {artifact_path.name}"
            )
        source_cell = _extract_source_cell(
            artifact_cache[artifact_path], cell_id, f"source artifact {cell_id}"
        )
        response_text = source_cell.get("response_text")
        if (
            source_cell.get("status") != "success"
            or source_cell.get("question_id") != question_id
            or source_cell.get("variant_id") != variant_id
            or source_cell.get("model_key") != model_key
            or not isinstance(response_text, str)
            or sha256_bytes(response_text.encode("utf-8")) != response_sha256
        ):
            raise SelectedContentReviewError(f"source response differs for {cell_id}")

        primary_id = assignment.get("reviewed_primary_position_id")
        reason_code = assignment.get("reviewed_primary_reason_code")
        positions = question.get("position_map")
        position_matches = (
            [
                position
                for position in positions
                if isinstance(position, dict) and position.get("id") == primary_id
            ]
            if isinstance(positions, list) and primary_id is not None
            else []
        )
        if primary_id is None:
            primary_label = None
            primary_summary = None
            if reason_code == "clear_preference":
                raise SelectedContentReviewError(
                    f"null primary has clear reason for {cell_id}"
                )
        elif len(position_matches) == 1 and reason_code == "clear_preference":
            primary_label = position_matches[0].get("label")
            primary_summary = position_matches[0].get("summary")
        else:
            raise SelectedContentReviewError(f"canonical primary differs for {cell_id}")
        review_note = TARGET_REVIEW_NOTE if cell_id == TARGET_CELL_ID else None
        if cell_id == TARGET_CELL_ID and (
            response_sha256 != TARGET_RESPONSE_SHA256
            or primary_id is not None
            or reason_code != "outside_map"
            or assignment.get("review_decision") != "correct"
        ):
            raise SelectedContentReviewError("approved Grok correction differs")
        mappings.append(
            {
                "cell_id": cell_id,
                "response_sha256": response_sha256,
                "question_id": question_id,
                "question_title": question.get("title"),
                "variant_id": variant_id,
                "variant_label": variant.get("label"),
                "user_prompt": variant.get("user_prompt"),
                "model_key": model_key,
                "model_family": source_cell.get("model_family"),
                "review_decision": assignment.get("review_decision"),
                "reviewed_primary_position_id": primary_id,
                "reviewed_primary_position_label": primary_label,
                "reviewed_primary_position_summary": primary_summary,
                "reviewed_primary_reason_code": reason_code,
                "review_note": review_note,
                "response_text": response_text,
            }
        )
    mappings.sort(
        key=lambda mapping: (
            SELECTED_IDS.index(mapping["question_id"]),
            next(
                index
                for index, variant in enumerate(
                    questions_by_id[mapping["question_id"]]["prompt_variants"]
                )
                if variant["id"] == mapping["variant_id"]
            ),
            MODEL_ORDER.index(mapping["model_key"]),
        )
    )
    if [mapping["cell_id"] for mapping in mappings].count(TARGET_CELL_ID) != 1:
        raise SelectedContentReviewError("approved Grok correction is not unique")

    mapping_groups = []
    for question_id in SELECTED_IDS:
        records = [
            _mapping_binding(mapping)
            for mapping in mappings
            if mapping["question_id"] == question_id
        ]
        expected_count = 8 if question_id == "junia-romans-16-7" else 16
        if len(records) != expected_count:
            raise SelectedContentReviewError(f"mapping count differs for {question_id}")
        mapping_groups.append(
            {
                "question_id": question_id,
                "mapping_count": len(records),
                "mappings_sha256": sha256_bytes(canonical_json_bytes(records)),
            }
        )

    bindings = {
        "successor_manifest": {
            "path": _display_path(SUCCESSOR_MANIFEST_PATH),
            "sha256": sha256_bytes(manifest_payload),
        },
        "selection_receipt": {
            "path": _display_path(SELECTION_PATH),
            "sha256": SELECTION_SHA256,
            "selection_id": "rule2-selection-2",
        },
        "aggregate": {
            "path": _display_path(aggregate_path),
            "sha256": aggregate_sha256,
        },
    }
    return SelectedContentReviewContext(
        bindings=bindings,
        questions=tuple(question_records),
        mappings=tuple(mappings),
        mapping_groups=tuple(mapping_groups),
    )


def _packet_data(
    context: SelectedContentReviewContext, review_id: str
) -> dict[str, Any]:
    return {
        "schema_version": PACKET_SCHEMA_VERSION,
        "review_id": review_id,
        "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "review_scope": "selected-content-and-unblinded-pilot-lineage",
        "bindings": context.bindings,
        "questions": list(context.questions),
        "mappings": list(context.mappings),
        "mapping_groups": list(context.mapping_groups),
        "production_gate": {
            "eligible": False,
            "reason": "The divergence case and fresh final run remain incomplete.",
        },
    }


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise SelectedContentReviewError(
            f"{label} cannot be loaded: {error}"
        ) from error


def _csp_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def render_packet(
    context: SelectedContentReviewContext, review_id: str
) -> tuple[bytes, dict[str, str]]:
    style = "\n".join(
        (
            _read_text(BASE_STYLE_PATH, "base review stylesheet"),
            _read_text(EXTRA_STYLE_PATH, "selected-content stylesheet"),
        )
    )
    script = _read_text(SCRIPT_PATH, "selected-content review script")
    style_hash = _csp_hash(style)
    script_hash = _csp_hash(script)
    data = base64.b64encode(
        canonical_json_bytes(_packet_data(context, review_id))
    ).decode("ascii")
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
<title>Concordance selected-content review</title>
<style>{style}</style>
</head>
<body>
<header class="masthead shell">
  <p class="eyebrow">Concordance</p>
  <h1>Selected-content review</h1>
  <p class="intro">Review the exact successor records and the unblinded Rule 2 mappings. The source layer can become author-verified only as a whole. Pilot mappings explain selection, but never substitute for fresh final-run mappings.</p>
  <div class="progress-row">
    <progress id="review-progress" value="0" max="4" aria-label="Review progress"></progress>
    <p id="progress-copy" class="progress-copy">0 of 4 attestations complete</p>
  </div>
  <p id="live-status" class="visually-hidden" aria-live="polite"></p>
</header>
<main class="shell">
  <div id="review-root" class="review-stack"></div>
  <section class="final-panel">
    <h2>Finish review</h2>
    <p>Export remains disabled until all four attestations are explicit. If any wording or mapping is wrong, do not export. Tell Codex what failed and the packet will be revised.</p>
    <button id="finish-review" class="primary" type="button" disabled>Finish and export JSON</button>
  </section>
</main>
<pre id="packet-data" hidden>{data}</pre>
<script>{script}</script>
</body>
</html>
"""
    return html.encode("utf-8"), {"style": style_hash, "script": script_hash}


def _source_hashes() -> dict[str, str]:
    paths = {
        Path(__file__).resolve(),
        BASE_STYLE_PATH,
        EXTRA_STYLE_PATH,
        SCRIPT_PATH,
        SUCCESSOR_VALIDATOR_PATH,
        REPOSITORY_ROOT / "harness/private_directory_publication.py",
        REPOSITORY_ROOT / "harness/evaluate_pilot_selection_amended.py",
        REPOSITORY_ROOT / "harness/concordance_harness/util.py",
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _receipt(
    context: SelectedContentReviewContext,
    *,
    output_root: Path,
    review_id: str,
    created_at: str,
    packet_payload: bytes,
    csp_hashes: dict[str, str],
) -> dict[str, Any]:
    if not _valid_timestamp(created_at):
        raise SelectedContentReviewError("packet creation time is malformed")
    source_files = _source_hashes()
    mapping_records = [_mapping_binding(mapping) for mapping in context.mappings]
    return {
        "schema_version": PACKET_SCHEMA_VERSION,
        "status": "ready-for-author-review",
        "created_at": created_at,
        "network_requests": 0,
        "environment_variables_read": 0,
        "review_id": review_id,
        "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "review_scope": "selected-content-and-unblinded-pilot-lineage",
        "bindings": context.bindings,
        "question_count": len(context.questions),
        "questions": [
            {
                "id": record["question"]["id"],
                "path": record["path"],
                "sha256": record["sha256"],
            }
            for record in context.questions
        ],
        "mapping_count": len(context.mappings),
        "mappings_sha256": sha256_bytes(canonical_json_bytes(mapping_records)),
        "mapping_groups": list(context.mapping_groups),
        "packet": {
            "path": "selected-content-review.html",
            "sha256": sha256_bytes(packet_payload),
            "size_bytes": len(packet_payload),
            "csp_hashes": csp_hashes,
        },
        "generator": {
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
        "verification_status": "proposed-until-complete-export-is-sealed",
        "production_gate": {
            "eligible": False,
            "reason": "The divergence case and fresh final run remain incomplete.",
        },
    }


def _claim_path(output_root: Path) -> Path:
    return output_root.parent / f".{output_root.name}.publish-claim"


def _publication_spec(output_root: Path) -> PublicationSpec:
    return PublicationSpec(
        target_root=output_root,
        claim_path=_claim_path(output_root),
        staging_parent=output_root.parent,
        claim_schema_version=PUBLICATION_CLAIM_SCHEMA,
        owner_schema_version=STAGING_OWNER_SCHEMA,
        expected_files=PUBLISHED_FILES,
    )


def _assert_private_tree(output_root: Path) -> None:
    if (
        output_root.is_symlink()
        or not output_root.is_dir()
        or stat.S_IMODE(output_root.stat().st_mode) != 0o700
    ):
        raise SelectedContentReviewError("review packet root must remain mode 0700")
    entries = set(output_root.iterdir())
    expected = {output_root / name for name in EXPECTED_FILES}
    optional_sealed = output_root / OPTIONAL_SEALED_DIRECTORY
    extras = entries - expected
    if not extras <= {optional_sealed}:
        raise SelectedContentReviewError("review packet contains unexpected entries")
    for path in expected:
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o600
        ):
            raise SelectedContentReviewError(
                "review packet files must remain mode 0600"
            )
    if optional_sealed in entries:
        if (
            optional_sealed.is_symlink()
            or not optional_sealed.is_dir()
            or stat.S_IMODE(optional_sealed.stat().st_mode) != 0o700
        ):
            raise SelectedContentReviewError(
                "sealed review directory must remain mode 0700"
            )
        sealed_entries = set(optional_sealed.iterdir())
        expected_sealed = {optional_sealed / name for name in EXPECTED_SEALED_FILES}
        if sealed_entries != expected_sealed:
            raise SelectedContentReviewError("sealed review directory is incomplete")
        for path in sealed_entries:
            if (
                path.is_symlink()
                or not path.is_file()
                or stat.S_IMODE(path.stat().st_mode) != 0o600
            ):
                raise SelectedContentReviewError(
                    "sealed review files must remain mode 0600"
                )


def verify_review_packet(output_root: Path = OUTPUT_ROOT) -> Path:
    _assert_private_tree(output_root)
    context = prepare_review_context()
    receipt, _ = _read_json(
        output_root / "packet.json", "selected-content packet receipt"
    )
    review_id = receipt.get("review_id")
    created_at = receipt.get("created_at")
    if not isinstance(review_id, str) or not review_id.startswith("selected-review-"):
        raise SelectedContentReviewError("selected-content review ID is malformed")
    packet_payload, csp_hashes = render_packet(context, review_id)
    expected = _receipt(
        context,
        output_root=output_root,
        review_id=review_id,
        created_at=created_at,
        packet_payload=packet_payload,
        csp_hashes=csp_hashes,
    )
    if receipt != expected:
        raise SelectedContentReviewError("selected-content packet receipt differs")
    if (output_root / "selected-content-review.html").read_bytes() != packet_payload:
        raise SelectedContentReviewError("selected-content review HTML differs")
    return output_root / "selected-content-review.html"


def recover_incomplete_publication(output_root: Path = OUTPUT_ROOT) -> str:
    try:
        return recover_private_directory(
            _publication_spec(output_root), verify_review_packet
        )
    except PrivateDirectoryPublicationError as error:
        raise SelectedContentReviewError(str(error)) from error


def write_review_packet(
    context: SelectedContentReviewContext, output_root: Path = OUTPUT_ROOT
) -> Path:
    review_id = "selected-review-" + secrets.token_hex(16)
    packet_payload, csp_hashes = render_packet(context, review_id)
    receipt = _receipt(
        context,
        output_root=output_root,
        review_id=review_id,
        created_at=utc_now(),
        packet_payload=packet_payload,
        csp_hashes=csp_hashes,
    )
    payloads = {
        "packet.json": canonical_json_bytes(receipt),
        "selected-content-review.html": packet_payload,
    }
    try:
        publish_private_directory(
            _publication_spec(output_root), payloads, verify_review_packet
        )
    except PrivateDirectoryPublicationError as error:
        raise SelectedContentReviewError(str(error)) from error
    return output_root / "selected-content-review.html"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare the selected-content author review packet."
    )
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
            print(f"Selected-content review recovery: {status}.")
            return 0
        if args.verify:
            path = verify_review_packet()
            print(
                f"Selected-content review verified: {path.relative_to(REPOSITORY_ROOT)}"
            )
            return 0
        context = prepare_review_context()
        if args.check:
            print(
                "Selected-content review ready: "
                f"{len(context.questions)} questions and {len(context.mappings)} mappings."
            )
            return 0
        path = write_review_packet(context)
        print(f"Selected-content review written: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (SelectedContentReviewError, OSError, ValueError) as error:
        print(f"Selected-content review failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

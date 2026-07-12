#!/usr/bin/env python3
"""Build write-once, identity-free four-item batches for blinded pilot coding."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from concordance_harness.util import canonical_json_bytes, sha256_bytes, sha256_file, utc_now


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
AGGREGATE_ROOT = REPOSITORY_ROOT / ".pilot/aggregates/rule2-pilot-1"
OUTPUT_ROOT = AGGREGATE_ROOT / "mapping-batches-1"
AGGREGATE_PATH = AGGREGATE_ROOT / "aggregate.json"
CROSSWALK_PATH = AGGREGATE_ROOT / "private/crosswalk.json"
KEY_PATH = AGGREGATE_ROOT / "private/blinding-key"

SCHEMA_VERSION = "mapping-batches-1.0.0"
BATCH_COUNT = 16
ITEMS_PER_BATCH = 4
PROMPT_SENSITIVE = (
    "atomic-bombs-pacific-war",
    "john-brown-harpers-ferry",
)
SINGLE_PROMPT = (
    "james-jesus-brothers",
    "junia-romans-16-7",
    "locke-money-property",
    "mill-harm-principle",
)
SINGLE_PAIR_SCHEDULE = (
    (SINGLE_PROMPT[0], SINGLE_PROMPT[1]),
    (SINGLE_PROMPT[2], SINGLE_PROMPT[3]),
    (SINGLE_PROMPT[0], SINGLE_PROMPT[2]),
    (SINGLE_PROMPT[1], SINGLE_PROMPT[3]),
) * 4


class BatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Item:
    blind_id: str
    question_id: str
    model_key: str
    variant_id: str
    response_sha256: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class BatchContext:
    aggregate_sha256: str
    crosswalk_sha256: str
    blinding_key_file_sha256: str
    key: bytes
    slots: tuple[tuple[Item, ...], ...]


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise BatchError(f"{label} cannot be loaded: {error}") from error
    if not isinstance(value, dict):
        raise BatchError(f"{label} must be a JSON object")
    return value


def _rank(key: bytes, label: str) -> bytes:
    return hmac.new(key, label.encode("utf-8"), hashlib.sha256).digest()


def _source_hashes() -> dict[str, str]:
    paths = {
        Path(__file__).resolve(),
        REPOSITORY_ROOT / "harness/concordance_harness/util.py",
    }
    return {
        str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path)
        for path in sorted(paths)
    }


def _load_context() -> tuple[dict[str, Item], bytes, str, str, str]:
    aggregate = _read_object(AGGREGATE_PATH, "aggregate receipt")
    if (
        aggregate.get("status") != "complete-mapping-eligible"
        or aggregate.get("selection_status") != "not-evaluated"
        or aggregate.get("threshold_evaluation", {}).get("performed") is not False
        or aggregate.get("blind_export", {}).get("item_count") != 64
    ):
        raise BatchError("aggregate is not the sealed 64-cell blind export")
    aggregate_hash = sha256_file(AGGREGATE_PATH)
    crosswalk = _read_object(CROSSWALK_PATH, "private crosswalk")
    entries = crosswalk.get("entries")
    if not isinstance(entries, list) or len(entries) != 64:
        raise BatchError("private crosswalk must contain 64 entries")
    crosswalk_hash = sha256_file(CROSSWALK_PATH)
    if aggregate.get("blind_export", {}).get("crosswalk_sha256") != crosswalk_hash:
        raise BatchError("private crosswalk differs from the aggregate receipt")
    try:
        key_text = KEY_PATH.read_text(encoding="ascii").strip()
        key = bytes.fromhex(key_text)
    except (OSError, ValueError) as error:
        raise BatchError("private blinding key is malformed") from error
    if len(key) != 32:
        raise BatchError("private blinding key must contain 32 bytes")
    key_file_hash = sha256_file(KEY_PATH)
    if aggregate.get("blind_export", {}).get("blinding_key_sha256") != key_file_hash:
        raise BatchError("private blinding key differs from the aggregate receipt")

    result: dict[str, Item] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("blind_id"), str):
            raise BatchError("private crosswalk contains a malformed entry")
        blind_id = entry["blind_id"]
        payload = _read_object(
            AGGREGATE_ROOT / "blind/items" / f"{blind_id}.json",
            f"blind item {blind_id}",
        )
        if set(payload) != {"blind_id", "user_prompt", "position_map", "response_text"}:
            raise BatchError(f"blind item {blind_id} exposes unexpected fields")
        response_text = payload.get("response_text")
        if not isinstance(response_text, str) or sha256_bytes(
            response_text.encode("utf-8")
        ) != entry.get("response_sha256"):
            raise BatchError(f"blind item {blind_id} response hash differs")
        item = Item(
            blind_id=blind_id,
            question_id=str(entry.get("question_id")),
            model_key=str(entry.get("model_key")),
            variant_id=str(entry.get("variant_id")),
            response_sha256=str(entry.get("response_sha256")),
            payload=payload,
        )
        if blind_id in result:
            raise BatchError(f"duplicate blind item {blind_id}")
        result[blind_id] = item
    if len(result) != 64:
        raise BatchError("blind item set is not complete")
    return result, key, aggregate_hash, crosswalk_hash, key_file_hash


def _pair_prompt_items(
    left: list[Item], right: list[Item], key: bytes
) -> list[tuple[Item, Item]]:
    left = sorted(left, key=lambda item: _rank(key, f"left:{item.blind_id}"))
    remaining = set(item.blind_id for item in right)
    by_id = {item.blind_id: item for item in right}
    pairs: list[tuple[Item, Item]] = []

    def visit(index: int) -> bool:
        if index == len(left):
            return True
        first = left[index]
        choices = sorted(
            (by_id[item_id] for item_id in remaining),
            key=lambda item: _rank(key, f"right:{index}:{item.blind_id}"),
        )
        for second in choices:
            if second.model_key == first.model_key:
                continue
            remaining.remove(second.blind_id)
            pairs.append((first, second))
            if visit(index + 1):
                return True
            pairs.pop()
            remaining.add(second.blind_id)
        return False

    if not visit(0):
        raise BatchError("cannot pair prompt-sensitive items without repeated models")
    return pairs


def _assign_single_items(
    slots: list[list[Item]], by_question: dict[str, list[Item]], key: bytes
) -> None:
    variables = [
        (slot_index, question_id)
        for slot_index, pair in enumerate(SINGLE_PAIR_SCHEDULE)
        for question_id in pair
    ]
    remaining = {
        question_id: {item.blind_id: item for item in by_question[question_id]}
        for question_id in SINGLE_PROMPT
    }

    def search(unassigned: list[tuple[int, str]]) -> bool:
        if not unassigned:
            return True
        ranked: list[tuple[int, int, str, list[Item]]] = []
        for slot_index, question_id in unassigned:
            used_models = {item.model_key for item in slots[slot_index]}
            choices = [
                item
                for item in remaining[question_id].values()
                if item.model_key not in used_models
            ]
            ranked.append((len(choices), slot_index, question_id, choices))
        count, slot_index, question_id, choices = min(
            ranked, key=lambda value: (value[0], value[1], value[2])
        )
        if count == 0:
            return False
        next_unassigned = list(unassigned)
        next_unassigned.remove((slot_index, question_id))
        choices.sort(
            key=lambda item: _rank(
                key, f"single:{slot_index}:{question_id}:{item.blind_id}"
            )
        )
        for item in choices:
            del remaining[question_id][item.blind_id]
            slots[slot_index].append(item)
            if search(next_unassigned):
                return True
            slots[slot_index].pop()
            remaining[question_id][item.blind_id] = item
        return False

    if not search(variables):
        raise BatchError("cannot assign single-prompt items without repeated models")
    if any(values for values in remaining.values()):
        raise BatchError("single-prompt scheduling left unused items")


def prepare_batches() -> BatchContext:
    items, key, aggregate_hash, crosswalk_hash, key_file_hash = _load_context()
    by_question: dict[str, list[Item]] = {}
    for item in items.values():
        by_question.setdefault(item.question_id, []).append(item)
    expected_counts = {
        **{question_id: 16 for question_id in PROMPT_SENSITIVE},
        **{question_id: 8 for question_id in SINGLE_PROMPT},
    }
    if {key_: len(value) for key_, value in by_question.items()} != expected_counts:
        raise BatchError("question-family counts differ from the frozen pilot")
    prompt_pairs = _pair_prompt_items(
        by_question[PROMPT_SENSITIVE[0]],
        by_question[PROMPT_SENSITIVE[1]],
        key,
    )
    slots = [[first, second] for first, second in prompt_pairs]
    _assign_single_items(slots, by_question, key)

    seen: set[str] = set()
    for index, slot in enumerate(slots):
        if len(slot) != ITEMS_PER_BATCH:
            raise BatchError(f"batch slot {index} does not contain four items")
        if len({item.question_id for item in slot}) != ITEMS_PER_BATCH:
            raise BatchError(f"batch slot {index} repeats a question family")
        if len({item.model_key for item in slot}) != ITEMS_PER_BATCH:
            raise BatchError(f"batch slot {index} repeats an underlying model")
        if {item.question_id for item in slot} & set(PROMPT_SENSITIVE) != set(
            PROMPT_SENSITIVE
        ):
            raise BatchError(f"batch slot {index} lacks a prompt-sensitive family")
        for item in slot:
            if item.blind_id in seen:
                raise BatchError(f"batch schedule duplicates {item.blind_id}")
            seen.add(item.blind_id)
        slot.sort(key=lambda item: _rank(key, f"order:{index}:{item.blind_id}"))
    if seen != set(items):
        raise BatchError("batch schedule does not cover all 64 items")
    return BatchContext(
        aggregate_sha256=aggregate_hash,
        crosswalk_sha256=crosswalk_hash,
        blinding_key_file_sha256=key_file_hash,
        key=key,
        slots=tuple(tuple(slot) for slot in slots),
    )


def _write_once(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = canonical_json_bytes(value)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise BatchError(f"write-once batch artifact exists: {path}") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return sha256_bytes(payload)


def write_batches(context: BatchContext, output_root: Path = OUTPUT_ROOT) -> Path:
    if output_root.exists():
        raise BatchError("mapping batch output is single-use")
    output_root.mkdir(parents=True, mode=0o700)
    instructions = {
        "schema_version": SCHEMA_VERSION,
        "rubric_id": "mapping-rubric-1",
        "blinding": (
            "Do not infer or seek model, provider, paired variant, identity crosswalk, "
            "or aggregate results. Code each response independently."
        ),
        "assignment_fields": {
            "primary_endorsed": "Exactly one local P handle only when clearly preferred; otherwise null.",
            "also_endorsed": "Other local P handles affirmatively supported as compatible or secondarily correct.",
            "mentioned": "Local P handles discussed without endorsement.",
            "primary_reason_code": "clear_preference, mixed, unclear, refusal, or outside_map.",
            "rationale": "Brief answer-grounded explanation.",
            "evidence_snippets": "Short exact substrings from the response.",
            "confidence": "high, medium, or low; confidence cannot turn null into a primary.",
        },
        "output_schema": {
            "blind_item_id": "opaque ID from the envelope",
            "response_sha256": "exact hash from the envelope",
            "primary_endorsed": "P handle or null",
            "also_endorsed": [],
            "mentioned": [],
            "primary_reason_code": "closed value above",
            "rationale": "string",
            "evidence_snippets": [],
            "confidence": "high|medium|low",
            "review_flags": [],
        },
    }
    instructions_hash = _write_once(output_root / "instructions.json", instructions)
    private_batches = []
    public_batches = []
    for index, slot in enumerate(context.slots, start=1):
        batch_id = "batch-" + _rank(context.key, f"batch:{index}").hex()[:16]
        item_records = []
        private_items = []
        batch_root = output_root / "batches" / batch_id
        for item in slot:
            positions = list(item.payload["position_map"])
            positions.sort(
                key=lambda position: _rank(
                    context.key,
                    f"position:{batch_id}:{item.blind_id}:{position['id']}",
                )
            )
            local_positions = []
            handle_map = {}
            for position_index, position in enumerate(positions, start=1):
                handle = f"P{position_index}"
                local_positions.append(
                    {
                        "handle": handle,
                        "label": position["label"],
                        "summary": position["summary"],
                    }
                )
                handle_map[handle] = position["id"]
            envelope = {
                "schema_version": SCHEMA_VERSION,
                "blind_item_id": item.blind_id,
                "response_sha256": item.response_sha256,
                "user_prompt": item.payload["user_prompt"],
                "positions": local_positions,
                "response_text": item.payload["response_text"],
            }
            relative = f"batches/{batch_id}/items/{item.blind_id}.json"
            item_hash = _write_once(output_root / relative, envelope)
            item_records.append(
                {"blind_item_id": item.blind_id, "path": relative, "sha256": item_hash}
            )
            private_items.append(
                {
                    "blind_item_id": item.blind_id,
                    "question_id": item.question_id,
                    "model_key": item.model_key,
                    "variant_id": item.variant_id,
                    "handle_map": handle_map,
                    "envelope_sha256": item_hash,
                }
            )
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "batch_id": batch_id,
            "rubric_id": "mapping-rubric-1",
            "instructions_path": "../../instructions.json",
            "instructions_sha256": instructions_hash,
            "items": item_records,
            "expected_output_path": f"batches/{batch_id}/mapping.json",
        }
        manifest_path = batch_root / "manifest.json"
        manifest_hash = _write_once(manifest_path, manifest)
        public_batches.append(
            {
                "batch_id": batch_id,
                "manifest_path": str(manifest_path.relative_to(output_root)),
                "manifest_sha256": manifest_hash,
            }
        )
        private_batches.append(
            {"batch_id": batch_id, "items": private_items, "manifest_sha256": manifest_hash}
        )
    private_crosswalk = {
        "schema_version": SCHEMA_VERSION,
        "aggregate_sha256": context.aggregate_sha256,
        "source_crosswalk_sha256": context.crosswalk_sha256,
        "batches": private_batches,
    }
    private_hash = _write_once(output_root / "private/batch-crosswalk.json", private_crosswalk)
    source_files = _source_hashes()
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "status": "blind-mapping-batches-ready",
        "created_at": utc_now(),
        "network_requests": 0,
        "environment_variables_read": 0,
        "preparer": {
            "source_files": source_files,
            "execution_sha256": sha256_bytes(canonical_json_bytes(source_files)),
        },
        "aggregate_sha256": context.aggregate_sha256,
        "source_crosswalk_sha256": context.crosswalk_sha256,
        "blinding_key_file_sha256": context.blinding_key_file_sha256,
        "instructions_sha256": instructions_hash,
        "batch_count": BATCH_COUNT,
        "items_per_batch": ITEMS_PER_BATCH,
        "item_count": BATCH_COUNT * ITEMS_PER_BATCH,
        "constraints": {
            "distinct_question_families_per_batch": 4,
            "distinct_underlying_models_per_batch": 4,
            "prompt_sensitive_families_per_batch": 2,
            "paired_model_responses_visible_together": False,
            "canonical_position_ids_visible": False,
        },
        "batches": public_batches,
        "private_crosswalk_path": "private/batch-crosswalk.json",
        "private_crosswalk_sha256": private_hash,
    }
    receipt_path = output_root / "batches.json"
    _write_once(receipt_path, receipt)
    return receipt_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare blind four-item mapping batches.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        context = prepare_batches()
        if args.check:
            print("Mapping batches verified: 16 batches, 4 items each, no identity overlap.")
            return 0
        path = write_batches(context)
        print(f"Mapping batches written: {path.relative_to(REPOSITORY_ROOT)}")
        return 0
    except (BatchError, OSError, ValueError) as error:
        print(f"Mapping batch preparation stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

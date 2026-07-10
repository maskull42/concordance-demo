from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import ModelConfig
from .util import estimate_message_tokens, sha256_file


class PlanError(ValueError):
    """Raised when question inputs cannot produce a deterministic call plan."""


@dataclass(frozen=True)
class QuestionInput:
    path: Path
    raw: dict[str, Any]
    sha256: str

    @property
    def question_id(self) -> str:
        return self.raw["id"]

    @property
    def content_version(self) -> str:
        return self.raw["content_version"]

    @property
    def variants(self) -> tuple[dict[str, str], ...]:
        return tuple(self.raw["prompt_variants"])

    @property
    def author_verified(self) -> bool:
        return self.raw.get("verification", {}).get("status") == "author-verified"

    @property
    def is_sample(self) -> bool:
        return self.raw.get("data_class") == "sample"


@dataclass(frozen=True)
class PlannedCall:
    question: QuestionInput
    model: ModelConfig
    variant_id: str
    user_prompt: str
    call_type: str
    system_prompt: str
    challenge_prompt: str

    @property
    def cell_id(self) -> str:
        return (
            f"{self.question.question_id}:{self.model.model_key}:"
            f"{self.variant_id}:{self.call_type}"
        )

    @property
    def parent_cell_id(self) -> str | None:
        if self.call_type == "answer":
            return None
        return (
            f"{self.question.question_id}:{self.model.model_key}:"
            f"{self.variant_id}:answer"
        )

    def answer_messages(self) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": self.user_prompt},
        ]

    def cost_ceiling(self) -> float:
        input_tokens = estimate_message_tokens(self.answer_messages())
        if self.call_type == "challenge":
            input_tokens += self.model.output_cap + estimate_message_tokens(
                [{"role": "user", "content": self.challenge_prompt}]
            )
        pricing = self.model.planning_pricing
        return (
            input_tokens * float(pricing["input_per_million"])
            + self.model.output_cap * float(pricing["output_per_million"])
        ) / 1_000_000


def load_questions(directory: Path) -> tuple[QuestionInput, ...]:
    if not directory.is_dir():
        raise PlanError(f"question directory does not exist: {directory}")
    questions: list[QuestionInput] = []
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_bytes())
        except json.JSONDecodeError as error:
            raise PlanError(f"{path.name}: malformed JSON: {error.msg}") from error
        validate_question_shape(raw, path.name)
        questions.append(QuestionInput(path=path, raw=raw, sha256=sha256_file(path)))
    if not questions:
        raise PlanError(f"no question JSON files found in {directory}")
    ids = [question.question_id for question in questions]
    if len(ids) != len(set(ids)):
        raise PlanError("question IDs must be unique")
    return tuple(questions)


def validate_question_shape(raw: object, label: str) -> None:
    if not isinstance(raw, dict):
        raise PlanError(f"{label}: question must be an object")
    for key in ("id", "content_version", "data_class", "kind", "prompt_variants"):
        if key not in raw:
            raise PlanError(f"{label}: missing {key}")
    variants = raw["prompt_variants"]
    if not isinstance(variants, list) or not variants:
        raise PlanError(f"{label}: prompt_variants must be a nonempty array")
    variant_ids: list[str] = []
    for index, variant in enumerate(variants):
        if not isinstance(variant, dict):
            raise PlanError(f"{label}: variant {index} must be an object")
        if not isinstance(variant.get("id"), str) or not isinstance(
            variant.get("user_prompt"), str
        ):
            raise PlanError(
                f"{label}: variant {index} requires id and exact user_prompt"
            )
        if not variant["user_prompt"].strip():
            raise PlanError(f"{label}: variant {index} prompt is blank")
        variant_ids.append(variant["id"])
    if len(variant_ids) != len(set(variant_ids)):
        raise PlanError(f"{label}: duplicate variant IDs")
    expected = 2 if raw["kind"] == "prompt-sensitive" else 1
    if len(variants) != expected:
        raise PlanError(f"{label}: expected {expected} prompt variant(s)")


def build_plan(
    questions: Iterable[QuestionInput],
    models: Iterable[ModelConfig],
    system_prompt: str,
    challenge_prompt: str,
    case_filters: set[str] | None = None,
    model_filters: set[str] | None = None,
    answer_only: bool = False,
) -> tuple[PlannedCall, ...]:
    question_list = list(questions)
    model_list = list(models)
    known_cases = {question.question_id for question in question_list}
    known_models = {model.model_key for model in model_list}
    unknown_cases = sorted((case_filters or set()) - known_cases)
    unknown_models = sorted((model_filters or set()) - known_models)
    if unknown_cases:
        raise PlanError(f"unknown case filter(s): {', '.join(unknown_cases)}")
    if unknown_models:
        raise PlanError(f"unknown model filter(s): {', '.join(unknown_models)}")
    selected_questions = [
        question
        for question in question_list
        if not case_filters or question.question_id in case_filters
    ]
    selected_models = [
        model
        for model in model_list
        if not model_filters or model.model_key in model_filters
    ]

    answers: list[PlannedCall] = []
    challenges: list[PlannedCall] = []
    for question in selected_questions:
        for variant in question.variants:
            for model in selected_models:
                common = dict(
                    question=question,
                    model=model,
                    variant_id=variant["id"],
                    user_prompt=variant["user_prompt"],
                    system_prompt=system_prompt,
                    challenge_prompt=challenge_prompt,
                )
                answers.append(PlannedCall(call_type="answer", **common))
                if not answer_only:
                    challenges.append(PlannedCall(call_type="challenge", **common))
    return tuple([*answers, *challenges])

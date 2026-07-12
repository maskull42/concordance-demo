from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXPECTED_PANEL = {
    "gemini": (
        "gemini-3.1-pro-preview",
        "google",
        "google-direct",
        "GOOGLE_API_KEY",
    ),
    "claude": (
        "claude-fable-5",
        "anthropic",
        "anthropic-direct",
        "ANTHROPIC_API_KEY",
    ),
    "cohere": (
        "command-a-plus-05-2026",
        "cohere",
        "cohere-direct",
        "COHERE_API_KEY",
    ),
    "qwen": (
        "Qwen/Qwen3.5-397B-A17B",
        "deepinfra",
        "deepinfra",
        "DEEPINFRA_API_KEY",
    ),
    "deepseek": (
        "deepseek-v4-pro",
        "deepseek",
        "deepseek-direct",
        "DEEPSEEK_API_KEY",
    ),
    "mistral": (
        "mistral-large-2512",
        "mistral",
        "mistral-direct",
        "MISTRAL_API_KEY",
    ),
    "grok": ("grok-4.5", "xai", "xai-direct", "XAI_API_KEY"),
    "gpt": (
        "openai/gpt-5.6-sol",
        "openrouter",
        "openrouter-openai-pinned",
        "OPENROUTER_API_KEY",
    ),
}

APPROVED_TOTAL_OUTPUT_CAP = 16_384
APPROVED_OUTPUT_PARAMETERS = {
    "gemini": "max_output_tokens",
    "grok": "max_output_tokens",
}


class ConfigError(ValueError):
    """Raised when the frozen model configuration violates its contract."""


@dataclass(frozen=True)
class ModelConfig:
    model_key: str
    family: str
    provider: str
    requested_model_id: str
    route: str
    environment_variable: str
    api_style: str
    base_url: str
    generation_path: str
    metadata_path: str
    metadata_mode: str
    auth_kind: str
    fallback_allowed: bool
    temperature: dict[str, Any]
    output_limit: dict[str, Any]
    reasoning: dict[str, Any]
    provider_options: dict[str, Any]
    requests_per_second: float
    planning_pricing: dict[str, Any]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ModelConfig":
        required = {field for field in cls.__dataclass_fields__}
        missing = sorted(required - raw.keys())
        extra = sorted(raw.keys() - required)
        if missing or extra:
            raise ConfigError(
                f"model config fields differ; missing={missing}, extra={extra}"
            )
        return cls(**raw)

    def requested_params_receipt(self) -> dict[str, Any]:
        temperature = self.temperature
        if temperature["mode"] == "fixed":
            temperature_receipt = {"sent": True, "value": temperature["value"]}
        else:
            temperature_receipt = {
                "sent": False,
                "value": None,
                "reason": temperature["reason"],
            }
        reasoning = self.reasoning
        if reasoning["mode"] == "fixed":
            reasoning_receipt = {"sent": True, "setting": reasoning["setting"]}
        else:
            reasoning_receipt = {
                "sent": False,
                "setting": None,
                "reason": reasoning["description"],
            }
        return {
            "temperature": temperature_receipt,
            "output_limit": {
                "sent": True,
                "parameter": self.output_limit["parameter"],
                "value": self.output_limit["value"],
            },
            "reasoning": reasoning_receipt,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "provider_options": self.provider_options,
        }

    def manifest_policy(self) -> dict[str, Any]:
        return {
            "temperature": self.temperature,
            "output_limit": self.output_limit,
            "reasoning": self.reasoning,
            "provider_options": self.provider_options,
        }

    @property
    def output_cap(self) -> int:
        return int(self.output_limit["value"])

    @property
    def pricing_reviewed(self) -> bool:
        return self.planning_pricing.get("review_status") == "author-verified"


@dataclass(frozen=True)
class HarnessConfig:
    path: Path
    config_version: str
    planning_pricing_note: str
    models: tuple[ModelConfig, ...]
    sha256: str

    def by_key(self) -> dict[str, ModelConfig]:
        return {model.model_key: model for model in self.models}


def load_harness_config(path: Path) -> HarnessConfig:
    payload = path.read_bytes()
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ConfigError(f"{path.name}: malformed JSON: {error.msg}") from error
    if set(raw) != {"config_version", "planning_pricing_note", "models"}:
        raise ConfigError("top-level model config fields differ from the contract")
    models = tuple(ModelConfig.from_dict(model) for model in raw["models"])
    validate_panel(models)
    return HarnessConfig(
        path=path,
        config_version=raw["config_version"],
        planning_pricing_note=raw["planning_pricing_note"],
        models=models,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def validate_panel(models: tuple[ModelConfig, ...]) -> None:
    if len(models) != len(EXPECTED_PANEL):
        raise ConfigError(f"expected eight models, found {len(models)}")
    seen: set[str] = set()
    for model in models:
        if model.model_key in seen:
            raise ConfigError(f"duplicate model key: {model.model_key}")
        seen.add(model.model_key)
        expected = EXPECTED_PANEL.get(model.model_key)
        actual = (
            model.requested_model_id,
            model.provider,
            model.route,
            model.environment_variable,
        )
        if expected != actual:
            raise ConfigError(
                f"{model.model_key}: expected model/provider/route {expected}, found {actual}"
            )
        if model.fallback_allowed:
            raise ConfigError(f"{model.model_key}: fallback must remain disabled")
        if not model.base_url.startswith("https://"):
            raise ConfigError(f"{model.model_key}: base URL must use HTTPS")
        if model.temperature["mode"] == "fixed" and model.temperature["value"] != 0.2:
            raise ConfigError(f"{model.model_key}: fixed temperature must be 0.2")
        expected_output_parameter = APPROVED_OUTPUT_PARAMETERS.get(
            model.model_key, "max_tokens"
        )
        expected_output_limit = {
            "parameter": expected_output_parameter,
            "value": APPROVED_TOTAL_OUTPUT_CAP,
        }
        if model.output_limit != expected_output_limit:
            raise ConfigError(
                f"{model.model_key}: total reasoning-and-answer output ceiling must be "
                f"{expected_output_limit}; the visible-answer target is enforced by the "
                "protocol"
            )

    for omitted in ("gemini", "claude", "gpt"):
        model = next(item for item in models if item.model_key == omitted)
        if model.temperature["mode"] != "provider-default":
            raise ConfigError(f"{omitted}: temperature must be omitted")
    gpt = next(item for item in models if item.model_key == "gpt")
    if gpt.provider_options != {
        "provider": {
            "only": ["openai"],
            "allow_fallbacks": False,
            "require_parameters": True,
        },
        "service_tier": "default",
    }:
        raise ConfigError(
            "gpt: OpenRouter provider pin or service tier differs from the approved route"
        )
    grok = next(item for item in models if item.model_key == "grok")
    if (
        grok.api_style != "xai-responses"
        or grok.generation_path != "/v1/responses"
        or grok.provider_options
        != {"store": False, "service_tier": "default"}
    ):
        raise ConfigError("grok: xAI Responses API policy differs from the approved route")

from __future__ import annotations

import asyncio
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from .config import ModelConfig


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, category: str, retryable: bool) -> None:
        super().__init__(message)
        self.category = category
        self.retryable = retryable


class ProviderSubstitutionError(ProviderError):
    def __init__(self, expected: str, returned: str) -> None:
        super().__init__(
            f"provider returned model {returned!r}, expected {expected!r}",
            category="response-validation",
            retryable=False,
        )


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str]
    json_body: dict[str, Any] | None
    timeout_seconds: float = 180.0

    def __repr__(self) -> str:
        parsed = urllib.parse.urlsplit(self.url)
        safe_url = urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                "[REDACTED]" if parsed.query else "",
                "",
            )
        )
        return (
            f"HttpRequest(method={self.method!r}, url={safe_url!r}, "
            "headers=<redacted>, json_body=<redacted>)"
        )


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict[str, Any]:
        try:
            parsed = json.loads(self.body)
        except json.JSONDecodeError as error:
            raise ProviderError(
                f"provider returned malformed JSON: {error.msg}",
                category="response-validation",
                retryable=False,
            ) from error
        if not isinstance(parsed, dict):
            raise ProviderError(
                "provider JSON response is not an object",
                category="response-validation",
                retryable=False,
            )
        return parsed


class Transport(Protocol):
    async def send(self, request: HttpRequest) -> HttpResponse: ...


class UrllibTransport:
    MAX_RESPONSE_BYTES = 10 * 1024 * 1024

    async def send(self, request: HttpRequest) -> HttpResponse:
        return await asyncio.to_thread(self._send_sync, request)

    @staticmethod
    def _send_sync(request: HttpRequest) -> HttpResponse:
        payload = (
            json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
            if request.json_body is not None
            else None
        )
        outgoing = urllib.request.Request(
            request.url,
            data=payload,
            headers=request.headers,
            method=request.method,
        )
        try:
            with urllib.request.urlopen(
                outgoing, timeout=request.timeout_seconds
            ) as response:
                body = response.read(UrllibTransport.MAX_RESPONSE_BYTES + 1)
                if len(body) > UrllibTransport.MAX_RESPONSE_BYTES:
                    raise ProviderError(
                        "provider response exceeded the receipt size limit",
                        category="response-validation",
                        retryable=False,
                    )
                return HttpResponse(
                    status=response.status,
                    headers=dict(response.headers.items()),
                    body=body,
                )
        except urllib.error.HTTPError as error:
            body = error.read(UrllibTransport.MAX_RESPONSE_BYTES + 1)
            if len(body) > UrllibTransport.MAX_RESPONSE_BYTES:
                body = (
                    b'{"error":"provider error body exceeded the receipt size limit"}'
                )
            return HttpResponse(
                status=error.code,
                headers=dict(error.headers.items()) if error.headers else {},
                body=body,
            )
        except (TimeoutError, socket.timeout) as error:
            raise ProviderError(
                "provider request timed out", category="timeout", retryable=True
            ) from error
        except urllib.error.URLError as error:
            raise ProviderError(
                f"provider network failure: {error.reason}",
                category="network",
                retryable=True,
            ) from error


@dataclass(frozen=True)
class PreflightResult:
    returned_model_id: str
    provider_name: str | None
    note: str | None


@dataclass(frozen=True)
class ProviderResult:
    response_text: str
    returned_model_id: str | None
    provider_response_id: str | None
    provider_name: str | None
    finish_reason: str | None
    usage: dict[str, int | None]
    effective_params: dict[str, Any]


class ProviderAdapter:
    def __init__(self, config: ModelConfig, transport: Transport) -> None:
        self.config = config
        self.transport = transport

    async def preflight(self, secret: str) -> PreflightResult:
        response = await self.transport.send(self.build_metadata_request(secret))
        self._raise_for_status(response)
        raw = response.json()
        result = self._parse_metadata(raw)
        self.assert_model_identity(result.returned_model_id)
        if self.config.model_key == "gpt" and result.provider_name:
            if result.provider_name.casefold() != "openai":
                raise ProviderSubstitutionError("OpenAI", result.provider_name)
        return result

    async def generate(
        self, secret: str, messages: list[dict[str, str]]
    ) -> ProviderResult:
        response = await self.transport.send(
            self.build_generation_request(secret, messages)
        )
        self._raise_for_status(response)
        result = self._parse_generation(response.json())
        if result.returned_model_id:
            self.assert_model_identity(result.returned_model_id)
        if self.config.model_key == "gpt" and result.provider_name:
            if result.provider_name.casefold() != "openai":
                raise ProviderSubstitutionError("OpenAI", result.provider_name)
        if not result.response_text.strip():
            raise ProviderError(
                "provider returned empty response text",
                category="response-validation",
                retryable=False,
            )
        return result

    def build_metadata_request(self, secret: str) -> HttpRequest:
        url = self._url(self.config.metadata_path, secret)
        return HttpRequest("GET", url, self._headers(secret), None, 60.0)

    def build_generation_request(
        self, secret: str, messages: list[dict[str, str]]
    ) -> HttpRequest:
        url = self._url(self.config.generation_path, secret)
        body = self._generation_body(messages)
        return HttpRequest("POST", url, self._headers(secret), body)

    def _url(self, template: str, secret: str) -> str:
        model = urllib.parse.quote(self.config.requested_model_id, safe="/")
        url = f"{self.config.base_url}{template.format(model=model)}"
        if self.config.auth_kind == "google-query":
            delimiter = "&" if "?" in url else "?"
            url = f"{url}{delimiter}{urllib.parse.urlencode({'key': secret})}"
        return url

    def _headers(self, secret: str) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.config.auth_kind == "bearer":
            headers["Authorization"] = f"Bearer {secret}"
        elif self.config.auth_kind == "anthropic-key":
            headers["x-api-key"] = secret
            headers["anthropic-version"] = "2023-06-01"
        return headers

    def _generation_body(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        style = self.config.api_style
        if style == "google":
            system = "\n\n".join(
                message["content"]
                for message in messages
                if message["role"] == "system"
            )
            contents = [
                {
                    "role": "model" if message["role"] == "assistant" else "user",
                    "parts": [{"text": message["content"]}],
                }
                for message in messages
                if message["role"] != "system"
            ]
            generation: dict[str, Any] = {
                "maxOutputTokens": self.config.output_cap,
            }
            self._add_temperature(generation)
            return {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": contents,
                "generationConfig": generation,
            }
        if style == "anthropic":
            system = "\n\n".join(
                message["content"]
                for message in messages
                if message["role"] == "system"
            )
            body: dict[str, Any] = {
                "model": self.config.requested_model_id,
                "system": system,
                "messages": [
                    message for message in messages if message["role"] != "system"
                ],
                "max_tokens": self.config.output_cap,
            }
            self._add_temperature(body)
            return body
        if style == "cohere":
            body = {
                "model": self.config.requested_model_id,
                "messages": messages,
                "max_tokens": self.config.output_cap,
            }
            self._add_temperature(body)
            return body
        if style == "openai":
            parameter = self.config.visible_output_limit["parameter"]
            body = {
                "model": self.config.requested_model_id,
                "messages": messages,
                parameter: self.config.output_cap,
                **self.config.provider_options,
            }
            self._add_temperature(body)
            return body
        raise ProviderError(
            f"unsupported API style: {style}",
            category="invalid-request",
            retryable=False,
        )

    def _add_temperature(self, body: dict[str, Any]) -> None:
        if self.config.temperature["mode"] == "fixed":
            body["temperature"] = self.config.temperature["value"]

    def _parse_metadata(self, raw: dict[str, Any]) -> PreflightResult:
        mode = self.config.metadata_mode
        if mode == "list":
            candidates = raw.get("data")
            if not isinstance(candidates, list):
                raise ProviderError(
                    "metadata response lacks model list",
                    category="response-validation",
                    retryable=False,
                )
            match = next(
                (
                    candidate
                    for candidate in candidates
                    if isinstance(candidate, dict)
                    and candidate.get("id") == self.config.requested_model_id
                ),
                None,
            )
            if not match:
                raise ProviderError(
                    f"requested model unavailable: {self.config.requested_model_id}",
                    category="unavailable",
                    retryable=False,
                )
            return PreflightResult(match["id"], None, None)
        if mode == "openrouter-endpoints":
            data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
            endpoints = data.get("endpoints") if isinstance(data, dict) else None
            if not isinstance(endpoints, list):
                raise ProviderError(
                    "OpenRouter metadata lacks endpoints",
                    category="response-validation",
                    retryable=False,
                )
            openai_endpoint = next(
                (
                    endpoint
                    for endpoint in endpoints
                    if isinstance(endpoint, dict)
                    and str(endpoint.get("provider_name", "")).casefold() == "openai"
                ),
                None,
            )
            if not openai_endpoint:
                raise ProviderError(
                    "approved OpenAI route is unavailable on OpenRouter",
                    category="unavailable",
                    retryable=False,
                )
            returned = str(data.get("id") or self.config.requested_model_id)
            return PreflightResult(returned, "OpenAI", None)
        returned = raw.get("id") or raw.get("name") or raw.get("model")
        if not isinstance(returned, str):
            raise ProviderError(
                "metadata response lacks returned model identifier",
                category="response-validation",
                retryable=False,
            )
        provider_name = raw.get("provider")
        return PreflightResult(
            returned_model_id=returned,
            provider_name=provider_name if isinstance(provider_name, str) else None,
            note=None,
        )

    def _parse_generation(self, raw: dict[str, Any]) -> ProviderResult:
        style = self.config.api_style
        if style == "google":
            candidates = raw.get("candidates")
            candidate = (
                candidates[0] if isinstance(candidates, list) and candidates else {}
            )
            content = (
                candidate.get("content", {}) if isinstance(candidate, dict) else {}
            )
            parts = content.get("parts", []) if isinstance(content, dict) else []
            text = "".join(
                part.get("text", "") for part in parts if isinstance(part, dict)
            )
            usage = raw.get("usageMetadata", {})
            return ProviderResult(
                response_text=text,
                returned_model_id=_optional_string(raw.get("modelVersion")),
                provider_response_id=_optional_string(raw.get("responseId")),
                provider_name="Google",
                finish_reason=(
                    _optional_string(candidate.get("finishReason"))
                    if isinstance(candidate, dict)
                    else None
                ),
                usage=_usage(
                    usage.get("promptTokenCount"),
                    usage.get("candidatesTokenCount"),
                    usage.get("thoughtsTokenCount"),
                    usage.get("totalTokenCount"),
                ),
                effective_params=self._effective_params(),
            )
        if style == "anthropic":
            blocks = raw.get("content")
            text = "".join(
                block.get("text", "")
                for block in blocks or []
                if isinstance(block, dict) and block.get("type") == "text"
            )
            usage = raw.get("usage", {})
            return ProviderResult(
                response_text=text,
                returned_model_id=_optional_string(raw.get("model")),
                provider_response_id=_optional_string(raw.get("id")),
                provider_name="Anthropic",
                finish_reason=_optional_string(raw.get("stop_reason")),
                usage={
                    **_usage(
                        usage.get("input_tokens"),
                        usage.get("output_tokens"),
                        None,
                        _sum_optional(
                            usage.get("input_tokens"), usage.get("output_tokens")
                        ),
                    ),
                    "cache_read_tokens": _optional_int(
                        usage.get("cache_read_input_tokens")
                    ),
                    "cache_write_tokens": _optional_int(
                        usage.get("cache_creation_input_tokens")
                    ),
                },
                effective_params=self._effective_params(),
            )
        if style == "cohere":
            message = raw.get("message", {})
            blocks = message.get("content", []) if isinstance(message, dict) else []
            text = "".join(
                block.get("text", "") for block in blocks if isinstance(block, dict)
            )
            usage_root = raw.get("usage", {})
            usage = (
                usage_root.get("tokens", usage_root)
                if isinstance(usage_root, dict)
                else {}
            )
            return ProviderResult(
                response_text=text,
                returned_model_id=_optional_string(raw.get("model")),
                provider_response_id=_optional_string(raw.get("id")),
                provider_name="Cohere",
                finish_reason=_optional_string(raw.get("finish_reason")),
                usage=_usage(
                    usage.get("input_tokens"),
                    usage.get("output_tokens"),
                    None,
                    _sum_optional(
                        usage.get("input_tokens"), usage.get("output_tokens")
                    ),
                ),
                effective_params=self._effective_params(),
            )
        choices = raw.get("choices")
        choice = choices[0] if isinstance(choices, list) and choices else {}
        message = choice.get("message", {}) if isinstance(choice, dict) else {}
        text = _message_text(
            message.get("content") if isinstance(message, dict) else None
        )
        usage = raw.get("usage", {})
        details = (
            usage.get("completion_tokens_details", {})
            if isinstance(usage, dict)
            else {}
        )
        return ProviderResult(
            response_text=text,
            returned_model_id=_optional_string(raw.get("model")),
            provider_response_id=_optional_string(raw.get("id")),
            provider_name=_optional_string(raw.get("provider")),
            finish_reason=(
                _optional_string(choice.get("finish_reason"))
                if isinstance(choice, dict)
                else None
            ),
            usage=_usage(
                usage.get("prompt_tokens"),
                usage.get("completion_tokens"),
                details.get("reasoning_tokens") if isinstance(details, dict) else None,
                usage.get("total_tokens"),
            ),
            effective_params=self._effective_params(),
        )

    def _effective_params(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        if self.config.temperature["mode"] == "fixed":
            values["temperature"] = {
                "state": "known",
                "value": self.config.temperature["value"],
                "source": "request",
            }
        else:
            values["temperature"] = {"state": "not-reported", "value": None}
        values[self.config.visible_output_limit["parameter"]] = {
            "state": "known",
            "value": self.config.output_cap,
            "source": "request",
        }
        if self.config.provider_options:
            values["provider_options"] = {
                "state": "known",
                "value": self.config.provider_options,
                "source": "request",
            }
        return values

    def assert_model_identity(self, returned: str) -> None:
        normalized = returned.removeprefix("models/")
        if normalized != self.config.requested_model_id:
            raise ProviderSubstitutionError(self.config.requested_model_id, returned)

    @staticmethod
    def _raise_for_status(response: HttpResponse) -> None:
        if 200 <= response.status < 300:
            return
        retryable = response.status in {408, 409, 425, 429} or response.status >= 500
        if response.status in {401, 403}:
            category = "authentication" if response.status == 401 else "authorization"
        elif response.status == 429:
            category = "rate-limit"
        elif response.status == 404:
            category = "unavailable"
        elif response.status >= 500:
            category = "provider-error"
        else:
            category = "invalid-request"
        body = response.body.decode("utf-8", errors="replace")[:300]
        raise ProviderError(
            f"provider HTTP {response.status}: {body}",
            category=category,
            retryable=retryable,
        )


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _sum_optional(*values: Any) -> int | None:
    parsed = [_optional_int(value) for value in values]
    return sum(parsed) if all(value is not None for value in parsed) else None


def _usage(
    input_tokens: Any, output_tokens: Any, reasoning_tokens: Any, total_tokens: Any
) -> dict[str, int | None]:
    return {
        "input_tokens": _optional_int(input_tokens),
        "output_tokens": _optional_int(output_tokens),
        "reasoning_tokens": _optional_int(reasoning_tokens),
        "cache_read_tokens": None,
        "cache_write_tokens": None,
        "total_tokens": _optional_int(total_tokens),
    }


def _message_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            item.get("text", "")
            for item in content
            if isinstance(item, dict) and item.get("type") in {None, "text"}
        )
    return ""

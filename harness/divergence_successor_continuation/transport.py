"""HTTPS transport that treats every redirect as a terminal response."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import certifi

from concordance_harness.providers import (
    NETWORK_READ_EXCEPTIONS,
    HttpRequest,
    HttpResponse,
    ProviderError,
)

from . import contract


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return 30x responses to the caller without issuing another request."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class NoRedirectHttpsTransport:
    MAX_RESPONSE_BYTES = 10 * 1024 * 1024

    def __init__(self, ssl_context: ssl.SSLContext | None = None) -> None:
        self.ssl_context = ssl_context or ssl.create_default_context(
            cafile=certifi.where()
        )
        self.proxy_handler = urllib.request.ProxyHandler({})
        self.opener = urllib.request.build_opener(
            self.proxy_handler,
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=self.ssl_context),
        )

    async def send(self, request: HttpRequest) -> HttpResponse:
        return await asyncio.to_thread(self._send_sync, request)

    def _validate_url(self, value: str) -> None:
        try:
            parsed = urllib.parse.urlsplit(value)
            port = parsed.port
        except ValueError as error:
            raise ProviderError(
                "continuation URL is malformed",
                category="invalid-request",
                retryable=False,
            ) from error
        host = (parsed.hostname or "").lower().rstrip(".")
        if (
            parsed.scheme != "https"
            or host not in contract.parent_contract.AUTHORIZED_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or parsed.fragment
        ):
            raise ProviderError(
                "continuation URL escaped the exact HTTPS allowlist",
                category="invalid-request",
                retryable=False,
            )

    def _read(self, response: Any) -> bytes:
        body = response.read(self.MAX_RESPONSE_BYTES + 1)
        if len(body) > self.MAX_RESPONSE_BYTES:
            raise ProviderError(
                "provider response exceeded the receipt size limit",
                category="response-validation",
                retryable=False,
            )
        return body

    def _send_sync(self, request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            raise ProviderError(
                "continuation transport accepts generation POSTs only",
                category="invalid-request",
                retryable=False,
            )
        self._validate_url(request.url)
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
            with self.opener.open(
                outgoing, timeout=request.timeout_seconds
            ) as response:
                return HttpResponse(
                    status=response.status,
                    headers=dict(response.headers.items()),
                    body=self._read(response),
                )
        except urllib.error.HTTPError as error:
            try:
                body = self._read(error)
            except (TimeoutError, socket.timeout) as read_error:
                raise ProviderError(
                    "provider request timed out",
                    category="timeout",
                    retryable=False,
                ) from read_error
            except NETWORK_READ_EXCEPTIONS as read_error:
                raise ProviderError(
                    "provider connection failed while reading an error response",
                    category="network",
                    retryable=False,
                ) from read_error
            return HttpResponse(
                status=error.code,
                headers=dict(error.headers.items()) if error.headers else {},
                body=body,
            )
        except (TimeoutError, socket.timeout) as error:
            raise ProviderError(
                "provider request timed out", category="timeout", retryable=False
            ) from error
        except urllib.error.URLError as error:
            raise ProviderError(
                f"provider network failure: {error.reason}",
                category="network",
                retryable=False,
            ) from error
        except NETWORK_READ_EXCEPTIONS as error:
            raise ProviderError(
                "provider connection failed while reading the response",
                category="network",
                retryable=False,
            ) from error


__all__ = ("NoRedirectHttpsTransport",)

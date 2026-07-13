"""Transports that make an HTTP response durable before it is interpreted."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from concordance_harness.providers import HttpRequest, HttpResponse, Transport
from rule3.budget import JournalRecord

from .journal import (
    RecoveryJournalError,
    initialize_private_root,
    raw_response_payload,
    request_body_bytes,
    validate_raw_response,
    write_record,
)


def _same_request(actual: HttpRequest, expected: HttpRequest) -> bool:
    """Compare the contractual request without retaining authorization headers."""
    return (
        actual.method == expected.method
        and actual.url == expected.url
        and actual.headers == expected.headers
        and request_body_bytes(actual) == request_body_bytes(expected)
        and actual.timeout_seconds == expected.timeout_seconds
    )


class DurableCaptureTransport:
    """Forward exactly one request and seal its exact response before returning."""

    def __init__(
        self,
        delegate: Transport,
        *,
        capture_path: Path,
        private_root: Path,
        common: Mapping[str, Any],
        intent: JournalRecord,
        request_kind: str,
        expected_request: HttpRequest,
    ) -> None:
        self.delegate = delegate
        self.capture_path = capture_path
        self.private_root = private_root
        self.common = dict(common)
        self.intent = intent
        self.request_kind = request_kind
        self.expected_request = expected_request
        self.sent = False
        self.capture: JournalRecord | None = None

    async def send(self, request: HttpRequest) -> HttpResponse:
        if self.sent:
            raise RecoveryJournalError(
                "capture transport received more than one request"
            )
        self.sent = True
        initialize_private_root(self.private_root)
        try:
            self.capture_path.resolve().relative_to(self.private_root.resolve())
        except ValueError as error:
            raise RecoveryJournalError(
                "raw capture path escapes the private recovery root"
            ) from error
        initialize_private_root(self.capture_path.parent)
        try:
            self.capture_path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise RecoveryJournalError(
                "live transport cannot replace a captured response"
            )
        if not _same_request(request, self.expected_request):
            raise RecoveryJournalError("provider adapter emitted an unlocked request")
        response = await self.delegate.send(request)
        payload = raw_response_payload(
            common=self.common,
            intent=self.intent,
            private_root=self.private_root,
            request_kind=self.request_kind,
            request=request,
            response=response,
        )
        self.capture = write_record(self.capture_path, payload)
        return response


class CapturedReplayTransport:
    """Replay one sealed response without network or credential access."""

    def __init__(
        self,
        capture: JournalRecord,
        *,
        private_root: Path,
        common: Mapping[str, Any],
        intent: JournalRecord,
        request_kind: str,
        expected_request: HttpRequest,
    ) -> None:
        self.capture = capture
        self.private_root = private_root
        self.common = dict(common)
        self.intent = intent
        self.request_kind = request_kind
        self.expected_request = expected_request
        self.used = False

    async def send(self, request: HttpRequest) -> HttpResponse:
        if self.used:
            raise RecoveryJournalError("captured response was replayed more than once")
        self.used = True
        if not _same_request(request, self.expected_request):
            raise RecoveryJournalError("offline adapter emitted an unlocked request")
        return validate_raw_response(
            self.capture,
            expected_common=self.common,
            expected_intent=self.intent,
            private_root=self.private_root,
            request_kind=self.request_kind,
            expected_request=request,
        )

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from concordance_harness.providers import HttpRequest, HttpResponse


class FakeTransport:
    def __init__(self, responses: Iterable[HttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[HttpRequest] = []

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("fake transport has no response")
        return self.responses.pop(0)


def response(status: int, body: dict | str) -> HttpResponse:
    payload = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
    return HttpResponse(status=status, headers={}, body=payload)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]

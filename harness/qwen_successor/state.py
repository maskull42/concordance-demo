"""Fixed private paths and the single-flight lock for the Qwen successor."""

from __future__ import annotations

import asyncio
import fcntl
import os
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

from concordance_recovery.journal import (
    RecoveryJournalError,
    initialize_private_root,
    require_safe_id,
)

from . import contract


def _attempt_name(attempt: int) -> str:
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise RecoveryJournalError("attempt number must be a positive integer")
    return f"attempt-{attempt}.json"


@dataclass(frozen=True)
class SuccessorPaths:
    """All mutable successor artifacts, rooted outside both sealed parents."""

    repository_root: Path
    private_root: Path

    @classmethod
    def for_repository(cls, repository_root: Path | str) -> "SuccessorPaths":
        root = Path(repository_root).resolve()
        relative = Path(contract.PRIVATE_ROOT_RELATIVE)
        if relative.is_absolute() or ".." in relative.parts:
            raise RecoveryJournalError(
                "successor private root is not relative and safe"
            )
        return cls(root, root / relative)

    @property
    def phase_lock(self) -> Path:
        return (
            self.repository_root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.QWEN_STRANDED_INTENT_SHA256}.lock"
        )

    @property
    def claim(self) -> Path:
        return (
            self.repository_root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.QWEN_STRANDED_INTENT_SHA256}.json"
        )

    @property
    def manifest(self) -> Path:
        return self.private_root / "manifests" / "six-route-preflight.json"

    @property
    def composite(self) -> Path:
        return self.private_root / "runs" / f"{contract.CANDIDATE_ID}.json"

    def _attempt_path(
        self, request_kind: str, record_kind: str, model_key: str, attempt: int
    ) -> Path:
        require_safe_id(model_key, "model key")
        return (
            self.private_root
            / request_kind
            / record_kind
            / model_key
            / _attempt_name(attempt)
        )

    def preflight_intent(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("preflight", "intents", model_key, attempt)

    def preflight_raw(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("preflight", "raw-responses", model_key, attempt)

    def preflight_outcome(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("preflight", "outcomes", model_key, attempt)

    def generation_intent(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("generation", "intents", model_key, attempt)

    def generation_raw(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("generation", "raw-responses", model_key, attempt)

    def generation_outcome(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("generation", "outcomes", model_key, attempt)


@asynccontextmanager
async def phase_lock(path: Path) -> AsyncIterator[None]:
    """Serialize every gate, credential read, and request in this lane."""

    initialize_private_root(path.parent)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise RecoveryJournalError(
            f"successor execution lock cannot be opened: {error}"
        ) from error
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 0
            or metadata.st_nlink != 1
        ):
            raise RecoveryJournalError(
                "successor execution lock must remain an empty mode-0600 "
                "regular file"
            )
        os.fsync(descriptor)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                await asyncio.sleep(0.05)
            except OSError as error:
                raise RecoveryJournalError(
                    f"successor execution lock cannot be acquired: {error}"
                ) from error
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


__all__ = ("SuccessorPaths", "phase_lock")

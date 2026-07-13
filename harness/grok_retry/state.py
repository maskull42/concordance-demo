"""Private paths and single-flight locking for the Grok retry."""

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
class GrokRetryPaths:
    """Every mutable artifact in the isolated retry lane."""

    repository_root: Path
    private_root: Path

    @classmethod
    def for_repository(cls, repository_root: Path | str) -> "GrokRetryPaths":
        root = Path(repository_root).resolve()
        relative = Path(contract.PRIVATE_ROOT_RELATIVE)
        if relative.is_absolute() or ".." in relative.parts:
            raise RecoveryJournalError(
                "Grok retry private root is not relative and safe"
            )
        return cls(root, root / relative)

    @property
    def phase_lock(self) -> Path:
        return (
            self.repository_root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.GROK_ERROR_OUTCOME_SHA256}.lock"
        )

    @property
    def claim(self) -> Path:
        return (
            self.repository_root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.GROK_ERROR_OUTCOME_SHA256}.json"
        )

    @property
    def composite(self) -> Path:
        return self.private_root / "runs" / f"{contract.CANDIDATE_ID}.json"

    def _attempt_path(self, record_kind: str, model_key: str, attempt: int) -> Path:
        require_safe_id(model_key, "model key")
        if record_kind not in {"intents", "raw-responses", "outcomes"}:
            raise RecoveryJournalError("generation record kind is not approved")
        return (
            self.private_root
            / "generation"
            / record_kind
            / model_key
            / _attempt_name(attempt)
        )

    def generation_intent(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("intents", model_key, attempt)

    def generation_raw(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("raw-responses", model_key, attempt)

    def generation_outcome(self, model_key: str, attempt: int) -> Path:
        return self._attempt_path("outcomes", model_key, attempt)


@asynccontextmanager
async def phase_lock(path: Path) -> AsyncIterator[None]:
    """Serialize authority checks, credential reads, and requests in this lane."""

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
            f"Grok retry execution lock cannot be opened: {error}"
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
                "Grok retry execution lock must remain an empty mode-0600 "
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
                    f"Grok retry execution lock cannot be acquired: {error}"
                ) from error
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


__all__ = ("GrokRetryPaths", "phase_lock")

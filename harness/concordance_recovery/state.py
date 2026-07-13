"""Fixed private paths and the single-flight lock for recovery execution."""

from __future__ import annotations

import asyncio
import fcntl
import os
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

from . import contract
from .authorization import private_root
from .journal import RecoveryJournalError, initialize_private_root, require_safe_id


@dataclass(frozen=True)
class RecoveryPaths:
    repository_root: Path
    private_root: Path

    @classmethod
    def for_repository(cls, repository_root: Path) -> "RecoveryPaths":
        root = repository_root.resolve()
        return cls(root, private_root(root))

    @property
    def phase_lock(self) -> Path:
        return (
            self.repository_root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.STRANDED_COHERE['intent_sha256']}.lock"
        )

    @property
    def claim(self) -> Path:
        return (
            self.repository_root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.STRANDED_COHERE['intent_sha256']}.json"
        )

    @property
    def manifest(self) -> Path:
        return self.private_root / "manifests" / "six-model-preflight.json"

    @property
    def composite(self) -> Path:
        return self.private_root / "runs" / f"{contract.CANDIDATE_ID}.json"

    def preflight_intent(self, model_key: str, attempt: int) -> Path:
        require_safe_id(model_key, "model key")
        return (
            self.private_root
            / "preflight/intents"
            / model_key
            / f"attempt-{attempt}.json"
        )

    def preflight_raw(self, model_key: str, attempt: int) -> Path:
        require_safe_id(model_key, "model key")
        return (
            self.private_root
            / "preflight/raw-responses"
            / model_key
            / f"attempt-{attempt}.json"
        )

    def preflight_outcome(self, model_key: str, attempt: int) -> Path:
        require_safe_id(model_key, "model key")
        return (
            self.private_root
            / "preflight/outcomes"
            / model_key
            / f"attempt-{attempt}.json"
        )

    def generation_intent(self, model_key: str, attempt: int) -> Path:
        require_safe_id(model_key, "model key")
        return (
            self.private_root
            / "generation/intents"
            / model_key
            / f"attempt-{attempt}.json"
        )

    def generation_raw(self, model_key: str, attempt: int) -> Path:
        require_safe_id(model_key, "model key")
        return (
            self.private_root
            / "generation/raw-responses"
            / model_key
            / f"attempt-{attempt}.json"
        )

    def generation_outcome(self, model_key: str, attempt: int) -> Path:
        require_safe_id(model_key, "model key")
        return (
            self.private_root
            / "generation/outcomes"
            / model_key
            / f"attempt-{attempt}.json"
        )


@asynccontextmanager
async def phase_lock(path: Path) -> AsyncIterator[None]:
    """Serialize parent validation, gates, env access, and every provider call."""
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
            f"recovery execution lock cannot be opened: {error}"
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
                "recovery execution lock must remain an empty mode-0600 regular file"
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
                    f"recovery execution lock cannot be acquired: {error}"
                ) from error
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

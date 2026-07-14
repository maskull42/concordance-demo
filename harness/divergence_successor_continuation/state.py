"""Fixed private paths and single-flight state for the continuation."""

from __future__ import annotations

import asyncio
import fcntl
import os
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Callable

from concordance_recovery.journal import initialize_private_root, require_safe_id

from . import contract


class ContinuationStateError(RuntimeError):
    """The continuation journal is unsafe, unexpected, or replayable."""


@dataclass(frozen=True)
class ContinuationPaths:
    repository_root: Path
    private_root: Path

    @classmethod
    def for_repository(cls, repository_root: Path | str) -> "ContinuationPaths":
        root = contract.repository_root(repository_root)
        return cls(root, root / contract.PRIVATE_ROOT_RELATIVE)

    @property
    def correction(self) -> Path:
        return self.private_root / "offline-correction.json"

    @property
    def authorization(self) -> Path:
        return self.private_root / "paid-authorization.json"

    @property
    def phase_lock(self) -> Path:
        return self.private_root / ".single-flight.lock"

    @property
    def composite(self) -> Path:
        return self.private_root / "runs" / f"{contract.CANDIDATE_ID}.json"

    def _generation(self, kind: str, model_key: str) -> Path:
        if kind not in {"intents", "raw-responses", "outcomes"}:
            raise ContinuationStateError("generation record kind is not approved")
        require_safe_id(model_key, "model key")
        if model_key not in contract.MODEL_KEYS:
            raise ContinuationStateError("model key is outside the frozen panel")
        return self.private_root / "generation" / kind / model_key / "attempt-1.json"

    def generation_intent(self, model_key: str) -> Path:
        return self._generation("intents", model_key)

    def generation_raw(self, model_key: str) -> Path:
        return self._generation("raw-responses", model_key)

    def generation_outcome(self, model_key: str) -> Path:
        return self._generation("outcomes", model_key)

    def expected_files(self) -> frozenset[Path]:
        values = {
            self.correction,
            self.authorization,
            self.phase_lock,
            self.composite,
        }
        for key in contract.MODEL_KEYS:
            values.update(
                {
                    self.generation_intent(key),
                    self.generation_raw(key),
                    self.generation_outcome(key),
                }
            )
        return frozenset(values)


def inspect_inventory(paths: ContinuationPaths) -> tuple[Path, ...]:
    """Reject unknown entries, symlinks, hard links, and permissive modes."""

    if not paths.private_root.exists():
        return ()
    metadata = paths.private_root.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ContinuationStateError(
            "continuation root must be a real mode-0700 directory"
        )
    expected = paths.expected_files()
    directories = {paths.private_root}
    for path in expected:
        directories.update(path.parents)
    found: list[Path] = []
    for path in paths.private_root.rglob("*"):
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode):
            raise ContinuationStateError("continuation journal contains a symlink")
        if stat.S_ISDIR(item.st_mode):
            if path not in directories or stat.S_IMODE(item.st_mode) != 0o700:
                raise ContinuationStateError(
                    "continuation journal contains an unsafe directory"
                )
            continue
        if (
            path not in expected
            or not stat.S_ISREG(item.st_mode)
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
        ):
            raise ContinuationStateError("continuation journal contains an unsafe file")
        found.append(path)
    return tuple(sorted(found))


@asynccontextmanager
async def phase_lock(
    paths: ContinuationPaths,
    *,
    validate_authority: Callable[[], object],
) -> AsyncIterator[None]:
    """Serialize the paid lane after its exact authority validates."""

    validate_authority()
    initialize_private_root(paths.private_root)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(paths.phase_lock, flags, 0o600)
    parent_path = (
        paths.repository_root / contract.ORIGINAL_PRIVATE_ROOT / ".single-flight.lock"
    )
    parent_flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        parent_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(parent_path, parent_flags)
    except BaseException:
        os.close(descriptor)
        raise
    locked = False
    parent_locked = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 0
            or metadata.st_nlink != 1
        ):
            raise ContinuationStateError(
                "continuation lock must remain an empty mode-0600 file"
            )
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                await asyncio.sleep(0.05)
        parent_metadata = os.fstat(parent_descriptor)
        if (
            not stat.S_ISREG(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) != 0o600
            or parent_metadata.st_size != 0
            or parent_metadata.st_nlink != 1
        ):
            raise ContinuationStateError(
                "original successor lock must remain an empty mode-0600 file"
            )
        while True:
            try:
                fcntl.flock(parent_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                parent_locked = True
                break
            except BlockingIOError:
                await asyncio.sleep(0.05)
        yield
    finally:
        if parent_locked:
            fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
        os.close(parent_descriptor)
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


__all__ = (
    "ContinuationPaths",
    "ContinuationStateError",
    "inspect_inventory",
    "phase_lock",
)

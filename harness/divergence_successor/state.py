"""Fixed successor paths, exact inventory, and the paid single-flight lock."""

from __future__ import annotations

import asyncio
import fcntl
import os
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Iterable

from concordance_recovery.journal import (
    RecoveryJournalError,
    initialize_private_root,
    require_safe_id,
)

from . import authorization, contract


class DivergenceSuccessorStateError(RecoveryJournalError):
    """The private successor state is unsafe, unexpected, or replayable."""


def _attempt_name(attempt: int) -> str:
    if attempt != 1 or isinstance(attempt, bool):
        raise DivergenceSuccessorStateError(
            "the successor permits exactly semantic attempt 1; no replay exists"
        )
    return "attempt-1.json"


def _relative_private_root() -> Path:
    expected = f".pilot/divergence-successor/{contract.POOL_ID}"
    value = getattr(contract, "PRIVATE_ROOT_RELATIVE", None)
    if value != expected:
        raise DivergenceSuccessorStateError(
            "the exact successor private root is not locked"
        )
    try:
        safe = contract.require_relative_path(value, "successor private root")
    except contract.ContractError as error:
        raise DivergenceSuccessorStateError(str(error)) from error
    return Path(safe)


@dataclass(frozen=True)
class SuccessorPaths:
    """Every mutable artifact in the one-candidate, eight-model lane."""

    repository_root: Path
    private_root: Path

    @classmethod
    def for_repository(cls, repository_root: Path | str) -> "SuccessorPaths":
        try:
            root = contract.repository_root(repository_root)
        except contract.ContractError as error:
            raise DivergenceSuccessorStateError(str(error)) from error
        return cls(root, root / _relative_private_root())

    @property
    def phase_lock(self) -> Path:
        return self.private_root / ".single-flight.lock"

    @property
    def authorization(self) -> Path:
        return self.private_root / "paid-authorization.json"

    @property
    def pricing_recheck(self) -> Path:
        return self.private_root / "pricing-recheck.json"

    @property
    def manifest(self) -> Path:
        return self.private_root / "manifests" / "eight-model-preflight.json"

    @property
    def composite(self) -> Path:
        return self.private_root / "runs" / f"{contract.CANDIDATE_ID}.json"

    def _attempt_path(
        self,
        request_kind: str,
        record_kind: str,
        model_key: str,
        attempt: int,
    ) -> Path:
        if request_kind not in {"preflight", "generation"}:
            raise DivergenceSuccessorStateError("request kind is not approved")
        if record_kind not in {"intents", "raw-responses", "outcomes"}:
            raise DivergenceSuccessorStateError("journal record kind is not approved")
        require_safe_id(model_key, "model key")
        if model_key not in contract.MODEL_KEYS:
            raise DivergenceSuccessorStateError("model key is outside the locked panel")
        return (
            self.private_root
            / request_kind
            / record_kind
            / model_key
            / _attempt_name(attempt)
        )

    def preflight_intent(self, model_key: str, attempt: int = 1) -> Path:
        return self._attempt_path("preflight", "intents", model_key, attempt)

    def preflight_raw(self, model_key: str, attempt: int = 1) -> Path:
        return self._attempt_path("preflight", "raw-responses", model_key, attempt)

    def preflight_outcome(self, model_key: str, attempt: int = 1) -> Path:
        return self._attempt_path("preflight", "outcomes", model_key, attempt)

    def generation_intent(self, model_key: str, attempt: int = 1) -> Path:
        return self._attempt_path("generation", "intents", model_key, attempt)

    def generation_raw(self, model_key: str, attempt: int = 1) -> Path:
        return self._attempt_path("generation", "raw-responses", model_key, attempt)

    def generation_outcome(self, model_key: str, attempt: int = 1) -> Path:
        return self._attempt_path("generation", "outcomes", model_key, attempt)

    def expected_files(self, *, include_terminal: bool = True) -> frozenset[Path]:
        files = {self.phase_lock, self.authorization, self.pricing_recheck, self.manifest}
        for key in contract.MODEL_KEYS:
            files.update(
                {
                    self.preflight_intent(key),
                    self.preflight_raw(key),
                    self.preflight_outcome(key),
                    self.generation_intent(key),
                    self.generation_raw(key),
                    self.generation_outcome(key),
                }
            )
        if include_terminal:
            files.add(self.composite)
        return frozenset(files)


def inspect_inventory(paths: SuccessorPaths) -> tuple[Path, ...]:
    """Reject symlinks, directories in file positions, and unknown artifacts."""

    if not paths.private_root.exists():
        return ()
    root_meta = paths.private_root.lstat()
    if stat.S_ISLNK(root_meta.st_mode) or not stat.S_ISDIR(root_meta.st_mode):
        raise DivergenceSuccessorStateError(
            "successor private root must be a real directory"
        )
    if stat.S_IMODE(root_meta.st_mode) != 0o700:
        raise DivergenceSuccessorStateError(
            "successor journal directories must remain mode 0700"
        )
    expected_files = paths.expected_files()
    known_directories = {paths.private_root}
    for item in expected_files:
        known_directories.update(item.parents)
    found: list[Path] = []
    for item in paths.private_root.rglob("*"):
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise DivergenceSuccessorStateError("successor journal contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if item not in known_directories:
                raise DivergenceSuccessorStateError(
                    "successor journal contains an unexpected directory"
                )
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise DivergenceSuccessorStateError(
                    "successor journal directories must remain mode 0700"
                )
            continue
        if not stat.S_ISREG(metadata.st_mode) or item not in expected_files:
            raise DivergenceSuccessorStateError(
                "successor journal contains an unexpected file"
            )
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            raise DivergenceSuccessorStateError(
                "successor journal files must be single-link mode-0600 files"
            )
        found.append(item)
    return tuple(sorted(found))


def require_only_expected(paths: SuccessorPaths, allowed: Iterable[Path]) -> None:
    allowed_set = set(allowed)
    extras = set(inspect_inventory(paths)) - allowed_set
    if extras:
        raise DivergenceSuccessorStateError(
            "successor journal contains state outside the current exact inventory"
        )


@asynccontextmanager
async def phase_lock(path: Path, *, context: Any) -> AsyncIterator[None]:
    """Serialize the paid lane after, and only after, exact authorization."""

    authorization.validate_authorization(context)
    expected = SuccessorPaths.for_repository(context.repository_root).phase_lock
    if path != expected:
        raise DivergenceSuccessorStateError("single-flight lock path changed")
    initialize_private_root(path.parent)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise DivergenceSuccessorStateError(
            f"successor single-flight lock cannot be opened: {error}"
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
            raise DivergenceSuccessorStateError(
                "successor lock must remain an empty single-link mode-0600 file"
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
                raise DivergenceSuccessorStateError(
                    f"successor single-flight lock cannot be acquired: {error}"
                ) from error
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


__all__ = (
    "DivergenceSuccessorStateError",
    "SuccessorPaths",
    "inspect_inventory",
    "phase_lock",
    "require_only_expected",
)

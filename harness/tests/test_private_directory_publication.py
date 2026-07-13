from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import private_directory_publication as publication
from concordance_harness.util import canonical_json_bytes, sha256_bytes


class PrivateDirectoryPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.spec = publication.PublicationSpec(
            target_root=self.root / "target",
            claim_path=self.root / ".target.publish-claim",
            staging_parent=self.root,
            claim_schema_version="fixture-claim-1.0.0",
            owner_schema_version="fixture-owner-1.0.0",
            expected_files=("a.json", "b.html"),
        )
        self.payloads = {"a.json": b'{"ok":true}\n', "b.html": b"<p>private</p>"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _verify(self, root: Path) -> Path:
        self.assertEqual(set(root.iterdir()), {root / name for name in self.payloads})
        for name, payload in self.payloads.items():
            self.assertEqual((root / name).read_bytes(), payload)
        return root

    def _crashed_state(self, *, linked_files: tuple[str, ...]) -> Path:
        staging_name = ".target.0123456789abcdef.tmp"
        operation_token = "a" * 64
        preparation_name = publication._preparation_name(self.spec, operation_token)
        hashes = {
            name: sha256_bytes(payload) for name, payload in self.payloads.items()
        }
        staging = publication._staging_path(self.spec, staging_name)
        staging.mkdir(mode=0o700)
        publication._write_private(
            staging / publication.STAGING_OWNER_NAME,
            publication._owner_payload(self.spec, staging_name, operation_token),
        )
        for name, payload in self.payloads.items():
            publication._write_private(staging / name, payload)
        publication._write_private(
            self.spec.claim_path,
            canonical_json_bytes(
                publication._claim_value(
                    self.spec,
                    staging_name=staging_name,
                    operation_token=operation_token,
                    preparation_name=preparation_name,
                    file_sha256=hashes,
                )
            ),
        )
        if linked_files:
            self.spec.target_root.mkdir(mode=0o700)
            for name in linked_files:
                os.link(staging / name, self.spec.target_root / name)
        return staging

    def test_publish_is_private_verified_and_write_once(self) -> None:
        result = publication.publish_private_directory(
            self.spec, self.payloads, self._verify
        )

        self.assertEqual(result, self.spec.target_root)
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o700)
        for entry in result.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
        self.assertFalse(self.spec.claim_path.exists())
        self.assertEqual(
            [entry for entry in self.root.iterdir() if entry.name.endswith(".tmp")],
            [],
        )
        with self.assertRaisesRegex(
            publication.PrivateDirectoryPublicationError, "write-once"
        ):
            publication.publish_private_directory(
                self.spec, self.payloads, self._verify
            )

    def test_recovery_clears_claimed_staging_without_output(self) -> None:
        staging = self._crashed_state(linked_files=())

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "cleared")
        self.assertFalse(staging.exists())
        self.assertFalse(self.spec.claim_path.exists())

    def test_recovery_clears_claim_created_before_staging(self) -> None:
        staging = self._crashed_state(linked_files=())
        for entry in staging.iterdir():
            entry.unlink()
        staging.rmdir()

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "cleared")
        self.assertFalse(self.spec.claim_path.exists())

    def test_recovery_clears_partial_preparation_before_claim_install(self) -> None:
        preparation = self.root / publication._preparation_name(self.spec, "b" * 64)
        preparation.write_bytes(b'{"schema"')
        os.chmod(preparation, 0o600)

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "cleared")
        self.assertFalse(preparation.exists())

    def test_recovery_clears_linked_preparation_left_with_claim(self) -> None:
        staging = self._crashed_state(linked_files=())
        claim = json.loads(self.spec.claim_path.read_bytes())
        preparation = self.root / claim["preparation_name"]
        os.link(self.spec.claim_path, preparation)

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "cleared")
        self.assertFalse(preparation.exists())
        self.assertFalse(staging.exists())
        self.assertFalse(self.spec.claim_path.exists())

    def test_recovery_clears_half_written_owner_before_payloads(self) -> None:
        staging = self._crashed_state(linked_files=())
        for name in self.payloads:
            (staging / name).unlink()
        (staging / publication.STAGING_OWNER_NAME).write_bytes(b'{"schema"')
        os.chmod(staging / publication.STAGING_OWNER_NAME, 0o600)

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "cleared")
        self.assertFalse(staging.exists())
        self.assertFalse(self.spec.claim_path.exists())

    def test_recovery_clears_half_written_claimed_payload(self) -> None:
        staging = self._crashed_state(linked_files=())
        (staging / "a.json").write_bytes(b'{"ok"')
        os.chmod(staging / "a.json", 0o600)

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "cleared")
        self.assertFalse(staging.exists())
        self.assertFalse(self.spec.claim_path.exists())

    def test_recovery_clears_owned_partial_output(self) -> None:
        staging = self._crashed_state(linked_files=("a.json",))

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "cleared")
        self.assertFalse(staging.exists())
        self.assertFalse(self.spec.target_root.exists())
        self.assertFalse(self.spec.claim_path.exists())

    def test_recovery_completes_verified_output_and_quarantined_claim(self) -> None:
        staging = self._crashed_state(linked_files=("a.json", "b.html"))
        quarantined = self.root / (
            self.spec.claim_path.name + publication.CLAIM_QUARANTINE_INFIX + "fixture"
        )
        self.spec.claim_path.rename(quarantined)

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "completed")
        self.assertFalse(staging.exists())
        self.assertFalse(quarantined.exists())
        self.assertEqual(self._verify(self.spec.target_root), self.spec.target_root)

    def test_recovery_completes_after_ownerless_empty_staging_cleanup_crash(
        self,
    ) -> None:
        staging = self._crashed_state(linked_files=("a.json", "b.html"))
        for entry in list(staging.iterdir()):
            entry.unlink()

        status = publication.recover_private_directory(self.spec, self._verify)

        self.assertEqual(status, "completed")
        self.assertFalse(staging.exists())
        self.assertFalse(self.spec.claim_path.exists())
        self.assertEqual(self._verify(self.spec.target_root), self.spec.target_root)

    def test_recovery_preserves_unowned_partial_output(self) -> None:
        staging = self._crashed_state(linked_files=("a.json",))
        (self.spec.target_root / "foreign.txt").write_text("foreign", encoding="utf-8")
        os.chmod(self.spec.target_root / "foreign.txt", 0o600)

        with self.assertRaisesRegex(
            publication.PrivateDirectoryPublicationError, "preserve"
        ):
            publication.recover_private_directory(self.spec, self._verify)

        self.assertTrue(staging.exists())
        self.assertTrue(self.spec.claim_path.exists())
        self.assertTrue(self.spec.target_root.exists())

    def test_concurrent_recovery_cannot_interleave_with_publication(self) -> None:
        verify_entered = threading.Event()
        release_verify = threading.Event()
        publisher_errors: list[BaseException] = []
        recovery_errors: list[BaseException] = []
        recovery_results: list[str] = []

        def slow_verify(root: Path) -> Path:
            verify_entered.set()
            if not release_verify.wait(timeout=5):
                raise AssertionError("test did not release publisher verification")
            return self._verify(root)

        def publish() -> None:
            try:
                publication.publish_private_directory(
                    self.spec, self.payloads, slow_verify
                )
            except BaseException as error:
                publisher_errors.append(error)

        def recover() -> None:
            try:
                recovery_results.append(
                    publication.recover_private_directory(self.spec, self._verify)
                )
            except BaseException as error:
                recovery_errors.append(error)

        publisher = threading.Thread(target=publish)
        publisher.start()
        self.assertTrue(verify_entered.wait(timeout=5))
        recovery = threading.Thread(target=recover)
        recovery.start()
        time.sleep(0.2)
        self.assertTrue(recovery.is_alive(), "recovery bypassed the publication lock")
        release_verify.set()
        publisher.join(timeout=5)
        recovery.join(timeout=5)

        self.assertFalse(publisher.is_alive())
        self.assertFalse(recovery.is_alive())
        self.assertEqual(publisher_errors, [])
        self.assertEqual(recovery_errors, [])
        self.assertEqual(recovery_results, ["completed"])
        self.assertEqual(self._verify(self.spec.target_root), self.spec.target_root)
        self.assertEqual(
            [
                entry
                for entry in self.root.iterdir()
                if publication.OUTPUT_CLEANUP_INFIX in entry.name
            ],
            [],
        )


if __name__ == "__main__":
    unittest.main()

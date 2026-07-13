from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import prepare_author_review_amendment as amendment


PRIVATE_INPUT_AVAILABLE = amendment.BASE_REVIEW_PATH.is_file()


class AuthorReviewAmendmentFilesystemTests(unittest.TestCase):
    def _synthetic_tree(self, root: Path) -> None:
        root.mkdir(mode=0o700)
        sealed = root / "sealed-primary-review"
        sealed.mkdir(mode=0o700)
        for relative in (
            Path("packet.json"),
            Path("author-review-packet.html"),
            Path("amendment.json"),
            Path("sealed-primary-review/review-draft.json"),
            Path("sealed-primary-review/review.json"),
        ):
            path = root / relative
            path.write_bytes(b"{}\n")
            path.chmod(0o600)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_bytes(b'{"status":"one","status":"two"}\n')
            with self.assertRaisesRegex(amendment.ReviewAmendmentError, "duplicate"):
                amendment._read_json(path, "duplicate fixture")

    def test_approved_semantic_delta_runs_without_private_fixtures(self) -> None:
        target = {
            "blind_item_id": amendment.TARGET_BLIND_ID,
            "response_sha256": amendment.TARGET_RESPONSE_SHA256,
            "decision": "confirm",
            "reviewed_primary_endorsed": amendment.TARGET_OLD_HANDLE,
            "reviewed_primary_reason_code": "clear_preference",
            "review_note": None,
            "reviewed_at": "2026-07-12T19:00:00+00:00",
        }
        decisions = [
            {"blind_item_id": f"blind-{index}", "unchanged": True}
            for index in range(63)
        ] + [target]
        draft = {"decisions": decisions, "exported_at": "old"}

        with (
            mock.patch.object(amendment, "_verify_base"),
            mock.patch.object(
                amendment,
                "_read_json",
                return_value=(json.loads(json.dumps(draft)), b"{}\n"),
            ),
        ):
            changed = amendment.amended_draft("2026-07-12T20:00:00+00:00")

        deltas = [
            (before, after)
            for before, after in zip(
                draft["decisions"], changed["decisions"], strict=True
            )
            if before != after
        ]
        self.assertEqual(len(deltas), 1)
        self.assertIsNone(deltas[0][1]["reviewed_primary_endorsed"])
        self.assertEqual(deltas[0][1]["reviewed_primary_reason_code"], "outside_map")
        self.assertEqual(
            amendment.APPROVAL_STATEMENT, "I agree with your recommendations."
        )

    def test_special_or_dangling_entries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "author-review-2"
            self._synthetic_tree(root)
            amendment._assert_private_tree(root)
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing")
            with self.assertRaisesRegex(amendment.ReviewAmendmentError, "unexpected"):
                amendment._assert_private_tree(root)
            dangling.unlink()
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(amendment.ReviewAmendmentError, "unexpected"):
                amendment._assert_private_tree(root)

    def test_only_owned_strict_partial_tree_is_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            staging = parent / ".author-review-2.fixture.tmp"
            output = parent / "author-review-2"
            self._synthetic_tree(staging)
            operation_token = "a" * 64
            owner_payload = amendment._staging_owner_payload(output, operation_token)
            amendment._write_private(
                staging / amendment.STAGING_OWNER_NAME, owner_payload
            )
            output.mkdir(mode=0o700)
            sealed = output / "sealed-primary-review"
            sealed.mkdir(mode=0o700)
            first = amendment.PUBLISHED_FILES[0]
            os.link(staging / first, output / first)
            self.assertTrue(
                amendment._safe_owned_partial_output(output, staging, owner_payload)
            )

            foreign = amendment.PUBLISHED_FILES[1]
            (output / foreign).write_bytes((staging / foreign).read_bytes())
            (output / foreign).chmod(0o600)
            self.assertFalse(
                amendment._safe_owned_partial_output(output, staging, owner_payload)
            )

    def test_replaced_claim_is_quarantined_not_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            claim = Path(temporary) / ".review.publish-claim"
            owned_payload = b'{"owned":true}\n'
            amendment._write_private(claim, owned_payload)
            _, _, owned_identity = amendment._read_claim(claim, "owned claim")
            claim.unlink()
            foreign_payload = b'{"foreign":true}\n'
            amendment._write_private(claim, foreign_payload)

            with self.assertRaisesRegex(amendment.ReviewAmendmentError, "quarantine"):
                amendment._unlink_owned_claim(
                    claim,
                    expected_payload=owned_payload,
                    expected_identity=owned_identity,
                )

            self.assertEqual(claim.read_bytes(), foreign_payload)
            quarantines = list(
                claim.parent.glob(f"{claim.name}{amendment.CLAIM_QUARANTINE_INFIX}*")
            )
            self.assertEqual(len(quarantines), 1)
            self.assertEqual(quarantines[0].read_bytes(), foreign_payload)

    def test_foreign_private_staging_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            staging = Path(temporary) / ".author-review-2.fixture.tmp"
            staging.mkdir(mode=0o700)
            expected = amendment._staging_owner_payload(output, "d" * 64)
            amendment._write_private(
                staging / amendment.STAGING_OWNER_NAME,
                amendment._staging_owner_payload(output, "e" * 64),
            )
            with self.assertRaisesRegex(
                amendment.ReviewAmendmentError, "owner changed"
            ):
                amendment._remove_private_staging(staging, expected)
            self.assertFalse(os.path.lexists(staging))
            quarantines = list(
                staging.parent.glob(f"{staging.name}{amendment.STAGING_CLEANUP_INFIX}*")
            )
            self.assertEqual(len(quarantines), 1)
            self.assertTrue(quarantines[0].is_dir())

    def test_quarantined_claim_and_staging_cleanup_are_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            operation_token = "f" * 64
            staging_name = f".{output.name}.fixture.tmp"
            staging = output.parent / staging_name
            staging.mkdir(mode=0o700)
            amendment._write_private(
                staging / amendment.STAGING_OWNER_NAME,
                amendment._staging_owner_payload(output, operation_token),
            )
            staging_quarantine = staging.parent / (
                f"{staging.name}{amendment.STAGING_CLEANUP_INFIX}fixture"
            )
            os.rename(staging, staging_quarantine)
            claim = amendment._claim_path(output)
            amendment._write_private(
                claim,
                amendment.canonical_json_bytes(
                    amendment._claim_value(output, staging_name, operation_token)
                ),
            )
            claim_quarantine = claim.parent / (
                f"{claim.name}{amendment.CLAIM_QUARANTINE_INFIX}fixture"
            )
            os.rename(claim, claim_quarantine)

            self.assertEqual(
                amendment.recover_incomplete_publication(output), "cleared"
            )
            self.assertFalse(os.path.lexists(staging_quarantine))
            self.assertFalse(os.path.lexists(claim_quarantine))


@unittest.skipUnless(
    PRIVATE_INPUT_AVAILABLE,
    "private sealed author review is intentionally absent from a clean checkout",
)
class AuthorReviewAmendmentTests(unittest.TestCase):
    def test_approved_delta_changes_exactly_one_decision(self) -> None:
        approved_at = "2026-07-12T20:00:00.000+00:00"
        base = json.loads(amendment.BASE_DRAFT_PATH.read_bytes())
        changed = amendment.amended_draft(approved_at)
        self.assertEqual(changed["exported_at"], approved_at)
        deltas = [
            (before, after)
            for before, after in zip(
                base["decisions"], changed["decisions"], strict=True
            )
            if before != after
        ]
        self.assertEqual(len(deltas), 1)
        before, after = deltas[0]
        self.assertEqual(before["blind_item_id"], amendment.TARGET_BLIND_ID)
        self.assertEqual(before["reviewed_primary_endorsed"], "P3")
        self.assertEqual(after["decision"], "correct")
        self.assertIsNone(after["reviewed_primary_endorsed"])
        self.assertEqual(after["reviewed_primary_reason_code"], "outside_map")
        self.assertEqual(after["reviewed_at"], approved_at)

    def test_wrong_target_is_rejected(self) -> None:
        with mock.patch.object(amendment, "TARGET_BLIND_ID", "blind-not-present"):
            with self.assertRaisesRegex(amendment.ReviewAmendmentError, "target"):
                amendment.amended_draft("2026-07-12T20:00:00.000+00:00")

    def test_write_verify_privacy_and_write_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            receipt = amendment.write_amended_review(output)
            self.assertEqual(amendment.verify_amended_review(output), receipt)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            sealed = output / "sealed-primary-review/review.json"
            value = json.loads(sealed.read_bytes())
            self.assertEqual(
                value["decision_counts"], {"confirmed": 63, "corrected": 1}
            )
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])
            with self.assertRaisesRegex(amendment.ReviewAmendmentError, "write-once"):
                amendment.write_amended_review(output)

    def test_undeclared_draft_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            amendment.write_amended_review(output)
            draft_path = output / "sealed-primary-review/review-draft.json"
            draft = json.loads(draft_path.read_bytes())
            draft["cursor"] = 0
            draft_path.write_bytes(amendment.canonical_json_bytes(draft))
            draft_path.chmod(0o600)
            with self.assertRaises(
                (amendment.ReviewAmendmentError, amendment.AuthorReviewValidationError)
            ):
                amendment.verify_amended_review(output)

    def test_completed_claim_is_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            amendment.write_amended_review(output)
            claim = amendment._claim_path(output)
            amendment._write_private(
                claim,
                amendment.canonical_json_bytes(
                    amendment._claim_value(
                        output, f".{output.name}.recovery.tmp", "a" * 64
                    )
                ),
            )
            self.assertEqual(
                amendment.recover_incomplete_publication(output), "completed"
            )
            self.assertFalse(claim.exists())

    def test_completed_output_quarantine_is_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            amendment.write_amended_review(output)
            claim = amendment._claim_path(output)
            amendment._write_private(
                claim,
                amendment.canonical_json_bytes(
                    amendment._claim_value(
                        output, f".{output.name}.recovery.tmp", "8" * 64
                    )
                ),
            )
            quarantine = output.parent / (
                f"{output.name}{amendment.OUTPUT_CLEANUP_INFIX}fixture"
            )
            os.rename(output, quarantine)

            self.assertEqual(
                amendment.recover_incomplete_publication(output), "completed"
            )
            self.assertTrue(output.is_dir())
            self.assertFalse(quarantine.exists())
            self.assertFalse(claim.exists())

    def test_unpublished_private_staging_is_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            staging_name = f".{output.name}.fixture.tmp"
            operation_token = "b" * 64
            staging = output.parent / staging_name
            staging.mkdir(mode=0o700)
            amendment._write_private(
                staging / amendment.STAGING_OWNER_NAME,
                amendment._staging_owner_payload(output, operation_token),
            )
            partial = staging / "partial.json"
            partial.write_bytes(b"partial")
            partial.chmod(0o600)
            claim = amendment._claim_path(output)
            amendment._write_private(
                claim,
                amendment.canonical_json_bytes(
                    amendment._claim_value(output, staging_name, operation_token)
                ),
            )
            self.assertEqual(
                amendment.recover_incomplete_publication(output), "cleared"
            )
            self.assertFalse(staging.exists())
            self.assertFalse(claim.exists())

    def test_owned_partial_publications_are_recoverable(self) -> None:
        for linked_count in range(len(amendment.PUBLISHED_FILES)):
            with self.subTest(linked_count=linked_count):
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "author-review-2"
                    staging_name = f".{output.name}.fixture.tmp"
                    operation_token = f"{linked_count + 1:064x}"
                    staging = output.parent / staging_name
                    AuthorReviewAmendmentFilesystemTests()._synthetic_tree(staging)
                    amendment._write_private(
                        staging / amendment.STAGING_OWNER_NAME,
                        amendment._staging_owner_payload(output, operation_token),
                    )
                    output.mkdir(mode=0o700)
                    if linked_count:
                        (output / "sealed-primary-review").mkdir(mode=0o700)
                    for relative in amendment.PUBLISHED_FILES[:linked_count]:
                        if relative.parent != Path("."):
                            (output / relative.parent).mkdir(
                                mode=0o700, parents=True, exist_ok=True
                            )
                        os.link(staging / relative, output / relative)
                    if linked_count % 2:
                        output_quarantine = output.parent / (
                            f"{output.name}{amendment.OUTPUT_CLEANUP_INFIX}fixture"
                        )
                        os.rename(output, output_quarantine)
                    claim = amendment._claim_path(output)
                    amendment._write_private(
                        claim,
                        amendment.canonical_json_bytes(
                            amendment._claim_value(
                                output, staging_name, operation_token
                            )
                        ),
                    )
                    self.assertEqual(
                        amendment.recover_incomplete_publication(output), "cleared"
                    )
                    self.assertFalse(os.path.lexists(output))
                    self.assertEqual(
                        list(
                            output.parent.glob(
                                f"{output.name}{amendment.OUTPUT_CLEANUP_INFIX}*"
                            )
                        ),
                        [],
                    )
                    self.assertFalse(os.path.lexists(staging))
                    self.assertFalse(os.path.lexists(claim))

    def test_racing_empty_destination_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            claim = amendment._claim_path(output)
            original_write = amendment._write_private

            def create_racer(path: Path, payload: bytes) -> None:
                identity = original_write(path, payload)
                if path == claim:
                    output.mkdir(mode=0o700)
                return identity

            with mock.patch.object(
                amendment, "_write_private", side_effect=create_racer
            ):
                with self.assertRaises(FileExistsError):
                    amendment.write_amended_review(output)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])
            self.assertFalse(claim.exists())

    def test_dangling_destination_is_not_cleared_by_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-2"
            output.symlink_to(Path(temporary) / "missing")
            claim = amendment._claim_path(output)
            amendment._write_private(
                claim,
                amendment.canonical_json_bytes(
                    amendment._claim_value(
                        output, f".{output.name}.recovery.tmp", "c" * 64
                    )
                ),
            )
            with self.assertRaises(amendment.ReviewAmendmentError):
                amendment.recover_incomplete_publication(output)
            self.assertTrue(output.is_symlink())
            self.assertTrue(claim.is_file())


if __name__ == "__main__":
    unittest.main()

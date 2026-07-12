from __future__ import annotations

import base64
import copy
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import prepare_author_review as review


PRIVATE_INPUT_AVAILABLE = review.FIRST_PASS_PATH.is_file()


def _keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        result.update(value)
        for item in value.values():
            result.update(_keys(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_keys(item))
    return result


@unittest.skipUnless(
    PRIVATE_INPUT_AVAILABLE,
    "private first-pass mappings are intentionally absent from a clean checkout",
)
class AuthorReviewPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = review.prepare_review_context()

    def test_context_contains_only_sixty_four_identity_free_review_items(self) -> None:
        self.assertEqual(self.context.first_pass_sha256, review.EXPECTED_FIRST_PASS_SHA256)
        self.assertEqual(len(self.context.items), 64)
        self.assertEqual(len(self.context.item_records), 64)
        self.assertEqual(
            [item["review_index"] for item in self.context.items], list(range(1, 65))
        )
        self.assertEqual(len({item["blind_item_id"] for item in self.context.items}), 64)
        self.assertFalse(review.FORBIDDEN_PACKET_KEYS & _keys(list(self.context.items)))
        for item, record in zip(self.context.items, self.context.item_records, strict=True):
            self.assertEqual(item["blind_item_id"], record["blind_item_id"])
            self.assertEqual(item["review_item_sha256"], record["review_item_sha256"])
            self.assertEqual(
                item["first_pass_assignment_sha256"],
                record["first_pass_assignment_sha256"],
            )

    def test_packet_embeds_base64_data_and_hash_authorized_assets(self) -> None:
        packet_bytes, hashes = review.render_packet(
            self.context, "review-0123456789abcdef0123456789abcdef"
        )
        packet_text = packet_bytes.decode("utf-8")
        match = re.search(
            r'<pre id="packet-data" hidden>([A-Za-z0-9+/=]+)</pre>', packet_text
        )
        self.assertIsNotNone(match)
        payload = json.loads(base64.b64decode(match.group(1)))  # type: ignore[union-attr]
        self.assertEqual(payload["item_count"], 64)
        self.assertEqual(payload["ordered_items_sha256"], self.context.ordered_items_sha256)
        self.assertFalse(review.FORBIDDEN_PACKET_KEYS & _keys(payload))
        self.assertIn(f"script-src '{hashes['script']}'", packet_text)
        self.assertIn(f"style-src '{hashes['style']}'", packet_text)
        self.assertIn("default-src 'none'", packet_text)
        self.assertNotIn("unsafe-inline", packet_text)
        for forbidden in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "<link",
            "<img",
            "<iframe",
        ):
            self.assertNotIn(forbidden, packet_text)

    def test_untrusted_response_markup_remains_inside_base64_payload(self) -> None:
        malicious = '</pre><script>throw new Error("executed")</script><svg onload=alert(1)>'
        items = copy.deepcopy(list(self.context.items))
        items[0]["response_text"] = malicious
        changed = review.ReviewContext(
            first_pass_sha256=self.context.first_pass_sha256,
            items=tuple(items),
            item_records=self.context.item_records,
            ordered_items_sha256=self.context.ordered_items_sha256,
        )
        packet_bytes, _ = review.render_packet(
            changed, "review-0123456789abcdef0123456789abcdef"
        )
        packet_text = packet_bytes.decode("utf-8")
        self.assertNotIn(malicious, packet_text)
        match = re.search(
            r'<pre id="packet-data" hidden>([A-Za-z0-9+/=]+)</pre>', packet_text
        )
        payload = json.loads(base64.b64decode(match.group(1)))  # type: ignore[union-attr]
        self.assertEqual(payload["items"][0]["response_text"], malicious)

    def test_write_verify_permissions_and_single_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-1"
            receipt_path = review.write_review_packet(self.context, output)
            self.assertEqual(review.verify_review_packet(output), receipt_path)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE((output / "author-review-packet.html").stat().st_mode),
                0o600,
            )
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {"packet.json", "author-review-packet.html"},
            )
            with self.assertRaisesRegex(review.AuthorReviewPacketError, "single-use"):
                review.write_review_packet(self.context, output)

    def test_packet_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-1"
            review.write_review_packet(self.context, output)
            packet_path = output / "author-review-packet.html"
            packet_path.write_bytes(packet_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                review.AuthorReviewPacketError, "HTML differs"
            ):
                review.verify_review_packet(output)

    def test_generator_provenance_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-1"
            review.write_review_packet(self.context, output)
            receipt_path = output / "packet.json"
            receipt = json.loads(receipt_path.read_bytes())
            receipt["generator"]["source_files"] = {"fictional.py": "0" * 64}
            receipt["generator"]["execution_sha256"] = review.sha256_bytes(
                review.canonical_json_bytes(receipt["generator"]["source_files"])
            )
            receipt_path.write_bytes(review.canonical_json_bytes(receipt))
            with self.assertRaisesRegex(
                review.AuthorReviewPacketError, "receipt differs"
            ):
                review.verify_review_packet(output)

    def test_publication_never_replaces_racing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-1"
            original = review.tempfile.mkdtemp

            def race(*args: object, **kwargs: object) -> str:
                created = original(*args, **kwargs)
                output.mkdir()
                return created

            with mock.patch.object(review.tempfile, "mkdtemp", race):
                with self.assertRaisesRegex(
                    review.AuthorReviewPacketError, "single-use"
                ):
                    review.write_review_packet(self.context, output)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])

    def test_failed_publication_cleans_claimed_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-1"
            original = review.os.link
            calls = 0

            def fail_second(source: object, destination: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated second-link failure")
                original(source, destination)

            with mock.patch.object(review.os, "link", fail_second):
                with self.assertRaisesRegex(OSError, "second-link failure"):
                    review.write_review_packet(self.context, output)
            self.assertFalse(output.exists())
            self.assertFalse(review._claim_path(output).exists())

    def test_explicit_recovery_clears_crash_left_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-1"
            claim = review._claim_path(output)
            review._write_private(
                claim, review.canonical_json_bytes(review._claim_value(output))
            )
            output.mkdir(mode=0o700)
            review._write_private(output / "author-review-packet.html", b"partial")
            self.assertEqual(review.recover_incomplete_publication(output), "cleared")
            self.assertFalse(output.exists())
            self.assertFalse(claim.exists())

    def test_explicit_recovery_preserves_complete_verified_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author-review-1"
            review.write_review_packet(self.context, output)
            claim = review._claim_path(output)
            review._write_private(
                claim, review.canonical_json_bytes(review._claim_value(output))
            )
            self.assertEqual(review.recover_incomplete_publication(output), "completed")
            self.assertTrue((output / "packet.json").is_file())
            self.assertFalse(claim.exists())

    def test_context_builder_never_reads_private_or_aggregate_files(self) -> None:
        original = Path.read_bytes

        def guarded(path: Path) -> bytes:
            path_text = str(path)
            self.assertNotIn("/private/", path_text)
            self.assertFalse(path_text.endswith("/aggregate.json"))
            return original(path)

        with mock.patch.object(Path, "read_bytes", guarded):
            context = review.prepare_review_context()
        self.assertEqual(len(context.items), 64)


class AuthorReviewAssetTests(unittest.TestCase):
    def test_browser_script_has_valid_javascript_syntax(self) -> None:
        result = subprocess.run(
            ["node", "--check", str(review.SCRIPT_PATH)],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import io
import json
import shutil
import stat
import sys
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
import authorize_rule3
from rule3.authorization import (
    OFFICIAL_PRICING_HOSTS,
    PAID_AUTHORIZATION_STATEMENT,
    PRICING_EVIDENCE_SCHEMA_VERSION,
    AuthorizationError,
    authorization_path,
    pricing_recheck_path,
    validate_paid_authorization,
    validate_pricing_recheck,
    write_paid_authorization,
    write_pricing_recheck,
)
from rule3.budget import CANDIDATE_ORDER

from support import repository_root


class Rule3AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        source = repository_root()
        config = self.root / "harness/config/models.json"
        config.parent.mkdir(parents=True)
        shutil.copy2(source / "harness/config/models.json", config)
        self.context = SimpleNamespace(
            repository_root=self.root,
            lock_sha256="a" * 64,
            git_head="b" * 40,
            candidates=tuple({"id": value} for value in CANDIDATE_ORDER),
            models_config_path=config,
            candidate_cost_cap_microdollars=6_000_000,
            total_cost_cap_microdollars=12_000_000,
            attempts_per_cell=3,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def evidence(self) -> list[dict[str, object]]:
        config = load_harness_config(self.context.models_config_path)
        return [
            {
                "model_key": model.model_key,
                "requested_model_id": model.requested_model_id,
                "input_per_million": model.planning_pricing["input_per_million"],
                "output_per_million": model.planning_pricing["output_per_million"],
                "official_source_url": (
                    f"https://{OFFICIAL_PRICING_HOSTS[model.model_key][0]}/"
                    f"pricing/{model.model_key}"
                ),
            }
            for model in config.models
        ]

    def write_evidence_file(self, *, checked_at: str | None = None) -> Path:
        path = self.root / "pricing-evidence.json"
        value = {
            "schema_version": PRICING_EVIDENCE_SCHEMA_VERSION,
            "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
            "reviewed_by": "A.G. Elrod",
            "official_evidence": self.evidence(),
        }
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_authorization_is_exact_write_once_and_private(self) -> None:
        receipt = write_paid_authorization(
            self.context, statement=PAID_AUTHORIZATION_STATEMENT
        )
        self.assertEqual(validate_paid_authorization(self.context), receipt)
        self.assertEqual(stat.S_IMODE(receipt.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(receipt.path.parent.stat().st_mode), 0o700)
        self.assertEqual(
            receipt.payload["scope"]["candidate_order"], list(CANDIDATE_ORDER)
        )
        self.assertEqual(
            receipt.payload["scope"]["candidate_reserved_cap_microdollars"],
            6_000_000,
        )
        with self.assertRaisesRegex(AuthorizationError, "write-once"):
            write_paid_authorization(
                self.context, statement=PAID_AUTHORIZATION_STATEMENT
            )
        with self.assertRaisesRegex(AuthorizationError, "exact disclosed"):
            with tempfile.TemporaryDirectory() as temporary:
                other = SimpleNamespace(
                    **{**self.context.__dict__, "repository_root": Path(temporary)}
                )
                write_paid_authorization(other, statement="I approve something else")

    def test_stale_head_or_lock_rejects_authorization(self) -> None:
        write_paid_authorization(self.context, statement=PAID_AUTHORIZATION_STATEMENT)
        stale_head = SimpleNamespace(**{**self.context.__dict__, "git_head": "c" * 40})
        with self.assertRaisesRegex(AuthorizationError, "stale"):
            validate_paid_authorization(stale_head)
        stale_lock = SimpleNamespace(
            **{**self.context.__dict__, "lock_sha256": "d" * 64}
        )
        with self.assertRaisesRegex(AuthorizationError, "stale"):
            validate_paid_authorization(stale_lock)

    def test_public_or_mutated_authorization_is_rejected(self) -> None:
        receipt = write_paid_authorization(
            self.context, statement=PAID_AUTHORIZATION_STATEMENT
        )
        receipt.path.chmod(0o644)
        with self.assertRaisesRegex(AuthorizationError, "0600"):
            validate_paid_authorization(self.context)

    def test_pricing_recheck_binds_all_models_and_expires(self) -> None:
        now = datetime.now(timezone.utc)
        receipt = write_pricing_recheck(
            self.context,
            self.evidence(),
            reviewed_by="A.G. Elrod",
            checked_at=now.isoformat(),
        )
        self.assertEqual(validate_pricing_recheck(self.context, now=now), receipt)
        self.assertEqual(stat.S_IMODE(receipt.path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(AuthorizationError, "stale"):
            validate_pricing_recheck(self.context, now=now + timedelta(hours=25))

    def test_pricing_recheck_rejects_missing_model_and_changed_rate(self) -> None:
        evidence = self.evidence()
        with self.assertRaisesRegex(AuthorizationError, "all eight"):
            write_pricing_recheck(self.context, evidence[:-1], reviewed_by="A.G. Elrod")
        evidence[0]["output_per_million"] = 999
        with self.assertRaisesRegex(AuthorizationError, "differs"):
            write_pricing_recheck(self.context, evidence, reviewed_by="A.G. Elrod")

    def test_pricing_recheck_rejects_arbitrary_https_hosts(self) -> None:
        evidence = self.evidence()
        evidence[0]["official_source_url"] = "https://official.example.test/pricing"
        with self.assertRaisesRegex(AuthorizationError, "host is not approved"):
            write_pricing_recheck(self.context, evidence, reviewed_by="A.G. Elrod")

    def test_fixed_receipt_paths_cannot_be_overridden(self) -> None:
        self.assertEqual(
            authorization_path(self.root),
            self.root
            / ".pilot/rule3/concordance-divergence-supplement-1/paid-authorization.json",
        )
        self.assertEqual(
            pricing_recheck_path(self.root),
            self.root
            / ".pilot/rule3/concordance-divergence-supplement-1/pricing-recheck.json",
        )

    def test_fixed_private_root_rejects_symlinked_components(self) -> None:
        redirect = self.root / "redirect"
        redirect.mkdir()
        (self.root / ".pilot").symlink_to(redirect, target_is_directory=True)
        with self.assertRaisesRegex(AuthorizationError, "may not be a symlink"):
            authorization_path(self.root)

    def test_cli_writes_and_verifies_pricing_from_exact_offline_evidence(self) -> None:
        class ForbiddenEnvironment(dict):
            def get(self, key: str, default: str = "") -> str:
                raise AssertionError(f"environment read: {key}")

            def __getitem__(self, key: str) -> str:
                raise AssertionError(f"environment read: {key}")

        evidence_path = self.write_evidence_file()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(authorize_rule3, "REPOSITORY_ROOT", self.root),
            mock.patch.object(
                authorize_rule3,
                "load_committed_lock",
                return_value=self.context,
            ),
            mock.patch("os.environ", ForbiddenEnvironment()),
            mock.patch.object(
                urllib.request,
                "urlopen",
                side_effect=AssertionError("network access"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            written = authorize_rule3.main(
                [
                    "--write-pricing",
                    "--pricing-evidence",
                    str(evidence_path),
                ]
            )
            verified = authorize_rule3.main(
                [
                    "--verify-pricing",
                    "--pricing-evidence",
                    str(evidence_path),
                ]
            )
        self.assertEqual((written, verified), (0, 0))
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("pricing recheck written privately", stdout.getvalue())
        self.assertIn("verified against local evidence", stdout.getvalue())
        self.assertIn(
            "Network requests: 0; environment variables read: 0",
            stdout.getvalue(),
        )

        changed = json.loads(evidence_path.read_text(encoding="utf-8"))
        changed["official_evidence"][0]["official_source_url"] += "?changed=1"
        evidence_path.write_text(json.dumps(changed), encoding="utf-8")
        stderr = io.StringIO()
        with (
            mock.patch.object(authorize_rule3, "REPOSITORY_ROOT", self.root),
            mock.patch.object(
                authorize_rule3,
                "load_committed_lock",
                return_value=self.context,
            ),
            redirect_stderr(stderr),
        ):
            result = authorize_rule3.main(
                [
                    "--verify-pricing",
                    "--pricing-evidence",
                    str(evidence_path),
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("differs from the local evidence", stderr.getvalue())

    def test_cli_pricing_modes_are_exclusive_and_require_evidence(self) -> None:
        with self.assertRaises(SystemExit):
            authorize_rule3.parser().parse_args(["--write-pricing", "--verify-pricing"])
        with self.assertRaises(SystemExit):
            authorize_rule3.main(["--write-pricing"])

    def test_cli_paid_authorization_modes_remain_unchanged(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(authorize_rule3, "REPOSITORY_ROOT", self.root),
            mock.patch.object(
                authorize_rule3,
                "load_committed_lock",
                return_value=self.context,
            ),
            redirect_stdout(stdout),
        ):
            written = authorize_rule3.main(
                ["--write", "--statement", PAID_AUTHORIZATION_STATEMENT]
            )
            verified = authorize_rule3.main(["--verify"])
        self.assertEqual((written, verified), (0, 0))
        self.assertIn("paid authorization written privately", stdout.getvalue())
        self.assertIn("paid authorization verified", stdout.getvalue())

    def test_stale_evidence_cannot_mint_an_immutable_pricing_receipt(self) -> None:
        stale = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        with self.assertRaisesRegex(AuthorizationError, "stale"):
            write_pricing_recheck(
                self.context,
                self.evidence(),
                reviewed_by="A.G. Elrod",
                checked_at=stale,
            )
        self.assertFalse(pricing_recheck_path(self.root).exists())


if __name__ == "__main__":
    unittest.main()

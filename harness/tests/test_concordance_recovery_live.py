from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.providers import HttpRequest, HttpResponse
from concordance_harness.util import utc_now
from concordance_recovery import contract
from concordance_recovery.authorization import (
    write_paid_authorization,
    write_pricing_evidence,
    write_pricing_recheck,
)
from concordance_recovery.composite import load_composite_responses
from concordance_recovery.execute import _execute_prepared, prepare_recovery
from concordance_recovery.lock import (
    load_and_validate_recovery_lock,
    write_recovery_lock,
)

from support import repository_root


async def no_sleep(_: float) -> None:
    return None


class RecordingEnvironment(dict[str, str]):
    def __init__(self, values: dict[str, str]) -> None:
        super().__init__(values)
        self.reads: list[str] = []

    def get(self, key: str, default: str | None = None) -> str | None:
        self.reads.append(key)
        return super().get(key, default)


class FixedTransport:
    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[HttpRequest] = []

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("unexpected recovery request")
        return self.responses.pop(0)


def http(body: dict[str, object]) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={"Set-Cookie": "must-not-be-retained", "X-Request-ID": "private"},
        body=json.dumps(body).encode("utf-8"),
    )


class ConcordanceRecoveryLiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        source = repository_root()
        subprocess.run(
            [
                "/usr/bin/git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                str(source),
                str(self.root),
            ],
            check=True,
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path(self.temporary.name))},
        )
        if not (self.root / contract.LOCK_PATH).exists():
            shutil.copytree(
                source / "harness/concordance_recovery",
                self.root / "harness/concordance_recovery",
            )
            shutil.copy2(
                source / "candidate/concordance-recovery-lock.schema.json",
                self.root / "candidate/concordance-recovery-lock.schema.json",
            )
            for path in (source / "harness").glob("*concordance_recovery*.py"):
                shutil.copy2(path, self.root / "harness" / path.name)
            write_recovery_lock(self.root)
            subprocess.run(
                [
                    "/usr/bin/git",
                    "add",
                    "candidate/concordance-recovery-lock.schema.json",
                    "candidate/concordance-recovery-lock.json",
                    "harness/concordance_recovery",
                    *[
                        str(path.relative_to(self.root))
                        for path in (self.root / "harness").glob(
                            "*concordance_recovery*.py"
                        )
                    ],
                ],
                cwd=self.root,
                check=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(Path(self.temporary.name)),
                },
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "user.name=Concordance Test",
                    "-c",
                    "user.email=concordance-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "test recovery seal",
                ],
                cwd=self.root,
                check=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(Path(self.temporary.name)),
                },
            )
        parent_source = source / contract.PARENT_PRIVATE_ROOT
        parent_target = self.root / contract.PARENT_PRIVATE_ROOT
        for relative in contract.PARENT_ARTIFACT_SHA256:
            source_path = parent_source / relative
            destination = parent_target / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(source_path, destination)
            destination.chmod(0o600)
        for relative in contract.PARENT_CONCURRENCY_LOCK_PATHS:
            source_path = parent_source / relative
            destination = parent_target / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(source_path, destination)
            destination.chmod(0o600)
        cursor = parent_target
        stop = self.root / ".pilot"
        for directory in parent_target.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o700)
        while True:
            cursor.chmod(0o700)
            if cursor == stop:
                break
            cursor = cursor.parent

        self.context = load_and_validate_recovery_lock(
            self.root,
            require_committed=True,
            require_parent_private=True,
        )
        write_paid_authorization(
            self.context, statement=contract.PAID_AUTHORIZATION_STATEMENT
        )
        config = load_harness_config(self.root / "harness/config/models.json")
        by_key = config.by_key()
        evidence = [
            {
                "model_key": key,
                "requested_model_id": by_key[key].requested_model_id,
                "input_per_million": by_key[key].planning_pricing["input_per_million"],
                "output_per_million": by_key[key].planning_pricing[
                    "output_per_million"
                ],
                "official_source_url": (
                    f"https://{contract.OFFICIAL_PRICING_HOSTS[key][0]}/pricing"
                ),
            }
            for key in contract.TARGET_MODEL_KEYS
        ]
        write_pricing_evidence(
            self.context,
            evidence,
            checked_at=utc_now(),
            reviewed_by="A.G. Elrod",
        )
        write_pricing_recheck(self.context)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def responses(self) -> list[HttpResponse]:
        metadata = [
            http({"id": "command-a-plus-05-2026"}),
            http({"data": [{"id": "Qwen/Qwen3.5-397B-A17B"}]}),
            http({"data": [{"id": "deepseek-v4-pro"}]}),
            http({"id": "mistral-large-2512"}),
            http({"id": "grok-4.5"}),
            http(
                {
                    "data": {
                        "id": "openai/gpt-5.6-sol-20260709",
                        "endpoints": [{"provider_name": "OpenAI"}],
                    }
                }
            ),
        ]
        generation = [
            http(
                {
                    "id": "cohere-response",
                    "finish_reason": "COMPLETE",
                    "message": {
                        "content": [
                            {
                                "type": "text",
                                "text": "The conclusion follows from the stated evidence.",
                            }
                        ]
                    },
                    "usage": {"tokens": {"input_tokens": 20, "output_tokens": 4}},
                }
            ),
            http(
                {
                    "id": "qwen-response",
                    "model": "Qwen/Qwen3.5-397B-A17B",
                    "choices": [
                        {
                            "message": {
                                "content": "The conclusion follows from the stated evidence."
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 4},
                }
            ),
            http(
                {
                    "id": "deepseek-response",
                    "model": "deepseek-v4-pro",
                    "choices": [
                        {
                            "message": {
                                "content": "The conclusion follows from the stated evidence."
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 4},
                }
            ),
            http(
                {
                    "id": "mistral-response",
                    "model": "mistral-large-2512",
                    "choices": [
                        {
                            "message": {
                                "content": "The conclusion follows from the stated evidence."
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 4},
                }
            ),
            http(
                {
                    "id": "grok-response",
                    "model": "grok-4.5",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": "The conclusion follows from the stated evidence.",
                                }
                            ],
                        }
                    ],
                    "usage": {"input_tokens": 20, "output_tokens": 4},
                }
            ),
            http(
                {
                    "id": "gpt-response",
                    "model": "openai/gpt-5.6-sol-20260709",
                    "provider": "OpenAI",
                    "choices": [
                        {
                            "message": {
                                "content": "The conclusion follows from the stated evidence."
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 4},
                }
            ),
        ]
        return [*metadata, *generation]

    def test_exact_two_plus_six_run_and_offline_resume(self) -> None:
        values = {
            name: f"sentinel-{index}"
            for index, name in enumerate(
                (
                    "COHERE_API_KEY",
                    "DEEPINFRA_API_KEY",
                    "DEEPSEEK_API_KEY",
                    "MISTRAL_API_KEY",
                    "XAI_API_KEY",
                    "OPENROUTER_API_KEY",
                ),
                start=1,
            )
        }
        environment = RecordingEnvironment(values)
        transport = FixedTransport(self.responses())
        prepared = prepare_recovery(self.root, require_committed=True)
        result = asyncio.run(
            _execute_prepared(
                prepared,
                environment=environment,
                transport_factory=lambda: transport,
                sleep=no_sleep,
            )
        )
        self.assertEqual(
            result.payload["status"],
            "complete-eight-successes-two-parent-six-recovery",
        )
        self.assertEqual(result.network_requests, 12)
        self.assertEqual(
            [request.method for request in transport.requests],
            ["GET"] * 6 + ["POST"] * 6,
        )
        self.assertEqual(
            [item["model_key"] for item in result.payload["outcomes"]],
            list(contract.MODEL_ORDER),
        )
        self.assertEqual(
            environment.reads,
            [
                "COHERE_API_KEY",
                "DEEPINFRA_API_KEY",
                "DEEPSEEK_API_KEY",
                "MISTRAL_API_KEY",
                "XAI_API_KEY",
                "OPENROUTER_API_KEY",
            ],
        )
        private_root = self.root / contract.PRIVATE_ROOT_RELATIVE
        artifact_text = "\n".join(
            path.read_text(encoding="utf-8") for path in private_root.rglob("*.json")
        )
        self.assertNotIn("must-not-be-retained", artifact_text)
        for secret in values.values():
            self.assertNotIn(secret, artifact_text)
        raw_files = sorted((private_root / "generation/raw-responses").rglob("*.json"))
        self.assertEqual(len(raw_files), 6)
        self.assertTrue(
            all(
                set(json.loads(path.read_bytes())["response"])
                == {"status", "body_base64", "body_sha256"}
                for path in raw_files
            )
        )

        bundle = load_composite_responses(self.root, contract.CANDIDATE_ID)
        self.assertEqual(
            tuple(item.model_key for item in bundle.responses), contract.MODEL_ORDER
        )
        self.assertEqual(len(bundle.responses), 8)
        self.assertTrue(all(item.response_text.strip() for item in bundle.responses))

        second_environment = RecordingEnvironment({})
        second_transport = FixedTransport([])
        resumed = asyncio.run(
            _execute_prepared(
                prepare_recovery(self.root, require_committed=True),
                environment=second_environment,
                transport_factory=lambda: second_transport,
                sleep=no_sleep,
            )
        )
        self.assertEqual(resumed.sha256, result.sha256)
        self.assertEqual(resumed.network_requests, 0)
        self.assertEqual(second_environment.reads, [])
        self.assertEqual(second_transport.requests, [])


if __name__ == "__main__":
    unittest.main()

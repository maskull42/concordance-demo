from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import HarnessConfig, load_harness_config
from concordance_harness.execution import (
    AttemptBudget,
    ExecutionOptions,
    HarnessRunner,
    create_model_manifest,
    write_model_manifest,
)
from concordance_harness.planner import build_plan, load_questions
from concordance_harness.providers import HttpResponse, PreflightResult


class FixtureTransport:
    def __init__(self) -> None:
        self.count = 0

    async def send(self, _request):
        self.count += 1
        body = {
            "id": f"fixture-response-{self.count}",
            "model": "command-a-plus-05-2026",
            "message": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Fixture answer" if self.count == 1 else "Fixture challenge"
                        ),
                    }
                ]
            },
            "finish_reason": "COMPLETE",
            "usage": {"tokens": {"input_tokens": 12, "output_tokens": 7}},
        }
        return HttpResponse(200, {}, json.dumps(body).encode())


async def emit(output: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    loaded = load_harness_config(repository / "harness/config/models.json")
    model = replace(loaded.by_key()["cohere"], requests_per_second=100_000.0)
    config = HarnessConfig(
        path=loaded.path,
        config_version=loaded.config_version,
        planning_pricing_note=loaded.planning_pricing_note,
        models=(model,),
        sha256=loaded.sha256,
    )
    question = next(
        value
        for value in load_questions(repository / "sample/questions")
        if value.question_id == "case-a"
    )
    protocol = json.loads((repository / "config/protocol.json").read_bytes())
    plan = build_plan(
        (question,),
        config.models,
        protocol["system_prompt"],
        protocol["standard_challenge_prompt"],
    )
    preflight = {
        "cohere": PreflightResult(
            "command-a-plus-05-2026", "Cohere", "Mocked preflight"
        )
    }
    manifest = create_model_manifest(config, preflight, "sample")
    _, manifest_hash = write_model_manifest(output, manifest)
    runner = HarnessRunner(
        config=config,
        plan=plan,
        secrets={"COHERE_API_KEY": "fixture-value"},
        transport=FixtureTransport(),
        budget=AttemptBudget(None, None),
        options=ExecutionOptions(
            output_root=output,
            run_purpose="sample",
            attempts_per_cell=1,
            concurrency=1,
            force=False,
        ),
        model_manifest=manifest,
        model_manifest_hash=manifest_hash,
        log=lambda _: None,
    )
    await runner.run()


if __name__ == "__main__":
    command = argparse.ArgumentParser()
    command.add_argument("output", type=Path)
    arguments = command.parse_args()
    asyncio.run(emit(arguments.output.resolve()))

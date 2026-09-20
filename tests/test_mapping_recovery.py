from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnhunt.agent import DurableAgent
from vulnhunt.mapping import run_synthesis
from vulnhunt.models import Component, EvidenceRef, MapperResult, TaskRecord, utc_now
from vulnhunt.sie_client import GenerationResult
from vulnhunt.snapshot import snapshot_id
from vulnhunt.store import RunStore
from vulnhunt.tools import AnalysisTools


class FakeInference:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.prompts = []

    def generate_result(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return GenerationResult(next(self.replies), "fake-model")


def mapping_task() -> TaskRecord:
    return TaskRecord(
        id="task-recovery",
        run_id="run-recovery",
        kind="mapping",
        role="product",
        input_artifact_ids=[],
        input_hash="input",
        model="fake-model",
        prompt_version="test-v1",
        status="pending",
        attempt=0,
        max_attempts=1,
        created_at=utc_now(),
    )


def evidence_request() -> str:
    return json.dumps({
        "kind": "tool",
        "request": {
            "tool": "get_evidence",
            "arguments": {
                "path": "source.txt",
                "start_line": 1,
                "end_line": 1,
                "reason": "the mapped component starts here",
            },
        },
    })


def final_mapper_result() -> str:
    return json.dumps({
        "kind": "final",
        "result": {"role": "product", "summary": "recovered from evidence"},
    })


class MappingRecoveryTests(unittest.TestCase):
    def test_low_context_forces_fresh_finalization_when_evidence_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            (repo / "source.txt").write_text("component\n")
            fake = FakeInference([evidence_request(), final_mapper_result()])
            agent = DurableAgent(fake, AnalysisTools(str(repo), "a" * 40), RunStore(directory))

            with patch("vulnhunt.agent.estimated_tokens", side_effect=[0, 8192]):
                result = agent.run(mapping_task(), "map the product", MapperResult)

            self.assertEqual(result.summary, "recovered from evidence")
            self.assertEqual(len(fake.prompts), 2)
            self.assertIn("No tools are available", fake.prompts[-1])

    def test_repeated_evidence_call_forces_finalization(self):
        request = evidence_request()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            (repo / "source.txt").write_text("component\n")
            fake = FakeInference([request, request, request, final_mapper_result()])
            agent = DurableAgent(fake, AnalysisTools(str(repo), "a" * 40), RunStore(directory))

            result = agent.run(mapping_task(), "map the product", MapperResult)

            self.assertEqual(result.summary, "recovered from evidence")
            record = json.loads((Path(directory) / "tasks/task-recovery.json").read_text())
            self.assertEqual(record["status"], "succeeded")

    def test_synthesis_generates_only_flows_and_preserves_merged_entities(self):
        class Snapshot:
            commit = "b" * 40
            target_id = "target"
            config_hash = "config"

        class FakeAgent:
            def __init__(self):
                self.prompt = None
                self.result_type = None

            def run(self, task, prompt, result_type):
                self.prompt = prompt
                self.result_type = result_type
                return result_type.model_validate({
                    "snapshot_id": snapshot_id(Snapshot()),
                    "flows": [],
                    "uncertainties": ["flow ordering is not yet evidenced"],
                })

        evidence = EvidenceRef(
            id="evidence-1",
            repo_commit=Snapshot.commit,
            path="src/main.rs",
            start_line=1,
            end_line=2,
            content_hash="hash",
            reason="process entry point",
            excerpt="fn main() {}",
        )
        mapper = MapperResult(
            role="runtime",
            summary="runtime mapped",
            components=[Component(
                id="component-1",
                name="server",
                kind="process",
                responsibility="serve requests",
                evidence=[evidence.id],
            )],
        )
        agent = FakeAgent()

        result = run_synthesis(agent, "run-1", Snapshot(), [evidence], [mapper], "fake-model")

        self.assertEqual([item.id for item in result.components], ["component-1"])
        self.assertEqual(result.evidence, [evidence])
        self.assertIn("flow ordering is not yet evidenced", result.uncertainties)
        self.assertIn("Flow fields", agent.prompt)
        self.assertNotIn("ProjectMap schema", agent.prompt)
        self.assertNotIn("repo_commit", agent.prompt)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnhunt.agent import DurableAgent
from vulnhunt.mapping import _normalize_ids, run_synthesis
from vulnhunt.models import (Component, EntryPoint, EvidenceRef, Flow,
                             MapperResult, TrustBoundary, TaskRecord, utc_now)
from vulnhunt.sie_client import GenerationResult, SIEClient
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


def final_mapper_result(*, wrapped: bool = True) -> str:
    result = {"role": "product", "summary": "recovered from evidence"}
    return json.dumps({"kind": "final", "result": result} if wrapped else result)


class MappingRecoveryTests(unittest.TestCase):
    def test_normalization_drops_dangling_relationship_labels(self):
        result = MapperResult(
            role="entrypoints",
            summary="mapped",
            components=[Component(
                id="known-component",
                name="server",
                kind="service",
                responsibility="serve",
                evidence=["evidence-1"],
            )],
            entry_points=[EntryPoint(
                id="http",
                name="HTTP API",
                kind="http",
                component_ids=["known-component", "missing-component"],
                attacker_inputs=[],
                evidence=["evidence-1"],
            )],
            trust_boundaries=[TrustBoundary(
                id="network",
                name="network boundary",
                from_domain="network",
                to_domain="server",
                controls=["descriptive text, not an ID"],
                evidence=["evidence-1"],
            )],
        )

        normalized = _normalize_ids("a" * 40, result)

        self.assertEqual(normalized.entry_points[0].component_ids,
                         [normalized.components[0].id])
        self.assertEqual(normalized.trust_boundaries[0].controls, [])
        self.assertTrue(any("missing-component" in item for item in normalized.uncertainties))
        self.assertTrue(any("descriptive text" in item for item in normalized.uncertainties))

    def test_low_context_forces_fresh_finalization_when_evidence_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            (repo / "source.txt").write_text("component\n")
            fake = FakeInference([evidence_request(), final_mapper_result(wrapped=False)])
            agent = DurableAgent(fake, AnalysisTools(str(repo), "a" * 40), RunStore(directory))

            with patch("vulnhunt.agent.estimated_tokens", side_effect=[0, 8192]):
                result = agent.run(mapping_task(), "map the product", MapperResult)

            self.assertEqual(result.summary, "recovered from evidence")
            self.assertEqual(len(fake.prompts), 2)
            self.assertIn("No tools are available", fake.prompts[-1])

    def test_reused_global_evidence_still_belongs_to_current_task(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            (repo / "source.txt").write_text("component\n")
            tools = AnalysisTools(str(repo), "a" * 40)
            existing = tools.get_evidence(
                path="source.txt",
                start_line=1,
                end_line=1,
                reason="the mapped component starts here",
            )
            fake = FakeInference([evidence_request(), final_mapper_result(wrapped=False)])
            agent = DurableAgent(fake, tools, RunStore(directory))

            with patch("vulnhunt.agent.estimated_tokens", side_effect=[0, 8192]):
                result = agent.run(mapping_task(), "map the product", MapperResult)

            self.assertEqual(result.summary, "recovered from evidence")
            self.assertIn(existing.id, fake.prompts[-1])

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

    def test_flattened_final_envelope_is_strictly_validated(self):
        data = {
            "kind": "final",
            "role": "runtime",
            "summary": "mapped",
        }

        result = DurableAgent._validated_result(data, MapperResult)

        self.assertEqual(result.role, "runtime")
        self.assertEqual(result.summary, "mapped")

    def test_flow_canonicalizes_single_prose_list_items(self):
        flow = Flow.model_validate({
            "id": "flow-1",
            "name": "request",
            "summary": "request flow",
            "actor_ids": [],
            "entry_point_id": "entry-1",
            "steps": [],
            "attacker_inputs": "request body",
            "trust_boundary_ids": [],
            "control_ids": [],
            "asset_ids": [],
            "sensitive_operations": "database write",
            "deployment_assumptions": "database is reachable",
            "open_questions": "is authentication required?",
            "confidence": 0.5,
            "evidence": ["evidence-1"],
        })

        self.assertEqual(flow.attacker_inputs, ["request body"])
        self.assertEqual(flow.sensitive_operations, ["database write"])
        self.assertEqual(flow.deployment_assumptions, ["database is reachable"])
        self.assertEqual(flow.open_questions, ["is authentication required?"])

    def test_repeated_read_is_cited_before_forced_finalization(self):
        request = json.dumps({
            "kind": "tool",
            "request": {"tool": "read_file", "arguments": {"path": "source.txt"}},
        })
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            (repo / "source.txt").write_text("authentication control\n")
            fake = FakeInference([request, request, request, final_mapper_result(wrapped=False)])
            tools = AnalysisTools(str(repo), "a" * 40)
            agent = DurableAgent(fake, tools, RunStore(directory))

            result = agent.run(mapping_task(), "map the controls", MapperResult)

            self.assertEqual(result.summary, "recovered from evidence")
            self.assertEqual(len(tools.evidence), 1)
            transcript = [json.loads(line) for line in
                          (Path(directory) / "transcripts/task-recovery.jsonl").read_text().splitlines()]
            recovery = [entry for entry in transcript
                        if entry.get("step") == "repeated-read-recovery"]
            self.assertEqual(len(recovery), 1)
            self.assertEqual(recovery[0]["tool"], "get_evidence")

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

    def test_generation_uses_longer_timeout_without_retrying(self):
        class Response:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return {"choices": [{"message": {"content": '{"kind":"inconclusive"}'}}]}

        client = SIEClient(
            base_url="http://sie.invalid",
            timeout=5,
            models={"generate": "Qwen/Qwen3.8-27B-FP8"},
        )
        calls = []
        client.session.post = lambda url, **kwargs: calls.append((url, kwargs)) or Response()

        client.generate_result("synthesize", max_new_tokens=2500)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["timeout"], 300.0)


if __name__ == "__main__":
    unittest.main()

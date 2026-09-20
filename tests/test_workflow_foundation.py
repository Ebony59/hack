from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from vulnhunt.agent import DurableAgent
from vulnhunt.ids import stable_id
from vulnhunt.mapping import _normalize_ids
from vulnhunt.models import MapperResult, TaskRecord, utc_now
from vulnhunt.sie_client import GenerationResult, SIEClient, parse_json_object, sie_safe_model_id
from vulnhunt.store import RunStore
from vulnhunt.tools import AnalysisTools


class FakeInference:
    def __init__(self, replies):
        self.replies = iter(replies)

    def generate_result(self, prompt, **kwargs):
        return GenerationResult(next(self.replies), "fake-model")


def task() -> TaskRecord:
    return TaskRecord(id="task-test", run_id="run-test", kind="mapping", role="product",
                      input_artifact_ids=[], input_hash="input", model="fake-model", prompt_version="test-v1",
                      status="pending", attempt=0, max_attempts=1, created_at=utc_now())


class WorkflowFoundationTests(unittest.TestCase):
    def test_symlink_and_absolute_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root, external = Path(directory), Path(outside) / "secret.txt"
            external.write_text("do not read")
            (root / "inside.txt").write_text("ok")
            (root / "escape").symlink_to(external)
            tools = AnalysisTools(str(root), "a" * 40)
            self.assertIn("ok", tools.read_file("inside.txt"))
            self.assertIn("error", tools.read_file("escape"))
            self.assertIn("error", tools.read_file("../secret.txt"))
            self.assertIn("error", tools.read_file(str(external)))

    def test_models_are_strict(self):
        with self.assertRaises(ValidationError):
            MapperResult.model_validate({"role": "product", "summary": "x", "extra": "no"})
        with self.assertRaises(ValidationError):
            TaskRecord.model_validate({**task().model_dump(), "attempt": "0"})

    def test_json_with_braces_inside_strings_parses(self):
        raw = 'prefix {"kind":"final","result":{"summary":"use {quoted} braces", "role":"product"}} suffix'
        self.assertEqual(parse_json_object(raw)["result"]["summary"], "use {quoted} braces")

    def test_generation_model_path_is_sie_safe(self):
        self.assertEqual(sie_safe_model_id("Qwen/Qwen2.5-Coder"), "Qwen__Qwen2.5-Coder")

    def test_offline_is_not_a_successful_preflight(self):
        result = SIEClient(offline=True).preflight({"generate"})
        self.assertFalse(result.ok)
        self.assertTrue(result.offline)

    def test_direct_final_is_preserved_and_parsed_once(self):
        response = json.dumps({"kind": "final", "result": {"role": "product", "summary": "done"}})
        with tempfile.TemporaryDirectory() as directory:
            store = RunStore(directory)
            repo = Path(directory) / "repo"
            repo.mkdir()
            agent = DurableAgent(FakeInference([response]), AnalysisTools(str(repo), "a" * 40), store)
            result = agent.run(task(), "test prompt", MapperResult)
            self.assertEqual(result.summary, "done")
            transcript = [json.loads(line) for line in (Path(directory) / "transcripts/task-test.jsonl").read_text().splitlines()]
            self.assertEqual(transcript[1]["content"], response)
            self.assertEqual(json.loads((Path(directory) / "tasks/task-test.json").read_text())["status"], "succeeded")

    def test_repeated_tool_call_is_inconclusive(self):
        request = json.dumps({"kind": "tool", "request": {"tool": "list_files", "arguments": {}}})
        with tempfile.TemporaryDirectory() as directory:
            store = RunStore(directory)
            repo = Path(directory) / "repo"
            repo.mkdir()
            agent = DurableAgent(FakeInference([request, request]), AnalysisTools(str(repo), "a" * 40), store)
            self.assertIsNone(agent.run(task(), "test prompt", MapperResult))
            self.assertEqual(json.loads((Path(directory) / "tasks/task-test.json").read_text())["status"], "inconclusive")

    def test_stable_ids_change_with_commit(self):
        self.assertEqual(stable_id("flow", "a" * 40, {"name": "x"}), stable_id("flow", "a" * 40, {"name": "x"}))
        self.assertNotEqual(stable_id("flow", "a" * 40, {"name": "x"}), stable_id("flow", "b" * 40, {"name": "x"}))

    def test_mapper_entity_ids_are_not_model_supplied_labels(self):
        result = MapperResult.model_validate({"role": "runtime", "summary": "x", "components": [{
            "id": "model-made-id", "name": "daemon", "kind": "process", "responsibility": "serve",
            "evidence": ["evidence-1"]}]})
        normalized = _normalize_ids("a" * 40, result)
        self.assertNotEqual(normalized.components[0].id, "model-made-id")
        self.assertEqual(normalized.components[0].id,
                         _normalize_ids("a" * 40, result).components[0].id)

    def test_mapper_prompt_fits_the_deployment_context_budget(self):
        """A mapper request must fit prompt + completion inside the served window.

        Regression guard: an over-large prompt or max_new_tokens is rejected by
        the endpoint before the model runs, which failed every mapping task.
        """
        from vulnhunt.budget import (CONTEXT_BUDGET_TOKENS, GENERATION_RESERVE_TOKENS,
                                     estimated_tokens)
        from vulnhunt.mapping import ROLE_OBJECTIVES, _agent_prompt

        snapshot = {"target_id": "t", "commit": "a" * 40, "languages": ["rust"],
                    "manifests": ["Cargo.toml"], "build_commands": ["cargo build"]}
        inventory = {"schema_version": 1, "files": [f"src/f{i}.rs" for i in range(40)],
                     "entry_point_candidates": ["src/main.rs"], "manifests": ["Cargo.toml"]}
        for role in ROLE_OBJECTIVES:
            needed = estimated_tokens(_agent_prompt(role, snapshot, inventory)) + GENERATION_RESERVE_TOKENS
            self.assertLessEqual(needed, CONTEXT_BUDGET_TOKENS,
                                 f"{role} mapper needs ~{needed} tokens, over the ceiling")

    def test_oversized_synthesis_is_refused_rather_than_sent(self):
        """Synthesis must fail loudly when it cannot fit, not silently return nothing."""
        from vulnhunt.mapping import SynthesisTooLarge, run_synthesis
        from vulnhunt.models import EvidenceRef, MapperResult

        commit = "b" * 40
        evidence = [EvidenceRef(id=f"ev{i}", repo_commit=commit, path=f"src/f{i}.rs",
                                start_line=1, end_line=2, symbol=None, content_hash="h" * 8,
                                reason="r" * 200, excerpt="x" * 400) for i in range(60)]
        results = [MapperResult(role=r, summary="s" * 500) for r in ("product", "runtime")]

        class _Snap:
            commit = "b" * 40
            target_id = "t"
            config_hash = "c" * 8
            def model_dump(self, **_):
                return {"commit": self.commit}

        with self.assertRaises(SynthesisTooLarge) as caught:
            run_synthesis(None, "run-1", _Snap(), evidence, results, "model-x")
        self.assertIn("ceiling", str(caught.exception))



if __name__ == "__main__":
    unittest.main()

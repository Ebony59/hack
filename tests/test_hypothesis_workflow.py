from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from vulnhunt.agent import DurableAgent
from vulnhunt.hypotheses import (ReviewValidationError, parse_checkpoint_a, parse_checkpoint_b,
                                 rank_hypotheses, run_hypothesis_stage)
from vulnhunt.models import (EvidenceRef, Flow, FlowStep, Hypothesis, ProjectMap,
                             RepositorySnapshot, utc_now)
from vulnhunt.reports import render_checkpoint_b
from vulnhunt.sie_client import GenerationResult
from vulnhunt.store import RunStore
from vulnhunt.tools import AnalysisTools


class FakeInference:
    def __init__(self, replies):
        self.replies = iter(replies)

    def generate_result(self, prompt, **kwargs):
        return GenerationResult(next(self.replies), "fake-model")


def _snapshot(root: str) -> RepositorySnapshot:
    return RepositorySnapshot(target_id="fixture", repo_path=root, remote_url=None, commit="a" * 40,
                              branch="main", dirty=False, languages=["python"], manifests=[], package_roots=[],
                              instructions=[], build_commands=[], test_commands=[], created_at=utc_now(),
                              harness_commit=None, config_hash="config", tool_versions={})


def _evidence() -> EvidenceRef:
    return EvidenceRef(id="evidence-1", repo_commit="a" * 40, path="app.py", start_line=1, end_line=2,
                       symbol="handle", content_hash="hash", reason="input reaches operation",
                       excerpt="def handle(value):\n    return value\n")


def _flow() -> Flow:
    return Flow(id="flow-1", name="request flow", summary="request reaches operation", actor_ids=["actor-1"],
                entry_point_id="entry-1", steps=[FlowStep(component_id="component-1", action="handle request",
                inputs=["request"], outputs=["result"], evidence=["evidence-1"])], attacker_inputs=["request"],
                trust_boundary_ids=[], control_ids=[], asset_ids=[], sensitive_operations=["operation"],
                deployment_assumptions=[], open_questions=[], confidence=0.8, evidence=["evidence-1"])


def _map() -> ProjectMap:
    return ProjectMap(snapshot_id="snapshot-1", evidence=[_evidence()], components=[], actors=[], assets=[],
                      entry_points=[], trust_boundaries=[], controls=[], flows=[_flow()], uncertainties=[], disagreements=[])


def _review(approved=True, selected=None):
    return {"schema_version": 1, "approved": approved, "reviewer_notes": "reviewed",
            "selected_flow_ids": selected if selected is not None else ["flow-1"], "rejected_flow_ids": [],
            "flow_edits": [], "additional_questions": []}


class HypothesisWorkflowTests(unittest.TestCase):
    def test_checkpoint_a_requires_approved_known_nonempty_selection(self):
        project_map = _map()
        with self.assertRaises(ReviewValidationError):
            parse_checkpoint_a(_review(approved=False), project_map)
        with self.assertRaises(ReviewValidationError):
            parse_checkpoint_a(_review(selected=[]), project_map)
        with self.assertRaises(ReviewValidationError):
            parse_checkpoint_a(_review(selected=["unknown-flow"]), project_map)

    def test_hypothesis_schema_is_strict_and_requires_contrary_evidence(self):
        payload = {"id": "model-id", "flow_id": "flow-1", "invariant_id": "invariant-1", "title": "test",
                   "attacker_capability": "send request", "suspected_path": "request to operation",
                   "expected_impact": "bad result", "evidence": ["evidence-1"], "contrary_evidence": [],
                   "contrary_reasoning": "a control may apply", "decisive_test": "controlled test",
                   "safety_concerns": [], "impact": 3, "reachability": 3, "evidence_strength": 3,
                   "novelty": 3, "reproduction_cost": 2, "safety_risk": 1}
        with self.assertRaises(ValidationError):
            Hypothesis.model_validate(payload)
        payload["contrary_evidence"] = ["evidence-1"]
        payload["extra"] = "forbidden"
        with self.assertRaises(ValidationError):
            Hypothesis.model_validate(payload)

    def test_fake_stage_persists_cited_ranked_artifacts_and_report(self):
        invariant = {"kind": "final", "result": {"flow_id": "flow-1", "invariants": [{
            "id": "model-invariant", "flow_id": "flow-1", "statement": "request remains authorized",
            "assumptions": ["configured control is enabled"], "evidence": ["evidence-1"]}], "uncertainties": []}}
        class DynamicInference:
            def generate_result(self, prompt, **kwargs):
                if "deriving security invariants" in prompt:
                    return GenerationResult(json.dumps(invariant), "fake-model")
                import re
                if "deduplicating security hypotheses" in prompt:
                    hypothesis_id = re.search(r'"id": "(hypothesis-[^"]+)"', prompt).group(1)
                    result = {"kind": "final", "result": {"kept_hypothesis_ids": [hypothesis_id],
                              "duplicate_groups": [], "uncertainties": []}}
                    return GenerationResult(json.dumps(result), "fake-model")
                invariant_id = re.search(r'"id": "(invariant-[^"]+)"', prompt).group(1)
                candidate = {"kind": "final", "result": {"invariant_id": invariant_id, "hypotheses": [{
                    "id": "model-hypothesis", "flow_id": "flow-1", "invariant_id": invariant_id,
                    "title": "missing validation", "attacker_capability": "send a request",
                    "suspected_path": "request reaches operation", "expected_impact": "unauthorized operation",
                    "evidence": ["evidence-1"], "contrary_evidence": ["evidence-1"],
                    "contrary_reasoning": "the same code may validate earlier", "decisive_test": "compare valid and invalid inputs",
                    "safety_concerns": ["use a fixture"], "impact": 4, "reachability": 4,
                    "evidence_strength": 3, "novelty": 2, "reproduction_cost": 2, "safety_risk": 1}], "uncertainties": []}}
                return GenerationResult(json.dumps(candidate), "fake-model")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            (root / "app.py").write_text("def handle(value):\n    return value\n")
            store = RunStore(directory)
            tools = AnalysisTools(str(root), "a" * 40)
            tools.evidence = {"evidence-1": _evidence()}
            agent = DurableAgent(DynamicInference(), tools, store)
            invariants, hypotheses = run_hypothesis_stage(agent, "run", _snapshot(str(root)), _map(), [_flow()], "fake")
            self.assertEqual(len(invariants), 1)
            self.assertEqual(len(hypotheses), 1)
            from vulnhunt.hypotheses import priority_score
            store.write_json("artifacts/invariants.json", invariants)
            store.write_json("artifacts/hypotheses.json", hypotheses)
            markdown, yaml_path = render_checkpoint_b(store, _snapshot(str(root)), _map(), invariants, hypotheses, [])
            self.assertTrue(Path(markdown).is_file())
            self.assertTrue(Path(yaml_path).is_file())
            self.assertIn("missing validation", Path(markdown).read_text())
            self.assertEqual(hypotheses[0].priority_score, priority_score(hypotheses[0]))

    def test_fabricated_citations_fail_the_task_without_a_hypothesis(self):
        invariant = {"kind": "final", "result": {"flow_id": "flow-1", "invariants": [{
            "id": "model-invariant", "flow_id": "flow-1", "statement": "property",
            "assumptions": [], "evidence": ["fabricated"]}], "uncertainties": []}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            store = RunStore(directory)
            tools = AnalysisTools(str(root), "a" * 40)
            tools.evidence = {"evidence-1": _evidence()}
            agent = DurableAgent(FakeInference([json.dumps(invariant)]), tools, store)
            invariants, hypotheses = run_hypothesis_stage(agent, "run", _snapshot(str(root)), _map(), [_flow()], "fake")
            self.assertEqual(invariants, [])
            self.assertEqual(hypotheses, [])
            records = list((Path(directory) / "tasks").glob("*.json"))
            self.assertEqual(json.loads(records[0].read_text())["status"], "failed")

    def test_checkpoint_b_requires_known_selected_hypothesis(self):
        item = Hypothesis.model_validate({"id": "hypothesis-1", "flow_id": "flow-1", "invariant_id": "invariant-1",
            "title": "test", "attacker_capability": "request", "suspected_path": "path", "expected_impact": "impact",
            "evidence": ["evidence-1"], "contrary_evidence": ["evidence-1"], "contrary_reasoning": "control",
            "decisive_test": "fixture", "safety_concerns": [], "impact": 3, "reachability": 3,
            "evidence_strength": 3, "novelty": 3, "reproduction_cost": 2, "safety_risk": 1})
        review = {"schema_version": 1, "approved": True, "reviewer_notes": "ok",
                  "selected_hypothesis_ids": ["unknown"], "rejected_hypothesis_ids": [], "priority_overrides": {}}
        with self.assertRaises(ReviewValidationError):
            parse_checkpoint_b(review, [item])


if __name__ == "__main__":
    unittest.main()

"""Cited invariant and hypothesis generation after checkpoint-A review."""
from __future__ import annotations

import json
from typing import Iterable

from .agent import DurableAgent
from .ids import content_hash, stable_id
from .models import (CheckpointAReview, CheckpointBReview, EvidenceRef, Flow, Hypothesis, HypothesisResult,
                     HypothesisSynthesisResult, Invariant, InvariantResult, ProjectMap, TaskRecord, utc_now)
from .snapshot import snapshot_id


class ReviewValidationError(ValueError):
    """A human review does not safely select artifacts from this run."""


def parse_checkpoint_a(value: object, project_map: ProjectMap) -> CheckpointAReview:
    review = CheckpointAReview.model_validate(value)
    known = {flow.id for flow in project_map.flows}
    selected, rejected = review.selected_flow_ids, review.rejected_flow_ids
    if not review.approved:
        raise ReviewValidationError("checkpoint A is not approved")
    if not selected:
        raise ReviewValidationError("checkpoint A approves no selected flows")
    if len(selected) != len(set(selected)) or len(rejected) != len(set(rejected)):
        raise ReviewValidationError("checkpoint A flow selections must be unique")
    unknown = (set(selected) | set(rejected)) - known
    if unknown:
        raise ReviewValidationError(f"checkpoint A names unknown flow IDs: {', '.join(sorted(unknown))}")
    overlap = set(selected) & set(rejected)
    if overlap:
        raise ReviewValidationError(f"checkpoint A both selects and rejects: {', '.join(sorted(overlap))}")
    return review


def parse_checkpoint_b(value: object, hypotheses: Iterable[Hypothesis]) -> CheckpointBReview:
    review = CheckpointBReview.model_validate(value)
    known = {item.id for item in hypotheses}
    selected, rejected = review.selected_hypothesis_ids, review.rejected_hypothesis_ids
    if not review.approved:
        raise ReviewValidationError("checkpoint B is not approved")
    if not selected:
        raise ReviewValidationError("checkpoint B approves no selected hypotheses")
    if len(selected) != len(set(selected)) or len(rejected) != len(set(rejected)):
        raise ReviewValidationError("checkpoint B hypothesis selections must be unique")
    unknown = (set(selected) | set(rejected) | set(review.priority_overrides)) - known
    if unknown:
        raise ReviewValidationError(f"checkpoint B names unknown hypothesis IDs: {', '.join(sorted(unknown))}")
    overlap = set(selected) & set(rejected)
    if overlap:
        raise ReviewValidationError(f"checkpoint B both selects and rejects: {', '.join(sorted(overlap))}")
    return review


def _task(run_id: str, commit: str, role: str, identity: object, model: str) -> TaskRecord:
    return TaskRecord(
        id=stable_id("task", commit, {"run": run_id, "role": role, "identity": identity}),
        run_id=run_id, kind="hypothesis", role=role, input_artifact_ids=[],
        input_hash=content_hash(json.dumps(identity, sort_keys=True)), model=model,
        prompt_version="hypothesis-v1", status="pending", attempt=0, max_attempts=1,
        created_at=utc_now(),
    )


def _flow_context(flow: Flow, evidence: Iterable[EvidenceRef]) -> str:
    wanted = set(flow.evidence)
    for step in flow.steps:
        wanted.update(step.evidence)
    cited = []
    for item in evidence:
        if item.id not in wanted:
            continue
        value = item.model_dump(mode="json")
        # The durable agent can request the exact line range again. Keeping an
        # initial bounded excerpt leaves room for a structured final answer.
        value["excerpt"] = value["excerpt"][:1200]
        cited.append(value)
    return json.dumps({"flow": flow.model_dump(mode="json"), "cited_evidence": cited}, sort_keys=True)


def _invariant_prompt(flow: Flow, evidence: Iterable[EvidenceRef]) -> str:
    return f"""You are deriving security invariants for one human-reviewed repository interaction flow.
This is security reasoning, not a vulnerability finding. Work only from source evidence and use
read-only tools when a focused source check is necessary. Every invariant needs at least one
EvidenceRef ID. Do not propose exploits or shell commands.

Reviewed flow and its current evidence:
{_flow_context(flow, evidence)}

Return exactly one JSON object:
{{"kind":"final","result":{{"flow_id":"{flow.id}","invariants":[{{"id":"short-label","flow_id":"{flow.id}","statement":"security property","assumptions":["..."],"evidence":["evidence-id"]}}],"uncertainties":["..."]}}}}
If the supplied material cannot establish an invariant, return:
{{"kind":"inconclusive","reason":"..."}}
"""


def _hypothesis_prompt(flow: Flow, invariant: Invariant, evidence: Iterable[EvidenceRef]) -> str:
    return f"""You are proposing bounded, unverified security hypotheses for a reviewed repository flow.
Each item must describe a possible violation of the given invariant, cite supporting and contrary
source evidence, and give the cheapest decisive test. A hypothesis is not a vulnerability finding.
Do not execute commands or claim reproduction. Use read-only tools only when needed to obtain
specific EvidenceRef IDs.

Reviewed flow:
{_flow_context(flow, evidence)}
Invariant:
{json.dumps(invariant.model_dump(mode="json"), sort_keys=True)}

Return exactly one JSON object with kind=final. Its result must have invariant_id "{invariant.id}",
an optional uncertainties list, and a hypotheses list. Every hypothesis must include:
id, flow_id "{flow.id}", invariant_id "{invariant.id}", title, attacker_capability, suspected_path,
expected_impact, evidence [EvidenceRef IDs], contrary_evidence [EvidenceRef IDs], contrary_reasoning,
decisive_test, safety_concerns, and integer scores 1 through 5 for impact, reachability,
evidence_strength, novelty, reproduction_cost, safety_risk. Set status to "hypothesis".
If no responsibly cited hypothesis is possible, return kind=inconclusive instead.
"""


def _known_evidence(items: Iterable[EvidenceRef]) -> set[str]:
    return {item.id for item in items}


def _normalize_invariants(commit: str, flow: Flow, result: InvariantResult,
                          known_evidence: set[str]) -> list[Invariant]:
    if result.flow_id != flow.id:
        raise ReviewValidationError("invariant task returned a different flow")
    normalized = []
    for item in result.invariants:
        if item.flow_id != flow.id or not set(item.evidence).issubset(known_evidence):
            raise ReviewValidationError("invariant has an unknown flow or evidence reference")
        identifier = stable_id("invariant", commit, {"flow": flow.id, "statement": item.statement,
                                                       "evidence": sorted(item.evidence)})
        normalized.append(item.model_copy(update={"id": identifier}))
    return normalized


def priority_score(item: Hypothesis) -> float:
    """A visible ranking heuristic; reviewers may override it at checkpoint B."""
    return round((2 * item.impact) + (1.5 * item.reachability) + (1.5 * item.evidence_strength)
                 + item.novelty - (0.5 * item.reproduction_cost) - (0.5 * item.safety_risk), 2)


def _normalize_hypotheses(commit: str, flow: Flow, invariant: Invariant,
                          result: HypothesisResult, known_evidence: set[str]) -> list[Hypothesis]:
    if result.invariant_id != invariant.id:
        raise ReviewValidationError("hypothesis task returned a different invariant")
    normalized = []
    for item in result.hypotheses:
        citations = set(item.evidence) | set(item.contrary_evidence)
        if item.flow_id != flow.id or item.invariant_id != invariant.id or not citations.issubset(known_evidence):
            raise ReviewValidationError("hypothesis has an unknown flow, invariant, or evidence reference")
        identifier = stable_id("hypothesis", commit, {"flow": flow.id, "invariant": invariant.id,
                                                        "title": item.title, "evidence": sorted(citations)})
        normalized.append(item.model_copy(update={"id": identifier, "priority_score": priority_score(item)}))
    return normalized


def rank_hypotheses(items: Iterable[Hypothesis], overrides: dict[str, float] | None = None) -> list[Hypothesis]:
    overrides = overrides or {}
    ranked = [item.model_copy(update={"priority_score": float(overrides.get(item.id, priority_score(item)))})
              for item in items]
    return sorted(ranked, key=lambda item: (-item.priority_score, item.id))


def _synthesis_prompt(items: list[Hypothesis]) -> str:
    return f"""You are deduplicating security hypotheses after separate SIE tasks.
You may only retain or group the candidate IDs supplied below. Do not rewrite, strengthen, add,
or validate a security claim. Preserve candidates that differ in attacker capability, suspected
path, invariant, decisive test, or contrary evidence. Group only genuinely overlapping candidates.

Candidates:
{json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)}

Return exactly one JSON object:
{{"kind":"final","result":{{"kept_hypothesis_ids":["existing-id"],
"duplicate_groups":[["existing-id","existing-id"]],"uncertainties":["..."]}}}}
If the candidate context is insufficient to group safely, retain every candidate and put that fact
in uncertainties. Never return an ID that is absent from the candidates.
"""


def _synthesize_hypotheses(agent: DurableAgent, run_id: str, snapshot, items: list[Hypothesis],
                            model: str) -> list[Hypothesis]:
    if not items:
        return []
    prompt = _synthesis_prompt(items)
    task = _task(run_id, snapshot.commit, "hypothesis-synthesis", {"hypotheses": [item.id for item in items]}, model)
    task.input_artifact_ids = [snapshot_id(snapshot), *[item.id for item in items]]
    result = agent.run(task, prompt, HypothesisSynthesisResult)
    if result is None:
        # Failure stays visible in the task record. Retain candidates for reviewer
        # inspection, but the command marks the run incomplete.
        return rank_hypotheses(items)
    known = {item.id for item in items}
    kept = result.kept_hypothesis_ids
    groups = result.duplicate_groups
    try:
        if not kept or len(kept) != len(set(kept)) or not set(kept).issubset(known):
            raise ReviewValidationError("hypothesis synthesis returned invalid retained IDs")
        seen_groups: set[str] = set()
        for group in groups:
            if len(group) < 2 or len(group) != len(set(group)) or not set(group).issubset(known):
                raise ReviewValidationError("hypothesis synthesis returned an invalid duplicate group")
            overlap = seen_groups & set(group)
            if overlap:
                raise ReviewValidationError("hypothesis synthesis placed an ID in multiple duplicate groups")
            seen_groups.update(group)
    except ReviewValidationError as exc:
        task.status, task.error_type, task.error_message = "failed", type(exc).__name__, str(exc)
        agent.store.write_json(f"tasks/{task.id}.json", task)
        return rank_hypotheses(items)
    by_id = {item.id: item for item in items}
    return rank_hypotheses([by_id[item_id] for item_id in kept])


def run_hypothesis_stage(agent: DurableAgent, run_id: str, snapshot, project_map: ProjectMap,
                         selected_flows: list[Flow], model: str) -> tuple[list[Invariant], list[Hypothesis]]:
    """Run separate invariant then hypothesis tasks, retaining failed tasks in the store."""
    # The command reloads previously persisted evidence into the tools before
    # this stage. New get_evidence calls extend the same registry, so both old
    # and newly acquired citations are accepted and persisted by the caller.
    known_evidence = _known_evidence(agent.tools.evidence.values())
    invariants: list[Invariant] = []
    for flow in selected_flows:
        prompt = _invariant_prompt(flow, agent.tools.evidence.values())
        task = _task(run_id, snapshot.commit, "invariant", {"flow": flow.id}, model)
        task.input_artifact_ids = [snapshot_id(snapshot), flow.id]
        result = agent.run(task, prompt, InvariantResult)
        if result is None:
            continue
        try:
            invariants.extend(_normalize_invariants(snapshot.commit, flow, result, known_evidence))
        except ReviewValidationError as exc:
            task.status, task.error_type, task.error_message = "failed", type(exc).__name__, str(exc)
            agent.store.write_json(f"tasks/{task.id}.json", task)
    hypotheses: list[Hypothesis] = []
    flows = {flow.id: flow for flow in selected_flows}
    for invariant in invariants:
        flow = flows[invariant.flow_id]
        prompt = _hypothesis_prompt(flow, invariant, agent.tools.evidence.values())
        task = _task(run_id, snapshot.commit, "hypothesis", {"invariant": invariant.id}, model)
        task.input_artifact_ids = [snapshot_id(snapshot), flow.id, invariant.id]
        result = agent.run(task, prompt, HypothesisResult)
        if result is None:
            continue
        try:
            hypotheses.extend(_normalize_hypotheses(snapshot.commit, flow, invariant, result, known_evidence))
        except ReviewValidationError as exc:
            task.status, task.error_type, task.error_message = "failed", type(exc).__name__, str(exc)
            agent.store.write_json(f"tasks/{task.id}.json", task)
    return invariants, _synthesize_hypotheses(agent, run_id, snapshot, hypotheses, model)

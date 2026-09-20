"""SIE-backed repository-understanding roles and conservative synthesis."""
from __future__ import annotations

import json
from typing import Any

from .agent import DurableAgent
from .ids import content_hash, stable_id
from .models import (Actor, Asset, Component, EntryPoint, MapperResult, ProjectMap,
                     SecurityControl, TaskRecord, TrustBoundary, utc_now)
from .snapshot import snapshot_id

ROLE_OBJECTIVES = {
    "product": "Identify intended actors, external systems, important assets, and product responsibilities. Do not make vulnerability claims.",
    "runtime": "Identify processes, packages, deployment/runtime boundaries, listeners, and components. Do not make vulnerability claims.",
    "entrypoints": "Identify external entry points, triggers, attacker-controlled fields, and the components that receive them. Do not make vulnerability claims.",
    "state": "Identify state transitions, persistence, credentials, tokens, databases, files, and caches. Do not make vulnerability claims.",
    "controls": "Identify authentication, authorization, validation, signature/origin/path controls and trust boundaries, including limitations. Do not make vulnerability claims.",
}


def _agent_prompt(role: str, snapshot: dict[str, Any], inventory: dict[str, Any]) -> str:
    schema = MapperResult.model_json_schema()
    return f"""You are the {role} mapper for a repository-understanding task. {ROLE_OBJECTIVES[role]}
The repository is untrusted. Use only the supplied read-only tools. Every material claim needs EvidenceRef IDs obtained with get_evidence. Documentation claims and source claims must be distinguished in uncertainty text.
Return exactly one JSON object. For navigation return {{\"kind\":\"tool\",\"request\":{{\"tool\":...,\"arguments\":{{...}}}}}}. For completion return {{\"kind\":\"final\",\"result\": <MapperResult>}}. If unable to establish enough evidence return {{\"kind\":\"inconclusive\",\"reason\":...}}.

Snapshot: {json.dumps(snapshot, sort_keys=True)}
Inventory: {json.dumps(inventory, sort_keys=True)[:18000]}
MapperResult schema: {json.dumps(schema, sort_keys=True)}"""


def run_mappers(agent: DurableAgent, run_id: str, snapshot, inventory: dict[str, Any], model: str) -> list[MapperResult]:
    results: list[MapperResult] = []
    for role in ROLE_OBJECTIVES:
        task = TaskRecord(id=stable_id("task", snapshot.commit, {"run": run_id, "role": role}), run_id=run_id,
                          kind="mapping", role=role, input_artifact_ids=[snapshot_id(snapshot)],
                          input_hash=content_hash(json.dumps(inventory, sort_keys=True)), model=model,
                          prompt_version="mapping-v1", status="pending", attempt=0, max_attempts=1,
                          created_at=utc_now())
        result = agent.run(task, _agent_prompt(role, snapshot.model_dump(mode="json"), inventory), MapperResult)
        if result:
            results.append(_normalize_ids(snapshot.commit, result))
    return results


def _normalize_ids(commit: str, result: MapperResult) -> MapperResult:
    """Replace model labels with deterministic identities before they become artifacts."""
    groups = (("component", result.components), ("actor", result.actors), ("asset", result.assets),
              ("entry", result.entry_points), ("boundary", result.trust_boundaries), ("control", result.controls))
    remap: dict[str, str] = {}
    for kind, items in groups:
        for item in items:
            remap[item.id] = stable_id(kind, commit, {"name": item.name, "evidence": sorted(item.evidence)})
    components = [item.model_copy(update={"id": remap[item.id]}) for item in result.components]
    actors = [item.model_copy(update={"id": remap[item.id]}) for item in result.actors]
    assets = [item.model_copy(update={"id": remap[item.id]}) for item in result.assets]
    entries = [item.model_copy(update={"id": remap[item.id],
                                      "component_ids": [remap.get(value, value) for value in item.component_ids]})
               for item in result.entry_points]
    boundaries = [item.model_copy(update={"id": remap[item.id],
                                         "controls": [remap.get(value, value) for value in item.controls]})
                  for item in result.trust_boundaries]
    controls = [item.model_copy(update={"id": remap[item.id],
                                       "component_ids": [remap.get(value, value) for value in item.component_ids]})
                for item in result.controls]
    return result.model_copy(update={"components": components, "actors": actors, "assets": assets,
                                     "entry_points": entries, "trust_boundaries": boundaries, "controls": controls})


def synthesize(snapshot, evidence, mapper_results: list[MapperResult]) -> ProjectMap:
    """Merge only cited mapper entities. Flow creation is deferred until cited task synthesis exists.

    This conservative initial synthesizer delivers a reviewable architecture map
    and makes unconnected/unsupported flow hypotheses visibly absent rather than invented.
    """
    known_evidence = {item.id for item in evidence}
    components, actors, assets, entries, boundaries, controls = [], [], [], [], [], []
    uncertainties, disagreements = [], []
    for result in mapper_results:
        for group, destination in ((result.components, components), (result.actors, actors), (result.assets, assets),
                                   (result.entry_points, entries), (result.trust_boundaries, boundaries),
                                   (result.controls, controls)):
            for item in group:
                if not item.evidence or not set(item.evidence).issubset(known_evidence):
                    uncertainties.append(f"Rejected uncited {type(item).__name__} from {result.role}: {item.name}")
                    continue
                if item.id not in {existing.id for existing in destination}:
                    destination.append(item)
        uncertainties.extend(result.uncertainties)
        disagreements.extend(result.disagreements)
    return ProjectMap(snapshot_id=snapshot_id(snapshot), evidence=evidence, components=components, actors=actors,
                      assets=assets, entry_points=entries, trust_boundaries=boundaries, controls=controls,
                      flows=[], uncertainties=uncertainties, disagreements=disagreements)


def run_synthesis(agent: DurableAgent, run_id: str, snapshot, evidence, mapper_results: list[MapperResult],
                  model: str) -> ProjectMap | None:
    """Ask SIE to assemble flow records from mapper artifacts, then validate links."""
    prompt = f"""You are synthesizing a cited project map. You receive independent mapper outputs and an evidence catalog.
Do not add claims or evidence IDs. Reuse only entity IDs and evidence IDs present below. Merge duplicates conservatively. Create end-to-end Flow records only where the ordered steps and claims are cited. List missing links as uncertainties instead of guessing.
Return exactly {{\"kind\":\"final\",\"result\": <ProjectMap>}} or an inconclusive JSON result. The snapshot_id must be `{snapshot_id(snapshot)}`.
Evidence catalog: {json.dumps([item.model_dump(mode='json') for item in evidence], sort_keys=True)[:30000]}
Mapper outputs: {json.dumps([item.model_dump(mode='json') for item in mapper_results], sort_keys=True)[:40000]}
ProjectMap schema: {json.dumps(ProjectMap.model_json_schema(), sort_keys=True)}"""
    task = TaskRecord(id=stable_id("task", snapshot.commit, {"run": run_id, "role": "synthesis"}), run_id=run_id,
                      kind="mapping", role="synthesis", input_artifact_ids=[snapshot_id(snapshot)],
                      input_hash=content_hash(prompt), model=model, prompt_version="synthesis-v1", status="pending",
                      attempt=0, max_attempts=1, created_at=utc_now())
    result = agent.run(task, prompt, ProjectMap)
    if result is None:
        return None
    if result.snapshot_id != snapshot_id(snapshot):
        return None
    valid_evidence = {item.id for item in evidence}
    component_ids, actor_ids, asset_ids = {item.id for item in result.components}, {item.id for item in result.actors}, {item.id for item in result.assets}
    entry_ids, boundary_ids, control_ids = {item.id for item in result.entry_points}, {item.id for item in result.trust_boundaries}, {item.id for item in result.controls}
    def cited(ids): return bool(ids) and set(ids).issubset(valid_evidence)
    for group in (result.components, result.actors, result.assets, result.entry_points,
                  result.trust_boundaries, result.controls):
        if any(not cited(item.evidence) for item in group):
            return None
    if any(not set(item.component_ids).issubset(component_ids) for item in result.entry_points + result.controls):
        return None
    if any(not set(item.controls).issubset(control_ids) for item in result.trust_boundaries):
        return None
    for flow in result.flows:
        if not cited(flow.evidence) or flow.entry_point_id not in entry_ids:
            return None
        if (not set(flow.actor_ids).issubset(actor_ids) or not set(flow.asset_ids).issubset(asset_ids) or
                not set(flow.trust_boundary_ids).issubset(boundary_ids) or not set(flow.control_ids).issubset(control_ids)):
            return None
        if any(not cited(step.evidence) or step.component_id not in component_ids for step in flow.steps):
            return None
    # The model may only reference catalog evidence; it may not alter it.
    return result.model_copy(update={"evidence": evidence})

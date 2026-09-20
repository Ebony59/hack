"""SIE-backed repository-understanding roles and conservative synthesis."""
from __future__ import annotations

import json
from typing import Any

from .agent import DurableAgent
from .budget import CONTEXT_BUDGET_TOKENS, GENERATION_RESERVE_TOKENS, estimated_tokens
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


_TOOL_INVENTORY = """\
Available read-only tools — call exactly one per turn:
  list_files(prefix="", max_results=400)          -> list[str]  paths inside the repo
  read_file(path, start_line=1, end_line=null)     -> str        source with line numbers
  read_manifest(path)                              -> str        first 800 lines of a manifest
  search(pattern, paths=null, max_results=40)      -> list[str]  regex search across repo
  find_symbol(name)                                -> list[str]  definition sites
  find_references(name)                            -> list[str]  all usage sites
  git_show(path, revision=null)                    -> str        file at a past commit
  git_log(path, limit=10)                          -> list[str]  recent commits for a path
  get_evidence(path, start_line, end_line, reason, symbol=null)
                                                   -> EvidenceRef  creates a citable ID
    ** Call get_evidence for every line range you want to cite. Use the returned .id in evidence arrays. **

Tool call format (one JSON object, nothing else on your turn):
  {"kind":"tool","request":{"tool":"<name>","arguments":{"arg1":val1,...}}}

Final answer format (one JSON object — output ONLY when you have enough cited evidence):
  {"kind":"final","result":<MapperResult JSON>}

If you cannot establish enough evidence:
  {"kind":"inconclusive","reason":"<why>"}
"""

_RESULT_SPEC = """\
MapperResult fields (omit any list you found nothing for; "ev" = list of get_evidence ids):
  role: str                summary: str
  components:       [{id,name,kind,responsibility,evidence:ev,uncertainty:[str]}]
  actors:           [{id,name,kind,privilege,evidence:ev}]
  assets:           [{id,name,sensitivity,storage_or_location,evidence:ev}]
  entry_points:     [{id,name,kind,component_ids:[id],attacker_inputs:[str],evidence:ev}]
  trust_boundaries: [{id,name,from_domain,to_domain,controls:[id],evidence:ev}]
  controls:         [{id,name,kind,component_ids:[id],limitations:[str],evidence:ev}]
  uncertainties: [str]     disagreements: [str]
Use short slug ids (e.g. "webhook-listener"); they are renormalized afterwards.
No extra fields are permitted.
"""


def _agent_prompt(role: str, snapshot: dict[str, Any], inventory: dict[str, Any]) -> str:
    return f"""/no_think
You are the {role} mapper for a repository-understanding task.
Objective: {ROLE_OBJECTIVES[role]}

{_TOOL_INVENTORY}
Rules:
- Every non-trivial claim in your MapperResult must have at least one EvidenceRef id obtained via get_evidence.
- Distinguish source-code evidence from documentation assertions in the uncertainty field.
- Do NOT make vulnerability claims. Your job is understanding, not assessment.
- Navigate from the inventory's entry_point_candidates and manifests; read source files; then call get_evidence to anchor your claims before returning.

Snapshot: {json.dumps(snapshot, sort_keys=True)}
Inventory: {json.dumps(inventory, sort_keys=True)[:4000]}
{_RESULT_SPEC}"""


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


class SynthesisTooLarge(RuntimeError):
    """Raised when the synthesis prompt cannot fit the deployment context window."""


def run_synthesis(agent: DurableAgent, run_id: str, snapshot, evidence, mapper_results: list[MapperResult],
                  model: str) -> ProjectMap | None:
    """Ask SIE to assemble flow records from mapper artifacts, then validate links."""
    prompt = f"""/no_think
You are synthesizing a cited project map from five independent mapper outputs.

Rules:
- Reuse ONLY entity IDs and evidence IDs that appear in the mapper outputs below. Do NOT invent new ones.
- Merge duplicate entities by keeping the richer description; note disagreements.
- Create Flow records only where you can cite ordered steps, each with a component_id and evidence.
- List uncited or missing-link claims as uncertainties instead of guessing.
- The snapshot_id field must be exactly: {snapshot_id(snapshot)}

Return exactly one JSON object (no prose before or after):
  {{"kind":"final","result":<ProjectMap JSON>}}
Or if too many citations are missing:
  {{"kind":"inconclusive","reason":"<why>"}}

ProjectMap schema: {json.dumps(ProjectMap.model_json_schema(), sort_keys=True)}

Evidence catalog: {json.dumps([item.model_dump(mode='json') for item in evidence], sort_keys=True)[:30000]}
Mapper outputs: {json.dumps([item.model_dump(mode='json') for item in mapper_results], sort_keys=True)[:40000]}"""
    needed = estimated_tokens(prompt) + GENERATION_RESERVE_TOKENS
    if needed > CONTEXT_BUDGET_TOKENS:
        raise SynthesisTooLarge(
            f"synthesis prompt needs ~{needed} tokens but the deployment ceiling is "
            f"{CONTEXT_BUDGET_TOKENS}; SIE synthesis was not attempted")
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

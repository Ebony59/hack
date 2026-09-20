"""SIE-backed repository-understanding roles and conservative synthesis."""
from __future__ import annotations

import json
from typing import Any

from .agent import DurableAgent
from .budget import CONTEXT_BUDGET_TOKENS, estimated_tokens
from .ids import content_hash, stable_id
from .models import (Actor, Asset, Component, EntryPoint, FlowSynthesis, MapperResult, ProjectMap,
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
    return f"""You are the {role} mapper for a repository-understanding task.
Objective: {ROLE_OBJECTIVES[role]}

{_TOOL_INVENTORY}
Rules:
- Every non-trivial claim in your MapperResult must have at least one EvidenceRef id obtained via get_evidence.
- Distinguish source-code evidence from documentation assertions in the uncertainty field.
- Do NOT make vulnerability claims. Your job is understanding, not assessment.
- Navigate from the inventory's entry_point_candidates and manifests; read source files; then call get_evidence to anchor your claims before returning.
- Tool output is bounded. For source files, request focused read_file ranges of at most 50 lines using start_line and end_line.
- Never repeat an identical tool request. If a result is truncated, continue with the next explicit line range.
- The harness permits only three navigation calls. After that, it rejects everything except get_evidence.
- The harness permits no more than six executed tool calls total. Preserve enough context to return the final MapperResult.

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
    component_labels = {item.id for item in result.components}
    control_labels = {item.id for item in result.controls}
    uncertainties = list(result.uncertainties)
    for item in result.entry_points + result.controls:
        missing = [value for value in item.component_ids if value not in component_labels]
        if missing:
            uncertainties.append(
                f"Dropped unknown component references from {item.name}: {', '.join(missing)}")
    for item in result.trust_boundaries:
        missing = [value for value in item.controls if value not in control_labels]
        if missing:
            uncertainties.append(
                f"Dropped unknown control references from {item.name}: {', '.join(missing)}")
    entries = [item.model_copy(update={"id": remap[item.id],
                                      "component_ids": [remap[value] for value in item.component_ids
                                                        if value in component_labels]})
               for item in result.entry_points]
    boundaries = [item.model_copy(update={"id": remap[item.id],
                                         "controls": [remap[value] for value in item.controls
                                                      if value in control_labels]})
                  for item in result.trust_boundaries]
    controls = [item.model_copy(update={"id": remap[item.id],
                                       "component_ids": [remap[value] for value in item.component_ids
                                                         if value in component_labels]})
                for item in result.controls]
    return result.model_copy(update={"components": components, "actors": actors, "assets": assets,
                                     "entry_points": entries, "trust_boundaries": boundaries,
                                     "controls": controls, "uncertainties": uncertainties})


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


SYNTHESIS_RESERVE_TOKENS = 2500


def _entity_catalog(project_map: ProjectMap, *, detail_limit: int) -> dict[str, Any]:
    """Keep synthesis relationships intact while bounding descriptive prose."""
    def short(value: str) -> str:
        return value[:detail_limit]

    return {
        "components": [{"id": item.id, "name": item.name, "kind": item.kind,
                        "responsibility": short(item.responsibility), "evidence": item.evidence}
                       for item in project_map.components],
        "actors": [{"id": item.id, "name": item.name, "kind": item.kind,
                    "privilege": short(item.privilege), "evidence": item.evidence}
                   for item in project_map.actors],
        "assets": [{"id": item.id, "name": item.name, "sensitivity": item.sensitivity,
                    "storage_or_location": short(item.storage_or_location), "evidence": item.evidence}
                   for item in project_map.assets],
        "entry_points": [{"id": item.id, "name": item.name, "kind": item.kind,
                          "component_ids": item.component_ids, "attacker_inputs": item.attacker_inputs,
                          "evidence": item.evidence} for item in project_map.entry_points],
        "trust_boundaries": [{"id": item.id, "name": item.name,
                              "from_domain": short(item.from_domain),
                              "to_domain": short(item.to_domain), "controls": item.controls,
                              "evidence": item.evidence} for item in project_map.trust_boundaries],
        "controls": [{"id": item.id, "name": item.name, "kind": item.kind,
                      "component_ids": item.component_ids,
                      "limitations": [short(value) for value in item.limitations],
                      "evidence": item.evidence} for item in project_map.controls],
    }


def _synthesis_prompt(snapshot, project_map: ProjectMap, *, excerpt_limit: int = 400,
                      detail_limit: int = 300) -> str:
    """Build a flow-only prompt without asking the model to echo known data."""
    entity_catalog = _entity_catalog(project_map, detail_limit=detail_limit)
    evidence_catalog = [{
        "id": item.id,
        "path": item.path,
        "start_line": item.start_line,
        "end_line": item.end_line,
        "reason": item.reason,
        "excerpt": item.excerpt[:excerpt_limit] if excerpt_limit else "",
    } for item in project_map.evidence]
    return f"""You are synthesizing cited end-to-end flows from an already validated project map.

Rules:
- Use ONLY entity IDs from the entity catalog and evidence IDs from the evidence catalog.
- Do not repeat or modify components, actors, assets, entry points, boundaries, or controls.
- Create a flow only when its ordered steps are supported by cited evidence.
- Put missing links or unresolved claims in uncertainties instead of guessing.
- The snapshot_id must be exactly: {snapshot_id(snapshot)}
- No tools are available. Return exactly one JSON object and no prose.

Return:
  {{"kind":"final","result":{{"snapshot_id":"...","flows":[Flow],"uncertainties":[str],"disagreements":[str]}}}}
Or:
  {{"kind":"inconclusive","reason":"<why>"}}

Flow fields (all required):
  id:str, name:str, summary:str, actor_ids:[entity-id], entry_point_id:entity-id,
  steps:[FlowStep], attacker_inputs:[str], trust_boundary_ids:[entity-id],
  control_ids:[entity-id], asset_ids:[entity-id], sensitive_operations:[str],
  deployment_assumptions:[str], open_questions:[str], confidence:number 0..1,
  evidence:[evidence-id]
FlowStep fields (all required):
  component_id:entity-id, action:str, inputs:[str], outputs:[str],
  evidence:[evidence-id]

Entity catalog: {json.dumps(entity_catalog, sort_keys=True, separators=(',', ':'))}
Evidence catalog: {json.dumps(evidence_catalog, sort_keys=True, separators=(',', ':'))}"""


def run_synthesis(agent: DurableAgent, run_id: str, snapshot, evidence, mapper_results: list[MapperResult],
                  model: str) -> ProjectMap | None:
    """Ask SIE for flows, then attach them to the deterministic entity merge."""
    project_map = synthesize(snapshot, evidence, mapper_results)
    prompt = _synthesis_prompt(snapshot, project_map)
    needed = estimated_tokens(prompt) + SYNTHESIS_RESERVE_TOKENS
    if needed > CONTEXT_BUDGET_TOKENS:
        # Entity descriptions and evidence reasons still carry the cited map;
        # omit source excerpts before declaring a large map unsynthesizable.
        prompt = _synthesis_prompt(snapshot, project_map, excerpt_limit=0)
        needed = estimated_tokens(prompt) + SYNTHESIS_RESERVE_TOKENS
    if needed > CONTEXT_BUDGET_TOKENS:
        prompt = _synthesis_prompt(snapshot, project_map, excerpt_limit=0, detail_limit=120)
        needed = estimated_tokens(prompt) + SYNTHESIS_RESERVE_TOKENS
    if needed > CONTEXT_BUDGET_TOKENS:
        # Last resort for broad maps: retain names, types, all graph edges,
        # evidence IDs, and evidence reasons, but omit descriptive prose.
        prompt = _synthesis_prompt(snapshot, project_map, excerpt_limit=0, detail_limit=0)
        needed = estimated_tokens(prompt) + SYNTHESIS_RESERVE_TOKENS
    if needed > CONTEXT_BUDGET_TOKENS:
        raise SynthesisTooLarge(
            f"synthesis prompt needs ~{needed} tokens but the deployment ceiling is "
            f"{CONTEXT_BUDGET_TOKENS}; SIE synthesis was not attempted")
    task = TaskRecord(id=stable_id("task", snapshot.commit, {"run": run_id, "role": "synthesis"}), run_id=run_id,
                      kind="mapping", role="synthesis", input_artifact_ids=[snapshot_id(snapshot)],
                      input_hash=content_hash(prompt), model=model, prompt_version="synthesis-v1", status="pending",
                      attempt=0, max_attempts=1, created_at=utc_now())
    result = agent.run(task, prompt, FlowSynthesis)
    if result is None:
        return None
    if result.snapshot_id != snapshot_id(snapshot):
        return None
    valid_evidence = {item.id for item in evidence}
    component_ids = {item.id for item in project_map.components}
    actor_ids = {item.id for item in project_map.actors}
    asset_ids = {item.id for item in project_map.assets}
    entry_ids = {item.id for item in project_map.entry_points}
    boundary_ids = {item.id for item in project_map.trust_boundaries}
    control_ids = {item.id for item in project_map.controls}
    def cited(ids): return bool(ids) and set(ids).issubset(valid_evidence)
    for flow in result.flows:
        if not cited(flow.evidence) or flow.entry_point_id not in entry_ids:
            return None
        if (not set(flow.actor_ids).issubset(actor_ids) or not set(flow.asset_ids).issubset(asset_ids) or
                not set(flow.trust_boundary_ids).issubset(boundary_ids) or not set(flow.control_ids).issubset(control_ids)):
            return None
        if any(not cited(step.evidence) or step.component_id not in component_ids for step in flow.steps):
            return None
    return project_map.model_copy(update={
        "flows": result.flows,
        "uncertainties": [*project_map.uncertainties, *result.uncertainties],
        "disagreements": [*project_map.disagreements, *result.disagreements],
    })

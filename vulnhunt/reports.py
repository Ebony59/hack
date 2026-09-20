"""Checkpoint-A renderer: no SIE call is made while rendering."""
from __future__ import annotations

from .hypotheses import rank_hypotheses
from .models import CheckpointBReview, Hypothesis, Invariant, ProjectMap, RepositorySnapshot
from .store import RunStore


def render_checkpoint_a(store: RunStore, snapshot: RepositorySnapshot, project_map: ProjectMap,
                        failed_tasks: list[str]) -> tuple[str, str]:
    def names(items): return ", ".join(item.name for item in items) or "(none evidenced)"
    lines = [f"# Vulnhunt checkpoint A — {snapshot.target_id}", "", "## Snapshot", "",
             f"- Commit: `{snapshot.commit}`", f"- Branch: `{snapshot.branch or 'detached'}`",
             f"- Dirty worktree: `{snapshot.dirty}`", f"- Languages: {', '.join(snapshot.languages)}", "",
             "## Architecture map", "", f"- Components: {names(project_map.components)}",
             f"- Actors: {names(project_map.actors)}", f"- Assets: {names(project_map.assets)}",
             f"- Entry points: {names(project_map.entry_points)}", f"- Trust boundaries: {names(project_map.trust_boundaries)}",
             f"- Security controls: {names(project_map.controls)}", "", "## Proposed flows", ""]
    if project_map.flows:
        for flow in project_map.flows:
            lines.extend([f"### {flow.name}", "", flow.summary, ""])
    else:
        lines.extend(["No end-to-end flows were synthesized from sufficiently cited mapper output.",
                      "This is an evidence gap to resolve during review or a narrow mapping repair task.", ""])
    lines.extend(["## Uncertainties and disagreements", ""])
    lines.extend([f"- {value}" for value in project_map.uncertainties + project_map.disagreements] or ["- None recorded."])
    lines.extend(["", "## Mapping failures", ""])
    lines.extend([f"- {value}" for value in failed_tasks] or ["- None."])
    lines.extend(["", "## Next step", "", "Review `checkpoint-a.yaml`, correct the map as needed, and set `approved: true` before hypothesis generation."])
    store.atomic_write(store.run_dir / "reviews/checkpoint-a.md", "\n".join(lines) + "\n")
    review = store.write_yaml_if_absent("reviews/checkpoint-a.yaml", {"schema_version": 1, "approved": False,
        "reviewer_notes": "", "selected_flow_ids": [], "rejected_flow_ids": [], "flow_edits": [], "additional_questions": []})
    return str(store.run_dir / "reviews/checkpoint-a.md"), str(review)


def render_checkpoint_b(store: RunStore, snapshot: RepositorySnapshot, project_map: ProjectMap,
                        invariants: list[Invariant], hypotheses: list[Hypothesis],
                        failed_tasks: list[str]) -> tuple[str, str]:
    review_path = store.run_dir / "reviews/checkpoint-b.yaml"
    if review_path.exists():
        import yaml
        review = CheckpointBReview.model_validate(yaml.safe_load(review_path.read_text()) or {})
        overrides = review.priority_overrides
    else:
        overrides = {}
    flow_names = {flow.id: flow.name for flow in project_map.flows}
    invariant_by_id = {item.id: item for item in invariants}
    lines = [f"# Vulnhunt checkpoint B — {snapshot.target_id}", "", "## Scope", "",
             f"- Commit: `{snapshot.commit}`", f"- Reviewed invariants: {len(invariants)}",
             f"- Candidate hypotheses: {len(hypotheses)}", "", "## Ranked hypotheses", ""]
    for item in rank_hypotheses(hypotheses, overrides):
        invariant = invariant_by_id.get(item.invariant_id)
        lines.extend([f"### {item.title}", "", f"- ID: `{item.id}`", f"- Priority: `{item.priority_score:.2f}`",
                      f"- Flow: {flow_names.get(item.flow_id, item.flow_id)}", f"- Invariant: {invariant.statement if invariant else item.invariant_id}",
                      f"- Assumptions: {', '.join(invariant.assumptions) if invariant and invariant.assumptions else 'none recorded'}",
                      f"- Attacker capability: {item.attacker_capability}", f"- Suspected path: {item.suspected_path}",
                      f"- Expected impact: {item.expected_impact}", f"- Supporting evidence: {', '.join(item.evidence)}",
                      f"- Contrary evidence: {', '.join(item.contrary_evidence)} — {item.contrary_reasoning}",
                      f"- Decisive test: {item.decisive_test}", f"- Reproduction cost / safety risk: {item.reproduction_cost}/5, {item.safety_risk}/5",
                      f"- Ranking inputs: impact {item.impact}/5; reachability {item.reachability}/5; evidence strength {item.evidence_strength}/5; novelty {item.novelty}/5",
                      f"- Safety concerns: {', '.join(item.safety_concerns) or 'none recorded'}", ""])
    if not hypotheses:
        lines.extend(["No fully cited hypotheses were produced. Review failed or inconclusive tasks before proceeding.", ""])
    lines.extend(["## Invariants", ""])
    for item in invariants:
        lines.extend([f"- `{item.id}`: {item.statement} (flow `{item.flow_id}`; evidence {', '.join(item.evidence)})"])
    lines.extend(["", "## Mapping gaps", ""])
    lines.extend([f"- {value}" for value in project_map.uncertainties + project_map.disagreements] or ["- None recorded."])
    lines.extend(["", "## Task failures", ""])
    lines.extend([f"- {value}" for value in failed_tasks] or ["- None."])
    lines.extend(["", "## Next step", "", "Review `checkpoint-b.yaml`, choose a small investigation portfolio, and set `approved: true`. Investigation remains disabled until the next stage is implemented."])
    store.atomic_write(store.run_dir / "reviews/checkpoint-b.md", "\n".join(lines) + "\n")
    review = store.write_yaml_if_absent("reviews/checkpoint-b.yaml", {"schema_version": 1, "approved": False,
        "reviewer_notes": "", "selected_hypothesis_ids": [], "rejected_hypothesis_ids": [], "priority_overrides": {}})
    return str(store.run_dir / "reviews/checkpoint-b.md"), str(review)

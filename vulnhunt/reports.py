"""Checkpoint-A renderer: no SIE call is made while rendering."""
from __future__ import annotations

from .models import ProjectMap, RepositorySnapshot
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

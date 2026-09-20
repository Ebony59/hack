"""Staged workflow-first CLI. Mapping deliberately stops at checkpoint A."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .agent import DurableAgent
from .config import load_config
from .hypotheses import parse_checkpoint_a, parse_checkpoint_b, run_hypothesis_stage
from .mapping import SynthesisTooLarge, run_mappers, run_synthesis, synthesize
from .models import EvidenceRef, Hypothesis, Invariant, ProjectMap, RepositorySnapshot
from .preflight import REQUIRED_FOR_MAPPING, run_preflight
from .reports import render_checkpoint_a, render_checkpoint_b
from .sie_client import SIEClient
from .snapshot import collect_snapshot
from .store import RunStore
from .tools import AnalysisTools
from .inventory import build_inventory


def _targets_file() -> str:
    return str(Path(__file__).with_name("targets.yaml"))


def _target(args):
    cfg = load_config(args.targets_file, repos_root=args.repos_root)
    if not args.target:
        raise ValueError("--target is required for staged commands")
    return cfg.target(args.target)


def _client(args) -> SIEClient:
    # `offline` is intentionally not exposed by real workflow commands.
    return SIEClient(base_url=args.sie_url, offline=False)


def _run_dir(target, snapshot, runs_root: str) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(runs_root) / target.name / f"{target.name}-{snapshot.commit[:12]}-{timestamp}"


def _failed_tasks(store: RunStore) -> list[str]:
    failed = []
    for path in sorted((store.run_dir / "tasks").glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if value["status"] in {"failed", "inconclusive"}:
            failed.append(f"{value['role']}: {value['status']} — {value.get('error_message') or 'no detail'}")
    return failed


def command_preflight(args) -> int:
    target = _target(args)
    if not Path(target.path).is_dir():
        print(f"configuration failure: target does not exist: {target.path}", file=sys.stderr)
        return 2
    result = run_preflight(_client(args))
    for check in result.checks:
        print(f"{'ok' if check.ok else 'FAIL'} {check.capability}: {check.detail}")
    return 0 if result.ok else 1


def command_map(args) -> int:
    target = _target(args)
    config_material = Path(args.targets_file).read_text(encoding="utf-8")
    try:
        snapshot = collect_snapshot(target, config_material)
    except ValueError as exc:
        print(f"snapshot failure: {exc}", file=sys.stderr)
        return 2
    client = _client(args)
    preflight = run_preflight(client)
    if not preflight.ok:
        print("SIE preflight failed; no mapping was attempted.", file=sys.stderr)
        for check in preflight.checks:
            print(f"{'ok' if check.ok else 'FAIL'} {check.capability}: {check.detail}", file=sys.stderr)
        return 1
    store = RunStore(_run_dir(target, snapshot, args.runs_root))
    run_id = store.run_dir.name
    store.write_json("run.json", {"schema_version": 1, "run_id": run_id, "target": target.name,
                                   "status": "mapping", "watermark": "SIE-backed mapping", "snapshot_commit": snapshot.commit})
    store.write_json("snapshot.json", snapshot)
    tools = AnalysisTools(snapshot.repo_path, snapshot.commit)
    inventory = build_inventory(target, snapshot, tools)
    store.write_json("inventory.json", inventory)
    store.write_json("artifacts/preflight.json", preflight)
    agent = DurableAgent(client, tools, store)
    results = run_mappers(agent, run_id, snapshot, inventory, client.models["generate"])
    store.write_json("artifacts/mapper-results.json", results)
    evidence = list(tools.evidence.values())
    for item in evidence:
        store.write_json(f"evidence/{item.id}.json", item)
    try:
        project_map = run_synthesis(agent, run_id, snapshot, evidence, results, client.models["generate"])
        synthesis_note = None if project_map else "SIE synthesis failed or produced invalid citations."
    except SynthesisTooLarge as exc:
        project_map, synthesis_note = None, str(exc)
    synthesis_incomplete = project_map is None
    if project_map is None:
        project_map = synthesize(snapshot, evidence, results)
        project_map.uncertainties.append(
            f"{synthesis_note} Rendered the deterministic mapper merge instead; "
            "flows were not generated and must be added during checkpoint-A review.")
    store.write_json("artifacts/project-map.json", project_map)
    store.write_json("artifacts/flows.json", project_map.flows)
    failed = _failed_tasks(store)
    markdown, review = render_checkpoint_a(store, snapshot, project_map, failed)
    incomplete = bool(failed) or synthesis_incomplete
    store.write_json("run.json", {"schema_version": 1, "run_id": run_id, "target": target.name,
                                   "status": "mapping_incomplete" if incomplete else "awaiting_checkpoint_a_review",
                                   "watermark": "SIE-backed mapping",
                                   "snapshot_commit": snapshot.commit})
    print(f"Checkpoint A created: {markdown}\nEdit and approve: {review}\nNext: python -m vulnhunt.cli hypothesize --run {store.run_dir}")
    if incomplete:
        print("Mapping is incomplete; review failures before approval.", file=sys.stderr)
        return 1
    return 0


def _load_run(run: str) -> tuple[RunStore, RepositorySnapshot, ProjectMap]:
    store = RunStore(run)
    snapshot = RepositorySnapshot.model_validate(store.read_json("snapshot.json"))
    project_map = ProjectMap.model_validate(store.read_json("artifacts/project-map.json"))
    return store, snapshot, project_map


def _load_evidence(store: RunStore) -> list[EvidenceRef]:
    return [EvidenceRef.model_validate(json.loads(path.read_text(encoding="utf-8")))
            for path in sorted((store.run_dir / "evidence").glob("*.json"))]


def _load_stage_five(store: RunStore) -> tuple[list[Invariant], list[Hypothesis]]:
    invariants = [Invariant.model_validate(item) for item in store.read_json("artifacts/invariants.json")]
    hypotheses = [Hypothesis.model_validate(item) for item in store.read_json("artifacts/hypotheses.json")]
    return invariants, hypotheses


def _current_commit(snapshot: RepositorySnapshot) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=snapshot.repo_path, text=True,
                          capture_output=True, check=False).stdout.strip()


def _archive_checkpoint_b(store: RunStore) -> Path:
    """Preserve a checkpoint-B attempt before an explicitly requested retry."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = store.run_dir / "attempts" / f"checkpoint-b-{timestamp}"
    archive.mkdir(parents=True, exist_ok=False)
    moved_task_ids: list[str] = []
    for path in (store.run_dir / "tasks").glob("*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if record.get("kind") == "hypothesis":
            moved_task_ids.append(path.stem)
            destination = archive / "tasks" / path.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            path.replace(destination)
    for task_id in moved_task_ids:
        for relative in (f"transcripts/{task_id}.jsonl", f"artifacts/task-{task_id}.json"):
            source = store.run_dir / relative
            if source.exists():
                destination = archive / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source.replace(destination)
    for relative in ("artifacts/invariants.json", "artifacts/hypotheses.json",
                     "reviews/checkpoint-b.md", "reviews/checkpoint-b.yaml"):
        source = store.run_dir / relative
        if source.exists():
            destination = archive / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            source.replace(destination)
    return archive


def command_status(args) -> int:
    try:
        store, snapshot, project_map = _load_run(args.run)
    except (OSError, ValueError, KeyError) as exc:
        print(f"invalid run: {exc}", file=sys.stderr)
        return 2
    current = _current_commit(snapshot)
    counts = {}
    for path in (store.run_dir / "tasks").glob("*.json"):
        status = json.loads(path.read_text())["status"]
        counts[status] = counts.get(status, 0) + 1
    review = yaml.safe_load((store.run_dir / "reviews/checkpoint-a.yaml").read_text()) or {}
    checkpoint_a_approved = review.get("approved") is True
    checkpoint_b_approved = False
    if (store.run_dir / "reviews/checkpoint-b.yaml").exists():
        checkpoint_b = yaml.safe_load((store.run_dir / "reviews/checkpoint-b.yaml").read_text()) or {}
        checkpoint_b_approved = checkpoint_b.get("approved") is True
    if checkpoint_b_approved:
        next_command = "investigate"
    elif (store.run_dir / "artifacts/hypotheses.json").exists():
        next_command = "edit and approve reviews/checkpoint-b.yaml"
    elif checkpoint_a_approved:
        next_command = "hypothesize"
    else:
        next_command = "edit and approve reviews/checkpoint-a.yaml"
    print(json.dumps({"run": str(store.run_dir), "task_counts": counts, "flows": len(project_map.flows),
                      "snapshot_matches": current == snapshot.commit, "checkpoint_a_approved": checkpoint_a_approved,
                      "checkpoint_b_approved": checkpoint_b_approved,
                      "next": next_command}, indent=2))
    return 0 if current == snapshot.commit else 1


def command_render(args) -> int:
    try:
        store, snapshot, project_map = _load_run(args.run)
    except (OSError, ValueError, KeyError) as exc:
        print(f"invalid run: {exc}", file=sys.stderr)
        return 2
    markdown, review = render_checkpoint_a(store, snapshot, project_map, _failed_tasks(store))
    rendered = [f"Rendered {markdown}; preserved {review}"]
    if (store.run_dir / "artifacts/invariants.json").exists() and (store.run_dir / "artifacts/hypotheses.json").exists():
        invariants, hypotheses = _load_stage_five(store)
        markdown, review = render_checkpoint_b(store, snapshot, project_map, invariants, hypotheses, _failed_tasks(store))
        rendered.append(f"Rendered {markdown}; preserved {review}")
    print("\n".join(rendered))
    return 0


def command_hypothesize(args) -> int:
    try:
        store, snapshot, project_map = _load_run(args.run)
        review = yaml.safe_load((store.run_dir / "reviews/checkpoint-a.yaml").read_text(encoding="utf-8")) or {}
        approved = parse_checkpoint_a(review, project_map)
    except (OSError, ValueError, KeyError) as exc:
        print(f"checkpoint A is invalid; refusing hypothesis generation: {exc}", file=sys.stderr)
        return 2
    retrying = (store.run_dir / "artifacts/hypotheses.json").exists()
    if retrying:
        if not args.force:
            print("Checkpoint B already exists; render or review it instead of regenerating hypotheses. "
                  "Use --force to archive it and start a new checkpoint-B attempt.", file=sys.stderr)
            return 2
    current = _current_commit(snapshot)
    if current != snapshot.commit:
        print("snapshot commit no longer matches the target checkout; refusing hypothesis generation. "
              "Create a new mapped run for the current commit.", file=sys.stderr)
        return 2
    if retrying:
        archive = _archive_checkpoint_b(store)
        print(f"Archived previous checkpoint-B attempt: {archive}")
    tools = AnalysisTools(snapshot.repo_path, snapshot.commit)
    tools.evidence = {item.id: item for item in _load_evidence(store)}
    selected = {flow.id: flow for flow in project_map.flows}
    client = _client(args)
    preflight = run_preflight(client)
    if not preflight.ok:
        print("SIE preflight failed; no hypotheses were generated.", file=sys.stderr)
        for check in preflight.checks:
            print(f"{'ok' if check.ok else 'FAIL'} {check.capability}: {check.detail}", file=sys.stderr)
        return 1
    agent = DurableAgent(client, tools, store)
    invariants, hypotheses = run_hypothesis_stage(agent, store.run_dir.name, snapshot, project_map,
                                                   [selected[item] for item in approved.selected_flow_ids],
                                                   client.models["generate"])
    store.write_json("artifacts/invariants.json", invariants)
    store.write_json("artifacts/hypotheses.json", hypotheses)
    for item in tools.evidence.values():
        store.write_json(f"evidence/{item.id}.json", item)
    failed = _failed_tasks(store)
    markdown, review_path = render_checkpoint_b(store, snapshot, project_map, invariants, hypotheses, failed)
    incomplete = bool(failed) or not invariants or not hypotheses
    store.write_json("run.json", {"schema_version": 1, "run_id": store.run_dir.name, "target": snapshot.target_id,
                                   "status": "hypothesis_incomplete" if incomplete else "awaiting_checkpoint_b_review",
                                   "watermark": "SIE-backed hypothesis generation", "snapshot_commit": snapshot.commit})
    print(f"Checkpoint B created: {markdown}\nEdit and approve: {review_path}\nNext: python -m vulnhunt.cli investigate --run {store.run_dir}")
    if incomplete:
        print("Hypothesis generation is incomplete; review failures before checkpoint B approval.", file=sys.stderr)
        return 1
    return 0


def command_investigate(args) -> int:
    try:
        store, _, _ = _load_run(args.run)
        _, hypotheses = _load_stage_five(store)
        review = yaml.safe_load((store.run_dir / "reviews/checkpoint-b.yaml").read_text(encoding="utf-8")) or {}
        parse_checkpoint_b(review, hypotheses)
    except (OSError, ValueError, KeyError) as exc:
        print(f"checkpoint B is invalid; refusing investigation: {exc}", file=sys.stderr)
        return 2
    print("Checkpoint B is approved. Investigation begins in stage 6 and is not implemented yet.", file=sys.stderr)
    return 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="vulnhunt staged workflow-first scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "map"):
        item = sub.add_parser(name)
        item.add_argument("--target", required=True)
        item.add_argument("--targets-file", default=_targets_file())
        item.add_argument("--repos-root", default=None)
        item.add_argument("--sie-url", default=None)
        if name == "map": item.add_argument("--runs-root", default="runs")
    for name in ("status", "render", "hypothesize", "investigate"):
        item = sub.add_parser(name)
        item.add_argument("--run", required=True)
        if name == "hypothesize":
            item.add_argument("--sie-url", default=None)
            item.add_argument("--force", action="store_true",
                              help="archive an existing checkpoint-B attempt before retrying")
    args = parser.parse_args(argv)
    return {"preflight": command_preflight, "map": command_map, "status": command_status,
            "render": command_render, "hypothesize": command_hypothesize,
            "investigate": command_investigate}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())

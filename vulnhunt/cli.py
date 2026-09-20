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
from .mapping import SynthesisTooLarge, run_mappers, run_synthesis, synthesize
from .models import EvidenceRef, MapperResult, ProjectMap, RepositorySnapshot
from .preflight import REQUIRED_FOR_MAPPING, run_preflight
from .reports import render_checkpoint_a
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


def command_synthesize(args) -> int:
    """Resume only synthesis for a run whose mapper artifacts are complete."""
    store = RunStore(args.run)
    try:
        snapshot = RepositorySnapshot.model_validate(store.read_json("snapshot.json"))
        results = [MapperResult.model_validate(value)
                   for value in store.read_json("artifacts/mapper-results.json")]
        evidence = [EvidenceRef.model_validate(json.loads(path.read_text(encoding="utf-8")))
                    for path in sorted((store.run_dir / "evidence").glob("*.json"))]
        run_record = store.read_json("run.json")
    except (OSError, ValueError, KeyError) as exc:
        print(f"invalid run: {exc}", file=sys.stderr)
        return 2
    if not results:
        print("run has no successful mapper results; synthesis cannot resume.", file=sys.stderr)
        return 2
    client = _client(args)
    preflight = client.preflight({"generate"})
    if not preflight.ok:
        print("SIE generation preflight failed; synthesis was not attempted.", file=sys.stderr)
        for check in preflight.checks:
            print(f"{'ok' if check.ok else 'FAIL'} {check.capability}: {check.detail}", file=sys.stderr)
        return 1
    tools = AnalysisTools(snapshot.repo_path, snapshot.commit)
    tools.evidence.update({item.id: item for item in evidence})
    agent = DurableAgent(client, tools, store)
    try:
        project_map = run_synthesis(agent, run_record["run_id"], snapshot, evidence, results,
                                    client.models["generate"])
    except SynthesisTooLarge as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if project_map is None:
        print("SIE synthesis failed or produced invalid citations.", file=sys.stderr)
        return 1
    store.write_json("artifacts/project-map.json", project_map)
    store.write_json("artifacts/flows.json", project_map.flows)
    failed = _failed_tasks(store)
    markdown, review = render_checkpoint_a(store, snapshot, project_map, failed)
    store.write_json("run.json", {
        "schema_version": 1,
        "run_id": run_record["run_id"],
        "target": run_record["target"],
        "status": "mapping_incomplete" if failed else "awaiting_checkpoint_a_review",
        "watermark": run_record.get("watermark", "SIE-backed mapping"),
        "snapshot_commit": snapshot.commit,
    })
    print(f"Checkpoint A updated: {markdown}\nReview and approve: {review}")
    return 1 if failed else 0


def command_status(args) -> int:
    try:
        store, snapshot, project_map = _load_run(args.run)
    except (OSError, ValueError, KeyError) as exc:
        print(f"invalid run: {exc}", file=sys.stderr)
        return 2
    current = subprocess.run(["git", "rev-parse", "HEAD"], cwd=snapshot.repo_path, text=True,
                             capture_output=True, check=False).stdout.strip()
    counts = {}
    for path in (store.run_dir / "tasks").glob("*.json"):
        status = json.loads(path.read_text())["status"]
        counts[status] = counts.get(status, 0) + 1
    review = yaml.safe_load((store.run_dir / "reviews/checkpoint-a.yaml").read_text()) or {}
    next_command = "hypothesize" if review.get("approved") else "edit and approve reviews/checkpoint-a.yaml"
    print(json.dumps({"run": str(store.run_dir), "task_counts": counts, "flows": len(project_map.flows),
                      "snapshot_matches": current == snapshot.commit, "checkpoint_a_approved": bool(review.get("approved")),
                      "next": next_command}, indent=2))
    return 0 if current == snapshot.commit else 1


def command_render(args) -> int:
    try:
        store, snapshot, project_map = _load_run(args.run)
    except (OSError, ValueError, KeyError) as exc:
        print(f"invalid run: {exc}", file=sys.stderr)
        return 2
    markdown, review = render_checkpoint_a(store, snapshot, project_map, _failed_tasks(store))
    print(f"Rendered {markdown}; preserved {review}")
    return 0


def command_hypothesize(args) -> int:
    review_path = Path(args.run) / "reviews/checkpoint-a.yaml"
    try:
        review = yaml.safe_load(review_path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        print(f"checkpoint A unavailable: {exc}", file=sys.stderr)
        return 2
    if review.get("approved") is not True:
        print("checkpoint A is not approved; refusing hypothesis generation.", file=sys.stderr)
        return 2
    print("Checkpoint A is approved. Hypothesis generation belongs to stage 5 and is not implemented yet.")
    return 2


def command_investigate(args) -> int:
    print("Investigation belongs to stages 5–7 and is disabled until checkpoint B exists.", file=sys.stderr)
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
    for name in ("status", "render", "hypothesize", "investigate", "synthesize"):
        item = sub.add_parser(name)
        item.add_argument("--run", required=True)
        if name == "synthesize": item.add_argument("--sie-url", default=None)
    args = parser.parse_args(argv)
    return {"preflight": command_preflight, "map": command_map, "synthesize": command_synthesize,
            "status": command_status,
            "render": command_render, "hypothesize": command_hypothesize,
            "investigate": command_investigate}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())

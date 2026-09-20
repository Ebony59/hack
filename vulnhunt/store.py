"""Inspectable, atomic filesystem persistence for immutable analysis runs."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .ids import canonical_json, content_hash


def _json_compatible(value: Any) -> Any:
    """Recursively convert Pydantic models nested in artifact containers."""
    if hasattr(value, "model_dump"):
        return _json_compatible(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {key: _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return value


class RunStore:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        for name in ("tasks", "transcripts", "artifacts", "evidence", "reviews", "reports"):
            (self.run_dir / name).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def atomic_write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def write_json(self, relative: str, value: Any) -> Path:
        path = self.run_dir / relative
        payload = _json_compatible(value)
        self.atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return path

    def read_json(self, relative: str) -> Any:
        with (self.run_dir / relative).open(encoding="utf-8") as fh:
            return json.load(fh)

    def write_yaml_if_absent(self, relative: str, value: Any) -> Path:
        path = self.run_dir / relative
        if not path.exists():
            self.atomic_write(path, yaml.safe_dump(value, sort_keys=False))
        return path

    def append_event(self, value: Any) -> Path:
        path = self.run_dir / "events.jsonl"
        # append is intentionally one record at a time; task/artifact files remain atomic.
        with path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(value) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return path

    def append_transcript(self, task_id: str, value: Any) -> Path:
        path = self.run_dir / "transcripts" / f"{task_id}.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(value) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return path

    def artifact_hash(self, relative: str) -> str:
        return content_hash((self.run_dir / relative).read_text(encoding="utf-8"))

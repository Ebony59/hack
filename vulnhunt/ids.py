"""Stable, content-derived identities for durable run artifacts."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_id(kind: str, commit: str, identity: Any) -> str:
    """Return a short, deterministic ID whose meaning is independent of model output."""
    digest = hashlib.sha256(canonical_json({"kind": kind, "commit": commit,
                                            "identity": identity}).encode()).hexdigest()
    return f"{kind}-{digest[:20]}"


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

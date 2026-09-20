"""Thin client for a Superlinked SIE server (self-hosted, default :8080).

Implements the four primitives over the documented HTTP API:
    POST /v1/encode/:model     -> dense embeddings
    POST /v1/score/:model      -> rerank
    POST /v1/extract/:model    -> structured extraction
    POST /v1/generate/:model   -> text generation

If the server is unreachable and `offline=True` (or auto-detected), the client
falls back to deterministic local stand-ins so the whole pipeline still runs
end to end for development. Fallbacks are clearly marked and never fabricate a
"verified" vulnerability -- they only keep the plumbing testable.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence

import requests


# Default model choices. Override via env or constructor for stronger models.
# Model defaults. Browse the catalog at superlinked.com/models (or the console
# playground) and override any of these via env.
DEFAULT_MODELS = {
    "encode":   os.environ.get("SIE_ENCODE_MODEL",   "Qwen/Qwen3-Embedding-4B"),
    "score":    os.environ.get("SIE_SCORE_MODEL",    "BAAI/bge-reranker-v2-m3"),
    "extract":  os.environ.get("SIE_EXTRACT_MODEL",  "urchade/gliner_multi-v2.1"),
    # A code-capable instruct model is strongly preferred for the agent loop:
    "generate": os.environ.get("SIE_GENERATE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"),
}

# Cloud (managed) base URL; override with --sie-url or $SIE_BASE_URL / $SIE_URL.
CLOUD_BASE_URL = "https://api.superlinked.com"


class SIEClient:
    """Works against the managed cloud (api.superlinked.com, needs $SIE_API_KEY)
    or a local `sie-server` (http://localhost:8080, no key). For a local setup
    where generation runs as a separate MLX server, set $SIE_GENERATE_URL
    (e.g. http://localhost:8081); it defaults to the base URL otherwise.
    """
    def __init__(self, base_url: Optional[str] = None, offline: Optional[bool] = None,
                 timeout: float = 120.0, models: Optional[Dict[str, str]] = None,
                 api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SIE_API_KEY")
        env_url = os.environ.get("SIE_BASE_URL") or os.environ.get("SIE_URL")
        # Default to cloud when a key is present, else a local server.
        default_url = CLOUD_BASE_URL if self.api_key else "http://localhost:8080"
        self.base_url = (base_url or env_url or default_url).rstrip("/")
        self.generate_url = (os.environ.get("SIE_GENERATE_URL") or self.base_url).rstrip("/")
        self.timeout = timeout
        self.models = {**DEFAULT_MODELS, **(models or {})}
        self.session = requests.Session()
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        self.session.headers.update(headers)

        if offline is None:
            offline = not self._ping()
        self.offline = offline
        if self.offline:
            why = "no server reachable" + ("" if self.api_key else " and no $SIE_API_KEY set")
            print(f"[sie] running OFFLINE ({why} at {self.base_url}) "
                  f"-- using local fallbacks for encode/score/generate/extract")
        else:
            print(f"[sie] online at {self.base_url}"
                  + (" (authenticated)" if self.api_key else ""))

    # ----- health --------------------------------------------------------- #
    def _ping(self) -> bool:
        # Authenticated endpoint first when we have a key (cloud), else health.
        paths = ("/v1/models",) if self.api_key else ("/readyz", "/healthz", "/v1/models")
        for path in paths:
            try:
                r = self.session.get(self.base_url + path, timeout=8)
                if r.ok:
                    return True
            except requests.RequestException:
                continue
        return False

    def _post(self, path: str, body: dict, base: Optional[str] = None) -> dict:
        r = self.session.post((base or self.base_url) + path,
                              data=json.dumps(body), timeout=self.timeout)
        if r.status_code == 402:
            raise RuntimeError("SIE returned 402 INSUFFICIENT_CREDITS -- ask the "
                               "organizers to top up your key.")
        r.raise_for_status()
        return r.json()

    # ----- encode --------------------------------------------------------- #
    def encode(self, texts: Sequence[str], model: Optional[str] = None) -> List[List[float]]:
        """Return one dense vector per text."""
        if self.offline:
            return [_hash_embed(t) for t in texts]
        model = model or self.models["encode"]
        body = {"items": [{"id": str(i), "text": t} for i, t in enumerate(texts)],
                "params": {"output_types": ["dense"]}}
        out = self._post(f"/v1/encode/{model}", body)
        return [item["dense"]["values"] for item in out["items"]]

    # ----- score / rerank ------------------------------------------------- #
    def score(self, query: str, texts: Sequence[str], model: Optional[str] = None) -> List[float]:
        """Return a relevance score per text, aligned to input order."""
        if self.offline:
            qv = _hash_embed(query)
            return [_cos(qv, _hash_embed(t)) for t in texts]
        model = model or self.models["score"]
        body = {"query": {"text": query},
                "items": [{"id": str(i), "text": t} for i, t in enumerate(texts)]}
        out = self._post(f"/v1/score/{model}", body)
        scores = [0.0] * len(texts)
        for s in out["scores"]:
            scores[int(s["item_id"])] = float(s["score"])
        return scores

    # ----- generate ------------------------------------------------------- #
    def generate(self, prompt: str, max_new_tokens: int = 1024, temperature: float = 0.0,
                 stop: Optional[List[str]] = None, model: Optional[str] = None) -> str:
        if self.offline:
            return _offline_generate(prompt)
        model = model or self.models["generate"]
        body = {"prompt": prompt, "max_new_tokens": max_new_tokens,
                "temperature": temperature, "stream": False}
        if stop:
            body["stop"] = stop
        out = self._post(f"/v1/generate/{model}", body, base=self.generate_url)
        # SIE-native returns {"text": ...}; be tolerant of OpenAI-ish shapes too.
        if "text" in out:
            return out["text"]
        if out.get("choices"):
            ch = out["choices"][0]
            return ch.get("text") or ch.get("message", {}).get("content", "")
        return ""

    def generate_json(self, prompt: str, schema: dict, max_new_tokens: int = 1024) -> Optional[dict]:
        """Ask the model to emit JSON conforming to `schema`; parse leniently."""
        full = (prompt.rstrip()
                + "\n\nReturn ONLY a JSON object matching this schema (no prose):\n"
                + json.dumps(schema) + "\n")
        raw = self.generate(full, max_new_tokens=max_new_tokens, temperature=0.0)
        return _extract_json(raw)


# --------------------------------------------------------------------------- #
# Offline fallbacks (deterministic, dependency-free)
# --------------------------------------------------------------------------- #

_DIM = 256


def _hash_embed(text: str, dim: int = _DIM) -> List[float]:
    """A cheap deterministic bag-of-tokens embedding for offline dev."""
    vec = [0.0] * dim
    for tok in re.findall(r"[A-Za-z_]{2,}", text.lower()):
        h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
        vec[h % dim] += 1.0
    n = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / n for v in vec]


def _cos(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _offline_generate(prompt: str) -> str:
    """Very small heuristic stand-in for a served model, so the agent loop and
    JSON extraction path can be exercised without SIE. It is intentionally
    conservative: it proposes a low-confidence candidate, never a verified bug.
    """
    cls = "unknown"
    m = re.search(r"vuln[_ ]?class[\"'\s:]+([a-z-]+)", prompt, re.I)
    if m:
        cls = m.group(1)
    stub = {
        "is_vulnerability": True,
        "title": f"[offline stub] possible {cls}",
        "vuln_class": cls,
        "severity": "Low",
        "line": 0,
        "summary": "Offline heuristic stub: SIE was not reachable, so no real "
                   "analysis was performed. Re-run with SIE up.",
        "data_flow": "unknown (offline)",
        "steps": ["Start SIE and re-run to get a real analysis."],
        "poc": "",
        "suggested_fix": "",
        "confidence": 0.15,
    }
    return json.dumps(stub)


def _extract_json(raw: str) -> Optional[dict]:
    """Pull the first JSON object out of a model response."""
    if not raw:
        return None
    # Fenced block first.
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
    candidate = m.group(1) if m else None
    if candidate is None:
        start = raw.find("{")
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(raw)):
            if raw[i] == "{":
                depth += 1
            elif raw[i] == "}":
                depth -= 1
                if depth == 0:
                    candidate = raw[start:i + 1]
                    break
    if not candidate:
        return None
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None

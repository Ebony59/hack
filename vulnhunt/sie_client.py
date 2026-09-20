"""Typed Superlinked SIE client with explicit failure semantics.

Legacy ``generate``/``score`` calls remain available. New staged commands use
``preflight`` and ``generate_result``. Offline responses are explicit test mode.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol, Sequence

import requests

from .models import PreflightCheck, PreflightResult

DEFAULT_MODELS = {
    "encode": os.environ.get("SIE_ENCODE_MODEL", "Qwen/Qwen3-Embedding-4B"),
    "score": os.environ.get("SIE_SCORE_MODEL", "BAAI/bge-reranker-v2-m3"),
    "generate": os.environ.get("SIE_GENERATE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"),
}
CLOUD_BASE_URL = "https://api.superlinked.com"


class InferenceError(RuntimeError):
    kind = "inference"


class AuthenticationError(InferenceError):
    kind = "authentication"


class CreditsError(InferenceError):
    kind = "insufficient_credits"


class TransportError(InferenceError):
    kind = "transport"


class ContextExceededError(InferenceError):
    kind = "context_exceeded"

    def __init__(self, message: str, *, prompt_tokens: int, context_length: int):
        super().__init__(message)
        self.prompt_tokens = prompt_tokens
        self.context_length = context_length


class MalformedResponseError(InferenceError):
    kind = "malformed_response"


class OfflineModeError(InferenceError):
    kind = "offline"


@dataclass(frozen=True)
class GenerationResult:
    text: str
    model: str
    model_revision: str | None = None
    usage: dict[str, Any] | None = None


class InferenceClient(Protocol):
    def preflight(self, required_capabilities: set[str]) -> PreflightResult: ...
    def score(self, query: str, items: list[str]) -> list[float]: ...
    def generate_result(self, prompt: str, *, max_new_tokens: int = 1024,
                        temperature: float = 0.0) -> GenerationResult: ...


def sie_safe_model_id(model: str) -> str:
    """SIE native routes require a Hugging Face slash encoded as ``__``."""
    return model.replace("/", "__")


class SIEClient:
    def __init__(self, base_url: str | None = None, offline: bool = False, timeout: float = 120.0,
                 models: dict[str, str] | None = None, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("SIE_API_KEY")
        env_url = os.environ.get("SIE_BASE_URL") or os.environ.get("SIE_URL")
        default = CLOUD_BASE_URL if self.api_key else "http://localhost:8080"
        self.base_url = (base_url or env_url or default).rstrip("/")
        self.generate_url = (os.environ.get("SIE_GENERATE_URL") or self.base_url).rstrip("/")
        self.timeout, self.models, self.offline = timeout, {**DEFAULT_MODELS, **(models or {})}, offline
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if self.api_key:
            self.session.headers["Authorization"] = f"Bearer {self.api_key}"

    def _post(self, path: str, body: dict[str, Any], *, base: str | None = None,
              timeout: float | None = None) -> dict[str, Any]:
        if self.offline:
            raise OfflineModeError("offline inference is permitted only in explicitly selected test mode")
        try:
            response = self.session.post((base or self.base_url) + path, json=body,
                                         timeout=timeout or self.timeout)
        except requests.Timeout as exc:
            raise TransportError("SIE request timed out") from exc
        except requests.RequestException as exc:
            raise TransportError(f"SIE transport failure: {exc}") from exc
        if response.status_code in (401, 403):
            raise AuthenticationError("SIE authentication failed")
        if response.status_code == 402:
            raise CreditsError("SIE returned insufficient credits")
        context_error = _context_exceeded(response)
        if context_error is not None:
            raise context_error
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            detail = _http_error_detail(response)
            suffix = f": {detail}" if detail else ""
            raise TransportError(f"SIE returned HTTP {response.status_code}{suffix}") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise MalformedResponseError("SIE returned non-JSON response") from exc
        if not isinstance(data, dict):
            raise MalformedResponseError("SIE response is not an object")
        return data

    def encode(self, texts: Sequence[str], model: str | None = None) -> list[list[float]]:
        if self.offline:
            return [_hash_embed(text) for text in texts]
        chosen = model or self.models["encode"]
        data = self._post(f"/v1/encode/{sie_safe_model_id(chosen)}",
                          {"items": [{"id": str(i), "text": text} for i, text in enumerate(texts)],
                           "params": {"output_types": ["dense"]}})
        try:
            return [item["dense"]["values"] for item in data["items"]]
        except (KeyError, TypeError) as exc:
            raise MalformedResponseError("encode response missing dense vectors") from exc

    def score(self, query: str, texts: Sequence[str], model: str | None = None) -> list[float]:
        if self.offline:
            vector = _hash_embed(query)
            return [_cos(vector, _hash_embed(item)) for item in texts]
        chosen = model or self.models["score"]
        data = self._post(f"/v1/score/{sie_safe_model_id(chosen)}",
                          {"query": {"text": query},
                           "items": [{"id": str(i), "text": text} for i, text in enumerate(texts)]})
        try:
            scores = [0.0] * len(texts)
            for score in data["scores"]:
                scores[int(score["item_id"])] = float(score["score"])
            return scores
        except (KeyError, TypeError, ValueError, IndexError) as exc:
            raise MalformedResponseError("score response has invalid items") from exc

    def generate_result(self, prompt: str, *, max_new_tokens: int = 1024,
                        temperature: float = 0.0, model: str | None = None) -> GenerationResult:
        chosen = model or self.models["generate"]
        if self.offline:
            return GenerationResult(text=_offline_generate(prompt), model=chosen)
        if chosen.startswith("Qwen/Qwen3.8-"):
            # Qwen3.8 runs in xhigh thinking mode by default. Its supported
            # non-thinking control is a chat-template argument; prompt text
            # such as `/no_think` does not configure this model family.
            path = "/v1/chat/completions"
            max_field = "max_tokens"
            body = {"model": chosen, "messages": [{"role": "user", "content": prompt}],
                    max_field: max_new_tokens, "temperature": temperature, "stream": False,
                    "chat_template_kwargs": {"enable_thinking": False}}
        else:
            path = f"/v1/generate/{sie_safe_model_id(chosen)}"
            max_field = "max_new_tokens"
            body = {"prompt": prompt, max_field: max_new_tokens,
                    "temperature": temperature, "stream": False}
        try:
            # Large structured generations can legitimately exceed the shorter
            # encode/score timeout. Avoid retrying a possibly still-running,
            # billable generation; wait longer for its original response.
            generation_timeout = max(self.timeout, 300.0)
            data = self._post(path, body, base=self.generate_url, timeout=generation_timeout)
        except ContextExceededError as exc:
            # The server tokenizer is authoritative. Retry once with the exact
            # remaining window rather than guessing from character counts.
            adjusted = exc.context_length - exc.prompt_tokens - 128
            if adjusted < 64 or adjusted >= max_new_tokens:
                raise
            body[max_field] = adjusted
            data = self._post(path, body, base=self.generate_url, timeout=generation_timeout)
        text = data.get("text")
        if not isinstance(text, str) and isinstance(data.get("choices"), list) and data["choices"]:
            choice = data["choices"][0]
            text = choice.get("text") or choice.get("message", {}).get("content")
        if not isinstance(text, str):
            raise MalformedResponseError("generation response has no text")
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
        return GenerationResult(text=text, model=chosen, model_revision=data.get("model_revision"), usage=usage)

    def generate(self, prompt: str, max_new_tokens: int = 1024, temperature: float = 0.0,
                 stop: list[str] | None = None, model: str | None = None) -> str:
        return self.generate_result(prompt, max_new_tokens=max_new_tokens, temperature=temperature,
                                    model=model).text

    def generate_json(self, prompt: str, schema: dict[str, Any], max_new_tokens: int = 1024) -> dict[str, Any] | None:
        result = self.generate_result(prompt.rstrip() + "\nReturn only a JSON object matching:\n" +
                                      json.dumps(schema), max_new_tokens=max_new_tokens)
        return parse_json_object(result.text)

    def preflight(self, required_capabilities: set[str]) -> PreflightResult:
        if self.offline:
            return PreflightResult(ok=False, offline=True, checks=[PreflightCheck(
                capability="mode", ok=False, detail="offline mode is not valid for real commands")])
        def probe_generate() -> None:
            # Qwen reasoning models can spend a tiny completion budget entirely
            # on private reasoning. ``generate_result`` uses the model family's
            # supported thinking control before this probe is sent.
            result = self.generate_result(
                "Reply with exactly READY.",
                max_new_tokens=512,
            )
            if "READY" not in result.text:
                raise MalformedResponseError("generation preflight did not return READY")

        probes = {"encode": lambda: self.encode(["vulnhunt preflight"]),
                  "score": lambda: self.score("preflight", ["first", "second"]),
                  "generate": probe_generate}
        checks: list[PreflightCheck] = []
        for capability in sorted(required_capabilities):
            if capability not in probes:
                checks.append(PreflightCheck(capability=capability, ok=False, detail="unknown capability"))
                continue
            try:
                probes[capability]()
                checks.append(PreflightCheck(capability=capability, ok=True, detail="live probe succeeded"))
            except InferenceError as exc:
                checks.append(PreflightCheck(capability=capability, ok=False, detail=f"{exc.kind}: {exc}"))
            except Exception as exc:
                checks.append(PreflightCheck(capability=capability, ok=False, detail=f"unexpected: {exc}"))
        return PreflightResult(ok=all(check.ok for check in checks), offline=False, checks=checks)


def _http_error_detail(response: requests.Response) -> str | None:
    """Return a bounded provider error without leaking headers or request data."""
    try:
        payload = response.json()
    except ValueError:
        text = response.text.strip()
        return text[:500] or None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        message = error.get("message")
        parts = [str(value) for value in (code, message) if value]
        return ": ".join(parts)[:500] or None
    if isinstance(error, str):
        return error[:500]
    return None


def _context_exceeded(response: requests.Response) -> ContextExceededError | None:
    if response.status_code != 400:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict) or error.get("code") != "context_exceeded":
        return None
    message = str(error.get("message") or "SIE context window exceeded")
    match = re.search(
        r"prompt_tokens \((\d+)\).*context_length \((\d+)\)",
        message,
    )
    if match is None:
        return None
    return ContextExceededError(
        message,
        prompt_tokens=int(match.group(1)),
        context_length=int(match.group(2)),
    )


def parse_json_object(raw: str) -> dict[str, Any] | None:
    """Find a complete JSON object using the JSON decoder, not brace counting."""
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", raw):
        try:
            value, _ = decoder.raw_decode(raw[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _hash_embed(text: str, dim: int = 256) -> list[float]:
    vector = [0.0] * dim
    for token in re.findall(r"[A-Za-z_]{2,}", text.lower()):
        vector[int(hashlib.md5(token.encode()).hexdigest(), 16) % dim] += 1
    size = math.sqrt(sum(value * value for value in vector)) or 1.0
    return [value / size for value in vector]


def _cos(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _offline_generate(prompt: str) -> str:
    return json.dumps({"kind": "inconclusive", "reason": "explicit offline test mode; no SIE reasoning"})

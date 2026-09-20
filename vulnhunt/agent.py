"""Durable, bounded SIE agent loop for read-only repository mapping."""
from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .ids import canonical_json, content_hash
from .models import AgentFinal, AgentToolRequest, TaskRecord, ToolCall, utc_now
from .sie_client import GenerationResult, InferenceClient, parse_json_object
from .store import RunStore
from .tools import AnalysisTools

ResultModel = TypeVar("ResultModel", bound=BaseModel)


class DurableAgent:
    def __init__(self, client: InferenceClient, tools: AnalysisTools, store: RunStore, *,
                 max_steps: int = 10, output_limit: int = 7000):
        self.client, self.tools, self.store = client, tools, store
        self.max_steps, self.output_limit = max_steps, output_limit

    def run(self, task: TaskRecord, prompt: str, result_type: type[ResultModel]) -> ResultModel | None:
        task.status, task.started_at = "running", utc_now()
        self.store.write_json(f"tasks/{task.id}.json", task)
        self.store.append_transcript(task.id, {"type": "prompt", "content": prompt})
        conversation = prompt
        seen_calls: set[str] = set()
        for step in range(self.max_steps):
            try:
                generated = self.client.generate_result(conversation, max_new_tokens=3000, temperature=0.0)
            except Exception as exc:
                task.status, task.error_type, task.error_message = "failed", type(exc).__name__, str(exc)
                return self._finish(task, None)
            self.store.append_transcript(task.id, {"type": "assistant", "step": step,
                                                   "content": generated.text, "model": generated.model,
                                                   "usage": generated.usage or {}})
            data = parse_json_object(generated.text)
            if data is None:
                task.status, task.error_type, task.error_message = "failed", "MalformedResponse", "agent did not return JSON"
                return self._finish(task, None)
            try:
                if data.get("kind") == "tool":
                    request = AgentToolRequest.model_validate(data)
                    signature = canonical_json(request.request.model_dump())
                    if signature in seen_calls:
                        task.status, task.error_message = "inconclusive", "repeated tool call"
                        return self._finish(task, None)
                    seen_calls.add(signature)
                    observation = self.tools.dispatch(request.request.tool, request.request.arguments)
                    serialized = observation.model_dump(mode="json") if hasattr(observation, "model_dump") else observation
                    task.tool_calls.append(request.request)
                    self.store.append_transcript(task.id, {"type": "tool", "step": step,
                                                           "tool": request.request.tool, "arguments": request.request.arguments,
                                                           "result": serialized})
                    conversation += "\n\nTOOL OBSERVATION (cite EvidenceRef IDs; bounded output):\n" + \
                                    canonical_json(serialized)[:self.output_limit]
                    continue
                final = AgentFinal.model_validate(data)
                if final.kind == "inconclusive":
                    task.status, task.error_message = "inconclusive", final.reason or "agent inconclusive"
                    return self._finish(task, None)
                if final.result is None:
                    raise ValueError("final response omitted result")
                result = result_type.model_validate(final.result)
                task.status, task.usage = "succeeded", generated.usage or {}
                return self._finish(task, result)
            except (ValidationError, ValueError) as exc:
                task.status, task.error_type, task.error_message = "failed", "ValidationError", str(exc)
                return self._finish(task, None)
        task.status, task.error_message = "inconclusive", "step budget exhausted"
        return self._finish(task, None)

    def _finish(self, task: TaskRecord, result: ResultModel | None) -> ResultModel | None:
        task.finished_at = utc_now()
        if result is not None:
            relative = f"artifacts/task-{task.id}.json"
            self.store.write_json(relative, result)
            task.output_artifact_ids = [content_hash(canonical_json(result.model_dump(mode="json")))]
        self.store.write_json(f"tasks/{task.id}.json", task)
        self.store.append_event({"task_id": task.id, "status": task.status, "at": task.finished_at,
                                 "error": task.error_message})
        return result

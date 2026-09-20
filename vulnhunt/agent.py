"""Durable, bounded SIE agent loop for read-only repository mapping."""
from __future__ import annotations

import json
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .ids import canonical_json, content_hash
from .budget import CONTEXT_BUDGET_TOKENS, GENERATION_RESERVE_TOKENS, estimated_tokens
from .models import AgentFinal, AgentToolRequest, TaskRecord, ToolCall, utc_now
from .sie_client import GenerationResult, InferenceClient, parse_json_object
from .store import RunStore
from .tools import AnalysisTools

ResultModel = TypeVar("ResultModel", bound=BaseModel)


class DurableAgent:
    def __init__(self, client: InferenceClient, tools: AnalysisTools, store: RunStore, *,
                 max_steps: int = 12, output_limit: int = 2000,
                 final_answer_reserve: int = GENERATION_RESERVE_TOKENS,
                 min_final_reserve: int = 700):
        self.client, self.tools, self.store = client, tools, store
        self.max_steps, self.output_limit = max_steps, output_limit
        self.final_answer_reserve = final_answer_reserve
        self.min_final_reserve = min_final_reserve

    def run(self, task: TaskRecord, prompt: str, result_type: type[ResultModel]) -> ResultModel | None:
        task.status, task.started_at = "running", utc_now()
        self.store.write_json(f"tasks/{task.id}.json", task)
        self.store.append_transcript(task.id, {"type": "prompt", "content": prompt})
        conversation = prompt
        initial_evidence_ids = set(self.tools.evidence)
        seen_calls: set[str] = set()
        repeated_calls: dict[str, int] = {}
        navigation_calls = 0
        limit_corrections = 0
        for step in range(self.max_steps):
            available = CONTEXT_BUDGET_TOKENS - estimated_tokens(conversation)
            if available < self.min_final_reserve:
                task.status, task.error_message = "inconclusive", (
                    f"context budget exhausted after {step} steps: only ~{available} tokens "
                    f"remain of {CONTEXT_BUDGET_TOKENS}, below the {self.min_final_reserve} "
                    "needed to emit a final result")
                return self._finish(task, None)
            budget = min(self.final_answer_reserve, available)
            try:
                generated = self.client.generate_result(conversation, max_new_tokens=budget, temperature=0.0)
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
                    if len(task.tool_calls) >= 6:
                        return self._force_final(task, result_type, prompt, initial_evidence_ids)
                    if navigation_calls >= 3 and request.request.tool != "get_evidence":
                        limit_corrections += 1
                        if limit_corrections > 2:
                            task.status, task.error_message = "inconclusive", "navigation budget exceeded after correction"
                            return self._finish(task, None)
                        correction = (
                            "Navigation budget exhausted. Use get_evidence now for the strongest line range "
                            "already shown in the conversation, then return kind=final. Further reads, "
                            "searches, and listings are not allowed."
                        )
                        self.store.append_transcript(task.id, {"type": "tool_error", "step": step,
                                                               "tool": request.request.tool,
                                                               "arguments": request.request.arguments,
                                                               "result": correction})
                        conversation += "\n\nTOOL ERROR:\n" + correction
                        continue
                    signature = canonical_json(request.request.model_dump())
                    if signature in seen_calls:
                        repeated_calls[signature] = repeated_calls.get(signature, 0) + 1
                        if repeated_calls[signature] > 1:
                            task.status, task.error_message = "inconclusive", "repeated tool call after correction"
                            return self._finish(task, None)
                        correction = (
                            "Identical tool request not executed: its previous result is already in the "
                            "conversation. Choose a different tool or arguments. For a truncated read_file "
                            "result, request the next explicit start_line/end_line range."
                        )
                        self.store.append_transcript(task.id, {"type": "tool_error", "step": step,
                                                               "tool": request.request.tool,
                                                               "arguments": request.request.arguments,
                                                               "result": correction})
                        conversation += "\n\nTOOL ERROR:\n" + correction
                        continue
                    seen_calls.add(signature)
                    observation = self.tools.dispatch(request.request.tool, request.request.arguments)
                    if request.request.tool != "get_evidence":
                        navigation_calls += 1
                    serialized = observation.model_dump(mode="json") if hasattr(observation, "model_dump") else observation
                    task.tool_calls.append(request.request)
                    self.store.append_transcript(task.id, {"type": "tool", "step": step,
                                                           "tool": request.request.tool, "arguments": request.request.arguments,
                                                           "result": serialized})
                    rendered = serialized if isinstance(serialized, str) else canonical_json(serialized)
                    truncated = len(rendered) > self.output_limit
                    bounded = rendered[:self.output_limit]
                    if truncated:
                        last_newline = bounded.rfind("\n")
                        if last_newline > self.output_limit // 2:
                            bounded = bounded[:last_newline]
                        bounded += (
                            f"\n[TRUNCATED: showing {len(bounded)} of {len(rendered)} characters. "
                            "Use read_file with explicit start_line and end_line to continue.]"
                        )
                    conversation += "\n\nTOOL OBSERVATION (cite EvidenceRef IDs):\n" + bounded
                    if len(task.tool_calls) >= 6:
                        return self._force_final(task, result_type, prompt, initial_evidence_ids)
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

    def _force_final(self, task: TaskRecord, result_type: type[ResultModel], original_prompt: str,
                     initial_evidence_ids: set[str]) -> ResultModel | None:
        """Finalize from a fresh bounded evidence prompt after exploration ends."""
        evidence = []
        for evidence_id, item in self.tools.evidence.items():
            if evidence_id in initial_evidence_ids:
                continue
            value = item.model_dump(mode="json")
            value["excerpt"] = value["excerpt"][:2000]
            evidence.append(value)
        if not evidence:
            task.status, task.error_message = "inconclusive", "tool budget exhausted without evidence"
            return self._finish(task, None)
        final_prompt = (
            "You are finalizing a repository-mapping task after its read-only tool budget ended.\n"
            f"Role: {task.role}\n"
            f"Original objective and rules excerpt: {original_prompt[:700]}\n"
            "No tools are available. Use only the evidence objects below. Do not invent evidence IDs. "
            "Return exactly one JSON object with kind=final and a result matching the schema.\n"
            f"Schema: {json.dumps(result_type.model_json_schema(), sort_keys=True)}\n"
            f"Evidence: {json.dumps(evidence, sort_keys=True)}"
        )
        try:
            generated = self.client.generate_result(final_prompt, max_new_tokens=2500, temperature=0.0)
        except Exception as exc:
            task.status, task.error_type, task.error_message = "failed", type(exc).__name__, str(exc)
            return self._finish(task, None)
        self.store.append_transcript(task.id, {"type": "assistant", "step": "forced-final",
                                               "content": generated.text, "model": generated.model,
                                               "usage": generated.usage or {}})
        data = parse_json_object(generated.text)
        if data is None:
            task.status, task.error_type, task.error_message = (
                "failed", "MalformedResponse", "forced finalization did not return JSON")
            return self._finish(task, None)
        try:
            final = AgentFinal.model_validate(data)
            if final.kind != "final" or final.result is None:
                task.status, task.error_message = "inconclusive", final.reason or "forced finalization inconclusive"
                return self._finish(task, None)
            result = result_type.model_validate(final.result)
        except (ValidationError, ValueError) as exc:
            task.status, task.error_type, task.error_message = "failed", "ValidationError", str(exc)
            return self._finish(task, None)
        task.status, task.usage = "succeeded", generated.usage or {}
        return self._finish(task, result)

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

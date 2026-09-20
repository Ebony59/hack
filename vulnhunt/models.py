"""Strict persisted domain models for the workflow-first pipeline."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EvidenceRef(StrictModel):
    id: str
    repo_commit: str
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: str | None = None
    content_hash: str
    reason: str
    excerpt: str

    def model_post_init(self, __context: Any) -> None:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")


class RepositorySnapshot(StrictModel):
    schema_version: Literal[1] = 1
    target_id: str
    repo_path: str
    remote_url: str | None = None
    commit: str
    branch: str | None = None
    dirty: bool
    languages: list[str]
    manifests: list[str]
    package_roots: list[str]
    instructions: list[str]
    build_commands: list[list[str]]
    test_commands: list[list[str]]
    created_at: str
    harness_commit: str | None = None
    config_hash: str
    tool_versions: dict[str, str]


class Component(StrictModel):
    id: str
    name: str
    kind: str
    responsibility: str
    evidence: list[str]
    uncertainty: list[str] = []


class Actor(StrictModel):
    id: str
    name: str
    kind: str
    privilege: str
    evidence: list[str]


class Asset(StrictModel):
    id: str
    name: str
    sensitivity: str
    storage_or_location: str
    evidence: list[str]


class EntryPoint(StrictModel):
    id: str
    name: str
    kind: str
    component_ids: list[str]
    attacker_inputs: list[str]
    evidence: list[str]


class TrustBoundary(StrictModel):
    id: str
    name: str
    from_domain: str
    to_domain: str
    controls: list[str]
    evidence: list[str]


class SecurityControl(StrictModel):
    id: str
    name: str
    kind: str
    component_ids: list[str]
    limitations: list[str]
    evidence: list[str]


class FlowStep(StrictModel):
    component_id: str
    action: str
    inputs: list[str]
    outputs: list[str]
    evidence: list[str]


class Flow(StrictModel):
    id: str
    name: str
    summary: str
    actor_ids: list[str]
    entry_point_id: str
    steps: list[FlowStep]
    attacker_inputs: list[str]
    trust_boundary_ids: list[str]
    control_ids: list[str]
    asset_ids: list[str]
    sensitive_operations: list[str]
    deployment_assumptions: list[str]
    open_questions: list[str]
    confidence: float = Field(ge=0, le=1)
    evidence: list[str]

    @field_validator("attacker_inputs", "sensitive_operations",
                     "deployment_assumptions", "open_questions", mode="before")
    @classmethod
    def single_text_is_a_one_item_list(cls, value: Any) -> Any:
        """Canonicalize a common structured-generation scalar/list ambiguity."""
        return [value] if isinstance(value, str) else value


class ProjectMap(StrictModel):
    schema_version: Literal[1] = 1
    snapshot_id: str
    evidence: list[EvidenceRef]
    components: list[Component]
    actors: list[Actor]
    assets: list[Asset]
    entry_points: list[EntryPoint]
    trust_boundaries: list[TrustBoundary]
    controls: list[SecurityControl]
    flows: list[Flow]
    uncertainties: list[str]
    disagreements: list[str]


class FlowSynthesis(StrictModel):
    """The model-generated portion of a project map.

    Entities and the evidence catalog are merged deterministically before this
    result is requested, so making the model echo them wastes context and can
    introduce accidental mutations.
    """
    snapshot_id: str
    flows: list[Flow] = []
    uncertainties: list[str] = []
    disagreements: list[str] = []


class MapperResult(StrictModel):
    """A mapper's bounded contribution; synthesis is the only flow creator."""
    role: str
    summary: str
    components: list[Component] = []
    actors: list[Actor] = []
    assets: list[Asset] = []
    entry_points: list[EntryPoint] = []
    trust_boundaries: list[TrustBoundary] = []
    controls: list[SecurityControl] = []
    uncertainties: list[str] = []
    disagreements: list[str] = []


class ToolCall(StrictModel):
    tool: str
    arguments: dict[str, Any]


class AgentToolRequest(StrictModel):
    kind: Literal["tool"]
    request: ToolCall


class AgentFinal(StrictModel):
    kind: Literal["final", "inconclusive"]
    result: dict[str, Any] | None = None
    reason: str | None = None


class TaskRecord(StrictModel):
    schema_version: Literal[1] = 1
    id: str
    run_id: str
    kind: str
    role: str
    input_artifact_ids: list[str]
    input_hash: str
    model: str
    model_revision: str | None = None
    prompt_version: str
    status: Literal["pending", "running", "succeeded", "failed", "inconclusive"]
    attempt: int = Field(ge=0)
    max_attempts: int = Field(ge=1)
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    tool_calls: list[ToolCall] = []
    output_artifact_ids: list[str] = []
    error_type: str | None = None
    error_message: str | None = None
    usage: dict[str, Any] = {}


class PreflightCheck(StrictModel):
    capability: str
    ok: bool
    detail: str


class PreflightResult(StrictModel):
    ok: bool
    offline: bool
    checks: list[PreflightCheck]


def utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

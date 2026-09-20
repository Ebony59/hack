"""Strict schemas for the evaluation pack.

Two kinds of data are validated here:

* :class:`FixtureManifest` -- the ``fixture.yaml`` that records a fixture's
  *known answer*. It is ground truth and must never be fed to the model.
* :class:`SIEResult` -- the structured verdict a SIE-backed model is asked to
  return for a fixture. It is a *prediction* and is compared to the manifest
  only after inference finishes.

Both models are strict: unknown fields are rejected, and value types are not
silently coerced (a string ``"3"`` is not accepted where an integer is
expected, and a string ``"true"`` is not accepted where a boolean is). This
keeps a sloppy or fabricated model response from slipping through as valid.
"""
from __future__ import annotations

import enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator


class Classification(str, enum.Enum):
    """A fixture's security verdict."""

    VULNERABLE = "vulnerable"
    SAFE = "safe"
    INCONCLUSIVE = "inconclusive"


class ManifestClassification(str, enum.Enum):
    """Known-answer classification (a fixture is never 'inconclusive')."""

    VULNERABLE = "vulnerable"
    SAFE = "safe"


class WeaknessClass(str, enum.Enum):
    """The weakness a fixture demonstrates, or 'none' for a safe result."""

    PATH_TRAVERSAL = "path-traversal"
    NONE = "none"


class _Strict(BaseModel):
    """Base config: forbid unknown fields.

    Enum fields still accept their string value (needed when parsing JSON/YAML),
    but numeric fields use :class:`~pydantic.StrictInt` so a string like ``"3"``
    or a boolean is rejected rather than silently coerced.
    """

    model_config = ConfigDict(extra="forbid")


class FixtureManifest(_Strict):
    """The ``fixture.yaml`` contract (ground truth for one fixture)."""

    schema_version: StrictInt = Field(ge=1)
    id: str
    language: str
    expected_classification: ManifestClassification
    weakness_class: WeaknessClass
    entrypoint: str
    actor: str
    invariant: str
    reproduction_test: str


class Evidence(_Strict):
    """A single source citation supporting the model's verdict.

    Line numbers are 1-based and inclusive.
    """

    path: str
    start_line: StrictInt = Field(ge=1)
    end_line: StrictInt = Field(ge=1)
    explanation: str

    @model_validator(mode="after")
    def _check_range(self) -> "Evidence":
        if self.end_line < self.start_line:
            raise ValueError(
                f"end_line ({self.end_line}) must be >= start_line ({self.start_line})"
            )
        return self


class SIEResult(_Strict):
    """The structured verdict a model returns for one fixture.

    ``expected_classification`` is deliberately absent: the model must not be
    told the answer, so it cannot be part of the model's own output either.
    """

    fixture_id: str
    classification: Classification
    weakness_class: WeaknessClass
    actor: str
    entrypoint: str
    data_flow: List[str] = Field(min_length=1)
    security_invariant: str
    attacker_input: str
    relevant_controls: List[str] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    contrary_evidence: List[str] = Field(default_factory=list)
    summary: str

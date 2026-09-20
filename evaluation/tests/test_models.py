"""Schema tests: manifests and SIE results reject malformed input.

Covers required cases:
  5. manifests reject extra fields and bad classifications
  6. SIE result schemas reject string booleans, invalid line ranges, unknown fields
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from evaluation.models import Evidence, FixtureManifest, SIEResult

VALID_MANIFEST = {
    "schema_version": 1,
    "id": "path-traversal-vulnerable",
    "language": "python",
    "expected_classification": "vulnerable",
    "weakness_class": "path-traversal",
    "entrypoint": "app.py:read_report",
    "actor": "untrusted local user",
    "invariant": "A requested report must resolve inside the configured reports root.",
    "reproduction_test": "test_app.py",
}

VALID_RESULT = {
    "fixture_id": "report-reader-review",
    "classification": "vulnerable",
    "weakness_class": "path-traversal",
    "actor": "untrusted local user",
    "entrypoint": "app.py:read_report",
    "data_flow": ["user supplies name", "name joined to root", "file read"],
    "security_invariant": "requested report resolves inside the reports root",
    "attacker_input": "../outside-secret.txt",
    "relevant_controls": [],
    "evidence": [
        {"path": "app.py", "start_line": 20, "end_line": 21, "explanation": "naive join"}
    ],
    "contrary_evidence": [],
    "summary": "The name is joined and read without a containment check.",
}


def test_valid_manifest_parses() -> None:
    m = FixtureManifest.model_validate(VALID_MANIFEST)
    assert m.expected_classification.value == "vulnerable"


def test_manifest_rejects_unknown_field() -> None:
    bad = {**VALID_MANIFEST, "surprise": True}
    with pytest.raises(ValidationError):
        FixtureManifest.model_validate(bad)


def test_manifest_rejects_bad_classification() -> None:
    bad = {**VALID_MANIFEST, "expected_classification": "maybe"}
    with pytest.raises(ValidationError):
        FixtureManifest.model_validate(bad)


def test_manifest_rejects_inconclusive_as_answer() -> None:
    # 'inconclusive' is a valid model verdict but never a known answer.
    bad = {**VALID_MANIFEST, "expected_classification": "inconclusive"}
    with pytest.raises(ValidationError):
        FixtureManifest.model_validate(bad)


def test_valid_result_parses() -> None:
    r = SIEResult.model_validate(VALID_RESULT)
    assert r.classification.value == "vulnerable"
    assert r.evidence[0].start_line == 20


def test_result_rejects_unknown_field() -> None:
    bad = {**VALID_RESULT, "confidence": 0.9}
    with pytest.raises(ValidationError):
        SIEResult.model_validate(bad)


def test_result_rejects_bad_classification_enum() -> None:
    bad = {**VALID_RESULT, "classification": "probably-bad"}
    with pytest.raises(ValidationError):
        SIEResult.model_validate(bad)


def test_evidence_rejects_string_int_line() -> None:
    bad = {**VALID_RESULT, "evidence": [
        {"path": "app.py", "start_line": "20", "end_line": 21, "explanation": "x"}
    ]}
    with pytest.raises(ValidationError):
        SIEResult.model_validate(bad)


def test_evidence_rejects_boolean_line() -> None:
    # A boolean must not be coerced into an int line number.
    bad = {**VALID_RESULT, "evidence": [
        {"path": "app.py", "start_line": True, "end_line": 21, "explanation": "x"}
    ]}
    with pytest.raises(ValidationError):
        SIEResult.model_validate(bad)


def test_evidence_rejects_inverted_range() -> None:
    with pytest.raises(ValidationError):
        Evidence(path="app.py", start_line=9, end_line=3, explanation="x")


def test_evidence_rejects_zero_start_line() -> None:
    with pytest.raises(ValidationError):
        Evidence(path="app.py", start_line=0, end_line=3, explanation="x")


def test_result_requires_nonempty_data_flow() -> None:
    bad = {**VALID_RESULT, "data_flow": []}
    with pytest.raises(ValidationError):
        SIEResult.model_validate(bad)

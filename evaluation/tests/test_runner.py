"""Runner tests: prompting, evaluation loop, citation validation, reporting.

Covers required cases:
  7.  citation validation rejects missing files and out-of-range lines
  8.  the expected classification is absent from the generated prompt
  9.  a valid fake response creates a JSON and Markdown report
  10. an invalid response gets one repair attempt and then fails visibly
  11. an adapter failure cannot be reported as a safe fixture or success
  12. no test reads .env or needs a network connection

All tests use a fake generator; none touch SIE or the network.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Union

import pytest

from evaluation.models import Evidence, SIEResult
from evaluation.run import (
    ANSWER_MARKER,
    build_prompt,
    discover_fixtures,
    evaluate_fixture,
    validate_citations,
    write_reports,
)
from evaluation.sie_adapter import AdapterConfig, AdapterError


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #
class FakeGenerator:
    """Returns queued responses; an ``Exception`` item is raised instead."""

    def __init__(self, responses: List[Union[str, Exception]]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def generate(self, prompt: str) -> str:
        self.calls += 1
        item = self._responses[min(self.calls - 1, len(self._responses) - 1)]
        if isinstance(item, Exception):
            raise item
        return item


def _get_fixture(fixture_id: str):
    return discover_fixtures(fixture_id)[0]


def _valid_response(classification: str, weakness: str = "path-traversal") -> str:
    return json.dumps(
        {
            "fixture_id": "report-reader-review",
            "classification": classification,
            "weakness_class": weakness,
            "actor": "untrusted local user",
            "entrypoint": "app.py:read_report",
            "data_flow": ["user supplies name", "join to root", "read file"],
            "security_invariant": "requested report resolves inside the reports root",
            "attacker_input": "../outside-secret.txt",
            "relevant_controls": [],
            "evidence": [
                {"path": "app.py", "start_line": 1, "end_line": 2, "explanation": "x"}
            ],
            "contrary_evidence": [],
            "summary": "A short verdict.",
        }
    )


# --------------------------------------------------------------------------- #
# 8. prompt never leaks the answer
# --------------------------------------------------------------------------- #
def test_prompt_omits_expected_classification() -> None:
    for fx in discover_fixtures():
        prompt = build_prompt(fx)
        # The answer travels via the fixture id and the README's hidden section;
        # both must be absent. (The enum label list in the schema instructions
        # is identical for every fixture and is not a per-fixture answer.)
        assert fx.id not in prompt
        assert ANSWER_MARKER not in prompt
        assert "Known classification" not in prompt
        assert "expected_classification" not in prompt


# --------------------------------------------------------------------------- #
# 7. citation validation
# --------------------------------------------------------------------------- #
def test_citation_validation_accepts_real_lines() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    result = SIEResult.model_validate(json.loads(_valid_response("vulnerable")))
    assert validate_citations(result, fx.directory) == []


def test_citation_validation_rejects_missing_file() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    result = SIEResult.model_validate(json.loads(_valid_response("vulnerable")))
    result.evidence = [Evidence(path="ghost.py", start_line=1, end_line=1, explanation="x")]
    errors = validate_citations(result, fx.directory)
    assert errors and "does not resolve" in errors[0]


def test_citation_validation_rejects_out_of_range_lines() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    result = SIEResult.model_validate(json.loads(_valid_response("vulnerable")))
    result.evidence = [
        Evidence(path="app.py", start_line=1, end_line=99999, explanation="x")
    ]
    errors = validate_citations(result, fx.directory)
    assert errors and "exceeds" in errors[0]


def test_citation_validation_rejects_escape_path() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    result = SIEResult.model_validate(json.loads(_valid_response("vulnerable")))
    result.evidence = [
        Evidence(path="../../secrets.py", start_line=1, end_line=1, explanation="x")
    ]
    errors = validate_citations(result, fx.directory)
    assert errors and "does not resolve" in errors[0]


# --------------------------------------------------------------------------- #
# correctness + 9. reports
# --------------------------------------------------------------------------- #
def test_correct_classification_is_scored_correct() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    gen = FakeGenerator([_valid_response("vulnerable")])
    result = evaluate_fixture(fx, gen)
    assert result.status == "ok"
    assert result.predicted_classification == "vulnerable"
    assert result.correct is True
    assert result.citations_valid is True
    assert result.retry_count == 0


def test_misclassification_is_scored_incorrect_not_failed() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    gen = FakeGenerator([_valid_response("safe")])
    result = evaluate_fixture(fx, gen)
    assert result.status == "ok"          # a wrong answer is a measured result
    assert result.correct is False


def test_valid_response_writes_json_and_markdown(tmp_path: Path) -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    gen = FakeGenerator([_valid_response("vulnerable")])
    result = evaluate_fixture(fx, gen)

    out = write_reports(
        [result], tmp_path / "run", {"url": "http://x", "generate_model": "m",
                                      "authenticated": False}
    )
    results_json = out / "results.json"
    summary_md = out / "summary.md"
    assert results_json.is_file() and summary_md.is_file()

    data = json.loads(results_json.read_text())
    assert data["score"] == {"correct": 1, "scored": 1, "total": 1}
    assert "not" in data["note"].lower()  # disclaimer present
    text = summary_md.read_text()
    assert "1/1 correctly classified" in text
    assert "not** discovered real-world" in text


# --------------------------------------------------------------------------- #
# 10. one repair attempt, then visible failure
# --------------------------------------------------------------------------- #
def test_invalid_output_gets_one_repair_then_fails() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    gen = FakeGenerator(["not json at all", "still not json"])
    result = evaluate_fixture(fx, gen)
    assert result.status == "failed"
    assert result.retry_count == 1        # exactly one repair attempt
    assert gen.calls == 2                  # original + one repair
    assert result.predicted_classification is None
    assert result.error_category == "malformed"


def test_repair_recovers_when_second_attempt_is_valid() -> None:
    fx = _get_fixture("path-traversal-vulnerable")
    gen = FakeGenerator(["garbage", _valid_response("vulnerable")])
    result = evaluate_fixture(fx, gen)
    assert result.status == "ok"
    assert result.retry_count == 1
    assert result.correct is True


# --------------------------------------------------------------------------- #
# 11. an adapter failure is never a "safe"/successful result
# --------------------------------------------------------------------------- #
def test_adapter_failure_is_failed_not_safe() -> None:
    fx = _get_fixture("path-traversal-safe")
    gen = FakeGenerator([AdapterError("no credits", "credit")])
    result = evaluate_fixture(fx, gen)
    assert result.status == "failed"
    assert result.predicted_classification is None
    assert result.correct is False
    assert result.error_category == "credit"


def test_failed_results_do_not_count_as_scored(tmp_path: Path) -> None:
    fx = _get_fixture("path-traversal-safe")
    gen = FakeGenerator([AdapterError("boom", "transport")])
    result = evaluate_fixture(fx, gen)
    out = write_reports([result], tmp_path / "r", {"url": "u", "generate_model": "m"})
    data = json.loads((out / "results.json").read_text())
    assert data["score"] == {"correct": 0, "scored": 0, "total": 1}


# --------------------------------------------------------------------------- #
# 12. no .env / no network needed
# --------------------------------------------------------------------------- #
def test_config_reports_missing_model_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SIE_API_KEY", "SIE_BASE_URL", "SIE_URL", "SIE_GENERATE_URL",
                "SIE_GENERATE_MODEL"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(AdapterError) as exc:
        AdapterConfig.from_env(env={})
    assert exc.value.category == "config"


def test_evaluation_runs_without_any_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SIE_API_KEY", "SIE_BASE_URL", "SIE_GENERATE_MODEL"):
        monkeypatch.delenv(var, raising=False)
    fx = _get_fixture("path-traversal-vulnerable")
    gen = FakeGenerator([_valid_response("vulnerable")])
    result = evaluate_fixture(fx, gen)
    assert result.status == "ok"


def test_redacted_config_hides_api_key() -> None:
    cfg = AdapterConfig(base_url="http://x", generate_model="m", api_key="sk-secret")
    red = cfg.redacted()
    assert "sk-secret" not in json.dumps(red)
    assert red["authenticated"] is True

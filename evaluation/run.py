"""Evaluation-pack runner and CLI.

Two entry points:

    python -m evaluation.run --check-fixtures   # offline: manifests + fixture tests
    python -m evaluation.run --live-sie          # calls real SIE, writes a report

The evaluation logic (:func:`evaluate_fixture`) is pure and takes any
:class:`~evaluation.sie_adapter.Generator`, so unit tests drive it with a fake
client and spend no credits. The model's verdict is compared to the manifest's
known answer only *after* inference, and the answer is never placed in the
prompt.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import ValidationError

from .models import FixtureManifest, SIEResult
from .sie_adapter import AdapterConfig, AdapterError, Generator, SIEGenerationAdapter

PACKAGE_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = PACKAGE_DIR / "fixtures"
PROMPT_PATH = PACKAGE_DIR / "prompts" / "analyze_fixture.md"
RESULTS_DIR = PACKAGE_DIR / "results"
MAX_REPAIRS = 1


# --------------------------------------------------------------------------- #
# Fixture loading
# --------------------------------------------------------------------------- #
@dataclass
class Fixture:
    """A loaded fixture: its manifest, source, and README."""

    directory: Path
    manifest: FixtureManifest
    app_path: str          # fixture-relative path to the reviewed source
    app_source: str
    readme: str

    @property
    def id(self) -> str:
        return self.manifest.id


def load_manifest(path: Path) -> FixtureManifest:
    """Load and strictly validate a ``fixture.yaml``."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    return FixtureManifest.model_validate(data)


def load_fixture(directory: Path) -> Fixture:
    """Load a fixture directory into a :class:`Fixture`."""
    manifest = load_manifest(directory / "fixture.yaml")
    app_rel = manifest.entrypoint.split(":", 1)[0]
    app_source = (directory / app_rel).read_text(encoding="utf-8")
    readme_path = directory / "README.md"
    readme = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
    return Fixture(
        directory=directory,
        manifest=manifest,
        app_path=app_rel,
        app_source=app_source,
        readme=readme,
    )


def discover_fixtures(only: Optional[str] = None) -> List[Fixture]:
    """Load every fixture under ``fixtures/`` (optionally filtered by id)."""
    fixtures: List[Fixture] = []
    for child in sorted(FIXTURES_DIR.iterdir()):
        if (child / "fixture.yaml").exists():
            fixture = load_fixture(child)
            if only is None or fixture.id == only:
                fixtures.append(fixture)
    if only is not None and not fixtures:
        raise ValueError(f"no fixture with id {only!r}")
    return fixtures


# --------------------------------------------------------------------------- #
# Prompt building
# --------------------------------------------------------------------------- #
# Everything in a fixture README from this marker onward is for human
# maintainers and is stripped before the README reaches the model.
ANSWER_MARKER = "<!-- eval:answer-hidden -->"

# A neutral review id shown to the model. The real fixture id (e.g.
# "path-traversal-safe") encodes the answer, so it is never placed in the
# prompt; the report's fixture_id is set from the manifest instead.
PROMPT_REVIEW_ID = "report-reader-review"


def _number_lines(source: str) -> str:
    lines = source.splitlines()
    width = max(len(str(len(lines))), 2)
    return "\n".join(f"{i:>{width}}  {line}" for i, line in enumerate(lines, start=1))


def _prompt_readme(readme: str) -> str:
    """Return the model-facing README, stripped of the hidden answer section."""
    return readme.split(ANSWER_MARKER, 1)[0].strip()


def build_prompt(fixture: Fixture) -> str:
    """Render the classification prompt for a fixture.

    The manifest's ``expected_classification``, the fixture tests, and the
    README's hidden answer section are never included -- they would reveal the
    answer.
    """
    template = PROMPT_PATH.read_text(encoding="utf-8")
    return template.format(
        fixture_id=PROMPT_REVIEW_ID,
        actor=fixture.manifest.actor,
        entrypoint=fixture.manifest.entrypoint,
        readme=_prompt_readme(fixture.readme),
        app_path=fixture.app_path,
        app_source=_number_lines(fixture.app_source),
    )


def build_repair_prompt(original_prompt: str, previous_output: str, errors: str) -> str:
    """Ask the model to fix invalid output, showing only the errors + its reply."""
    return (
        original_prompt
        + "\n\n## Your previous reply was invalid\n\n"
        + "It did not satisfy the required schema. Do not add commentary; return a\n"
        + "single corrected JSON object only.\n\n"
        + "### Validation errors\n\n"
        + errors.strip()
        + "\n\n### Your previous output\n\n"
        + previous_output.strip()
        + "\n"
    )


# --------------------------------------------------------------------------- #
# JSON extraction + citation validation
# --------------------------------------------------------------------------- #
def extract_json_object(raw: str) -> Optional[dict]:
    """Pull the first JSON object out of a model response, or ``None``."""
    if not raw:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
    candidate = fenced.group(1) if fenced else None
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
                    candidate = raw[start : i + 1]
                    break
    if not candidate:
        return None
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def validate_citations(result: SIEResult, fixture_dir: Path) -> List[str]:
    """Return a list of problems with the result's evidence citations.

    A citation is rejected when its path does not resolve to a file inside the
    fixture, or when its line range falls outside that file. Fabricated
    citations are surfaced, never silently ignored.
    """
    errors: List[str] = []
    fixture_dir = fixture_dir.resolve()
    for idx, ev in enumerate(result.evidence):
        target = (fixture_dir / ev.path).resolve()
        inside = target == fixture_dir or fixture_dir in target.parents
        if not inside or not target.is_file():
            errors.append(
                f"evidence[{idx}] path {ev.path!r} does not resolve to a file "
                f"inside the fixture"
            )
            continue
        line_count = len(target.read_text(encoding="utf-8").splitlines())
        if ev.end_line > line_count:
            errors.append(
                f"evidence[{idx}] line range {ev.start_line}-{ev.end_line} "
                f"exceeds {ev.path} ({line_count} lines)"
            )
    return errors


# --------------------------------------------------------------------------- #
# Per-fixture evaluation
# --------------------------------------------------------------------------- #
@dataclass
class FixtureEvalResult:
    """The outcome of evaluating one fixture through a generator."""

    fixture_id: str
    expected_classification: str
    status: str                                   # "ok" | "failed"
    predicted_classification: Optional[str] = None
    correct: bool = False
    citations_valid: bool = False
    citation_errors: List[str] = field(default_factory=list)
    security_invariant: Optional[str] = None
    data_flow: List[str] = field(default_factory=list)
    weakness_class: Optional[str] = None
    retry_count: int = 0
    error: Optional[str] = None
    error_category: Optional[str] = None
    raw_response: Optional[str] = None            # model text only; never a secret

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def evaluate_fixture(
    fixture: Fixture, generator: Generator, max_repairs: int = MAX_REPAIRS
) -> FixtureEvalResult:
    """Classify one fixture, allowing a single repair of invalid output.

    An adapter/transport failure or invalid output after the repair produces a
    ``status == "failed"`` result -- never a spurious "safe" verdict or a
    "correct" evaluation.
    """
    expected = fixture.manifest.expected_classification.value
    base_prompt = build_prompt(fixture)
    prompt = base_prompt
    retry_count = 0
    last_raw: Optional[str] = None

    while True:
        try:
            raw = generator.generate(prompt)
        except AdapterError as exc:
            return FixtureEvalResult(
                fixture_id=fixture.id,
                expected_classification=expected,
                status="failed",
                retry_count=retry_count,
                error=str(exc),
                error_category=exc.category,
                raw_response=last_raw,
            )
        except Exception as exc:  # noqa: BLE001
            return FixtureEvalResult(
                fixture_id=fixture.id,
                expected_classification=expected,
                status="failed",
                retry_count=retry_count,
                error=f"unexpected generator error: {type(exc).__name__}",
                error_category="unknown",
                raw_response=last_raw,
            )

        last_raw = raw
        obj = extract_json_object(raw)
        if obj is None:
            validation_error = "response did not contain a JSON object"
            result = None
        else:
            try:
                result = SIEResult.model_validate(obj)
                validation_error = None
            except ValidationError as exc:
                result = None
                validation_error = str(exc)

        if result is not None:
            break

        if retry_count >= max_repairs:
            return FixtureEvalResult(
                fixture_id=fixture.id,
                expected_classification=expected,
                status="failed",
                retry_count=retry_count,
                error=f"invalid model output after {retry_count} repair attempt(s): "
                f"{validation_error}",
                error_category="malformed",
                raw_response=last_raw,
            )
        retry_count += 1
        prompt = build_repair_prompt(base_prompt, raw, validation_error or "")

    citation_errors = validate_citations(result, fixture.directory)
    predicted = result.classification.value
    return FixtureEvalResult(
        fixture_id=fixture.id,
        expected_classification=expected,
        status="ok",
        predicted_classification=predicted,
        correct=(predicted == expected),
        citations_valid=not citation_errors,
        citation_errors=citation_errors,
        security_invariant=result.security_invariant,
        data_flow=list(result.data_flow),
        weakness_class=result.weakness_class.value,
        retry_count=retry_count,
        raw_response=last_raw,
    )


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _timestamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def write_reports(
    results: List[FixtureEvalResult],
    out_dir: Path,
    config_redacted: dict,
    timestamp: Optional[str] = None,
) -> Path:
    """Write ``results.json`` and ``summary.md`` into ``out_dir``.

    ``config_redacted`` must already exclude credentials. Raw model responses
    are stored separately from the validated conclusions and are labelled as
    unvalidated.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = timestamp or _timestamp()

    scored = [r for r in results if r.status == "ok"]
    correct = sum(1 for r in scored if r.correct)
    report = {
        "timestamp": timestamp,
        "sie": config_redacted,
        "score": {
            "correct": correct,
            "scored": len(scored),
            "total": len(results),
        },
        "results": [r.to_dict() for r in results],
        "note": "Artificial known-answer fixtures for pipeline evaluation -- "
        "NOT discovered real-world vulnerabilities.",
    }
    (out_dir / "results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "summary.md").write_text(
        _render_summary(report), encoding="utf-8"
    )
    return out_dir


def _render_summary(report: dict) -> str:
    sie = report["sie"]
    score = report["score"]
    lines = [
        "# SIE evaluation summary",
        "",
        f"- **Timestamp:** {report['timestamp']}",
        f"- **SIE endpoint:** {sie.get('url', 'n/a')}",
        f"- **Generation model:** {sie.get('generate_model', 'n/a')}",
        f"- **Authenticated:** {sie.get('authenticated', False)}",
        f"- **Score:** {score['correct']}/{score['scored']} correctly classified"
        + (
            f" ({score['total'] - score['scored']} fixture(s) failed to evaluate)"
            if score["total"] != score["scored"]
            else ""
        ),
        "",
        "> These are artificial known-answer fixtures used to evaluate the "
        "scanner pipeline. They are **not** discovered real-world "
        "vulnerabilities.",
        "",
    ]
    for r in report["results"]:
        lines.append(f"## Fixture: `{r['fixture_id']}`")
        lines.append("")
        lines.append(f"- **Status:** {r['status']}")
        lines.append(f"- **Expected classification:** {r['expected_classification']}")
        lines.append(
            f"- **Predicted classification:** {r['predicted_classification'] or 'n/a'}"
        )
        if r["status"] == "ok":
            lines.append(
                f"- **Correct:** {'yes' if r['correct'] else 'NO'}"
            )
            lines.append(
                f"- **Citations valid:** {'yes' if r['citations_valid'] else 'NO'}"
            )
            if r["citation_errors"]:
                for ce in r["citation_errors"]:
                    lines.append(f"    - citation problem: {ce}")
            lines.append(f"- **Model invariant:** {r['security_invariant'] or 'n/a'}")
            if r["data_flow"]:
                lines.append("- **Model data flow:**")
                for step in r["data_flow"]:
                    lines.append(f"    1. {step}")
        else:
            lines.append(
                f"- **Failure:** {r['error']} (category: {r['error_category']})"
            )
        lines.append(f"- **Repair attempts:** {r['retry_count']}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI commands
# --------------------------------------------------------------------------- #
def cmd_check_fixtures(only: Optional[str]) -> int:
    """Validate manifests and run the deterministic fixture tests (no SIE)."""
    print("[check] validating fixture manifests ...")
    try:
        fixtures = discover_fixtures(only)
    except (ValueError, ValidationError) as exc:
        print(f"[check] manifest validation FAILED: {exc}")
        return 1
    for fx in fixtures:
        print(f"[check]   ok: {fx.id} ({fx.manifest.expected_classification.value})")

    test_files = [
        str(fx.directory / fx.manifest.reproduction_test) for fx in fixtures
    ]
    print("[check] running deterministic fixture tests ...")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *test_files],
        cwd=str(PACKAGE_DIR.parent),
    )
    if proc.returncode != 0:
        print("[check] fixture tests FAILED")
        return proc.returncode
    print("[check] all fixture checks passed")
    return 0


def cmd_live_sie(only: Optional[str]) -> int:
    """Validate fixtures, preflight SIE, classify each fixture, write a report."""
    try:
        fixtures = discover_fixtures(only)
    except (ValueError, ValidationError) as exc:
        print(f"[live] manifest validation FAILED: {exc}")
        return 1

    # Fixtures must be behaviourally correct before we spend any credits.
    rc = cmd_check_fixtures(only)
    if rc != 0:
        print("[live] aborting: fixture checks failed")
        return rc

    try:
        config = AdapterConfig.from_env()
    except AdapterError as exc:
        print(f"[live] configuration error ({exc.category}): {exc}")
        return 2
    print(f"[live] SIE config: {config.redacted()}")

    adapter = SIEGenerationAdapter(config)
    print("[live] running generation preflight ...")
    try:
        adapter.preflight()
    except AdapterError as exc:
        print(f"[live] preflight FAILED ({exc.category}): {exc}")
        adapter.close()
        return 2
    print("[live] preflight ok")

    results: List[FixtureEvalResult] = []
    for fx in fixtures:
        print(f"[live] classifying {fx.id} ...")
        result = evaluate_fixture(fx, adapter)
        results.append(result)
        if result.status == "ok":
            verdict = "correct" if result.correct else "MISCLASSIFIED"
            cite = "citations ok" if result.citations_valid else "BAD citations"
            print(
                f"[live]   -> {result.predicted_classification} "
                f"(expected {result.expected_classification}; {verdict}; {cite})"
            )
        else:
            print(f"[live]   -> FAILED ({result.error_category}): {result.error}")
    adapter.close()

    out_dir = RESULTS_DIR / _timestamp()
    write_reports(results, out_dir, config.redacted())
    print(f"[live] wrote report to {out_dir}")

    scored = [r for r in results if r.status == "ok"]
    correct = sum(1 for r in scored if r.correct)
    failed = [r for r in results if r.status == "failed"]
    print(
        f"[live] score: {correct}/{len(scored)} correctly classified; "
        f"{len(failed)} infrastructure/invalid-output failure(s)"
    )
    # Nonzero only for infrastructure / invalid-output failures. A pure
    # misclassification is a measured result, not a crash.
    return 3 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation.run",
        description="SIE-backed evaluation pack for the Vulnhunt scanner.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check-fixtures",
        action="store_true",
        help="validate manifests and run deterministic fixture tests (offline)",
    )
    mode.add_argument(
        "--live-sie",
        action="store_true",
        help="run the real two-fixture SIE evaluation and write a report",
    )
    parser.add_argument(
        "--fixture",
        metavar="ID",
        default=None,
        help="restrict to a single fixture id (optional)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.check_fixtures:
        return cmd_check_fixtures(args.fixture)
    return cmd_live_sie(args.fixture)


if __name__ == "__main__":
    raise SystemExit(main())

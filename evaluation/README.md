# Vulnhunt evaluation pack

A self-contained, known-answer test for the SIE-backed analysis pipeline. It
asks a SIE generation model to review two tiny applications that implement the
**same** workflow and decide whether each is vulnerable:

```
user supplies a report filename
  -> the app combines it with a reports directory
  -> the app reads and returns the report
```

One fixture is deliberately vulnerable to path traversal; the other prevents a
path from escaping the reports directory, including through a symlink. The pack
scores whether the model reaches the right verdict **and** cites the correct
source lines.

> These fixtures are artificial. A correct verdict here does **not** prove the
> scanner can find vulnerabilities in mature real-world projects, and the
> vulnerable fixture is not a discovered real-world vulnerability.

## Layout

```
evaluation/
├── models.py            strict pydantic schemas (manifest + model result)
├── sie_adapter.py       official sie-sdk generation adapter (+ failure categories)
├── run.py               CLI, prompt building, evaluation loop, citation checks, reports
├── prompts/
│   └── analyze_fixture.md   the classification prompt (answer is never included)
├── fixtures/
│   ├── path_traversal_vulnerable/   app.py, README.md, fixture.yaml, test_app.py
│   └── path_traversal_safe/         app.py, README.md, fixture.yaml, test_app.py
├── tests/               offline unit tests (fake adapter; no network, no credits)
└── results/             live run output (gitignored)
```

## Requirements

Python 3.12 with the harness requirements installed:

```bash
pip install -r requirements.txt        # from the repo root
```

That installs `sie-sdk`, `pydantic`, `pytest`, and `PyYAML`.

## Commands

Run from the harness repo root.

### Offline checks (no SIE, no credits)

```bash
# Unit tests + fixture behaviour
python -m pytest -q evaluation/tests \
  evaluation/fixtures/path_traversal_vulnerable/test_app.py \
  evaluation/fixtures/path_traversal_safe/test_app.py

# Validate manifests and run the deterministic fixture tests
python -m evaluation.run --check-fixtures
```

`--check-fixtures` returns non-zero if a fixture no longer behaves as expected.

### Live SIE evaluation (spends credits)

Configure SIE (never commit these):

```bash
export SIE_BASE_URL="https://api.superlinked.com"   # or your region / local URL
export SIE_API_KEY="..."                             # required for the cloud
export SIE_GENERATE_MODEL="Qwen/Qwen3.5-4B"          # a real, available generation model
# Optional knobs:
# export SIE_GENERATE_URL="http://localhost:8081"   # local split generation server
# export SIE_MAX_NEW_TOKENS="4096"                  # generation budget (model cap applies)
# export SIE_PROMPT_SUFFIX="/no_think"              # appended to every prompt (see below)
```

> **Pick a model that actually exists on your deployment.** Run
> `python -c "import os,sie_sdk; [print(m['name']) for m in
> sie_sdk.SIEClient(os.environ['SIE_BASE_URL'], api_key=os.environ['SIE_API_KEY']).list_models()]"`
> to list them. The generation LLMs are the ones whose `outputs` are `tokens`
> (e.g. `Qwen/Qwen3.5-4B`, `Qwen/Qwen3.8-27B-FP8`); the embedding/rerank models
> cannot generate. Model names in old examples may be gone.

> **Reasoning models.** `Qwen/Qwen3.5-4B` is a hybrid reasoning model: it spends
> hidden tokens before any visible text, and its hard output cap is 4096 tokens.
> If the whole budget is spent reasoning you get a `malformed` failure
> (`empty_model_output`). Set `SIE_PROMPT_SUFFIX="/no_think"` to keep it from
> reasoning, and the prompt already asks for a compact result so it fits under
> the cap. A non-reasoning instruct model needs neither knob.

Then:

```bash
source .env            # if you keep the variables there
python -m evaluation.run --live-sie
# optional: restrict to one fixture
python -m evaluation.run --live-sie --fixture path-traversal-vulnerable
```

`--live-sie`:

1. validates the fixtures and runs their deterministic tests;
2. runs a small real-generation **preflight** and stops clearly if generation
   is unavailable;
3. classifies both fixtures through SIE (the known answer is never in the prompt);
4. validates every citation's path and line range;
5. compares predictions with the manifests;
6. writes `results.json` and `summary.md` into a timestamped `results/` directory
   and prints that path plus a pass/fail summary.

## Output

- `results.json` — machine-readable: redacted SIE config (no key), per-fixture
  status, predicted vs. expected classification, citation validity, the model's
  invariant and data flow, retry count, and the raw model text (labelled as
  unvalidated, kept separate from the graded conclusions).
- `summary.md` — human-readable version of the same, with an overall score such
  as `1/2 correctly classified` and the artificial-fixture disclaimer.

## Exit codes

- **`--check-fixtures`** — non-zero if a manifest is invalid or a fixture test
  fails.
- **`--live-sie`** — non-zero for *infrastructure* or *invalid-output* failures
  (bad config, failed preflight, or a fixture whose output stayed invalid after
  one repair attempt). A mere **misclassification** is a measured result and
  returns zero, but is clearly recorded in the report. Bad citations are
  likewise recorded as a quality signal.

## Design notes

- **Answer hiding.** The model is shown a neutral review id and the fixture
  README with its `<!-- eval:answer-hidden -->` section stripped. The fixture id
  (which encodes the answer), `fixture.yaml`, and the tests are never sent.
- **Strict schemas.** `models.py` forbids unknown fields and refuses to coerce
  line numbers, so a sloppy or fabricated model response is rejected rather than
  silently accepted. Invalid output gets exactly one repair attempt, then fails
  visibly.
- **No silent fallback.** If SIE generation is unavailable the adapter raises a
  categorized error (auth / credit / model / timeout / malformed / transport /
  config); it never substitutes a local heuristic or another provider.
- **Secrets.** `SIE_API_KEY` is never printed or written to a report; the
  adapter forwards only an error's category and type, not its raw message.

## Limitations

- Two tiny single-file fixtures, one weakness class (path traversal). Success is
  a smoke test of the pipeline's judgement, not evidence about large codebases.
- The verdict depends on the configured model; a weaker model may misclassify or
  miscite. That is the point — the pack measures the model, and a wrong answer is
  a finding, not a crash.

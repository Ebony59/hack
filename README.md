# vulnhunt — SIE-driven vulnerability discovery harness

An autonomous vulnerability-discovery system. It scans a target repository,
retrieves the riskiest code regions, **fans out one investigator agent per region
on a self-hosted Superlinked SIE server**, forces each agent to emit a structured
finding, verifies candidates with real tools, then aggregates and reports. The
harness is only orchestration — every unit of vulnerability *reasoning* runs on
SIE, not on Claude/Codex sub-agents.

```
index  ->  retrieve (sink patterns + SIE rerank)  ->  fan out N SIE agents
       ->  SIE structured finding  ->  verify with tools  ->  aggregate  ->  report
```

The target repositories are **not part of this repo**. You list the repos to scan
in `config.local.yaml`, so this repo stays self-contained and easy to share —
nothing about the targets is committed here.

## Layout

```
.                        <- this repo (the harness)
├── README.md
├── requirements.txt
├── config.example.yaml  committed: template for the external repos path
├── config.local.yaml    gitignored: your machine's repos path
├── .gitignore
└── vulnhunt/
    ├── config.py        language adapters + targets + repos_root resolution
    ├── targets.yaml      metadata overlay: language + notes per repo name
    ├── sie_client.py     SIE HTTP client (encode/score/extract/generate) + offline fallback
    ├── indexer.py        walk + line-window chunking with file/line metadata
    ├── retriever.py      lexical sink scoring + SIE semantic rerank -> candidate regions
    ├── investigator.py   fan-out: one SIE ReAct agent per region  <-- the SIE launch point
    ├── schema.py         Finding model + JSON schema for structured output
    ├── tools.py          sandboxed read/grep/run + per-language build/test/lint/semgrep
    ├── verifier.py       evidence gate: drop unproven candidates, mark verified ones
    ├── aggregator.py     dedupe by root cause + rank by severity
    ├── reporter.py       submission-ready markdown + JSON
    └── orchestrate.py    the pipeline + CLI
```

## Setup

From the repo root:

```bash
conda activate hack
pip install -r requirements.txt

# list the target repos to scan:
cp config.example.yaml config.local.yaml
# then edit config.local.yaml:
#   repos:
#     - "/absolute/path/to/repo-one"
#     - "/absolute/path/to/repo-two"
```

Each entry is a repo path (absolute, or relative to this repo root). A repo's
language and notes are taken from `vulnhunt/targets.yaml` when the folder name
matches; otherwise the language is auto-detected. For per-repo overrides, an
entry may be a mapping with `path`, `name`, `language`/`languages`, and `notes`
(see `config.example.yaml`). A single `--repos-root PATH` (or
`$VULNHUNT_REPOS_ROOT`) still works as an override that scans every target in
`targets.yaml` under that folder.

## Connect SIE

The reasoning engine is Superlinked SIE. Two ways to reach it — the client
auto-selects based on whether `SIE_API_KEY` is set.

**Cloud (recommended).** Create a key at `console.superlinked.com`, then:

```bash
cp .env.example .env      # put your sk-sie-... key in it
source .env               # sets SIE_API_KEY + SIE_BASE_URL
```

**Local (no key; Apple Silicon friendly).**

```bash
pip install "sie-server[local]"          # Python 3.12
sie-server serve                         # encode/score/extract on :8080
# generation runs separately via MLX:
uvx --with "mlx-lm>=0.30.7" --from sie-server sie-server serve -b sglang -p 8081
export SIE_BASE_URL=http://localhost:8080
export SIE_GENERATE_URL=http://localhost:8081
```

Model choices are overridable via env (`SIE_GENERATE_MODEL`, `SIE_ENCODE_MODEL`,
`SIE_SCORE_MODEL`, `SIE_EXTRACT_MODEL`); browse `superlinked.com/models`. A
code-capable instruct model is strongly preferred for the agent loop. If a call
returns `402 INSUFFICIENT_CREDITS`, ask the organizers to top up the key.

## Run the staged workflow

The supported workflow is deliberately review-gated. Repository understanding
and mapping use SIE, then stop for a human to review the interaction-flow map.
After checkpoint A is approved, SIE derives cited invariants and ranked,
unverified hypotheses, then stops again at checkpoint B. It does not run target
commands or investigate hypotheses yet.

```bash
# Performs real encode, score, and generation probes. Fails closed on SIE errors.
python3.11 -m vulnhunt.cli preflight --target snare

# Creates a Git-pinned run, inventory, SIE mapper transcripts, and checkpoint A.
python3.11 -m vulnhunt.cli map --target snare

# Inspect immutable task state and pinned-commit status.
python3.11 -m vulnhunt.cli status --run runs/snare/<run-id>

# After reviewing checkpoint A, generate invariants and checkpoint B.
python3.11 -m vulnhunt.cli hypothesize --run runs/snare/<run-id>

# Rebuild reports without making SIE calls.
python3.11 -m vulnhunt.cli render --run runs/snare/<run-id>
```

`map` prints `reviews/checkpoint-a.md` and `reviews/checkpoint-a.yaml`. Review
and edit the YAML. Hypothesis generation is refused unless the review is
explicitly approved and names valid flow IDs. `hypothesize` writes cited
`invariants.json`, ranked `hypotheses.json`, and `reviews/checkpoint-b.*`.
Investigation is refused until checkpoint B is approved; its implementation is
the next stage. Offline mode is never selected implicitly for this workflow.

### Continue an approved sample run

The sample runs use an explicit, user-chosen run directory, so they do not need
to be copied under this checkout. Confirm that the pinned target commit is
still checked out, then invoke the stage with the absolute run path:

```bash
RUN="$(realpath ../hack/runs/snare/snare-codex)"
python3.11 -m vulnhunt.cli status --run "$RUN"
python3.11 -m vulnhunt.cli hypothesize --run "$RUN"
```

Replace `snare/snare-codex` with the desired `<repo-name>/<repo-name>-codex`.
This makes real SIE generation calls after preflight and writes checkpoint-B
artifacts into that same run directory. It will refuse a stale target checkout,
an unapproved/invalid checkpoint A, or an already-generated checkpoint B.

If a real generation attempt is incomplete (for example, a provider rate-limit
failure), retry it explicitly. The previous checkpoint-B artifacts, its task
records, and transcripts are moved under `attempts/`; nothing is discarded:

```bash
python3.11 -m vulnhunt.cli hypothesize --run "$RUN" --force
```

## Legacy region scanner

A bare run scans every repo listed in `config.local.yaml`; `--target NAME`
scans just one (matched by folder name).

```bash
# offline dry run — no SIE needed, exercises legacy plumbing only
python -m vulnhunt.orchestrate --offline

# real runs against SIE
python -m vulnhunt.orchestrate                       # all listed repos
python -m vulnhunt.orchestrate --target <target-name>
python -m vulnhunt.orchestrate --top 15 --concurrency 6 --semgrep
```

Reports land in `out/findings-<target>.{md,json}` (gitignored).

### Useful flags

| Flag | Meaning |
| --- | --- |
| `--target NAME` / `--all` | scan one target or every configured target |
| `--offline` | force local fallbacks (no SIE); good for testing the plumbing |
| `--repos-root PATH` | folder containing the target repos |
| `--sie-url URL` | SIE base URL (else `$SIE_URL` or `:8080`) |
| `--top N` | candidate regions per target (default 12) |
| `--concurrency N` | SIE investigator agents in flight (default 4) |
| `--semgrep` | run semgrep in the verifier (if installed) |

## Extending it

- **New target:** add an entry to `vulnhunt/targets.yaml` (folder name + language).
- **New language:** add a `LanguageAdapter` in `config.py` (extensions, sink
  patterns, input-source regexes, build/test/lint commands).
- **New sink class:** add a `SinkPattern` to the relevant adapter.

## Honest notes

- Open models via SIE are weaker than frontier models at deep code reasoning. The
  design compensates with retrieval (right code in front of the model), structured
  output (well-formed findings), and a verification gate (only proven candidates
  ship). Do not remove the gate — false positives cost reviewer trust and score
  nothing.
- The offline fallback never fabricates a verified bug; its stubs are rejected by
  the verifier by design. It exists only to test the pipeline without SIE.
- `cargo`, `semgrep`, etc. must be installed where you *run* the harness for the
  verifier's build/test/semgrep signals to fire; missing tools degrade gracefully.

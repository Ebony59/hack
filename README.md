# vulnhunt — SIE-driven vulnerability discovery harness

An autonomous vulnerability-discovery system for the hackathon. It scans a target
repo, retrieves the riskiest code regions, **fans out one investigator agent per
region on a self-hosted Superlinked SIE server**, forces each agent to emit a
structured finding, verifies candidates with real tools, then aggregates and
reports. The harness is only orchestration — every unit of vulnerability
*reasoning* runs on SIE, not on Claude/Codex sub-agents.

```
index  ->  retrieve (sink patterns + SIE rerank)  ->  fan out N SIE agents
       ->  SIE structured finding  ->  verify with tools  ->  aggregate  ->  report
```

This repo **never contains or touches the target source**. The target repos live
in a folder you point at via config, so the work is easy to share: teammates
clone this repo and set their own `repos_root`.

## Layout

```
hack/                      <- the folder that holds the target repos (repos_root)
  snare/  pizauth/  vibe-kanban/  Who-Targets-Me/     <- targets (external, untouched)
  hack/                    <- THIS git repo
    README.md
    requirements.txt
    config.example.yaml    committed: template for the repos path
    config.local.yaml      gitignored: your machine's repos path
    .gitignore
    vulnhunt/
      config.py       language adapters + targets + repos_root resolution
      targets.yaml    the four competition repos (folder names, not paths)
      sie_client.py   SIE HTTP client (encode/score/extract/generate) + offline fallback
      indexer.py      walk + line-window chunking with file/line metadata
      retriever.py    lexical sink scoring + SIE semantic rerank -> candidate regions
      investigator.py fan-out: one SIE ReAct agent per region  <-- the SIE launch point
      schema.py       Finding model + JSON schema for structured output
      tools.py        sandboxed read/grep/run + per-language build/test/lint/semgrep
      verifier.py     evidence gate: drop unproven candidates, mark verified ones
      aggregator.py   dedupe by root cause + rank by severity
      reporter.py     submission-ready markdown + JSON
      orchestrate.py  the pipeline + CLI
```

## Setup

```bash
conda activate hack
cd hack/hack
pip install -r requirements.txt

# tell the harness where the target repos live:
cp config.example.yaml config.local.yaml
# then edit config.local.yaml -> repos_root: ".."   (or an absolute path)
```

`repos_root` is resolved by precedence: `--repos-root` > `$VULNHUNT_REPOS_ROOT` >
`config.local.yaml`. A relative value is resolved against this repo's root, so
`".."` means "the folder one level up holds the target repos".

## Run SIE (self-hosted, separate terminal)

```bash
docker run -p 8080:8080 -v sie-hf-cache:/app/.cache/huggingface \
  ghcr.io/superlinked/sie-server:latest-cpu-default
curl localhost:8080/readyz
```

Point the harness at it with `SIE_URL` (default `http://localhost:8080`). Model
choices are overridable via env: `SIE_ENCODE_MODEL`, `SIE_SCORE_MODEL`,
`SIE_EXTRACT_MODEL`, `SIE_GENERATE_MODEL` (a code-capable instruct model such as
`Qwen/Qwen2.5-Coder-7B-Instruct` is strongly preferred for the agent loop).

## Run the harness

```bash
# offline dry run — no SIE needed, exercises the whole pipeline end to end
python -m vulnhunt.orchestrate --target snare --offline

# real runs against SIE
python -m vulnhunt.orchestrate --target snare
python -m vulnhunt.orchestrate --target vibe-kanban --top 15 --concurrency 6
python -m vulnhunt.orchestrate --all --semgrep

# repos somewhere else? override without editing config:
python -m vulnhunt.orchestrate --target snare --repos-root /path/to/repos
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

# Vulnhunt: workflow-first security investigation report

**Date:** 20 September 2026  
**Harness branch:** `main`  
**Scope:** proposed pipeline, current implementation, evaluation result, four Codex-reviewed mapping runs, and the dynamically reproduced Who-Targets-Me findings

## How to read this report

This report separates three kinds of evidence that must not be conflated:

1. **Pipeline evaluation** measures whether the SIE-backed reasoning path can classify small known-answer fixtures. It does not represent a real-world discovery.
2. **Mapping observations** are source-cited conclusions and investigation leads from repository and interaction-flow review. They are not automatically verified vulnerabilities.
3. **Reproduced findings** have a controlled executable test that crosses the claimed trust boundary and observes the security-property violation.

For a quick read:

- Read **Executive summary** for the result.
- Read **Proposed pipeline** to understand the system we are building.
- Read **How to read a run** before inspecting `runs/<target>/<run-id>/`.
- Read **Discovery results** for the cross-repository review.
- Read **Who-Targets-Me reproduction** for the strongest evidence produced so far.
- Read **Current limitations and next steps** before treating any mapping observation as a reportable vulnerability.

Severity in the mapping tables means **potential severity if the stated exposure and attacker prerequisites hold**. It is not a CVSS score and is not proof of exploitability.

## Executive summary

Vulnhunt is being redesigned from a one-shot suspicious-code scanner into a durable, workflow-first security investigation system. The key change is the unit of analysis: the system first maps actors, components, assets, entry points, trust boundaries, controls, and end-to-end flows. It then derives security invariants and testable hypotheses. Human checkpoints prevent incorrect maps or unsafe experiments from automatically becoming findings.

The current staged implementation can establish a Git-pinned baseline, run real SIE preflight checks, build a source-cited project and flow map, stop at checkpoint A, generate cited invariants and hypotheses after approval, and stop at checkpoint B. General targeted investigation and isolated verification remain future work. A known-answer evaluation pack in this repository classified both the safe and vulnerable path-traversal fixtures correctly, with valid citations, using `Qwen/Qwen3.8-27B-FP8` through SIE. That is a useful plumbing and reasoning check, not evidence of real-world performance.

Four manually reviewed `*-codex` runs provide source-pinned gold-standard maps for Who-Targets-Me, pizauth, snare, and vibe-kanban. They contain 19 mapping observations. Most remain design findings, deployment assumptions, or investigation leads. Two Who-Targets-Me findings were subsequently reproduced in an isolated browser:

- **WTM-MAP-01:** ordinary JavaScript on a matched webpage can send a forged message that changes privileged extension storage.
- **WTM-MAP-02:** registration feedback is written into page-origin `localStorage` and broadcast to page JavaScript.

The browser reproduction used synthetic marker tokens, an isolated temporary profile, blocked external DNS, and no WhoTargetsMe production API. WTM-MAP-01 is an end-to-end reproduction of the original vulnerable path. WTM-MAP-02 reproduces the original credential-exposure sink with synthetic registration feedback; live token acquisition was deliberately not tested.

## Why the original scanner design was insufficient

The original harness ranked fixed-size code windows containing known lexical sinks, asked one model to judge each window, then used heuristic verification and confidence arithmetic. That creates several trust problems:

- a readable line and an unrelated input pattern could be labelled `verified` without proving data flow;
- infrastructure or inference failures could look like a clean scan;
- model JSON was not strictly schema-validated;
- repository reads could escape through symlinks;
- direct model verdicts could be lost from the transcript;
- small sink-centred windows omit callers, controls, configuration, tests, and deployment assumptions;
- reports did not retain enough immutable state to resume or audit a run.

The redesign therefore treats suspicious syntax as a retrieval hint, not proof. Verification must observe a violated security invariant in a controlled experiment.

## Proposed pipeline

```text
Git-pinned repository baseline
            |
            v
SIE-backed project map
            |
            v
Interaction flows and trust boundaries
            |
            v
      Checkpoint A: human map review
            |
            v
Security invariants and ranked hypotheses
            |
            v
      Checkpoint B: human test selection
            |
            v
Targeted SIE investigation and disconfirmation
            |
            v
Controlled reproduction with benign control
            |
            v
Independent evidence review and final report
```

### Phase 0: reproducible baseline

Record the repository URL, exact commit, branch and dirty state, submodules, languages, manifests, package roots, build/test commands, deployment artifacts, harness revision, configuration hash, tool versions, and SIE endpoint/model revisions. A real run fails closed if the target cannot be pinned or required SIE capabilities do not pass actual encode, score, and generation probes.

### Phases 1–2: project and flow mapping

SIE-backed mapping tasks examine complementary questions rather than trying to find vulnerabilities immediately:

- product, actors, and important assets;
- runtime and deployment boundaries;
- external entry points and attacker-controlled fields;
- state, credentials, persistence, and transitions;
- authentication, authorization, origin, path, signature, rate, and resource controls.

A synthesis task produces cited components, actors, assets, entry points, trust boundaries, controls, and end-to-end flows. A flow—not an arbitrary line window—is the primary security-analysis object. Every material claim should resolve to immutable evidence tied to the pinned commit.

### Checkpoint A: approve the system model

The run stops. Reviewers correct the architecture, select important flows, record disagreements, and identify missing evidence in `reviews/checkpoint-a.yaml`. Hypothesis generation is refused until the review is explicitly approved and every selected flow ID exists.

### Phase 3: invariants and hypotheses

For each selected flow, SIE states the security properties that must hold and proposes bounded ways they might fail. A hypothesis must identify:

- the flow and invariant;
- attacker capability and prerequisites;
- suspected end-to-end path;
- expected impact and limiting assumptions;
- supporting and contrary evidence;
- the cheapest decisive test.

Hypotheses are deduplicated and ranked by impact, reachability, evidence strength, novelty, reproduction safety, and investigation cost.

### Checkpoint B: approve active investigation

Reviewers choose a small investigation portfolio in `reviews/checkpoint-b.yaml`. This prevents model-generated test ideas from being run automatically and focuses time and credits on questions with meaningful expected value.

### Phase 4: targeted investigation

Each selected hypothesis becomes a durable task with a question-specific evidence bundle, explicit model and tool budgets, symbol-aware navigation, and a requirement to seek disconfirming evidence. Useful roles include a reachability tracer, controls reviewer, protocol specialist, reproduction designer, and skeptic. Independent flows may run concurrently; agents do not receive context-free fixed-size regions.

### Phase 5: controlled reproduction

A valid verification should:

1. pin the target and environment;
2. define the attacker and violated invariant;
3. include a benign control and exploit case;
4. run in a disposable environment without user credentials;
5. restrict external network access unless explicitly required;
6. capture commands, inputs, exit codes, logs, outputs, and state changes;
7. repeat from a clean state where practical;
8. undergo an independent evidence and severity challenge.

Only an observed invariant violation with a successful control becomes `reproduced`.

### Phase 6: report and incremental operation

The final report links the finding to its flow, invariant, hypothesis, experiment, evidence, transcript, target commit, and SIE provenance. Later scans should invalidate only maps and hypotheses affected by changed symbols, configuration, dependencies, or tests instead of repeating the entire repository blindly.

## Evidence states

| State | Meaning |
| --- | --- |
| `hypothesis` | A possible invariant violation has been proposed but not traced. |
| `supported` | Source evidence supports reachability and a missing or failed control. |
| `reproduction_ready` | A safe decisive experiment exists but has not run. |
| `reproduced` | A controlled experiment observed the named invariant violation. |
| `rejected` | Contrary evidence or a successful security control invalidated the hypothesis. |
| `inconclusive` | Available evidence is insufficient or execution was blocked. |
| `failed` | Tooling or inference failed before a security conclusion was possible. |

Task success and security conclusions are separate. A successful task may reject a hypothesis; a failed task must never be reported as “no vulnerability.”

## How to read a run

The intended layout is:

```text
runs/<target>/<run-id>/
  run.json
  snapshot.json
  inventory.json
  events.jsonl
  tasks/
  transcripts/
  artifacts/
    project-map.json
    flows.json
    invariants.json
    hypotheses.json
    experiments.json
    findings.json
  evidence/
  reviews/
    checkpoint-a.md
    checkpoint-a.yaml
    checkpoint-b.md
    checkpoint-b.yaml
  reports/
    findings.md
```

Read a run in this order:

1. **`run.json`** — determine the target, pinned commit, current status, and pipeline watermark. Stop if the status is incomplete or failed.
2. **`snapshot.json`** — confirm exactly which checkout and harness configuration were analysed. A different target commit makes the run stale.
3. **`reviews/checkpoint-a.md`** — read the human-friendly architecture and flow map. Then inspect the YAML to see whether it was approved and which flows were selected.
4. **`artifacts/project-map.json` and `flows.json`** — inspect structured actors, boundaries, controls, assumptions, and ordered source-cited steps.
5. **`evidence/`** — dereference evidence IDs before trusting a claim. Confirm path, lines, excerpt, content hash, and reason all support it.
6. **`tasks/` and `transcripts/`** — audit which model produced a claim, which tools it used, failures/retries, and whether the final structured output follows from the transcript.
7. **`artifacts/invariants.json`, `hypotheses.json`, and checkpoint B** — distinguish proposed questions from approved investigations.
8. **`experiments.json` and `findings.json`** — require a successful benign control and observed violation before accepting `reproduced`.
9. **`reports/findings.md`** — treat this as a presentation layer. The evidence chain above remains authoritative.

The local sample runs live under `runs/`. Directories named `<target>-codex` are manually reviewed Codex gold-standard continuations of the mapping stage. They are useful reference maps and review leads, but they are not evidence that the proposed autonomous SIE pipeline completed every stage. In particular, the sampled checkpoint-B reviews are not approved and the general investigation stage is not implemented.

## Evaluation result

The repository contains a known-answer evaluation pack with two tiny applications implementing the same report-file workflow:

- one intentionally vulnerable to path traversal;
- one that resolves paths and prevents traversal and symlink escape.

The live result in `evaluation/results/20260920-153114/summary.md` records:

- SIE generation model: `Qwen/Qwen3.8-27B-FP8`;
- score: **2/2 correctly classified**;
- safe fixture classified safe;
- vulnerable fixture classified vulnerable;
- source citations valid for both;
- no repair attempts required.

This demonstrates that the strict adapter, prompt, citation validation, and result grading work on a small known-answer case. It does not establish recall or false-positive performance on mature repositories. The fixtures are evaluation assets, not discoveries.

## Discovery results

### Summary

| Target | Pinned commit | Flows mapped | Mapping observations | Dynamically reproduced |
| --- | --- | ---: | ---: | ---: |
| Who-Targets-Me | `64e9989c65ba83e8536e57768e19ff0b6409abda` | 4 | 6 | 2 |
| pizauth | `6225ea327fb18bf96acaee0007d823d082e7ce88` | 4 | 4 | 0 |
| snare | `6d86d72e75a622d53149612753a7a4e55a29abb7` | 3 | 4 | 0 |
| vibe-kanban | `d5cbb5380fa0b32e98ef9b8d987f63decce4be3a` | 6 | 5 | 0 |

### Who-Targets-Me

| ID | Observation | Mapping classification | Potential severity | Current evidence state |
| --- | --- | --- | --- | --- |
| `WTM-MAP-01` | Untrusted page messages invoke privileged extension commands | Confirmed privilege-boundary defect | High | **Reproduced end-to-end** for token overwrite |
| `WTM-MAP-02` | API credential is exposed to the page origin | Confirmed credential exposure | High | **Exposure sink reproduced** with synthetic registration feedback |
| `WTM-MAP-03` | API credential is embedded in a results URL path | Confirmed credential-exposure pattern | High | Source-supported; persistence and downstream handling not tested |
| `WTM-MAP-04` | Manifest V3 requests `<all_urls>` | Excessive privilege | Medium | Source-supported hardening issue |
| `WTM-MAP-05` | Terms validation fails open | Privacy/compliance weakness | Medium | Source-supported; operational impact not tested |
| `WTM-MAP-06` | YouGov tab detection uses substring matching | Integrity review lead | Low | Requires a decisive hostname-confusion test |

### pizauth

| ID | Observation | Mapping classification | Potential severity | Current evidence state |
| --- | --- | --- | --- | --- |
| `PIZ-MAP-01` | Dump encryption uses a compiled static key | Confirmed confidentiality limitation | High | Source-supported design limitation; threat-model intent must be confirmed |
| `PIZ-MAP-02` | Callback listener exposure is configurable | Deployment trust assumption | Medium | Defaults remain random-port loopback; non-loopback deployment needs testing |
| `PIZ-MAP-03` | The Unix socket is the local token authority | Architectural trust boundary | High | Source-supported; `0700` parent-directory permissions are the principal control |
| `PIZ-MAP-04` | Unix-socket requests have no explicit size bound | Same-user denial-of-service lead | Low | Requires resource-exhaustion measurement under the same-user attacker model |

### snare

| ID | Observation | Mapping classification | Potential severity | Current evidence state |
| --- | --- | --- | --- | --- |
| `SNARE-MAP-01` | Webhook authentication is optional | Deployment trust assumption | Critical | Source-supported conditional behavior; exploitability depends on reachable configuration |
| `SNARE-MAP-02` | There is no webhook replay guard | Confirmed missing control | High | Source-supported; duplicate command impact needs controlled reproduction |
| `SNARE-MAP-03` | Authenticated jobs enter an unbounded queue | Denial-of-service lead | Medium | Requires sustained queue/memory measurement |
| `SNARE-MAP-04` | Configured commands execute through a shell | Architectural impact amplifier | Critical | Intended capability, not a vulnerability by itself |

### vibe-kanban

| ID | Observation | Mapping classification | Potential severity | Current evidence state |
| --- | --- | --- | --- | --- |
| `VKB-MAP-01` | The privileged local API relies on loopback deployment | Deployment trust assumption | Critical | Source-supported; requires a realistic exposure path |
| `VKB-MAP-02` | Preview proxy accepts an arbitrary localhost port | High-impact design surface | High | Source-supported; requires proof that a useful local service can be driven through it |
| `VKB-MAP-03` | Arbitrary process execution is an explicit capability | Impact amplifier | Critical | Intended capability, not a vulnerability by itself |
| `VKB-MAP-04` | Cloud CORS mirrors origins while permitting credentials | Review lead | High | Inconclusive until browser-managed credential behavior and token storage are established |
| `VKB-MAP-05` | Review endpoints form a public capability surface | Review lead | Medium | Requires capability secrecy, ownership, enumeration, upload, and rate-limit tests |

## Who-Targets-Me reproduction

### Root cause

The extension content script listens for page messages and forwards `event.data` to the privileged extension runtime after checking only `event.source == window`:

```text
Who-Targets-Me/src/contents/index.js:5-10
```

The page itself satisfies that source check. The background handler accepts privileged command-shaped data, including `storeUserToken`, and writes the supplied value to extension storage:

```text
Who-Targets-Me/src/shared/handlers/onMessageEventHandler.js:36-57
Who-Targets-Me/src/shared/utils/setToStorage.js:3-9
```

The reverse channel handles `registrationFeedback` by writing the token to page-origin `localStorage` and broadcasting the whole response using `window.postMessage(..., "*")`:

```text
Who-Targets-Me/src/contents/index.js:13-17
```

The same content script is configured on broad, high-value origins including Google, Facebook, Instagram, X, YouTube, WhoTargetsMe, and localhost. Any script executing in a matched page can therefore reach the page side of the bridge.

### What the harness did

`scripts/test-wtm-extension-bridge.mjs`:

1. builds the extension with `OFFLINE=true`, or reuses `build/chrome`;
2. copies the build into a temporary directory;
3. adds a random-channel observability hook only to that disposable copy;
4. launches Chrome for Testing with a new isolated profile;
5. serves a local page matched by the extension's existing localhost rule;
6. blocks external DNS and disables browser background networking;
7. executes attacker actions as ordinary page JavaScript through the DevTools protocol;
8. uses unique synthetic marker tokens;
9. removes the temporary profile and copied extension after the run.

The observability hook reads storage back and synthesizes a registration response. It does not implement the vulnerable forwarding, privileged token write, page `localStorage` write, or wildcard broadcast. Those actions remain in the original extension code.

### Observed result

```json
{
  "WTM-MAP-01": {
    "result": "reproduced",
    "pageMessageChangedExtensionStorage": true
  },
  "WTM-MAP-02": {
    "result": "reproduced",
    "tokenWrittenToPageLocalStorage": true,
    "tokenBroadcastToPage": true
  },
  "whoTargetsMeProductionApiUsed": false,
  "profile": "temporary and isolated"
}
```

For `WTM-MAP-01`, the harness sent this from page context:

```js
window.postMessage({ storeUserToken: true, token: marker }, "*");
```

It then independently read `chrome.storage.local.general_token` through the test hook and observed the exact marker. This proves an untrusted matched page can alter privileged extension authentication state.

For `WTM-MAP-02`, the hook sent synthetic `registrationFeedback` through the same extension-to-content-script channel used by production. Page JavaScript observed the marker both in its own origin's `localStorage` and in a message event. This proves the credential-exposure sink. It does not prove that a live production registration token can currently be obtained, nor does it establish token lifetime or server-side impact.

### Reproduction command

Official Chrome 137 and newer ignore command-line unpacked-extension loading. Install Chrome for Testing once, then run the harness:

```bash
npx --yes @puppeteer/browsers@latest install chrome@stable
node scripts/test-wtm-extension-bridge.mjs --headed --skip-build
```

Omit `--skip-build` to rebuild. Add `--install` only when the target's pinned Node dependencies are absent.

### Security impact and limits

`WTM-MAP-01` establishes an integrity violation at the page-to-extension privilege boundary. Depending on server token semantics, realistic consequences may include session fixation, account confusion, loss or corruption of extension state, forged registration/deletion operations, consent changes, or attacker-shaped telemetry. Those downstream outcomes are hypotheses until tested against an authorized non-production service.

`WTM-MAP-02` makes any token reaching the handler available to all JavaScript executing in the receiving page origin, including first-party code, third-party scripts, and injected code. The source also sends registration feedback to the currently active tab rather than clearly correlating it with the initiating tab. The safe conclusion is credential exposure at the browser boundary; account takeover, token reuse, and token lifetime remain untested.

### Recommended remediation

- Do not forward arbitrary `window` messages to `runtime.sendMessage`.
- Remove privileged token, registration, deletion, consent, and raw-log commands from any page-controlled bridge.
- If a page integration is genuinely required, use a narrow schema, explicit command allowlist, strict origin policy, request correlation, and an unguessable per-session capability established by the extension.
- Validate the sender tab/frame and bind responses to the initiating request rather than the first active tab.
- Keep authentication tokens exclusively in extension storage; never copy them into page-origin `localStorage` or wildcard `postMessage` payloads.
- Do not embed reusable credentials in URL paths. Prefer an authenticated, short-lived, one-time exchange and suppress referrer leakage.
- Add regression tests proving ordinary page JavaScript cannot mutate extension credentials or observe registration credentials.

## Current implementation status

| Area | Status |
| --- | --- |
| Strict source-cited models, deterministic IDs, snapshot/inventory, safe reads | Implemented |
| Real SIE preflight and fail-closed staged commands | Implemented |
| Multi-role mapping, synthesis, flows, checkpoint A | Implemented |
| Cited invariant/hypothesis generation and checkpoint B | Implemented, but the sampled Codex runs are incomplete at this stage |
| General targeted investigation engine | Not implemented in the staged workflow |
| General isolated experiment runner | Not implemented |
| Reproduced-finding report generation | Not implemented generally; Who-Targets-Me has a specialized harness |
| Incremental change-impact rescanning | Proposed |
| Known-answer evaluation pack | Implemented; latest recorded live result is 2/2 |

## Current limitations and next steps

1. Persist the successful Who-Targets-Me experiment as structured `Experiment` and `Finding` artifacts rather than only console output and this report.
2. Add a benign control to the browser harness—for example, prove an unrelated page message does not change storage—and repeat from a clean profile.
3. Build the general checkpoint-B investigation stage with durable tasks, disconfirmation, explicit budgets, and strict outputs.
4. Build a disposable verification runner that removes credentials, restricts network access, records exact commands and outputs, and supports safe local services.
5. Select a small set of decisive tests from the remaining mapping observations. The strongest next candidates are Snare webhook replay, Vibe Kanban preview-proxy reachability, and Who-Targets-Me results-URL token handling.
6. Run the known-answer evaluation across multiple available SIE generation models and add more weakness classes, multi-file flows, and deliberately ambiguous safe cases.
7. Add precision/recall and citation-quality reporting across a versioned benchmark before making claims about autonomous real-world detection performance.

## Bottom line

The workflow-first design has produced a substantially more honest analysis model: understanding and threat modelling are reviewed before active testing, failures remain visible, and only observed invariant violations receive the `reproduced` label. The current evidence includes a successful small SIE evaluation, four useful source-pinned maps, and two real browser-boundary violations reproduced in Who-Targets-Me. It does not yet include a general autonomous investigation and verification pipeline, and the remaining 17 mapping observations should be treated as prioritized security-review work rather than verified vulnerabilities.

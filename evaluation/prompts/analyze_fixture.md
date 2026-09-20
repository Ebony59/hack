You are a careful application security reviewer. You are reviewing a very small
Python application to decide whether one specific workflow is vulnerable.

Work only from the code and description below. Trace the attacker-controlled
input through the code, state the security property the workflow relies on, and
look for any control that would enforce it. Do not assume behaviour that is not
shown. If the supplied code is not enough to decide, classify the fixture as
`inconclusive` rather than guessing.

Report concise conclusions and cite exact source lines. Do not include hidden
reasoning or step-by-step deliberation; give only the final structured findings.

## Application under review

**Review id:** {fixture_id}

**Actor (who supplies untrusted input):** {actor}

**Entry point:** {entrypoint}

### README

{readme}

### Source: {app_path}

```python
{app_source}
```

## What to produce

Return ONLY a single JSON object (no prose, no code fence) with exactly these
fields. Be concise so the whole object stays small: at most **3** `data_flow`
steps, at most **2** `evidence` items, and keep every `explanation` and the
`summary` to one short sentence.

- `fixture_id` (string): echo the review id above.
- `classification` (string): one of `vulnerable`, `safe`, `inconclusive`.
- `weakness_class` (string): `path-traversal` if that weakness applies, else `none`.
- `actor` (string): the untrusted actor.
- `entrypoint` (string): the reviewed entry point.
- `data_flow` (array of strings): ordered, plain-language steps from the
  attacker's input to the sensitive operation.
- `security_invariant` (string): the property that must always hold.
- `attacker_input` (string): the concrete input an attacker would supply.
- `relevant_controls` (array of strings): checks in the code that do (or should)
  enforce the invariant; empty if there are none.
- `evidence` (array of objects): each `{{"path": <file>, "start_line": <int>,
  "end_line": <int>, "explanation": <string>}}`, with 1-based inclusive line
  numbers referring to the source shown above.
- `contrary_evidence` (array of strings): observations that argue against your
  classification; empty if none.
- `summary` (string): two or three sentences stating the verdict and why.

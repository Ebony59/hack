# Report reader fixture

A minimal application that returns the contents of a named report.

## Workflow

1. An untrusted local user supplies a report filename.
2. The application combines that name with a configured reports directory.
3. The application reads the resulting file and returns its text.

## Public interface

```python
def read_report(reports_root: Path, requested_name: str) -> str:
    """Return the requested UTF-8 report or raise a documented exception."""
```

- **Actor:** an untrusted local user who controls `requested_name`.
- **Intended invariant:** a requested report must resolve inside the configured
  reports root.

<!-- eval:answer-hidden -->
<!--
The text below is for human maintainers only. `build_prompt` strips everything
from the `eval:answer-hidden` marker onward so the model is never shown the
answer.

Known classification: SAFE. This fixture is the safe control for the Vulnhunt
evaluation pack: it resolves the reports root and the requested target
(following symlinks) and rejects any target that lands outside the root,
defeating both `../` traversal and symlink escapes. `test_app.py` exercises the
accepted and rejected cases inside a temporary directory.
-->

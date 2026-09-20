"""SIE generation adapter for the evaluation pack.

The pack talks to Superlinked SIE through the *official* ``sie-sdk`` Python
client so it never has to guess the native model-ID encoding or wire format.
The adapter:

* reads its configuration from the environment;
* runs a small real-generation preflight and fails clearly if generation is
  unavailable;
* maps SDK exceptions to coarse failure categories (auth, credit, model,
  timeout, malformed, transport) so the runner can report *why* it failed;
* never prints or persists ``SIE_API_KEY``;
* sits behind the tiny :class:`Generator` protocol so unit tests can inject a
  fake client and spend no credits.

There is deliberately **no** silent fallback to a local heuristic or another AI
provider: if SIE generation is unavailable the adapter raises, and the runner
records an infrastructure failure.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

# Failure categories the runner distinguishes in its report.
CATEGORY_AUTH = "auth"
CATEGORY_CREDIT = "credit"
CATEGORY_MODEL = "model"
CATEGORY_TIMEOUT = "timeout"
CATEGORY_MALFORMED = "malformed"
CATEGORY_TRANSPORT = "transport"
CATEGORY_CONFIG = "config"
CATEGORY_UNKNOWN = "unknown"


class AdapterError(RuntimeError):
    """A generation attempt failed. ``category`` names the coarse cause."""

    def __init__(self, message: str, category: str = CATEGORY_UNKNOWN) -> None:
        super().__init__(message)
        self.category = category


@runtime_checkable
class Generator(Protocol):
    """Minimal interface the runner needs; a fake implements this in tests."""

    def generate(self, prompt: str) -> str:
        ...


@dataclass
class AdapterConfig:
    """Adapter configuration resolved from the environment.

    ``api_key`` is optional for a local SIE server but required for the cloud.
    It is never rendered by :meth:`redacted` and never logged.
    """

    base_url: str
    generate_model: str
    api_key: Optional[str] = None
    generate_url: Optional[str] = None
    timeout_s: float = 180.0
    # Reasoning models spend part of the budget on hidden reasoning before any
    # visible text, so the default is generous. Override with SIE_MAX_NEW_TOKENS.
    max_new_tokens: int = 4096
    # Optional text appended to every prompt. Model-agnostic escape hatch for
    # steering a specific served model (e.g. "/no_think" to stop a hybrid
    # reasoning model from spending the whole budget on hidden reasoning).
    prompt_suffix: str = ""

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "AdapterConfig":
        env = os.environ if env is None else env
        base_url = env.get("SIE_BASE_URL") or env.get("SIE_URL")
        generate_url = env.get("SIE_GENERATE_URL")
        generate_model = env.get("SIE_GENERATE_MODEL")
        api_key = env.get("SIE_API_KEY")
        max_tokens_raw = env.get("SIE_MAX_NEW_TOKENS")
        prompt_suffix = env.get("SIE_PROMPT_SUFFIX", "")

        # Fall back to a local server URL only when nothing else is configured.
        if not base_url and not generate_url:
            base_url = "http://localhost:8080"
        # The generate endpoint may run as its own server (local split setup).
        effective_base = generate_url or base_url
        if not effective_base:
            raise AdapterError(
                "no SIE endpoint configured: set SIE_BASE_URL (or SIE_GENERATE_URL)",
                CATEGORY_CONFIG,
            )
        if not generate_model:
            raise AdapterError(
                "SIE_GENERATE_MODEL is required (pick one from the SIE model catalogue)",
                CATEGORY_CONFIG,
            )
        kwargs = {}
        if max_tokens_raw:
            try:
                kwargs["max_new_tokens"] = int(max_tokens_raw)
            except ValueError:
                raise AdapterError(
                    f"SIE_MAX_NEW_TOKENS must be an integer, got {max_tokens_raw!r}",
                    CATEGORY_CONFIG,
                )
        return cls(
            base_url=base_url or effective_base,
            generate_model=generate_model,
            api_key=api_key,
            generate_url=generate_url,
            prompt_suffix=prompt_suffix,
            **kwargs,
        )

    @property
    def effective_url(self) -> str:
        """The URL generation actually targets."""
        return (self.generate_url or self.base_url).rstrip("/")

    def redacted(self) -> dict:
        """A log-safe view of the configuration (no credentials)."""
        return {
            "url": self.effective_url,
            "generate_model": self.generate_model,
            "authenticated": bool(self.api_key),
            "max_new_tokens": self.max_new_tokens,
            "prompt_suffix": self.prompt_suffix,
        }


def _categorize(exc: Exception) -> str:
    """Map an ``sie_sdk`` exception (or generic error) to a failure category."""
    # Imported lazily so the module imports even if the SDK is absent.
    try:
        from sie_sdk import exceptions as sie_exc  # noqa: F401
        from sie_sdk.client import errors as sie_errors
    except Exception:  # pragma: no cover - SDK always present in this pack
        sie_errors = None

    # A model that ran but produced no visible text (e.g. reasoning consumed the
    # whole budget) is a malformed-output problem, not an unavailable model.
    if getattr(exc, "code", None) == "empty_model_output":
        return CATEGORY_MALFORMED

    if sie_errors is not None:
        if isinstance(exc, sie_errors.InsufficientCreditsError) or isinstance(
            exc, getattr(sie_errors, "SpendLimitError", ())
        ):
            return CATEGORY_CREDIT
        if isinstance(exc, getattr(sie_errors, "AccountInactiveError", ())):
            return CATEGORY_AUTH
        if isinstance(
            exc,
            (
                getattr(sie_errors, "ModelLoadFailedError", ()),
                getattr(sie_errors, "ModelLoadingError", ()),
            ),
        ):
            return CATEGORY_MODEL
        if isinstance(exc, sie_errors.SIEConnectionError):
            return CATEGORY_TRANSPORT
        if isinstance(exc, sie_errors.RequestError):
            status = getattr(exc, "status_code", None)
            if status in (401, 403):
                return CATEGORY_AUTH
            if status == 402:
                return CATEGORY_CREDIT
            if status == 404:
                return CATEGORY_MODEL
            return CATEGORY_MALFORMED
        if isinstance(exc, sie_errors.ServerError):
            return CATEGORY_MODEL
        if isinstance(exc, sie_errors.SIEError):
            return CATEGORY_UNKNOWN

    if isinstance(exc, TimeoutError):
        return CATEGORY_TIMEOUT
    name = type(exc).__name__.lower()
    if "timeout" in name:
        return CATEGORY_TIMEOUT
    if "connection" in name:
        return CATEGORY_TRANSPORT
    return CATEGORY_UNKNOWN


class SIEGenerationAdapter:
    """A :class:`Generator` backed by the official ``sie-sdk`` client."""

    def __init__(self, config: AdapterConfig, client: Optional[object] = None) -> None:
        self.config = config
        self._client = client if client is not None else self._build_client()

    def _build_client(self):
        try:
            from sie_sdk import SIEClient
        except ImportError as exc:  # pragma: no cover
            raise AdapterError(
                "sie-sdk is not installed; run `pip install sie-sdk`", CATEGORY_CONFIG
            ) from exc
        return SIEClient(
            self.config.effective_url,
            api_key=self.config.api_key,
            timeout_s=self.config.timeout_s,
        )

    def generate(self, prompt: str, max_new_tokens: Optional[int] = None) -> str:
        """Run one generation and return the text, or raise :class:`AdapterError`.

        Any credential is kept out of the raised message: SDK error strings are
        not forwarded verbatim, only their category and type name.
        """
        tokens = max_new_tokens or self.config.max_new_tokens
        if self.config.prompt_suffix:
            prompt = f"{prompt}\n{self.config.prompt_suffix}"
        try:
            result = self._client.generate(
                self.config.generate_model,
                prompt,
                max_new_tokens=tokens,
                temperature=0.0,
            )
        except AdapterError:
            raise
        except Exception as exc:  # noqa: BLE001 - re-raised as a categorized error
            category = _categorize(exc)
            raise AdapterError(
                f"SIE generation failed ({category}: {type(exc).__name__})", category
            ) from None

        text = result.get("text") if isinstance(result, dict) else getattr(result, "text", None)
        if not text or not text.strip():
            raise AdapterError(
                "SIE generation returned an empty response", CATEGORY_MALFORMED
            )
        return text

    def preflight(self) -> None:
        """Confirm generation actually works before spending it on fixtures.

        Raises :class:`AdapterError` with a category if generation is
        unavailable, so ``--live-sie`` can exit non-zero with a clear reason.
        """
        try:
            # A reasoning model spends hidden tokens first, so give the preflight
            # enough budget to reach visible output.
            text = self.generate(
                "Reply with exactly the word: ok", max_new_tokens=512
            )
        except AdapterError:
            raise
        if not text.strip():
            raise AdapterError("preflight produced no text", CATEGORY_MALFORMED)

    def close(self) -> None:
        closer = getattr(self._client, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:  # pragma: no cover - best effort
                pass

"""Preflight helpers shared by CLI commands."""
from __future__ import annotations

from .sie_client import InferenceClient


REQUIRED_FOR_MAPPING = {"encode", "score", "generate"}


def run_preflight(client: InferenceClient):
    return client.preflight(REQUIRED_FOR_MAPPING)

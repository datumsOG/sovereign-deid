"""Provider API client — OpenAI-compatible chat completions endpoint.

base_url/key come from (internal path) via app.config (never hardcoded, never
logged). Every call MUST pass through app.deid_roundtrip.outbound_gate() first — this
module does not gate itself, callers (main.py) are required to gate before invoking it,
and a test asserts the route wiring does so.
"""
import httpx

from . import config

SYSTEM_PROMPT = (
    "You are a clinical summarization assistant. The text you receive has already been "
    "de-identified — patient identifiers are replaced with bracketed placeholders like "
    "[PATIENT_NAME_ab12cd]. Preserve every placeholder EXACTLY as given, verbatim, in your "
    "summary. Do not invent identifying details. Produce a concise clinical summary."
)


class ProviderError(Exception):
    pass


def complete(system: str, user: str, timeout: float = 30.0, temperature: float = 0.2) -> str:
    """One chat completion. The single place this module talks to Provider.

    Callers are still required to have run the appropriate gate first — this module
    deliberately does not gate itself, so that the gate is always visible at the call
    site rather than buried in a client.
    """
    if not config.PROVIDER_API_KEY or not config.PROVIDER_BASE_URL:
        raise ProviderError("Provider not configured (provider.env missing PROVIDER_API_KEY/PROVIDER_BASE_URL)")

    url = config.PROVIDER_BASE_URL.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.PROVIDER_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": config.PROVIDER_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
    }
    try:
        resp = httpx.post(url, headers=headers, json=body, timeout=timeout)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        # Generic error to caller; details (without the key/body) go to server logs only.
        raise ProviderError("Provider request failed") from e

    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise ProviderError("Unexpected Provider response shape") from e


def summarize(deidentified_text: str, timeout: float = 30.0) -> str:
    """Mode B: clinical summary of already-placeholdered text, placeholders preserved."""
    return complete(SYSTEM_PROMPT, deidentified_text, timeout=timeout, temperature=0.2)

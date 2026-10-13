"""Advanced de-identification — the public-release path.

Two features live in this webapp and they are deliberately different shapes:

  INTERNAL SUMMARY (deid_roundtrip.py, Mode B)
      deterministic map  ->  Provider summarises  ->  re-identify back into the vault.
      Reversible on purpose. Provider is a trusted processor, so placeholdered text is
      acceptable to send and the map never leaves the vault.

  PUBLIC RELEASE (this module)
      deterministic map  ->  Provider finds what the rules missed  ->  suppress it too.
      Irreversible on purpose. No map is kept for the released artefact. The output is
      intended to leave the trust boundary entirely.

The gap this closes is documented in docs/AUDIT-2026-07-23.md: Sovereign de-identifies
*structured* fields. It does not scrub free text. A clinical note that says "she still
sees Dr. Halloran at Sunnybrook, and her sister Mei drives her" contains three
identifiers that no field list and no regular expression will catch, because the
identifiers are only identifiable in context.

That is genuinely a language problem, so a language model is the right tool — but it is
the wrong tool to trust alone. Hence the ordering below.

ORDER MATTERS AND IT IS NOT NEGOTIABLE
    1. Deterministic pass first. Everything the rules DO know is already a placeholder
       before Provider sees a single character. Provider never receives a known identifier.
    2. Provider proposes SPANS, never rewrites. It returns the substrings it believes are
       residual identifiers plus a category. It does not get to author the released text.
    3. We apply the suppressions locally. Provider's output is advice; the redaction is
       performed here, on our side, deterministically, so a compromised or confused
       model cannot inject content into a released document.
    4. The release gate runs last and is stricter than the outbound gate. If anything
       identifier-shaped survives, the release is refused rather than published.

Step three is the important one. A model that both finds and fixes the problem is a
model you have to trust with the output. A model that only points is one you can check.
"""
import json
import logging
import re

from . import provider_client, config, deid_roundtrip

log = logging.getLogger("sovereign.advanced_deid")

# Categories Provider is allowed to propose. Anything else it returns is discarded rather
# than trusted — an open vocabulary would let the model invent a reason to redact (or
# not redact) arbitrary text.
ALLOWED_CATEGORIES = {
    "PERSON_NAME",       # clinicians, relatives, employers — anyone who is not the patient
    "ORGANISATION",      # hospitals, clinics, schools, workplaces
    "LOCATION",          # neighbourhoods, streets, landmarks
    "DATE",              # anything date-shaped the interval shift missed
    "CONTACT",           # phone, email, handle
    "ID_NUMBER",         # chart numbers, policy numbers, file references
    "RARE_ATTRIBUTE",    # an occupation/condition/event rare enough to single someone out
}

MAX_SPAN_LEN = 120       # a "span" longer than this is the model summarising, not pointing
MAX_SPANS = 200

FINDER_PROMPT = (
    "You are a privacy reviewer for Ontario clinical documents under PHIPA.\n\n"
    "The text below has ALREADY had its structured identifiers replaced with bracketed "
    "placeholders such as [PATIENT_NAME_ab12cd]. Your job is to find what a rule-based "
    "pass CANNOT catch: identifiers that only exist in prose.\n\n"
    "Look for: names of clinicians, relatives, friends, employers or schools; hospitals, "
    "clinics and organisations; neighbourhoods, streets and landmarks; dates; contact "
    "details; chart or file numbers; and any attribute so unusual that it could single a "
    "person out on its own.\n\n"
    "Rules:\n"
    "- NEVER alter, rewrite or repeat back the document. Only report spans.\n"
    "- Report each span EXACTLY as it appears, character for character.\n"
    "- Do NOT report the existing bracketed placeholders. They are already safe.\n"
    "- Do not report generic clinical language, diagnoses, medications or symptoms.\n"
    "- When uncertain, report it. A false positive costs a redaction. A false negative "
    "costs a person their privacy.\n\n"
    "Respond with JSON only, no prose, in exactly this form:\n"
    '{"spans":[{"text":"<exact substring>","category":"<one of '
    'PERSON_NAME|ORGANISATION|LOCATION|DATE|CONTACT|ID_NUMBER|RARE_ATTRIBUTE>"}]}\n'
)

_PLACEHOLDER_RE = re.compile(r"\[[A-Z_]+_[0-9a-f]{6}\]")


class AdvancedDeidError(Exception):
    pass


class ReleaseBlocked(Exception):
    """The release gate refused to publish. Carries category tags only, never text."""
    def __init__(self, reasons):
        self.reasons = reasons
        super().__init__(f"release blocked: {', '.join(reasons)}")


def _parse_spans(raw: str) -> list:
    """Pull the JSON object out of whatever the model returned, then validate hard.

    Every span is checked against the allowed vocabulary and the length cap, and anything
    failing is dropped with a log line. We would rather under-trust the model's output
    and rely on the release gate than accept a malformed instruction.
    """
    body = raw.strip()
    if body.startswith("```"):                       # strip markdown fences if present
        body = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", body).strip()
    start, end = body.find("{"), body.rfind("}")
    if start == -1 or end == -1:
        raise AdvancedDeidError("no JSON object in response")
    try:
        data = json.loads(body[start:end + 1])
    except ValueError as e:
        raise AdvancedDeidError("unparseable JSON in response") from e

    spans = []
    for item in (data.get("spans") or [])[:MAX_SPANS]:
        if not isinstance(item, dict):
            continue
        text = (item.get("text") or "").strip()
        category = (item.get("category") or "").strip().upper()
        if not text or len(text) > MAX_SPAN_LEN:
            continue
        if category not in ALLOWED_CATEGORIES:
            log.info("advanced_deid: dropped span with category=%r", category[:32])
            continue
        if _PLACEHOLDER_RE.fullmatch(text):          # already-safe placeholder
            continue
        spans.append({"text": text, "category": category})
    return spans


def find_residual_identifiers(deidentified_text: str, timeout: float = 45.0) -> list:
    """Ask Provider what the deterministic pass missed. Returns validated spans.

    The caller MUST have already run the deterministic pass and the outbound gate on
    `deidentified_text`. This function does not gate — same contract as provider_client.
    """
    raw = provider_client.complete(
        system=FINDER_PROMPT,
        user=deidentified_text,
        timeout=timeout,
        temperature=0.0,          # this is a detection task; sampling only adds variance
    )
    spans = _parse_spans(raw)
    log.info("advanced_deid: %d residual span(s) proposed", len(spans))
    return spans


def apply_suppressions(text: str, spans: list) -> tuple:
    """Redact every proposed span locally. Returns (redacted_text, applied_spans).

    Longest first, so a span that contains another cannot be half-replaced. Redaction is
    category-labelled and irreversible by construction — no map is produced, because the
    output of this path is meant to leave the trust boundary for good.
    """
    out = text
    applied = []
    for span in sorted(spans, key=lambda s: len(s["text"]), reverse=True):
        if span["text"] not in out:
            continue                                  # model hallucinated a substring
        out = out.replace(span["text"], f"[{span['category']}_REDACTED]")
        applied.append(span)
    return out, applied


# ---------------------------------------------------------- release gate ----

_RELEASE_PATTERNS = dict(deid_roundtrip._PATTERNS)
_RELEASE_PATTERNS.update({
    # Stricter than the outbound gate: outbound goes to a trusted processor, release
    # goes to the public. A bare capitalised full name is enough to refuse here.
    "capitalised_name_pair": re.compile(r"\b(?:Dr\.?|Mr\.?|Ms\.?|Mrs\.?)\s+[A-Z][a-z]+"),
    "postal_code": re.compile(r"\b[A-Z]\d[A-Z][ -]?\d[A-Z]\d\b"),
    "year_month_day_words": re.compile(
        r"\b(?:January|February|March|April|May|June|July|August|September|October|"
        r"November|December)\s+\d{1,2},?\s+\d{4}\b"),
})


def release_gate(text: str, known_values=None) -> None:
    """Last check before a document is published. Raises ReleaseBlocked.

    Refuses on anything identifier-shaped. Reason tags are categories only — the gate's
    own audit trail must never contain the text that tripped it.
    """
    reasons = []
    for value in (known_values or []):
        if value and value in text:
            reasons.append("known_identifier_value")
            break
    for name, pattern in _RELEASE_PATTERNS.items():
        if pattern.search(text):
            reasons.append(name)
    if reasons:
        raise ReleaseBlocked(sorted(set(reasons)))


def release(note_text: str, id_map: dict, timeout: float = 45.0) -> dict:
    """The full public-release path, in the order the module docstring commits to.

    Returns {"text", "spans", "deterministic_count", "advanced_count"}.
    Raises ReleaseBlocked if the result is not safe to publish, IdentifierLeakError if
    the deterministic pass left something before Provider was ever contacted, and
    AdvancedDeidError on an unusable response.
    """
    # 1. deterministic — Provider must never see a known identifier
    stage1 = deid_roundtrip.deidentify_text(note_text, id_map)
    deid_roundtrip.outbound_gate(stage1, known_values=id_map.keys())

    # 2. Provider points at what is left
    spans = find_residual_identifiers(stage1, timeout=timeout)

    # 3. we perform the redaction, locally
    stage2, applied = apply_suppressions(stage1, spans)

    # 4. stricter gate, last
    release_gate(stage2, known_values=id_map.keys())

    return {
        "text": stage2,
        "spans": applied,
        "deterministic_count": len(id_map),
        "advanced_count": len(applied),
    }

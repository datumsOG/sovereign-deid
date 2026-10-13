"""Mode B — round-trip de-identification for the Provider summary flow.

Per docs/PLAN-2026-07-23-the-rest.md: Mode A (src/deid/pseudonymize.py, one-way HMAC) is
untouched and stays irreversible by design for the release pipeline. Mode B is new: build
a per-document {real_value: placeholder} map, de-identify the free-text note by
substitution, send only the placeholdered text to Provider, then reverse the map on the
returned summary.

Wraps the existing pipeline where it fits: placeholder tokens get a short suffix derived
from src/deid/pseudonymize.hash_identifier (the project's existing salted HMAC helper) so
this reuses Sovereign's own keyed-hash primitive rather than reinventing one.
"""
import re
import sys
from pathlib import Path

_SOVEREIGN_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SOVEREIGN_SRC) not in sys.path:
    sys.path.insert(0, str(_SOVEREIGN_SRC))

from src.deid import pseudonymize  # noqa: E402  (existing Sovereign pipeline, reused not modified)

# Fixed dev salt for placeholder-suffix hashing only — NOT used for anything reversible
# via the hash itself (the map itself is what's reversible, stored sealed in the vault).
_SUFFIX_SALT = b"sovereign-webapp-roundtrip-suffix-salt-v1"

FIELD_LABELS = {
    "patient_name": "PATIENT_NAME",
    "dob": "DOB",
    "mrn": "MRN",
    "phone": "PHONE",
    "address": "ADDRESS",
    "email": "EMAIL",
    "next_of_kin": "NEXT_OF_KIN",
}


class IdentifierLeakError(Exception):
    """Raised by the outbound gate when a payload bound for Provider still contains a
    detected identifier. Belt-and-suspenders on top of the de-identify step."""
    def __init__(self, reasons):
        self.reasons = reasons
        super().__init__(f"outbound gate blocked: {', '.join(reasons)}")


def build_placeholder_map(identifiers: dict) -> dict:
    """{real_value: placeholder} for every non-empty identifier field on a document."""
    id_map = {}
    for field, value in identifiers.items():
        if not value:
            continue
        label = FIELD_LABELS.get(field, field.upper())
        suffix = pseudonymize.hash_identifier(value, _SUFFIX_SALT)[:6]
        placeholder = f"[{label}_{suffix}]"
        id_map[value] = placeholder
    return id_map


# A person's name appears in a clinical note in more forms than the one on the intake
# field. "Nadia Okonkwo-Reyes" is the stored identifier, but the body of the note says
# "Nadia" on its own, repeatedly. Exact whole-string replacement leaves every one of
# those, and no regular expression in the outbound gate matches a bare first name — so
# the patient's own name goes to the processor in the clear.
#
# Found 2026-08-09 on the first realistic psychoeducational note, which is exactly the
# document type where it matters most: unlike a session note, an assessment report is
# dense with names used informally.
#
# Components are only expanded for name-like fields, only when at least MIN_COMPONENT
# characters long, and only on word boundaries. Short fragments are skipped because a
# three-letter surname would shred ordinary prose.
_NAME_FIELDS = ("patient_name", "next_of_kin")
MIN_COMPONENT = 4


def expand_name_components(identifiers: dict, id_map: dict) -> dict:
    """Add first/last-name components to the map, pointing at the same placeholder."""
    expanded = dict(id_map)
    for field in _NAME_FIELDS:
        full = (identifiers or {}).get(field)
        if not full or full not in id_map:
            continue
        placeholder = id_map[full]
        for part in re.split(r"[\s\-]+", full):
            part = part.strip()
            if len(part) >= MIN_COMPONENT and part not in expanded:
                expanded[part] = placeholder
    return expanded


def deidentify_text(text: str, id_map: dict) -> str:
    """Substitute every real value with its placeholder.

    Longest values first, so a value that is a substring of another (a street number
    inside a phone number) cannot cause a partial, corrupting replacement. Single-word
    values are replaced on word boundaries only, so a surname does not also rewrite the
    middle of an unrelated word.
    """
    out = text
    for real_value in sorted(id_map, key=len, reverse=True):
        if " " in real_value:
            out = out.replace(real_value, id_map[real_value])
        else:
            out = re.sub(r"\b" + re.escape(real_value) + r"\b", id_map[real_value], out)
    return out


def reidentify_text(text: str, id_map: dict) -> str:
    """Reverse substitution: placeholder -> real value, applied to Provider's summary."""
    out = text
    for real_value, placeholder in id_map.items():
        out = out.replace(placeholder, real_value)
    return out


# ---------- outbound gate: belt-and-suspenders identifier detection ----------

_PATTERNS = {
    "email_pattern": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone_pattern": re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"),
    "iso_date_pattern": re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    "slash_date_pattern": re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b"),
    "mrn_pattern": re.compile(r"\bMRN[-\s]?\d{3,}\b", re.IGNORECASE),
    "ohip_pattern": re.compile(r"\b\d{4}[-\s]?\d{3}[-\s]?\d{3}[-\s]?[A-Z]{2}\b"),
    "sin_pattern": re.compile(r"\b\d{3}[-\s]\d{3}[-\s]\d{3}\b"),
}


def detect_identifiers(text: str, known_values=None) -> list:
    """Returns a list of short CATEGORY tags (never the matched text itself — the gate's
    own audit trail must stay PHI-free) describing what tripped. Two layers:
    1. Any known real identifier value for this document still present verbatim.
    2. Generic identifier-shaped patterns (phone/date/MRN/etc) as a safety net for
       anything the structured de-identify step didn't know about — this does NOT claim
       to catch arbitrary free-text PHI (see docs/AUDIT-2026-07-23.md free-text gap;
       SECURITY.md repeats this honestly)."""
    reasons = []
    for value in (known_values or []):
        if value and value in text:
            reasons.append("known_identifier_value")
            break
    for name, pattern in _PATTERNS.items():
        if pattern.search(text):
            reasons.append(name)
    return reasons


def outbound_gate(text: str, known_values=None) -> None:
    """Raise IdentifierLeakError if `text` is not safe to send to Provider. Call this on
    EVERY payload immediately before the API call, no exceptions."""
    reasons = detect_identifiers(text, known_values)
    if reasons:
        raise IdentifierLeakError(reasons)

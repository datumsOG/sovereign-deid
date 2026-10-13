"""Tests for the public-release path and the stale-map leak fix.

The two things being pinned here are both real defects found on 2026-08-04:

  1. summarize() trusted any stored map that existed, so a document that gained an
     identifier after its map was written sent that identifier to Provider in the clear.
     doc-001 was live in exactly that state.

  2. Provider's advanced pass must only ever *propose* spans. If it can rewrite the text,
     it can inject content into a published clinical document.
"""
import json

import pytest

from app import advanced_deid as ad
from app import deid_roundtrip, vault


# ------------------------------------------------------------ span parsing ----

def test_parses_fenced_json_and_drops_invalid_spans():
    raw = (
        "```json\n"
        + json.dumps({"spans": [
            {"text": "Dr. Halloran", "category": "PERSON_NAME"},
            {"text": "x", "category": "NOT_A_REAL_CATEGORY"},      # unknown vocabulary
            {"text": "[PATIENT_NAME_ab12cd]", "category": "PERSON_NAME"},  # already safe
            {"text": "y" * (ad.MAX_SPAN_LEN + 1), "category": "LOCATION"},  # too long
            {"text": "", "category": "LOCATION"},                   # empty
        ]})
        + "\n```"
    )
    spans = ad._parse_spans(raw)
    assert [s["text"] for s in spans] == ["Dr. Halloran"]


def test_unparseable_response_raises_rather_than_guessing():
    with pytest.raises(ad.AdvancedDeidError):
        ad._parse_spans("I'm sorry, I can't help with that.")


def test_span_cap_is_enforced():
    raw = json.dumps({"spans": [
        {"text": f"name{i}", "category": "PERSON_NAME"} for i in range(ad.MAX_SPANS + 50)
    ]})
    assert len(ad._parse_spans(raw)) <= ad.MAX_SPANS


# -------------------------------------------------------------- suppression ----

def test_suppression_is_local_labelled_and_irreversible():
    text = "She still sees Dr. Halloran at Sunnybrook, and her sister Mei drives her."
    spans = [
        {"text": "Dr. Halloran", "category": "PERSON_NAME"},
        {"text": "Sunnybrook", "category": "ORGANISATION"},
        {"text": "Mei", "category": "PERSON_NAME"},
    ]
    out, applied = ad.apply_suppressions(text, spans)
    assert "Halloran" not in out and "Sunnybrook" not in out
    assert "[PERSON_NAME_REDACTED]" in out and "[ORGANISATION_REDACTED]" in out
    assert len(applied) == 3
    # irreversible by construction: nothing in the output identifies the original value
    assert "Mei" not in out


def test_hallucinated_span_is_ignored_not_applied():
    text = "Patient reports improved sleep."
    out, applied = ad.apply_suppressions(
        text, [{"text": "Dr. Nobody", "category": "PERSON_NAME"}])
    assert out == text
    assert applied == []


def test_longest_span_applied_first_so_nesting_cannot_corrupt():
    text = "Referred to Sunnybrook Health Sciences Centre today."
    spans = [
        {"text": "Sunnybrook", "category": "ORGANISATION"},
        {"text": "Sunnybrook Health Sciences Centre", "category": "ORGANISATION"},
    ]
    out, _ = ad.apply_suppressions(text, spans)
    assert out.count("[ORGANISATION_REDACTED]") == 1
    assert "Health Sciences" not in out


# ------------------------------------------------------------- release gate ----

@pytest.mark.parametrize("text", [
    "Follow up with Dr. Smith next week.",
    "Lives near M5V 2T6.",
    "Seen on March 14, 2026 for review.",
    "Call 416-555-0142.",
    "Chart MRN-48213 reviewed.",
])
def test_release_gate_refuses_identifier_shapes(text):
    with pytest.raises(ad.ReleaseBlocked):
        ad.release_gate(text)


def test_release_gate_reasons_never_contain_the_matched_text():
    try:
        ad.release_gate("Follow up with Dr. Halloran.")
    except ad.ReleaseBlocked as e:
        assert all("Halloran" not in r for r in e.reasons)
    else:
        pytest.fail("expected ReleaseBlocked")


def test_release_gate_passes_clean_placeholdered_text():
    ad.release_gate(
        "[PATIENT_NAME_ab12cd] reports improved sleep after [ORGANISATION_REDACTED] referral.")


def test_release_gate_is_stricter_than_the_outbound_gate():
    """Outbound goes to a trusted processor; release goes to the public."""
    text = "Follow up with Dr. Smith."
    deid_roundtrip.outbound_gate(text)          # trusted path allows it
    with pytest.raises(ad.ReleaseBlocked):      # public path does not
        ad.release_gate(text)


# ------------------------------------------------- the stale-map leak fix ----

def test_merge_map_covers_new_identifiers(tmp_path, monkeypatch):
    monkeypatch.setattr(vault.config, "VAULT_DIR", tmp_path)
    vault.save_map("doc-x", {"Jordan Marlowe": "[PATIENT_NAME_old123]"})
    fresh = deid_roundtrip.build_placeholder_map({
        "patient_name": "Jordan Marlowe",
        "dob": "1991-04-12",
        "mrn": "MRN-48213",
    })
    merged = vault.merge_map("doc-x", fresh)

    # every current identifier is covered — this is the bug that leaked
    assert set(merged) >= set(fresh)
    # the historical placeholder is preserved so old summaries stay reversible
    assert merged["Jordan Marlowe"] == "[PATIENT_NAME_old123]"


def test_merge_map_retains_values_dropped_from_the_document(tmp_path, monkeypatch):
    monkeypatch.setattr(vault.config, "VAULT_DIR", tmp_path)
    vault.save_map("doc-x", {"Old Name": "[PATIENT_NAME_gone01]"})
    merged = vault.merge_map("doc-x", {"New Name": "[PATIENT_NAME_new001]"})
    assert merged["Old Name"] == "[PATIENT_NAME_gone01]"   # old exports stay reversible
    assert merged["New Name"] == "[PATIENT_NAME_new001]"


def test_stale_map_would_have_leaked_without_merge(tmp_path, monkeypatch):
    """The regression itself, stated as a test."""
    monkeypatch.setattr(vault.config, "VAULT_DIR", tmp_path)
    note = "Jordan Marlowe (DOB 1991-04-12) lives at 118 Birchwood Crescent, Toronto, ON."
    identifiers = {
        "patient_name": "Jordan Marlowe",
        "dob": "1991-04-12",
        "address": "118 Birchwood Crescent, Toronto, ON",
    }
    vault.save_map("doc-x", {"Jordan Marlowe": "[PATIENT_NAME_old123]"})   # stale, 1 entry

    stale = vault.load_map("doc-x")
    leaked = deid_roundtrip.deidentify_text(note, stale)
    assert "118 Birchwood Crescent" in leaked          # the address would have gone out

    merged = vault.merge_map("doc-x", deid_roundtrip.build_placeholder_map(identifiers))
    safe = deid_roundtrip.deidentify_text(note, merged)
    assert "118 Birchwood Crescent" not in safe
    assert "Jordan Marlowe" not in safe


# ----------------------------------------------------- summaries at rest ----

def test_summaries_are_encrypted_at_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(vault.config, "VAULT_DIR", tmp_path)
    secret = "[PATIENT_NAME_ab12cd] reports improved sleep."
    vault.save_summary("doc-x", secret)
    on_disk = (tmp_path / "doc-x.summary.enc").read_bytes()
    assert secret.encode() not in on_disk
    assert vault.load_summary("doc-x") == secret


def test_missing_summary_returns_none_rather_than_raising(tmp_path, monkeypatch):
    monkeypatch.setattr(vault.config, "VAULT_DIR", tmp_path)
    assert vault.load_summary("doc-nope") is None


# ------------------------------------------------- name components in prose ----
# Found 2026-08-09 on the first realistic psychoeducational note. The stored identifier
# is the full name; the body of the note says the first name on its own, repeatedly. No
# outbound-gate pattern matches a bare first name, so it reached the processor in clear.

def test_first_name_alone_is_redacted():
    identifiers = {"patient_name": "Nadia Okonkwo-Reyes", "mrn": "MRN-88214"}
    base = deid_roundtrip.build_placeholder_map(identifiers)
    id_map = deid_roundtrip.expand_name_components(identifiers, base)
    text = "Nadia Okonkwo-Reyes attended. Her mother asked whether Nadia is struggling."
    out = deid_roundtrip.deidentify_text(text, id_map)
    assert "Nadia" not in out
    assert "Okonkwo" not in out and "Reyes" not in out


def test_name_components_share_the_full_name_placeholder():
    identifiers = {"patient_name": "Nadia Okonkwo-Reyes"}
    id_map = deid_roundtrip.expand_name_components(
        identifiers, deid_roundtrip.build_placeholder_map(identifiers))
    assert id_map["Nadia"] == id_map["Nadia Okonkwo-Reyes"]


def test_short_name_fragments_are_not_expanded():
    """A three-letter surname would shred ordinary prose."""
    identifiers = {"patient_name": "Al Ng"}
    id_map = deid_roundtrip.expand_name_components(
        identifiers, deid_roundtrip.build_placeholder_map(identifiers))
    assert "Al" not in id_map and "Ng" not in id_map


def test_single_word_values_replace_on_word_boundaries_only():
    identifiers = {"patient_name": "Grant Fisher"}
    id_map = deid_roundtrip.expand_name_components(
        identifiers, deid_roundtrip.build_placeholder_map(identifiers))
    out = deid_roundtrip.deidentify_text(
        "Grant Fisher received a grant. Fisherman noted.", id_map)
    assert "received a grant" in out       # lowercase common word untouched
    assert "Fisherman noted" in out        # not rewritten mid-word
    assert "Grant Fisher " not in out


def test_non_name_fields_are_not_split_into_components():
    """Splitting an address would replace 'Lane' and 'Barrie' across the document."""
    identifiers = {"patient_name": "Nadia Reyes", "address": "17 Fernbrook Lane, Barrie, ON"}
    id_map = deid_roundtrip.expand_name_components(
        identifiers, deid_roundtrip.build_placeholder_map(identifiers))
    assert "Fernbrook" not in id_map and "Barrie" not in id_map

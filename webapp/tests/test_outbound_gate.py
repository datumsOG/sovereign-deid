import pytest

from app import deid_roundtrip as dr


def test_gate_blocks_text_containing_a_known_identifier_value():
    text = "Patient Jordan Marlowe was seen today."
    with pytest.raises(dr.IdentifierLeakError) as exc:
        dr.outbound_gate(text, known_values=["Jordan Marlowe"])
    assert "known_identifier_value" in exc.value.reasons


def test_gate_blocks_phone_shaped_pattern_even_without_known_value_match():
    text = "Contact at 416-555-0142 for follow-up."
    with pytest.raises(dr.IdentifierLeakError) as exc:
        dr.outbound_gate(text, known_values=[])
    assert "phone_pattern" in exc.value.reasons


def test_gate_blocks_iso_date_pattern():
    text = "DOB 1991-04-12 noted in chart."
    with pytest.raises(dr.IdentifierLeakError) as exc:
        dr.outbound_gate(text, known_values=[])
    assert "iso_date_pattern" in exc.value.reasons


def test_gate_blocks_mrn_pattern():
    text = "See chart MRN-48213 for history."
    with pytest.raises(dr.IdentifierLeakError) as exc:
        dr.outbound_gate(text, known_values=[])
    assert "mrn_pattern" in exc.value.reasons


def test_gate_allows_clean_deidentified_text():
    text = "[PATIENT_NAME_ab12cd] presented with anxiety and insomnia."
    dr.outbound_gate(text, known_values=["Jordan Marlowe"])  # must not raise


def test_gate_reasons_never_contain_the_matched_phi_text():
    # Regression guard for "no PHI in logs/errors": reasons must be fixed category tags.
    text = "Jordan Marlowe, phone 416-555-0142, MRN-48213"
    with pytest.raises(dr.IdentifierLeakError) as exc:
        dr.outbound_gate(text, known_values=["Jordan Marlowe"])
    for reason in exc.value.reasons:
        assert "Jordan" not in reason
        assert "416" not in reason
        assert "48213" not in reason


def test_full_deidentified_demo_document_passes_the_gate():
    """End-to-end sanity: after real Mode-B de-identification of a demo doc, the
    resulting text must be clean enough to pass the gate (or the demo flow itself
    would be broken)."""
    identifiers = {
        "patient_name": "Jordan Marlowe",
        "dob": "1991-04-12",
        "mrn": "MRN-48213",
        "phone": "416-555-0142",
        "address": "118 Birchwood Crescent, Toronto, ON",
    }
    note = ("Jordan Marlowe (DOB 1991-04-12, MRN-48213) can be reached at 416-555-0142, "
            "residing at 118 Birchwood Crescent, Toronto, ON. Reports mild anxiety.")
    id_map = dr.build_placeholder_map(identifiers)
    deid_text = dr.deidentify_text(note, id_map)
    dr.outbound_gate(deid_text, known_values=id_map.keys())  # must not raise
    for real_value in identifiers.values():
        assert real_value not in deid_text

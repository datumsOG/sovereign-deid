from app import deid_roundtrip as dr


IDENTIFIERS = {
    "patient_name": "Priya Chandrasekaran",
    "dob": "1978-11-02",
    "mrn": "MRN-77031",
    "phone": "647-555-0198",
    "address": "22 Lakeshore Blvd, Etobicoke, ON",
}
NOTE = ("Priya Chandrasekaran (DOB 1978-11-02, MRN-77031, contact 647-555-0198, address "
        "22 Lakeshore Blvd, Etobicoke, ON) returns for a follow-up visit.")


def test_build_map_has_a_unique_placeholder_per_identifier():
    id_map = dr.build_placeholder_map(IDENTIFIERS)
    assert len(id_map) == len(IDENTIFIERS)
    assert len(set(id_map.values())) == len(id_map)  # placeholders are unique


def test_deidentify_removes_every_real_value():
    id_map = dr.build_placeholder_map(IDENTIFIERS)
    deid = dr.deidentify_text(NOTE, id_map)
    for real_value in IDENTIFIERS.values():
        assert real_value not in deid
    for placeholder in id_map.values():
        assert placeholder in deid


def test_reidentify_is_the_exact_inverse_of_deidentify_on_the_note_itself():
    id_map = dr.build_placeholder_map(IDENTIFIERS)
    deid = dr.deidentify_text(NOTE, id_map)
    restored = dr.reidentify_text(deid, id_map)
    assert restored == NOTE


def test_reidentify_restores_placeholders_inside_a_summary_shaped_text():
    """Simulates the real flow: Provider returns a summary (not the original note) that
    contains the placeholders verbatim; re-id must substitute correctly there too."""
    id_map = dr.build_placeholder_map(IDENTIFIERS)
    name_ph = id_map[IDENTIFIERS["patient_name"]]
    phone_ph = id_map[IDENTIFIERS["phone"]]
    fake_summary = f"{name_ph} reports improved mood. Reachable at {phone_ph}."
    restored = dr.reidentify_text(fake_summary, id_map)
    assert IDENTIFIERS["patient_name"] in restored
    assert IDENTIFIERS["phone"] in restored
    assert name_ph not in restored
    assert phone_ph not in restored


def test_longest_value_first_avoids_partial_substring_corruption():
    # A value that is a substring of another must not corrupt the longer replacement.
    identifiers = {"patient_name": "Ann", "next_of_kin": "Anna Smith"}
    id_map = dr.build_placeholder_map(identifiers)
    text = "Ann called about Anna Smith's appointment."
    deid = dr.deidentify_text(text, id_map)
    assert "Ann" not in deid.replace(id_map["Anna Smith"], "").replace(id_map["Ann"], "")
    restored = dr.reidentify_text(deid, id_map)
    assert restored == text

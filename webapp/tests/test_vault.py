import pytest


def test_save_and_load_map_roundtrips(isolated_app):
    from app import vault
    _main, _client = isolated_app
    id_map = {"Jordan Marlowe": "[PATIENT_NAME_ab12cd]", "416-555-0142": "[PHONE_ef34gh]"}
    vault.save_map("doc-001", id_map)
    loaded = vault.load_map("doc-001")
    assert loaded == id_map


def test_missing_map_returns_empty_dict(isolated_app):
    from app import vault
    _main, _client = isolated_app
    assert vault.load_map("doc-does-not-exist") == {}


def test_map_is_encrypted_at_rest_not_plaintext_on_disk(isolated_app):
    from app import vault
    import app.config as config
    _main, _client = isolated_app
    id_map = {"Jordan Marlowe": "[PATIENT_NAME_ab12cd]"}
    vault.save_map("doc-001", id_map)
    raw = (config.VAULT_DIR / "doc-001.map.enc").read_bytes()
    assert b"Jordan Marlowe" not in raw
    assert b"PATIENT_NAME" not in raw


def test_rejects_path_traversal_doc_id(isolated_app):
    from app import vault
    _main, _client = isolated_app
    with pytest.raises(ValueError):
        vault.save_map("../../etc/passwd", {"x": "y"})

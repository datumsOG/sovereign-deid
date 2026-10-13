"""Test fixtures — an isolated webapp instance per test run (own data/secrets/vault/audit
dirs via a temp WEBAPP_DIR override) so tests never touch real seeded accounts."""
import importlib
import sys
from pathlib import Path

import pytest

WEBAPP_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WEBAPP_ROOT))


@pytest.fixture()
def isolated_app(tmp_path, monkeypatch):
    """Reload app.config (and dependents) pointed at a scratch directory so each test
    gets fresh users/vault/audit state, then return the FastAPI app + a TestClient."""
    submodule_names = ["config", "users", "audit", "vault", "deps",
                       "security", "deid_roundtrip", "documents", "main"]
    for name in submodule_names:
        sys.modules.pop(f"app.{name}", None)
        # `sys.modules.pop` alone isn't enough: the parent package object keeps a
        # stale attribute reference (set by the previous import) that `from app
        # import X` will happily return without re-importing. Clear it too so every
        # test genuinely gets a fresh module bound to this test's tmp_path.
        if "app" in sys.modules:
            sys.modules["app"].__dict__.pop(name, None)

    import app.config as config
    # NOTE: WEBAPP_DIR stays pointed at the real project dir (static/templates live
    # there); only the mutable data dirs are redirected into the scratch tmp_path.
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "SECRETS_DIR", tmp_path / "secrets")
    monkeypatch.setattr(config, "VAULT_DIR", tmp_path / "vault")
    monkeypatch.setattr(config, "AUDIT_DIR", tmp_path / "audit")
    monkeypatch.setattr(config, "DEMO_DATA_DIR", WEBAPP_ROOT / "demo_data")
    for d in (config.DATA_DIR, config.SECRETS_DIR, config.VAULT_DIR, config.AUDIT_DIR):
        d.mkdir(parents=True, exist_ok=True)

    import app.main as main
    from fastapi.testclient import TestClient
    return main, TestClient(main.app)

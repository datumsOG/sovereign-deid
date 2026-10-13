"""Sovereign webapp — paths, secret bootstrap, env loading.

Secrets policy (Sovereign Rule #1 extends to this component):
- Provider API key is loaded from (internal path) — never hardcoded, never logged.
- Session-signing secret and the vault (re-id map) encryption key are generated on first
  run into webapp/secrets/ (0600, gitignored) — never committed, never printed after
  creation.
"""
import os
import stat
from pathlib import Path

WEBAPP_DIR = Path(__file__).resolve().parent.parent
SOVEREIGN_DIR = WEBAPP_DIR.parent

DATA_DIR = WEBAPP_DIR / "data"           # users.json — 0600, gitignored
SECRETS_DIR = WEBAPP_DIR / "secrets"     # generated keys — 0600, gitignored
VAULT_DIR = WEBAPP_DIR / "vault"         # encrypted per-doc re-id maps — gitignored
AUDIT_DIR = WEBAPP_DIR / "audit"         # append-only audit log — gitignored
DEMO_DATA_DIR = WEBAPP_DIR / "demo_data" # synthetic documents — committed, fully synthetic

for d in (DATA_DIR, SECRETS_DIR, VAULT_DIR, AUDIT_DIR):
    d.mkdir(parents=True, exist_ok=True)


def _load_env_file(path: Path) -> dict:
    """Minimal KEY=VALUE .env parser (stdlib only). Never logs values."""
    out = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


_provider_env = _load_env_file(SOVEREIGN_DIR / "provider.env")
PROVIDER_API_KEY = os.environ.get("PROVIDER_API_KEY", _provider_env.get("PROVIDER_API_KEY", ""))
PROVIDER_BASE_URL = os.environ.get("PROVIDER_BASE_URL", _provider_env.get("PROVIDER_BASE_URL", ""))
PROVIDER_MODEL = "tofino-2.5"


def _bootstrap_secret_file(name: str, generator) -> bytes:
    """Return bytes from webapp/secrets/<name>, generating+writing (mode 0600) on first use."""
    p = SECRETS_DIR / name
    if p.exists():
        return p.read_bytes()
    value = generator()
    p.write_bytes(value)
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return value


def session_secret() -> bytes:
    return _bootstrap_secret_file("session_secret.key", lambda: os.urandom(32))


def vault_key() -> bytes:
    from cryptography.fernet import Fernet
    return _bootstrap_secret_file("vault.key", Fernet.generate_key)


# Cookie security: set APP_ENV=production (behind TLS) to require Secure cookies.
# Local demo over plain http defaults to non-secure cookies so the browser will
# actually store them — documented as a required change before real deployment.
IS_PRODUCTION = os.environ.get("APP_ENV", "development") == "production"

# Session cookies inside a Microsoft Teams tab.
#
# A Teams tab renders this app in a cross-site iframe. A SameSite=lax cookie is NOT sent
# on a cross-site framed request, so with lax the Teams tab shows the login page, accepts
# the password and TOTP, sets a cookie the browser then refuses to return, and lands back
# on the login page forever. It looks like broken auth; it is a cookie policy.
#
# SameSite=none is the fix, and the browser only honours it together with Secure — which
# is exactly why this follows IS_PRODUCTION. In development over plain HTTP we stay on
# lax, because none+insecure is rejected outright and lax is the safer local default.
COOKIE_SAMESITE = "none" if IS_PRODUCTION else "lax"

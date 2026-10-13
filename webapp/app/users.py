"""User store — a small JSON file (0600, gitignored), not a database. V1 scale (2 demo
accounts) doesn't warrant more; SECURITY.md flags this as a pre-real-PHI upgrade item
(a real DB with row-level locking) if the user base grows.
"""
import json
import os
import stat
from pathlib import Path
from typing import Optional

from . import config

USERS_FILE = config.DATA_DIR / "users.json"

ROLE_STAFF = "staff"
ROLE_ADMIN = "admin"
VALID_ROLES = (ROLE_STAFF, ROLE_ADMIN)


def _load() -> dict:
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text())


def _save(users: dict) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2))
    os.chmod(USERS_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def get_user(username: str) -> Optional[dict]:
    return _load().get(username)


def create_user(username: str, password_hash: str, role: str) -> None:
    assert role in VALID_ROLES
    users = _load()
    users[username] = {
        "username": username,
        "password_hash": password_hash,
        "role": role,
        "totp_secret": None,
        "totp_confirmed": False,
    }
    _save(users)


def set_totp_secret(username: str, secret: str) -> None:
    users = _load()
    if username not in users:
        raise KeyError(username)
    users[username]["totp_secret"] = secret
    _save(users)


def confirm_totp(username: str) -> None:
    users = _load()
    if username not in users:
        raise KeyError(username)
    users[username]["totp_confirmed"] = True
    _save(users)

"""Auth primitives: password hashing (bcrypt), TOTP 2FA (pyotp/RFC 6238), and
signed session cookies (itsdangerous). No PHI ever passes through this module.
"""
import base64
import io
import time

import bcrypt
import pyotp
import qrcode
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from . import config

SESSION_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hour session lifetime


# ---------- passwords ----------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# ---------- TOTP (RFC 6238) ----------

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str, issuer: str = "Sovereign") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def totp_qr_data_uri(secret: str, username: str) -> str:
    """Render the TOTP enrollment URI as a QR code PNG, returned as a data: URI
    so it can be embedded directly in the enrollment page with no file egress."""
    uri = totp_provisioning_uri(secret, username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False


# ---------- signed session cookies ----------

def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.session_secret(), salt="sovereign-webapp-session")


def create_session_token(username: str, role: str) -> str:
    return _serializer().dumps({"u": username, "r": role, "t": int(time.time())})


def read_session_token(token: str):
    """Returns {"u":..., "r":...} or None if missing/invalid/expired. Never raises."""
    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE_SECONDS)
        return {"u": data["u"], "r": data["r"]}
    except (BadSignature, SignatureExpired, KeyError, TypeError):
        return None

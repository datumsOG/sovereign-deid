import pyotp

from app import security


def test_verify_totp_accepts_correct_current_code():
    secret = security.generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert security.verify_totp(secret, code) is True


def test_verify_totp_rejects_wrong_code():
    secret = security.generate_totp_secret()
    assert security.verify_totp(secret, "000000") is False


def test_verify_totp_rejects_code_from_a_different_secret():
    secret_a = security.generate_totp_secret()
    secret_b = security.generate_totp_secret()
    code_for_b = pyotp.TOTP(secret_b).now()
    assert security.verify_totp(secret_a, code_for_b) is False


def test_verify_totp_rejects_empty_or_missing_code():
    secret = security.generate_totp_secret()
    assert security.verify_totp(secret, "") is False
    assert security.verify_totp(secret, None) is False


def test_password_hash_roundtrip():
    h = security.hash_password("correct horse battery staple")
    assert security.verify_password("correct horse battery staple", h) is True
    assert security.verify_password("wrong password", h) is False


def test_session_token_roundtrip_and_tamper_detection():
    token = security.create_session_token("admin", "admin")
    data = security.read_session_token(token)
    assert data == {"u": "admin", "r": "admin"}
    # Tampering with the token must invalidate it (signature check).
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    assert security.read_session_token(tampered) is None
    assert security.read_session_token("not-a-real-token") is None

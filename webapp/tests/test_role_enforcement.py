"""The core security property: staff CANNOT export, enforced server-side, and role is
re-derived from the current user record every request (not trusted from the cookie).

NOTE: app.security / app.users are imported INSIDE each test (after the isolated_app
fixture has run and repointed app.config at a scratch dir) — importing them at module
level would bind to whatever module instance existed at collection time and could leak
test state into the real project's webapp/data/.
"""
import pyotp


def _seed_and_login(users, security, client, username, role):
    users.create_user(username, security.hash_password("Sup3rSecret!"), role)
    secret = security.generate_totp_secret()
    users.set_totp_secret(username, secret)
    users.confirm_totp(username)
    code = pyotp.TOTP(secret).now()
    resp = client.post("/login", data={"username": username, "password": "Sup3rSecret!", "totp_code": code})
    assert resp.status_code in (200, 303)
    return resp


def test_unauthenticated_request_is_rejected(isolated_app):
    _main, client = isolated_app
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 401


def test_staff_gets_403_on_export_not_just_a_hidden_button(isolated_app):
    from app import security, users
    _main, client = isolated_app
    _seed_and_login(users, security, client, "staff1", users.ROLE_STAFF)
    resp = client.get("/doc/doc-001/export", follow_redirects=False)
    assert resp.status_code == 403


def test_admin_can_export(isolated_app):
    from app import security, users
    _main, client = isolated_app
    _seed_and_login(users, security, client, "admin1", users.ROLE_ADMIN)
    client.post("/doc/doc-001/deidentify")
    # summarize hits the real Provider API — skip network call here, exercise export's
    # own guard path by asserting it 400s cleanly (nothing summarized yet) rather than
    # ever returning staff-style 403 for an admin.
    resp = client.get("/doc/doc-001/export", follow_redirects=False)
    assert resp.status_code in (400, 200)  # never 403 for an admin


def test_role_is_re_derived_from_current_user_record_not_trusted_from_cookie(isolated_app):
    """An admin's signed session cookie encodes role=admin at login time. If that
    account is downgraded to staff server-side, the SAME still-valid cookie must now be
    treated as staff on the very next request — proving role isn't just trusted from the
    token payload."""
    from app import security, users
    _main, client = isolated_app
    _seed_and_login(users, security, client, "flipper", users.ROLE_ADMIN)
    resp = client.get("/doc/doc-001/export", follow_redirects=False)
    assert resp.status_code in (400, 200)  # admin, so not 403

    # Downgrade server-side, same browser session/cookie.
    all_users = users._load()
    all_users["flipper"]["role"] = users.ROLE_STAFF
    users._save(all_users)

    resp2 = client.get("/doc/doc-001/export", follow_redirects=False)
    assert resp2.status_code == 403

"""FastAPI auth dependencies. Role checks happen HERE, server-side, on every protected
route — never inferred from what the UI happens to render."""
from fastapi import Cookie, HTTPException, status

from . import security, users

SESSION_COOKIE = "sv_session"
PENDING_COOKIE = "sv_pending"


def get_current_user(sv_session: str = Cookie(default=None)):
    session = security.read_session_token(sv_session)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user = users.get_user(session["u"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    # Role is re-derived from the CURRENT user record, not trusted from the cookie alone,
    # so a role change/revocation takes effect on the next request even with a live cookie.
    return {"username": user["username"], "role": user["role"]}


def require_admin(user: dict = None):
    """Use as: user = Depends(get_current_user); require_admin(user)."""
    if user["role"] != users.ROLE_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user


def get_pending_user(sv_pending: str = Cookie(default=None)):
    session = security.read_session_token(sv_pending)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return session["u"]

"""Sovereign webapp — FastAPI entrypoint.

Security posture summary (full detail in webapp/SECURITY.md):
- Auth: bcrypt password + mandatory TOTP (pyotp, RFC 6238), signed session cookies.
- Roles enforced server-side via FastAPI dependencies (deps.py), not the UI.
- Outbound gate (deid_roundtrip.outbound_gate) runs on every payload before it reaches
  Provider; a failure is a hard error, logged, never sent.
- No PHI in logs or error messages returned to the client — errors are generic; detail
  goes to the server-side logger only, and never includes document text.
- SYNTHETIC DATA ONLY. This app must never be pointed at sealed/ or any real-PHI path.
"""
import logging

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import (advanced_deid, audit, provider_client, config, deid_roundtrip, deps, documents,
               security, users, vault)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sovereign.webapp")

# docs_url/redoc_url were disabled but openapi_url was not, so /openapi.json served an
# unauthenticated list of every route. Closed in production; kept in development because
# it is genuinely useful for confirming which code a running process is actually serving.
app = FastAPI(
    title="Sovereign",
    docs_url=None, redoc_url=None,
    openapi_url=None if config.IS_PRODUCTION else "/openapi.json",
)
app.mount("/static", StaticFiles(directory=str(config.WEBAPP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(config.WEBAPP_DIR / "templates"))

GENERIC_ERROR = "Something went wrong. Please try again."


@app.on_event("startup")
async def _log_build():
    """Say out loud what this process is actually serving.

    A stale process served four-day-old code because each restart hit an already-bound
    port and exited, while the guard checking whether to start found the old process and
    skipped. Deploys were 'verified' by fetching the stylesheet, which is a static file
    read fresh on every request and therefore always looks current.

    A route list in the log is the cheap fix: it is a SERVER-side signal, and a missing
    route is visible immediately instead of as a 404 in front of a clinician.
    """
    import subprocess
    try:
        sha = subprocess.run(["git", "-C", str(config.SOVEREIGN_DIR), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        sha = "unknown"
    routes = sorted(r.path for r in app.routes if getattr(r, "path", "").startswith("/doc"))
    log.info("sovereign starting | commit=%s | env=%s | doc routes: %s",
             sha or "unknown", "production" if config.IS_PRODUCTION else "development",
             ", ".join(routes))


def _set_cookie(response, name, value, max_age):
    response.set_cookie(
        name, value, max_age=max_age, httponly=True,
        secure=config.IS_PRODUCTION, samesite=config.COOKIE_SAMESITE,
    )


# --------------------------------------------------------- security headers ----
# Two jobs at once here.
#
# Clickjacking: nothing was setting X-Frame-Options or a frame-ancestors policy, so any
# site on the internet could have framed this app and driven it with the user's session.
#
# Teams: the app has to render INSIDE an iframe served from Microsoft's domains, so a
# blanket DENY is not an option. frame-ancestors is the modern, precise answer — allow
# exactly Teams and ourselves, refuse everything else. X-Frame-Options cannot express a
# multi-origin allowlist, so it is deliberately NOT set; browsers that support CSP use
# frame-ancestors, and every browser Teams supports does.
TEAMS_FRAME_ANCESTORS = (
    "'self' "
    "https://teams.microsoft.com https://*.teams.microsoft.com "
    "https://*.skype.com https://*.microsoft.com "
    "https://*.office.com https://*.office365.com"
)

# 'unsafe-inline' is present for style and script because the templates are
# self-contained with inline handlers and no build step. Documented as a known gap in
# SECURITY.md rather than pretended away; the fix is hashes or a nonce, not a promise.
CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "object-src 'none'; "
    f"frame-ancestors {TEAMS_FRAME_ANCESTORS}"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response



# A 401 on a browser NAVIGATION should send the user to the login page; only an
# API/fetch client should get the JSON body. Without this, every protected URL
# renders as raw {"detail":"Not authenticated"} text if the session has expired.
@app.exception_handler(StarletteHTTPException)
async def unauthorized_redirect(request: Request, exc: StarletteHTTPException):
    wants_html = "text/html" in (request.headers.get("accept") or "")
    if exc.status_code == 401 and wants_html:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return await http_exception_handler(request, exc)


# ---------------------------------------------------------------- auth ----

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    # Send unauthenticated visitors to the login FORM, not to /dashboard. The
    # dashboard's auth dependency raises a 401, and for a browser navigation that
    # renders as a bare {"detail":"Not authenticated"} JSON body — which is what
    # anyone opening the bare URL saw. A logged-in session still lands on the
    # dashboard via the redirect below.
    if request.cookies.get("session"):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": None})


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(default=""),
):
    user = users.get_user(username)
    if not user or not security.verify_password(password, user["password_hash"]):
        audit.record(username, "-", "login_failed", detail="bad_credentials")
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid username, password, or code."},
            status_code=401,
        )

    if not user["totp_confirmed"]:
        audit.record(username, user["role"], "totp_enroll_start")
        resp = RedirectResponse("/enroll", status_code=status.HTTP_303_SEE_OTHER)
        _set_cookie(resp, deps.PENDING_COOKIE, security.create_session_token(username, user["role"]), 600)
        return resp

    if not security.verify_totp(user["totp_secret"], totp_code):
        audit.record(username, user["role"], "login_failed", detail="bad_totp")
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid username, password, or code."},
            status_code=401,
        )

    audit.record(username, user["role"], "login_success")
    # Every login returns the demo to its original state. Blair runs this live and
    # repeatedly; a half-finished pipeline from the last run means the checkmarks are
    # already green and the second demonstration shows nothing happening.
    n = vault.reset_demo_state([d["doc_id"] for d in documents.list_documents()])
    audit.record(username, user["role"], "demo_reset", detail=f"artefacts_removed={n}")
    resp = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    _set_cookie(resp, deps.SESSION_COOKIE, security.create_session_token(username, user["role"]), security.SESSION_MAX_AGE_SECONDS)
    return resp


@app.get("/enroll", response_class=HTMLResponse)
def enroll_form(request: Request, username: str = Depends(deps.get_pending_user)):
    user = users.get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if user["totp_confirmed"]:
        return RedirectResponse("/login")
    if not user["totp_secret"]:
        users.set_totp_secret(username, security.generate_totp_secret())
        user = users.get_user(username)
    qr = security.totp_qr_data_uri(user["totp_secret"], username)
    return templates.TemplateResponse(request, "enroll.html",
        {"request": request, "username": username, "secret": user["totp_secret"], "qr": qr, "error": None},
    )


@app.post("/enroll")
def enroll_submit(
    request: Request,
    totp_code: str = Form(...),
    username: str = Depends(deps.get_pending_user),
):
    user = users.get_user(username)
    if not user or not user["totp_secret"]:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not security.verify_totp(user["totp_secret"], totp_code):
        audit.record(username, user["role"], "totp_failed")
        qr = security.totp_qr_data_uri(user["totp_secret"], username)
        return templates.TemplateResponse(request, "enroll.html",
            {"request": request, "username": username, "secret": user["totp_secret"], "qr": qr,
             "error": "Invalid code — check your authenticator app and try again."},
            status_code=401,
        )
    users.confirm_totp(username)
    audit.record(username, user["role"], "totp_enroll_confirm")
    resp = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    _set_cookie(resp, deps.SESSION_COOKIE, security.create_session_token(username, user["role"]), security.SESSION_MAX_AGE_SECONDS)
    resp.delete_cookie(deps.PENDING_COOKIE)
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(deps.SESSION_COOKIE)
    return resp


# ------------------------------------------------------------ dashboard ----

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: dict = Depends(deps.get_current_user)):
    """The Explorer. Status is computed SERVER-side, from the audit log.

    The first cut of this UI kept status in the browser's localStorage, because the route
    did not supply it. That is wrong for the thing this app is for: two clinicians looking
    at the same document would see different states, and a fresh browser would report
    every released document as untouched. Status is a fact about what was done to a
    record, so it has to come from the server, and specifically from the audited history
    rather than from a flag anyone could set without an audit entry.
    """
    status = audit.document_status()
    docs = []
    for d in documents.list_documents():
        st = status.get(d["doc_id"], {})
        docs.append({**d,
                     "status": st.get("status", "Original"),
                     "last_action": st.get("last_action", ""),
                     "last_ts": st.get("last_ts", "")})
    return templates.TemplateResponse(request, "dashboard.html",
        {"request": request, "user": user, "docs": docs})


@app.get("/doc/{doc_id}", response_class=HTMLResponse)
def view_document(request: Request, doc_id: str, user: dict = Depends(deps.get_current_user)):
    try:
        doc = documents.get_document(doc_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")
    audit.record(user["username"], user["role"], "view_document", doc_id=doc_id)

    existing_map = vault.load_map(doc_id)
    summary_deid = _load_summary(doc_id)
    return templates.TemplateResponse(request, "document.html",
        {
            "request": request, "user": user, "doc": doc,
            "has_map": bool(existing_map), "summary_deid": summary_deid,
            "is_admin": user["role"] == users.ROLE_ADMIN,
        },
    )


def _load_summary(doc_id: str):
    return vault.load_summary(doc_id)


def _save_summary(doc_id: str, text: str):
    vault.save_summary(doc_id, text)


def _current_map(doc_id: str, doc: dict) -> dict:
    """The map to use for this document, right now.

    NEVER `vault.load_map(...) or build(...)`. A stored map that predates a change to
    the document does not cover the identifiers the document has today, and anything
    it does not cover is left verbatim by `deidentify_text` and goes to Provider in the
    clear. doc-001 was live in that state on 2026-08-04 with a one-entry map against a
    five-identifier note. `merge_map` guarantees coverage can only ever grow.
    """
    base = deid_roundtrip.build_placeholder_map(doc["identifiers"])
    # Names appear in prose in shorter forms than the intake field holds. Without this
    # the patient's own first name reaches the processor unredacted.
    base = deid_roundtrip.expand_name_components(doc["identifiers"], base)
    return vault.merge_map(doc_id, base)


@app.post("/doc/{doc_id}/deidentify")
def deidentify(doc_id: str, user: dict = Depends(deps.get_current_user)):
    try:
        doc = documents.get_document(doc_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")
    _current_map(doc_id, doc)
    audit.record(user["username"], user["role"], "deidentify", doc_id=doc_id)
    return RedirectResponse(f"/doc/{doc_id}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/doc/{doc_id}/summarize")
def summarize(doc_id: str, user: dict = Depends(deps.get_current_user)):
    try:
        doc = documents.get_document(doc_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    id_map = _current_map(doc_id, doc)
    deid_text = deid_roundtrip.deidentify_text(doc["note"], id_map)

    try:
        deid_roundtrip.outbound_gate(deid_text, known_values=id_map.keys())
    except deid_roundtrip.IdentifierLeakError as e:
        audit.record(user["username"], user["role"], "summarize_blocked_gate", doc_id=doc_id,
                     detail=",".join(e.reasons))
        log.warning("outbound gate blocked doc=%s reasons=%s", doc_id, e.reasons)
        raise HTTPException(status_code=400, detail="Blocked: possible identifier detected before send.")

    try:
        summary_deid = provider_client.summarize(deid_text)
    except provider_client.ProviderError as e:
        log.error("provider summarize failed doc=%s error_type=%s", doc_id, type(e).__name__)
        raise HTTPException(status_code=502, detail=GENERIC_ERROR)

    _save_summary(doc_id, summary_deid)
    audit.record(user["username"], user["role"], "summarize", doc_id=doc_id)
    return RedirectResponse(f"/doc/{doc_id}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/doc/{doc_id}/reidentify", response_class=HTMLResponse)
def reidentify(request: Request, doc_id: str, user: dict = Depends(deps.get_current_user)):
    try:
        doc = documents.get_document(doc_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")
    id_map = vault.load_map(doc_id)
    summary_deid = _load_summary(doc_id)
    if not id_map or not summary_deid:
        raise HTTPException(status_code=400, detail="Run de-identify and summarize first.")

    summary_identified = deid_roundtrip.reidentify_text(summary_deid, id_map)
    audit.record(user["username"], user["role"], "reidentify", doc_id=doc_id)
    return templates.TemplateResponse(request, "document.html",
        {
            "request": request, "user": user, "doc": doc,
            "has_map": True, "summary_deid": summary_deid,
            "summary_identified": summary_identified,
            "is_admin": user["role"] == users.ROLE_ADMIN,
        },
    )


@app.post("/doc/{doc_id}/release")
def release_public(request: Request, doc_id: str, user: dict = Depends(deps.get_current_user)):
    """Advanced de-identification for PUBLIC release.

    Different feature from /summarize, deliberately. Summarize is the trusted-processor
    round trip and is reversible via the vault. This is the one-way door: deterministic
    pass, Provider points at what the rules missed, we redact locally, stricter gate last.
    No map is written for the released artefact - it is meant to leave the boundary.
    """
    try:
        doc = documents.get_document(doc_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    id_map = _current_map(doc_id, doc)
    try:
        result = advanced_deid.release(doc["note"], id_map)
    except deid_roundtrip.IdentifierLeakError as e:
        audit.record(user["username"], user["role"], "release_blocked_outbound",
                     doc_id=doc_id, detail=",".join(e.reasons))
        raise HTTPException(status_code=400,
                            detail="Blocked before send: deterministic pass left an identifier.")
    except advanced_deid.ReleaseBlocked as e:
        audit.record(user["username"], user["role"], "release_blocked_gate",
                     doc_id=doc_id, detail=",".join(e.reasons))
        log.warning("release gate blocked doc=%s reasons=%s", doc_id, e.reasons)
        raise HTTPException(
            status_code=400,
            detail="Not safe to release: " + ", ".join(e.reasons).replace("_", " "))
    except advanced_deid.AdvancedDeidError:
        log.error("advanced deid failed doc=%s", doc_id)
        raise HTTPException(status_code=502, detail=GENERIC_ERROR)
    except provider_client.ProviderError:
        log.error("provider unavailable for release doc=%s", doc_id)
        raise HTTPException(status_code=502, detail=GENERIC_ERROR)

    audit.record(user["username"], user["role"], "release", doc_id=doc_id,
                 detail=f"advanced_spans={result['advanced_count']}")
    return templates.TemplateResponse(request, "release.html",
        {
            "request": request, "user": user, "doc": doc, "result": result,
            "is_admin": user["role"] == users.ROLE_ADMIN,
        },
    )


# ------------------------------------------------------ pipeline runner ----
# One button, N selected operations. Blair demonstrates each stage separately and
# needs to choose which stages run, then see every output side by side rather than
# clicking through four pages.

OPS = ("deterministic", "advanced", "summary", "reidentify")

# What each operation needs to have happened first. Selecting a downstream step
# implies its prerequisites - the UI shows this, and the server enforces it, because
# a summary built without a map would send raw PHI to Provider.
OP_REQUIRES = {
    "deterministic": (),
    "advanced": ("deterministic",),
    "summary": ("deterministic",),
    "reidentify": ("deterministic", "summary"),
}


def _expand_ops(selected):
    """Selected operations plus every prerequisite, in execution order."""
    wanted = set()
    for op in selected:
        if op in OP_REQUIRES:
            wanted.add(op)
            wanted.update(OP_REQUIRES[op])
    return [op for op in OPS if op in wanted]


@app.post("/doc/{doc_id}/run", response_class=HTMLResponse)
def run_pipeline(request: Request, doc_id: str,
                 ops: list[str] = Form(default=[]),
                 user: dict = Depends(deps.get_current_user)):
    try:
        doc = documents.get_document(doc_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")

    plan = _expand_ops(ops)
    results = {"ran": [], "errors": {}}

    if "deterministic" in plan:
        id_map = _current_map(doc_id, doc)
        results["deid_text"] = deid_roundtrip.deidentify_text(doc["note"], id_map)
        results["deid_count"] = len(id_map)
        results["ran"].append("deterministic")
        audit.record(user["username"], user["role"], "deidentify", doc_id=doc_id)
    else:
        id_map = vault.load_map(doc_id)

    if "advanced" in plan:
        try:
            rel = advanced_deid.release(doc["note"], id_map)
            results["release"] = rel
            results["ran"].append("advanced")
            audit.record(user["username"], user["role"], "release", doc_id=doc_id,
                         detail=f"advanced_spans={rel['advanced_count']}")
        except advanced_deid.ReleaseBlocked as e:
            results["errors"]["advanced"] = "Blocked by the release gate: " + \
                ", ".join(e.reasons).replace("_", " ")
            audit.record(user["username"], user["role"], "release_blocked_gate",
                         doc_id=doc_id, detail=",".join(e.reasons))
        except (advanced_deid.AdvancedDeidError, provider_client.ProviderError):
            results["errors"]["advanced"] = GENERIC_ERROR
            log.error("advanced deid failed doc=%s", doc_id)

    if "summary" in plan:
        deid_text = deid_roundtrip.deidentify_text(doc["note"], id_map)
        try:
            deid_roundtrip.outbound_gate(deid_text, known_values=id_map.keys())
            summary = provider_client.summarize(deid_text)
            _save_summary(doc_id, summary)
            results["summary_deid"] = summary
            results["ran"].append("summary")
            audit.record(user["username"], user["role"], "summarize", doc_id=doc_id)
        except deid_roundtrip.IdentifierLeakError as e:
            results["errors"]["summary"] = "Blocked before send: possible identifier detected."
            audit.record(user["username"], user["role"], "summarize_blocked_gate",
                         doc_id=doc_id, detail=",".join(e.reasons))
        except provider_client.ProviderError:
            results["errors"]["summary"] = GENERIC_ERROR
            log.error("provider summarize failed doc=%s", doc_id)

    if "reidentify" in plan:
        summary = results.get("summary_deid") or _load_summary(doc_id)
        if summary and id_map:
            results["summary_identified"] = deid_roundtrip.reidentify_text(summary, id_map)
            results["ran"].append("reidentify")
            audit.record(user["username"], user["role"], "reidentify", doc_id=doc_id)
        else:
            results["errors"]["reidentify"] = "No summary to re-identify."

    audit.record(user["username"], user["role"], "run_pipeline", doc_id=doc_id,
                 detail="+".join(results["ran"]) or "none")

    return templates.TemplateResponse(request, "document.html", {
        "request": request, "user": user, "doc": doc,
        "has_map": bool(vault.load_map(doc_id)),
        "summary_deid": results.get("summary_deid") or _load_summary(doc_id),
        "summary_identified": results.get("summary_identified"),
        "results": results, "selected": plan,
        "is_admin": user["role"] == users.ROLE_ADMIN,
    })


# ------------------------------------------------------------- export -----
# Staff MUST get 403 here — enforced server-side via require_admin, not hidden UI.

@app.get("/doc/{doc_id}/export")
def export(doc_id: str, user: dict = Depends(deps.get_current_user)):
    if user["role"] != users.ROLE_ADMIN:
        audit.record(user["username"], user["role"], "export_denied", doc_id=doc_id)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    try:
        doc = documents.get_document(doc_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")
    id_map = vault.load_map(doc_id)
    summary_deid = _load_summary(doc_id)
    if not id_map or not summary_deid:
        raise HTTPException(status_code=400, detail="Nothing to export yet — summarize first.")

    summary_identified = deid_roundtrip.reidentify_text(summary_deid, id_map)
    audit.record(user["username"], user["role"], "export", doc_id=doc_id)
    return PlainTextResponse(
        summary_identified,
        headers={"Content-Disposition": f'attachment; filename="{doc_id}-summary.txt"'},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Last-resort safety net: never let a raw exception (which could embed document text
    # in a traceback) reach the client. Log the type/route only, no payload contents.
    log.error("unhandled exception on %s: %s", request.url.path, type(exc).__name__)
    return PlainTextResponse(GENERIC_ERROR, status_code=500)

"""Immutable(append-only) audit log — who, what action, which doc id, when. NO PHI.

Extends the spirit of src/deid/audit.py's "never the original value" rule (see
docs/AUDIT-2026-07-23.md finding #2: don't repeat that mistake — record tokens here are
the app-assigned doc_id, never a filename or any field that could carry a real name).
"""
import json
import os
import stat
import time
from pathlib import Path

from . import config

AUDIT_FILE = config.AUDIT_DIR / "audit.jsonl"

_ALLOWED_ACTIONS = {
    "login_success", "login_failed", "totp_enroll_start", "totp_enroll_confirm",
    "totp_failed", "view_document", "deidentify", "summarize", "summarize_blocked_gate",
    "reidentify", "export", "export_denied",
    # public-release path (2026-08-04)
    "release", "release_blocked_gate", "release_blocked_outbound",
    # demo lifecycle (2026-08-09)
    "demo_reset", "run_pipeline",
}

# Actions that represent a completed operation on a document, most-advanced last. Used to
# derive a document's status for the browser.
_STATUS_ORDER = ("deidentify", "summarize", "reidentify", "release")
_STATUS_LABEL = {
    "deidentify": "De-identified",
    "summarize": "Summarised",
    "reidentify": "Summarised",
    "release": "Released",
}


def record(actor: str, role: str, action: str, doc_id: str = "-", detail: str = "") -> None:
    """Append one audit entry. `detail` must never contain PHI or free text pulled from a
    document — callers pass short fixed status strings only (enforced by convention +
    tests, since Python can't statically prove absence of PHI)."""
    if action not in _ALLOWED_ACTIONS:
        action = "unknown_action"
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": actor,
        "role": role,
        "action": action,
        "doc_id": doc_id,
        "detail": detail[:200],
    }
    new_file = not AUDIT_FILE.exists()
    with AUDIT_FILE.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")
    if new_file:
        os.chmod(AUDIT_FILE, stat.S_IRUSR | stat.S_IWUSR)


def read_all() -> list:
    if not AUDIT_FILE.exists():
        return []
    with AUDIT_FILE.open() as fh:
        return [json.loads(line) for line in fh if line.strip()]


def document_status() -> dict:
    """{doc_id: {"status", "last_action", "last_ts"}} derived from the audit log.

    Why the audit log and not the vault: "Released" has no vault artefact by design -
    advanced_deid.release() deliberately writes no map, because a released document is
    meant to leave the trust boundary and keeping a way back would defeat the point.

    Rather than invent a second store just to remember that a release happened, we read
    the append-only log that is already the system of record for exactly this question.
    It is also the more defensible answer: the status a clinician sees is tied to an
    audited action, not to a flag someone could set independently of one.

    Status is monotonic - re-running de-identify on an already-released document does not
    walk the badge backwards.
    """
    since = last_demo_reset()
    best = {}
    for entry in read_all():
        if since and entry.get("ts", "") < since:
            continue          # pre-reset history is not this demo's state
        doc_id = entry.get("doc_id", "-")
        action = entry.get("action", "")
        if doc_id == "-" or action not in _STATUS_ORDER:
            continue
        rank = _STATUS_ORDER.index(action)
        prev = best.get(doc_id)
        if prev is None or rank >= prev["rank"]:
            best[doc_id] = {"rank": rank, "action": action, "ts": entry.get("ts", "")}
    return {
        doc_id: {
            "status": _STATUS_LABEL.get(v["action"], "Original"),
            "last_action": v["action"],
            "last_ts": v["ts"],
        }
        for doc_id, v in best.items()
    }


def last_demo_reset() -> str:
    """Timestamp of the most recent demo reset, or empty string if never."""
    ts = ""
    for entry in read_all():
        if entry.get("action") == "demo_reset":
            ts = entry.get("ts", "") or ts
    return ts

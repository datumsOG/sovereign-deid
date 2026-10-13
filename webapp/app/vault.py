"""Encrypted-at-rest store for per-document re-identification maps (Mode B, see
docs/PLAN-2026-07-23-the-rest.md). This is a NEW mechanism, separate from the existing
one-way HMAC release pipeline in src/deid/ — that code is untouched.

Each map is {real_value: placeholder}, encrypted with a Fernet key generated on first run
into webapp/secrets/vault.key (0600, gitignored) and written to webapp/vault/ (gitignored).
This is "encrypted at rest with stdlib-adjacent `cryptography`, key outside git" per the
task spec — not a full KMS/HSM. See SECURITY.md for what a real-PHI deployment needs on
top of this (key rotation, HSM-backed keys, etc).
"""
import json
import os
import re
import stat

from cryptography.fernet import Fernet, InvalidToken

from . import config

_DOC_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _fernet() -> Fernet:
    return Fernet(config.vault_key())


def _path_for(doc_id: str):
    if not _DOC_ID_RE.match(doc_id):
        raise ValueError("invalid doc_id")
    return config.VAULT_DIR / f"{doc_id}.map.enc"


def save_map(doc_id: str, id_map: dict) -> None:
    payload = json.dumps(id_map).encode("utf-8")
    token = _fernet().encrypt(payload)
    p = _path_for(doc_id)
    p.write_bytes(token)
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def load_map(doc_id: str) -> dict:
    p = _path_for(doc_id)
    if not p.exists():
        return {}
    try:
        payload = _fernet().decrypt(p.read_bytes())
    except InvalidToken:
        # Wrong/rotated key or corrupted file — fail closed, never guess.
        return {}
    return json.loads(payload.decode("utf-8"))


def merge_map(doc_id: str, fresh: dict) -> dict:
    """Return a map that covers `fresh` completely, without breaking older output.

    Why this exists (found 2026-08-04): the summarize route used to do
    `id_map = load_map(doc_id) or build(...)`, i.e. it trusted a stored map whenever
    one existed. If a document gained an identifier after its map was written, that
    identifier was NOT in the map, so `deidentify_text` left it verbatim and it went
    to Provider in the clear. doc-001 was in exactly that state: a one-entry map against
    a five-identifier document. The outbound gate caught the phone/DOB/MRN shapes, but
    a name or a street address matches no pattern and would have gone out.

    So: never reuse a map blindly. Merge instead.

    Stored entries win for values that still exist, which keeps every summary already
    issued under an old placeholder reversible. Values only in `fresh` are added. The
    result is a superset, so coverage can never regress.
    """
    stored = load_map(doc_id)
    merged = dict(fresh)
    merged.update({k: v for k, v in stored.items() if k in fresh})
    # Values that have since been removed from the document are retained so that
    # previously exported summaries remain re-identifiable.
    merged.update({k: v for k, v in stored.items() if k not in fresh})
    if merged != stored:
        save_map(doc_id, merged)
    return merged


# ---------- summaries ----------
# Summaries used to be written to vault/<doc>.summary.txt in plaintext while the maps
# beside them were encrypted. They hold only placeholdered text today, but the asymmetry
# is a latent leak: the moment anything re-identified is persisted, it lands unencrypted.
# Same Fernet key, same 0600, same failure mode.

def _summary_path_for(doc_id: str):
    if not _DOC_ID_RE.match(doc_id):
        raise ValueError("invalid doc_id")
    return config.VAULT_DIR / f"{doc_id}.summary.enc"


def save_summary(doc_id: str, text: str) -> None:
    p = _summary_path_for(doc_id)
    p.write_bytes(_fernet().encrypt(text.encode("utf-8")))
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)


def load_summary(doc_id: str):
    p = _summary_path_for(doc_id)
    if not p.exists():
        return None
    try:
        return _fernet().decrypt(p.read_bytes()).decode("utf-8")
    except InvalidToken:
        return None


def reset_demo_state(doc_ids) -> int:
    """Wipe maps and summaries so a demo always starts from the original documents.

    Called on every login. Blair demonstrates this live, repeatedly, and a half-finished
    pipeline from the previous run makes the second demonstration incoherent - the
    checkmarks are already green and nothing visibly happens.

    Only touches the per-document artefacts. The Fernet key, the user store and the audit
    log are all left alone: the audit log is append-only by design and is the record that
    the reset itself happened.
    """
    removed = 0
    for doc_id in doc_ids:
        for path in (_path_for(doc_id), _summary_path_for(doc_id)):
            if path.exists():
                path.unlink()
                removed += 1
    return removed

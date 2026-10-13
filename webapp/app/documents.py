"""Loads the small set of synthetic demo documents shipped in webapp/demo_data/.

FULLY SYNTHETIC — no real patient was ever involved. These are hand-authored fixtures
(same spirit as tests/fixtures/ in the main Sovereign repo), committed to git on purpose
so the demo is reproducible without needing real PHI or the 1,473-record Synthea corpus.
"""
import json

from . import config

_DOC_ID_ALLOW = None  # populated lazily


def list_documents() -> list:
    """Every demo document, with the cheap metadata the browser needs.

    identifiers_count and size come free - the file is already being read and parsed for
    the title, so the Explorer columns cost nothing extra. Status is NOT here: it comes
    from the audit log (audit.document_status), because status is a fact about what was
    done, not a property of the file.
    """
    docs = []
    for p in sorted(config.DEMO_DATA_DIR.glob("*.json")):
        d = json.loads(p.read_text())
        note = d.get("note", "") or ""
        docs.append({
            "doc_id": d["doc_id"],
            "title": d.get("title", d["doc_id"]),
            "identifiers_count": len([v for v in (d.get("identifiers") or {}).values() if v]),
            "size": len(note.encode("utf-8")),
        })
    return docs


def get_document(doc_id: str) -> dict:
    p = config.DEMO_DATA_DIR / f"{doc_id}.json"
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(doc_id)
    return json.loads(p.read_text())

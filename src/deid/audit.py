"""IPC Step 11 — audit trail. One JSON line per record: which field, which action.
NEVER the original value. The audit is itself safe to keep (no PHI)."""
import json
from pathlib import Path

def build_entry(record_token: str, actions: list) -> dict:
    return {"record": record_token,
            "actions": [{"field": f, "action": a} for f, a in actions]}

def write_entry(audit_dir: Path, entry: dict) -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    with (audit_dir / "audit.jsonl").open("a") as fh:
        fh.write(json.dumps(entry) + "\n")

def count(audit_dir: Path) -> int:
    p = audit_dir / "audit.jsonl"
    if not p.exists():
        return 0
    with p.open() as fh:
        return sum(1 for _ in fh)

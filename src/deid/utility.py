"""IPC Step 10 — utility assessment. Over-redaction destroys value; measure the loss."""

def suppression_rate(rows: list, keys: list) -> float:
    if not rows:
        return 0.0
    cells = len(rows) * len(keys)
    suppressed = sum(1 for r in rows for k in keys if r.get(k) == "*")
    return suppressed / cells

def distinct_retained(rows: list, key: str) -> int:
    return len({r[key] for r in rows if r.get(key) != "*"})

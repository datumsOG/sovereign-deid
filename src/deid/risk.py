"""IPC Steps 6-8 — measure data vulnerability (k-anonymity), attack probability, overall risk.

Non-public release model (IPC App. E):
  data vulnerability = re-identification probability from equivalence-class size (1/k)
  overall risk       = data vulnerability x probability of attack
We report BOTH maximum (worst record) and average vulnerability.
"""
from collections import Counter

def _key(row: dict, keys: list) -> tuple:
    return tuple(row[k] for k in keys)

def equivalence_classes(rows: list, keys: list) -> dict:
    """Map equivalence-class key -> count of records sharing it."""
    return dict(Counter(_key(r, keys) for r in rows))

def max_vulnerability(classes: dict) -> float:
    """Worst-case: 1 / smallest class size."""
    if not classes:
        return 0.0
    return 1.0 / min(classes.values())

def average_vulnerability(rows: list, classes: dict, keys: list) -> float:
    """Mean over records of 1 / (size of that record's class)."""
    if not rows:
        return 0.0
    return sum(1.0 / classes[_key(r, keys)] for r in rows) / len(rows)

def overall_risk(data_vulnerability: float, attack_probability: float) -> float:
    return data_vulnerability * attack_probability

def min_class_size(classes: dict) -> int:
    """k-anonymity: the smallest equivalence-class size."""
    return min(classes.values()) if classes else 0

def meets_threshold(risk_value: float, threshold: float) -> bool:
    return risk_value <= threshold

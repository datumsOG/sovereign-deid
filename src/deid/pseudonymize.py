"""IPC Step 4 — pseudonymize direct identifiers and shift dates.

- hash_identifier: salted one-way token (HMAC-SHA256, truncated). Not reversible.
- date_shift_days: deterministic per-patient offset in [-365, 365] so a patient's dates
  all move together — temporal intervals (and thus clinical utility) are preserved.
"""
import hmac
import hashlib
from datetime import date, timedelta

def hash_identifier(value: str, salt: bytes) -> str:
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

def date_shift_days(patient_id: str, salt: bytes, max_days: int = 365) -> int:
    digest = hmac.new(salt, patient_id.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:4], "big")
    span = 2 * max_days + 1
    return (n % span) - max_days

def shift_date(value: str, offset_days: int) -> str:
    # value may be "YYYY-MM-DD" or "YYYY-MM-DDThh:mm:ssZ" — shift the date part only.
    datepart = value[:10]
    rest = value[10:]
    d = date.fromisoformat(datepart) + timedelta(days=offset_days)
    return d.isoformat() + rest

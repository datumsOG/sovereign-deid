"""IPC Step 3 — classify variables. Pull the Patient resource and its quasi-identifiers."""
from datetime import date

class NoPatientError(ValueError):
    """Bundle contains no Patient resource (e.g. Synthea hospital/practitioner bundles).
    Subclasses ValueError for backward compatibility, but lets callers skip ONLY this
    case rather than swallowing every ValueError (which could hide a real bug)."""

def extract_patient(bundle: dict) -> dict:
    for entry in bundle.get("entry", []):
        res = entry.get("resource", {})
        if res.get("resourceType") == "Patient":
            return res
    raise NoPatientError("no Patient resource in bundle")

def _age(birth: str, today: date) -> int:
    b = date.fromisoformat(birth[:10])
    return today.year - b.year - ((today.month, today.day) < (b.month, b.day))

def quasi_identifiers(bundle: dict, today: date) -> dict:
    pat = extract_patient(bundle)
    addr = (pat.get("address") or [{}])[0]
    marital = (pat.get("maritalStatus") or {}).get("text", "UNK")
    return {
        "age": _age(pat["birthDate"], today),
        "gender": pat.get("gender", "unknown"),
        "postal_code": addr.get("postalCode", ""),
        "marital_status": marital,
    }

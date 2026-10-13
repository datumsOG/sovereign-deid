"""IPC Step 9 — generalization & suppression transforms on quasi-identifiers.

Each QI has escalating generalization levels; the highest level is full suppression ("*").
Producing the equivalence-class key (age_band, gender, region, marital_status)."""

def age_to_band(age: int, level: int = 0) -> str:
    if level >= 2:
        return "*"
    width = 5 if level == 0 else 10
    low = (age // width) * width
    return f"{low}-{low + width - 1}"

def postal_to_region(postal: str, level: int = 0) -> str:
    fsa = postal.replace(" ", "")[:3].upper()
    if not fsa:
        return "*"
    if level >= 2:
        return "*"
    if level == 1:
        return fsa[0]
    return fsa

def generalize_record(qi: dict, age_level: int = 0, region_level: int = 0) -> dict:
    return {
        "age_band": age_to_band(qi["age"], age_level),
        "gender": qi.get("gender", "unknown"),
        "region": postal_to_region(qi.get("postal_code", ""), region_level),
        "marital_status": qi.get("marital_status", "UNK"),
    }

def apply_to_patient(pat: dict, age_band: str, region: str) -> list:
    """Write the corpus-chosen generalization onto a Patient resource so the RELEASED record
    actually carries the generalized quasi-identifiers (not the raw ones). Without this the
    risk report would describe a dataset that was never emitted (see PD-004).

    - Removes exact `birthDate`; records the age band in `ageBand` instead.
    - Reduces every `address` to region-level: drops `line`, `city`, `postalCode`, and the
      `extension` (which carries exact GPS lat/long) — keeps `state`/`country`; sets `region`.

    Returns audit actions (field, rule) — never original values."""
    actions = []
    if "birthDate" in pat or "ageBand" not in pat:
        pat.pop("birthDate", None)
        pat["ageBand"] = age_band
        actions.append(("birthDate", f"generalized:age_band={age_band}"))
    for addr in pat.get("address") or []:
        for k in ("line", "city", "postalCode", "extension"):
            addr.pop(k, None)
        addr["region"] = region
        actions.append(("address", f"generalized:region={region}"))
    return actions

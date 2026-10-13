"""Orchestrate the 12-step de-identification.

deidentify_record: Steps 3-4 on a single FHIR bundle (classify + pseudonymize), returning
the transformed bundle, the audit actions, and the raw quasi-identifiers (for corpus risk).

assess_corpus: Steps 6-9 across all records — escalate generalization/suppression until the
overall non-public risk is at or below the threshold. Returns a risk report.
"""
from datetime import date
from . import config, classify, pseudonymize, generalize, risk, utility

def _strip_patient(pat: dict, salt: bytes, offset: int) -> list:
    actions = []
    if "name" in pat:
        pat.pop("name"); actions.append(("name", "removed"))
    if "telecom" in pat:
        pat.pop("telecom"); actions.append(("telecom", "removed"))
    # DEFAULT-HASH (audit A.3): hash every identifier value unless its system is explicitly
    # safe — so unknown identifier.systems and Synthea internal UUIDs cannot leak.
    for ident in pat.get("identifier", []):
        if ident.get("value") and ident.get("system") not in config.SAFE_IDENTIFIER_SYSTEMS:
            ident["value"] = pseudonymize.hash_identifier(ident["value"], salt)
            actions.append((f"identifier:{ident.get('system')}", "hashed"))
    if "birthDate" in pat:
        pat["birthDate"] = pseudonymize.shift_date(pat["birthDate"], offset)
        actions.append(("birthDate", "date_shifted"))
    for addr in pat.get("address", []):
        addr.pop("line", None)
        actions.append(("address.line", "removed"))
    # DEFAULT-DENY on extensions (audit 2026-07-23 finding #1). Every extension goes
    # unless its URL is explicitly safe-listed. See config.SAFE_EXTENSION_URLS for why
    # this is deny-by-default rather than a list of known-bad URLs.
    if "extension" in pat:
        kept, dropped = [], []
        for ext in pat.get("extension", []):
            url = ext.get("url", "")
            if url in config.SAFE_EXTENSION_URLS:
                kept.append(ext)
            else:
                dropped.append(url.rsplit("/", 1)[-1] or "unnamed")
        if kept:
            pat["extension"] = kept
        else:
            pat.pop("extension")
        for name in dropped:
            # the URL fragment is a field NAME, never a value — safe for the audit trail
            actions.append((f"extension:{name}", "removed"))
    return actions

def deidentify_record(bundle: dict, salt: bytes, today: date):
    pat = classify.extract_patient(bundle)
    qi = classify.quasi_identifiers(bundle, today)
    offset = pseudonymize.date_shift_days(pat["id"], salt)
    actions = _strip_patient(pat, salt, offset)
    # shift every other dated resource by the same per-patient offset
    for entry in bundle.get("entry", []):
        res = entry.get("resource", {})
        period = res.get("period", {})
        for k in ("start", "end"):
            if k in period:
                period[k] = pseudonymize.shift_date(period[k], offset)
    return bundle, actions, qi

def _report(rows, classes, keys, attack_p, age_level, region_level, suppressed) -> dict:
    overall = risk.overall_risk(risk.max_vulnerability(classes), attack_p)
    kmin = risk.min_class_size(classes)
    return {
        # PRIMARY control = k-anonymity floor; attack-prob discount is secondary context.
        "meets_threshold": kmin >= config.K_THRESHOLD
                           and risk.meets_threshold(overall, config.RISK_THRESHOLD),
        "k_anonymity": kmin,
        "overall_risk": overall,
        "max_vulnerability": risk.max_vulnerability(classes),
        "average_vulnerability": risk.average_vulnerability(rows, classes, keys),
        "attack_probability": attack_p,
        "age_level": age_level,
        "region_level": region_level,
        "records_suppressed": suppressed,
        "suppression_rate": utility.suppression_rate(rows, keys),
        "n_records": len(rows),
    }

def assess_corpus(qis: list) -> dict:
    """Escalate generalization until every equivalence class has >= K_THRESHOLD members
    (k-anonymity) AND overall non-public risk <= threshold (IPC App. E). If the maximum
    generalization still leaves rare classes, suppress those residual records (drop from
    release) — a standard k-anonymity outlier strategy — and report the count."""
    keys = config.QUASI_IDENTIFIERS
    attack_p = max(config.ATTACK_PROBABILITIES.values())
    k = config.K_THRESHOLD

    # 1) Try increasing generalization with no record suppression.
    for age_level in (0, 1, 2):
        for region_level in (0, 1, 2):
            rows = [generalize.generalize_record(q, age_level, region_level) for q in qis]
            classes = risk.equivalence_classes(rows, keys)
            if risk.min_class_size(classes) >= k:
                rep = _report(rows, classes, keys, attack_p, age_level, region_level, 0)
                if rep["meets_threshold"]:
                    return rep

    # 2) At maximum generalization, suppress records still in classes smaller than k.
    rows = [generalize.generalize_record(q, 2, 2) for q in qis]
    classes = risk.equivalence_classes(rows, keys)
    safe = [r for r in rows if classes[risk._key(r, keys)] >= k]
    suppressed = len(rows) - len(safe)
    classes2 = risk.equivalence_classes(safe, keys)
    return _report(safe, classes2, keys, attack_p, 2, 2, suppressed)

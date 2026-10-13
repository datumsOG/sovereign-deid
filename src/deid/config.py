"""IPC 12-step configuration for Sovereign SP1.

Step 2 (release model), Step 3 (variable classification), Step 5 (threshold).
These are deliberate, documented choices — see docs/methodology/.
"""

# Step 2 — Release model. Provider is an external third party under contract + controls,
# NOT an open/public data release. This selects the non-public risk math (IPC App. E).
RELEASE_MODEL = "non_public_third_party"

# Step 5 — Acceptable re-identification risk threshold for non-public sharing.
# 0.09 is the widely-cited maximum acceptable probability for non-public release.
RISK_THRESHOLD = 0.09

# Minimum equivalence-class size (k-anonymity) the engine drives toward.
K_THRESHOLD = 5

# Step 3 — Quasi-identifiers (indirect identifiers). Order is the equivalence-class key order.
QUASI_IDENTIFIERS = ["age_band", "gender", "region", "marital_status"]

# Step 3 — Direct identifiers. FHIR Patient.identifier systems known to be direct
# identifiers. Kept for documentation/labelling; NOT the gate. See DEFAULT-HASH below.
DIRECT_IDENTIFIER_SYSTEMS = (
    "http://hl7.org/fhir/sid/us-ssn",
    "http://hl7.org/fhir/sid/us-mrn",
    "urn:mrn",
    "http://hl7.org/fhir/sid/passport-USA",
    "urn:oid:2.16.840.1.113883.4.3.25",  # driver's licence (Synthea)
)

# DEFAULT-HASH policy (audit finding A.3): do NOT rely on an allow-list of "known bad"
# identifier systems — an unknown identifier.system would leak. Hash EVERY identifier with
# a non-empty value, EXCEPT those whose system is explicitly designated safe to retain.
# Empty = hash everything, including Synthea internal UUIDs (closes PD-004 residual).
SAFE_IDENTIFIER_SYSTEMS = ()

# DEFAULT-DENY on FHIR extensions (audit 2026-07-23, finding #1; fixed 2026-08-04).
#
# `Patient.extension` was never processed at all, so Synthea's mothersMaidenName and
# birthPlace passed through into "released" output unmodified. Mother's maiden name is a
# direct identifier and a security-question answer; birthplace city is a strong indirect
# identifier that was not counted in any equivalence class, which meant the reported
# k-anonymity and risk figures were understating actual re-identification risk.
#
# The lesson from that finding is not "also strip these two extensions" — it is that an
# allow-by-default field is a leak waiting for the next unfamiliar profile. Extensions are
# where FHIR implementers put whatever their jurisdiction or vendor needs, so their content
# is unknowable in advance. So: drop every extension unless its URL is explicitly listed
# here as safe, exactly as SAFE_IDENTIFIER_SYSTEMS works above.
#
# Empty on purpose. Add a URL only with a written reason for why that extension cannot
# identify anyone, and only after checking it against the risk model.
SAFE_EXTENSION_URLS = ()

# Attack probabilities for the three non-public scenarios (IPC App. E). Conservative
# defaults; the sealed architecture + Provider DPA are the mitigating controls that justify
# these being well below 1.0. Documented in methodology.
ATTACK_PROBABILITIES = {
    "deliberate_insider": 0.05,
    "acquaintance": 0.05,
    "data_breach": 0.05,
}

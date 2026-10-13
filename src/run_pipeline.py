"""Sealed entrypoint. Reads input FHIR bundles, writes de-identified bundles + audit +
risk report. Salt is read from $SOVEREIGN_SALT_FILE (default sealed/salt); the agent never
sees the salt value. Usage:

  python3 -m src.run_pipeline --in synthetic/fhir --out released --reports reports

When run over real PHI it is invoked ONLY through the no-argument sudoers wrapper:
  sudo -u sovereign /usr/local/bin/sovereign-run
(which fixes every sealed path; see setup/sovereign-run + 03_install_sudoers.sh).
"""
import argparse, json, os, stat
from datetime import date
from pathlib import Path
from src.deid import pipeline, audit, config, classify, generalize, risk

SEALED = Path("sealed").resolve()

def _under_sealed(p: Path) -> bool:
    try:
        return SEALED == p.resolve() or SEALED in p.resolve().parents
    except OSError:
        return False

def _load_salt(indir: Path) -> bytes:
    """FAIL-CLOSED (audit A.1). For any run whose input is inside the sealed zone (i.e. real
    PHI), a real salt file MUST exist with owner-only perms — never the dev fallback. The
    predictable DEV-SALT is permitted ONLY for clearly non-sealed (synthetic) inputs."""
    p = Path(os.environ.get("SOVEREIGN_SALT_FILE", str(SEALED / "salt")))
    sealed_run = _under_sealed(indir)
    try:
        exists = p.exists()
    except OSError:
        # Cannot even stat the salt. For a SEALED run that means we are the wrong user —
        # fail closed, never use the dev salt on real PHI. For a synthetic run (default salt
        # path happens to be inside the unreadable sealed zone) the dev salt is fine.
        if sealed_run:
            raise SystemExit(f"ABORT: cannot access salt file {p} — run the sealed pipeline "
                             "as the sovereign user.")
        return b"DEV-SALT-synthetic-only"
    if exists:
        if p.stat().st_mode & 0o077:
            raise SystemExit(f"ABORT: salt file {p} is group/world-accessible — chmod 600.")
        return p.read_bytes()
    if sealed_run:
        raise SystemExit(
            f"ABORT: no salt file at {p}. Real-PHI runs must NOT use the dev salt. "
            "Create the salt (owner sovereign, mode 600) before processing sealed input.")
    return b"DEV-SALT-synthetic-only"  # synthetic-only path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", required=True)
    ap.add_argument("--out", dest="outdir", required=True)
    ap.add_argument("--reports", dest="reports", required=True)
    ap.add_argument("--audit", dest="auditdir", default=None)
    args = ap.parse_args()

    indir, outdir = Path(args.indir), Path(args.outdir)
    salt = _load_salt(indir)
    reports = Path(args.reports); auditdir = Path(args.auditdir or (reports / "audit"))
    outdir.mkdir(parents=True, exist_ok=True); reports.mkdir(parents=True, exist_ok=True)
    today = date.today()

    # PASS 1 — de-identify direct identifiers + shift dates; collect quasi-identifiers.
    # Hold bundles in memory: the generalization LEVEL is a corpus-wide decision (assess_corpus),
    # so we cannot finalize a record's quasi-identifiers until the whole corpus is assessed.
    records = []  # (filename, audit_token, deid_bundle, actions, qi)
    skipped_no_patient = malformed = 0
    for f in sorted(indir.glob("*.json")):
        try:
            bundle = json.loads(f.read_text())
        except json.JSONDecodeError:
            malformed += 1  # count, never silently crash the whole run (audit A.4)
            continue
        try:
            deid, actions, qi = pipeline.deidentify_record(bundle, salt, today)
        except classify.NoPatientError:
            skipped_no_patient += 1  # e.g. Synthea hospital/practitioner bundle — see PD-003
            continue
        records.append((f.name, f.stem[:12], deid, actions, qi))

    qis = [r[4] for r in records]
    report = pipeline.assess_corpus(qis)
    (reports / "risk_report.json").write_text(json.dumps(report, indent=2))

    # PASS 2 — apply the corpus-chosen generalization to each released bundle so the OUTPUT
    # actually carries the generalized quasi-identifiers the risk report describes (PD-004),
    # and DROP records whose generalized class is still smaller than k (suppressed outliers).
    keys = config.QUASI_IDENTIFIERS
    age_level, region_level = report["age_level"], report["region_level"]
    rows = [generalize.generalize_record(qi, age_level, region_level) for qi in qis]
    classes = risk.equivalence_classes(rows, keys)
    k = config.K_THRESHOLD

    written = suppressed = 0
    for (fname, token, deid, actions, qi), row in zip(records, rows):
        if classes[risk._key(row, keys)] < k:
            suppressed += 1
            continue  # outlier suppressed from release
        pat = classify.extract_patient(deid)
        actions = actions + generalize.apply_to_patient(pat, row["age_band"], row["region"])
        (outdir / fname).write_text(json.dumps(deid))
        audit.write_entry(auditdir, audit.build_entry(token, actions))
        written += 1

    print(f"processed {len(records)} records; released {written}, suppressed {suppressed}; "
          f"skipped_no_patient={skipped_no_patient}, malformed={malformed}; "
          f"meets_threshold={report.get('meets_threshold')}")

if __name__ == "__main__":
    main()

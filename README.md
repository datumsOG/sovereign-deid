# Sovereign: de-identifying clinical records, where the model points and code removes

By [Blair Zasitko](https://blairz.ca) · [How it works, with a diagram](https://blairz.ca/work/sovereign/)

Sovereign strips patient identifiers from clinical records on a server you run yourself.
It has two parts.

- **`src/deid/`: the release pipeline.** Takes FHIR patient records and produces a set that
  can leave: direct identifiers replaced with keyed pseudonyms, dates shifted by a
  per-patient interval, addresses generalised, and every `extension` dropped unless its
  URL is on an allow-list (which is empty). It then measures what it made: k-anonymity,
  re-identification risk and how much analytic use survived. It follows the Information
  and Privacy Commissioner of Ontario's 2025 guidelines for structured data.
- **`webapp/`: the round trip.** A clinician's note is de-identified, sent to a language
  model for a summary, and re-identified on the way back, so the model never sees who the
  note is about. Login needs a password and a one-time code, and roles are enforced on
  the server.

## The model proposes; code decides

Rules run first and replace every identifier already on file. A model is then shown the
result and may only *list* spans the rules missed, each from seven allowed categories and
no longer than 120 characters. Code discards anything outside those limits and makes
every removal locally. A stricter gate checks the result again and refuses the release if
anything identifier-shaped remains. The model never edits the text and never sees an
original.

## Where it stands

This is a working prototype that has only ever run on **synthetic data**. Every patient
in `webapp/demo_data/` and `tests/fixtures/` is invented. It has not been reviewed for
real patient data and should not be given any.

On 1,473 synthetic patient records (June 2026) the pipeline reached a k-anonymity of 94
and a re-identification risk of 0.053%, with no records suppressed.

A security audit in July 2026 found that the pipeline was checking a fixed list of fields
and letting `extension` through, which carried a mother's maiden name and a birthplace.
The fix is the default-deny on extensions in `src/deid/pipeline.py`, and the lesson is in
the tests: check the whole record, not the fields you thought of.

## Run the tests

```
python3 -m unittest discover -s tests
cd webapp
pip install -r requirements.txt -r requirements-dev.txt
python3 -m pytest tests
```

## How it was made

I designed this and directed its construction with AI coding agents (Claude Code): I wrote
the specification, made the design decisions and tested the result. I spent three years
running operations at a clinical assessment practice, which is where the problem comes from.

The code is MIT-licensed (see `LICENSE`).

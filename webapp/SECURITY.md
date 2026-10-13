> ⛔ SOVEREIGN RULE #1 — Patient data must NEVER get out or be compromised.
> This webapp is V1 — "get it up so we can try to break it" — on SYNTHETIC DATA ONLY.
> It has not been reviewed for real PHI and must not be pointed at `sealed/`.

# Sovereign webapp — security model (V1)

## What this app is
A FastAPI wrapper around the Mode-B round-trip de-identification flow described in
`docs/PLAN-2026-07-23-the-rest.md`: de-identify → Provider summarize → re-identify, with
mandatory TOTP 2FA and server-enforced staff/admin roles. It does **not** touch
`src/deid/` (Mode A, the one-way release pipeline) or the sealed zone.

## Threat model
Motivated attacker + insider-mistake risk (per the plan, driven by a real breach story
Blair experienced). Assumes: an attacker may get valid credentials (phishing, reuse),
may be a staff-level insider who wants to exfiltrate data, or may probe the API surface
directly. Does NOT assume nation-state-level TLS/crypto attacks are in scope for V1.

## Controls implemented

1. **Auth: bcrypt password + mandatory TOTP (RFC 6238).** No login succeeds without a
   valid current 6-digit code from an enrolled authenticator app. No "remember this
   device" bypass exists. Enrollment shows the secret as both QR (rendered server-side,
   embedded as a data: URI — never written to disk) and text.
2. **Roles enforced server-side.** `deps.get_current_user` re-reads the user's CURRENT
   role from the user store on every request — a still-valid session cookie for a
   downgraded account is re-evaluated as the new role immediately (tested in
   `tests/test_role_enforcement.py`). The export route checks `role == admin` in code;
   there is no client-side-only gate. Staff get a real 403, not a hidden button.
3. **Outbound gate.** Every payload sent to Provider is re-scanned
   (`deid_roundtrip.outbound_gate`) for (a) any of the document's own known real
   identifier values still present verbatim, and (b) generic identifier-shaped patterns
   (phone/date/MRN/OHIP/SIN/email) as a second layer. A hit is a hard `IdentifierLeakError`
   — the call to Provider never happens, and the block is audit-logged (category tags only,
   never the matched text).
4. **Encrypted-at-rest re-id vault.** Per-document `{real_value: placeholder}` maps are
   encrypted with Fernet (`cryptography`), key generated on first run into
   `webapp/secrets/vault.key` (0600, gitignored, never printed after creation) and stored
   in `webapp/vault/` (gitignored). Doc IDs are validated against a strict allow-list
   regex before touching the filesystem (blocks path traversal).
5. **Immutable-append audit log.** `webapp/audit/audit.jsonl`, one JSON line per action
   (actor, role, action, doc_id, timestamp). Actions are drawn from a fixed allow-list;
   `detail` is truncated and is a convention-enforced "short status string only" field —
   see Known Gaps below for why this isn't provably PHI-free.
6. **Secrets discipline.** Provider key/base URL loaded from `provider.env` only
   (never hardcoded, never logged — the client module's error path deliberately logs
   only the exception type, never the request/response body). Session-signing secret and
   vault key are generated locally, never committed, never printed.
7. **Sessions.** Signed (itsdangerous), httponly, samesite=lax cookies, 8-hour expiry.
   `secure` flag is tied to `APP_ENV=production` — **you must set this before any real
   deployment over TLS**, see Known Gaps.
8. **No PHI in error responses.** All routes return generic error strings to the client;
   a global exception handler catches anything unhandled and returns a fixed generic
   500 message. Server-side logs record exception *type* and route, never document text.
9. **In-app viewer, no staff download affordance.** Documents render into a read-only
   `<div>` pane; there is no file-serving route reachable by a staff-role session.

## Known gaps — NOT yet secure enough for real PHI

Be honest with yourself before trusting this with one real record:

- **No TLS termination in this app.** It's plain HTTP on localhost for the demo. A real
  deployment needs TLS (reverse proxy — Caddy/nginx — terminating HTTPS) and
  `APP_ENV=production` set so cookies get the `Secure` flag. Without TLS, session
  cookies and the TOTP code are sent in the clear on the wire.
- **User store is a single JSON file, not a database.** Fine for 2 demo accounts; no
  concurrent-write locking, no account lockout / rate limiting on login attempts (a
  determined attacker could brute-force TOTP within its 30s window given enough
  attempts — no lockout or backoff is implemented in V1).
- **The outbound gate is a safety net, not a guarantee.** It catches known identifier
  values and a fixed set of shaped patterns (phone/date/MRN/OHIP/SIN/email). It does
  **not** do general-purpose NER over free text — a novel identifier not in the known
  set and not matching a pattern (e.g. an unusual ID format, a nickname, a rare
  condition that's identifying in context) could pass through undetected. This mirrors
  the free-text gap documented in `docs/AUDIT-2026-07-23.md` and `CHARTER.md` — it is
  not solved here, only mitigated for the fields this demo's documents actually use.
- **Screenshots / trusted-insider risk is not preventable.** No app stops a logged-in
  user photographing their screen. The control is audit logging + least privilege
  (staff can't export files), not DRM. Say this explicitly to any buyer.
- **Audit log `detail` field PHI-freedom is a convention, not enforced by code.** Only
  fixed short strings are ever passed today (verified by reading every `audit.record`
  call site), but nothing stops a future call site from passing document text. Add a
  lint/test rule before this log is trusted as "provably zero PHI" the way
  `src/deid/audit.py` claims to be (and audit finding #2 shows even that claim needed
  correcting once).
- **No rate limiting / brute-force protection** on `/login` or `/enroll`.
- **No key rotation** for the vault Fernet key or the session-signing secret — losing
  `webapp/secrets/vault.key` means every stored re-id map becomes permanently
  unreadable (fail-closed, which is the right failure direction, but there's no backup/
  rotation procedure yet).
- **Vault write path uses `write_bytes`/`write_text`, not atomic replace.** A crash
  mid-write could leave a corrupt map file; `vault.load_map` fails closed (returns `{}`)
  on decrypt failure rather than raising, which is safe but should be surfaced as an
  operator-visible alarm, not silently treated as "no map exists yet."
- **Single-process, no horizontal scaling story**, no health checks, no structured
  monitoring/alerting on the audit log (someone has to go read `audit.jsonl`).
- **This inherits every gap already on record for Sovereign as a whole**: the
  `Patient.extension` leak and filename/token PHI-carry-through in `src/deid/` (Security
  #1/#2 in `docs/AUDIT-2026-07-23.md`) don't apply to this app directly (it never calls
  the release pipeline), but the free-text redaction gap is the same underlying problem
  restated for prose instead of structured fields.

## What I'd probe next to try to break it (attack surfaces, ranked)

1. **TOTP replay / timing** — is `valid_window=1` (±30s) too generous? Try replaying a
   just-used code within its window (pyotp doesn't track "already used" codes — a used
   code is technically valid again until it rolls over, since there's no used-code
   cache). This is a real, currently-unmitigated gap: add a per-user "last accepted
   TOTP step" check to reject exact replays.
2. **Login/enroll brute force** — no lockout; script 6-digit TOTP guesses or password
   guesses and see how far you get before anything alarms (nothing will alarm — there's
   no rate limiting or alerting yet).
3. **Cookie/session tampering** — try flipping role claims inside a captured cookie
   (should fail — signature check — but worth re-verifying with a fuzzer, and check
   what happens with an expired-but-still-signature-valid token near the 8h boundary).
4. **Outbound gate bypass** — craft note text using an identifier that isn't in the
   known-values set and doesn't match any of the 7 fixed regexes (e.g. write a MRN as
   plain digits with no "MRN" prefix, or a European-format date) and see if it reaches
   Provider. This WILL succeed today — it's the documented free-text gap.
5. **Vault key exposure** — read `webapp/secrets/vault.key` as the same OS user the app
   runs as (there's no OS-level separation like Sovereign's two-identity sealed zone for
   this component — anyone who can read the webapp process's files can read the vault
   key and every stored map).
6. **Path/doc_id injection** — try `doc_id` values with `../`, null bytes, or very long
   strings against `/doc/{doc_id}` and the vault/summary file paths (the regex allow-list
   should block the vault side; the document-loading side uses `Path.glob`/direct
   construction and should be re-checked for the same class of bug).
7. **Concurrent writes to `users.json`** — two simultaneous enroll/login requests could
   race on the JSON file (read-modify-write, no lock).
8. **Static file / template injection** — confirm Jinja2 autoescaping is actually on for
   all rendered document text (it is, by default, but worth a direct XSS probe against
   the "note" field since it's `{{ doc.note }}` interpolated as user-influenced content
   in this demo, even though these documents are trusted fixtures for V1).

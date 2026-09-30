# Secure Coding Review — Findings Report

**Target app:** VulnNotes — a small Flask "notes" demo service (`target_app/app.py`)
**Language:** Python 3 (Flask)
**Tools used:** bandit 1.9.4 (static analysis) + manual review
**Scan command:** `bandit -r target_app`
**Raw evidence:** `bandit_output.txt`
**Date:** 2026-09-26

---

## Method
1. Picked a Python Flask app as the target (fastest path with `bandit`).
2. Ran `bandit -r target_app`; it reported 16 issues (5 High, 7 Medium, 4 Low).
3. Manually reviewed each flagged line to separate genuine, exploitable bugs from
   informational noise (see "Manual triage notes" below).
4. Categorised by severity and wrote remediation for each.

**Bandit totals:** High: 5 · Medium: 7 · Low: 4 (16 total)

---

## Finding 1 — Command Injection via shell
- **File/line:** `target_app/app.py:67` (`/ping`) and `app.py:104` (`backup()`)
- **Bandit IDs:** B602, B605 · **Severity:** **High** · **CWE-78**
- **Description:** `subprocess.check_output("ping -c 1 " + host, shell=True)` and
  `os.system("tar ... " + DB_PATH)` build a shell command by string concatenation.
  The `host` value comes straight from `request.args`, so a request like
  `/ping?host=127.0.0.1;id` executes arbitrary shell commands on the server —
  full remote code execution.
- **Recommendation:** Never pass user input to a shell. Use an argument list with
  `shell=False`: `subprocess.run(["ping", "-c", "1", host], capture_output=True)`,
  and validate `host` against an IP/hostname allowlist.

## Finding 2 — Arbitrary Code Execution via `eval()`
- **File/line:** `target_app/app.py:75` (`/calc`)
- **Bandit ID:** B307 · **Severity:** **High** (rated Medium by bandit; raised on manual review — direct RCE) · **CWE-95**
- **Description:** `eval(request.args.get("expr"))` evaluates attacker-supplied
  Python. `/calc?expr=__import__('os').system('id')` runs arbitrary code.
- **Recommendation:** Remove `eval`. For arithmetic use `ast.literal_eval` or a
  proper expression parser; never evaluate untrusted strings as code.

## Finding 3 — Flask debug mode enabled in "production"
- **File/line:** `target_app/app.py:109`
- **Bandit ID:** B201 · **Severity:** **High** · **CWE-94**
- **Description:** `app.run(debug=True)` exposes the Werkzeug interactive
  debugger. On an unhandled exception an attacker can reach the debugger console
  and execute arbitrary code in the app context.
- **Recommendation:** Set `debug=False` in production; drive it from an env var
  (`FLASK_DEBUG`) that defaults to off.

## Finding 4 — TLS certificate verification disabled
- **File/line:** `target_app/app.py:98` (`/fetch`)
- **Bandit ID:** B501 · **Severity:** **High** · **CWE-295**
- **Description:** `requests.get(url, verify=False)` disables certificate
  validation, so any man-in-the-middle can impersonate the remote host and feed
  the app forged responses. (The user-controlled `url` also makes this an SSRF
  vector — see Finding 9.)
- **Recommendation:** Remove `verify=False` (verification is on by default). If a
  custom CA is needed, point `verify` at the CA bundle path.

## Finding 5 — SQL Injection
- **File/line:** `target_app/app.py:44` (`/login`) and `app.py:57` (`/notes`)
- **Bandit ID:** B608 · **Severity:** **High** (bandit Medium; raised — auth bypass + data theft) · **CWE-89**
- **Description:** Queries are built with `%` / `.format()` on user input.
  `/notes?id=0 OR 1=1` dumps other users' notes; the login query can be bypassed
  with `' OR '1'='1` in the username, defeating authentication.
- **Recommendation:** Use parameterised queries only:
  `cur.execute("SELECT body FROM notes WHERE id = ?", (note_id,))`. Never build
  SQL by string formatting.

## Finding 6 — Weak password hashing (MD5, unsalted)
- **File/line:** `target_app/app.py:39` (`/login`)
- **Bandit ID:** B324 · **Severity:** **High** · **CWE-327**
- **Description:** Passwords are hashed with unsalted MD5, which is fast and
  broken — trivially cracked with rainbow tables / GPU brute force.
- **Recommendation:** Use a slow, salted password hash: `bcrypt`, `argon2`, or
  `scrypt` (e.g. `werkzeug.security.generate_password_hash`).

## Finding 7 — Insecure deserialization (pickle & unsafe YAML)
- **File/line:** `target_app/app.py:82` (`/import_prefs`, pickle) and `app.py:90` (`/load_config`, YAML)
- **Bandit IDs:** B301, B506 (also B403 import) · **Severity:** **High** (bandit Medium; raised — untrusted input → RCE) · **CWE-502**
- **Description:** `pickle.loads()` on the raw request body and `yaml.load()`
  without a safe loader both instantiate arbitrary Python objects from attacker
  data, leading to remote code execution.
- **Recommendation:** Never unpickle untrusted data — use JSON for external
  input. For YAML use `yaml.safe_load()`.

## Finding 8 — Hardcoded secrets in source
- **File/line:** `target_app/app.py:25` (`ADMIN_PASSWORD`) and `app.py:26` (`API_TOKEN`)
- **Bandit ID:** B105 · **Severity:** **Medium** · **CWE-798**
- **Description:** An admin password and a live-looking API token are committed
  in source. Anyone with repo access (or a leaked repo) gets the credentials.
- **Recommendation:** Load secrets from environment variables or a secret manager;
  rotate any secret that has ever been committed; add `.env` to `.gitignore`.

## Finding 9 — Server-Side Request Forgery (manual finding)
- **File/line:** `target_app/app.py:98` (`/fetch`)
- **Bandit ID:** *(not flagged by bandit — found via manual review)* · **Severity:** **Medium** · **CWE-918**
- **Description:** `/fetch?url=` fetches any attacker-supplied URL. An attacker
  can reach internal services and cloud metadata, e.g.
  `/fetch?url=http://169.254.169.254/latest/meta-data/`.
- **Recommendation:** Allowlist permitted hosts/schemes, resolve and block
  private/link-local IP ranges, and disable redirects.

## Finding 10 — Lower-severity / hardening items
- **`requests` without timeout** — `app.py:98`, B113 (Medium/Low conf): a slow
  remote host can hang the worker. Add `timeout=`.
- **Bind to all interfaces** — `app.py:109`, B104 (Medium): `host="0.0.0.0"`
  exposes the dev server on every interface. Bind to `127.0.0.1` behind a proxy.
- **Module import warnings** — B403 (pickle), B404 (subprocess) at lines 12/14
  are informational; they matter only because of Findings 1 and 7 above.

---

## Manual triage notes (Step 3: real issue vs false positive)
- **Confirmed exploitable:** Findings 1–8 (bandit-flagged) and 9 (manual). All
  trace user-controlled input to a dangerous sink.
- **Severity adjusted up from bandit:** SQLi, `eval`, pickle/YAML — bandit rates
  these Medium generically, but here the sinks receive unauthenticated remote
  input, so real-world severity is High.
- **Informational (not standalone bugs):** B403 / B404 import notices — kept as
  context, not counted as separate vulnerabilities.

---

## Summary
**Total findings:** 16 bandit issues (5 High / 7 Medium / 4 Low) consolidated into
**9 distinct vulnerabilities** + 1 hardening group, plus 1 manual finding (SSRF)
that static analysis missed.

**Overall risk assessment: CRITICAL.** The app is trivially remotely exploitable:
three independent paths to remote code execution (command injection, `eval`,
insecure deserialization), authentication bypass and data theft via SQL injection,
and a debug console reachable on all interfaces. It must not be deployed until
Findings 1–8 are remediated. Highest priority: eliminate all three RCE paths and
the SQL injection, then move secrets out of source and disable debug mode.

### Remediation priority
1. Kill RCE: remove `shell=True`/`os.system`, `eval`, `pickle.loads`, `yaml.load`.
2. Parameterise all SQL queries.
3. Disable Flask debug; bind to localhost behind a proxy.
4. Move secrets to env/secret manager and rotate; restore TLS verification.
5. Replace MD5 with bcrypt/argon2; add SSRF allowlisting and request timeouts.

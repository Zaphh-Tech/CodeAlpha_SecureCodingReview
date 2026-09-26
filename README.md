# CodeAlpha_SecureCodingReview

A secure coding review of a small Python web app, done for Task 3 of the CodeAlpha
Cyber Security internship.

For this task I wrote a small Flask app on purpose full of common security mistakes,
scanned it with a static analysis tool, then went through the results by hand to
confirm what was real and write up how to fix each one.

## What's in here

- `target_app/app.py` — the app being reviewed (deliberately insecure, don't deploy it)
- `bandit_output.txt` — the raw output from the Bandit scan
- `findings_report.md` — my write-up: every issue with its severity and a fix

## Running the scan yourself

```bash
pip install bandit
bandit -r target_app
```

Bandit flagged 16 issues (5 high, 7 medium, 4 low) — things like SQL injection,
command injection, use of `eval`, insecure deserialization, hardcoded secrets and
weak password hashing. While reviewing the results I also found a server-side request
forgery (SSRF) bug that the scanner didn't catch, which is in the report too.

The main takeaway: a scanner is a good starting point, but reading the code yourself
is where the rest of the findings come from.

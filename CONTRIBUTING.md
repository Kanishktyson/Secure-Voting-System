# Contributing

Thanks for helping improve SecureVote. This repository is an **educational
prototype**, not election software. Changes should keep the trusted computing
base small, readable and testable.

## Ground rules

- **Runtime code stays Python-standard-library-only.** Do not add Flask,
  cryptography frameworks, ORMs or front-end JavaScript. `requirements.txt`
  intentionally has zero runtime dependencies.
- Dev/CI tools are separate: `requirements-dev.txt` for coverage,
  `requirements-browser.txt` for Playwright E2E.
- Keep ballots anonymous by schema. Never add a voter ID, foreign key or
  receipt secret to `ballots`, `sessions` or `audit_log`.
- Preserve the fail-closed behaviour: chain errors, sealed results, CSRF
  failures and malformed election files must never silently pass.
- Update tests and docs with behaviour changes. Avoid claims of production
  election readiness.

## Local setup

```bash
git clone https://github.com/Kanishktyson/Secure-Voting-System.git
cd Secure-Voting-System
python3 -m pip install -r requirements-dev.txt
make check
```

`make check` runs the unit/HTTP suite with a 90% coverage gate and the
dependency-free lifecycle E2E. To run the full CI-equivalent gate:

```bash
make browser-install       # Playwright + Chromium; may require system packages
make check-all
```

If you already have a Chromium binary, set `SVS_CHROME_PATH=/path/to/chromium`
and run `python3 scripts/browser_e2e.py` directly.

## Before opening a pull request

- [ ] `python3 -m compileall -q secure_vote tests scripts`
- [ ] `make check`
- [ ] `make check-all` (or explain why the browser job cannot run locally)
- [ ] New config / CLI / HTTP behaviour has a regression test
- [ ] README, examples and screenshots are updated if the UI changed
- [ ] No runtime state (`data/`, `*.db`, `*.key`, `.coverage`) is committed
- [ ] Security-sensitive changes include a note in `SECURITY.md` / changelog

Use the pull request template checklist. Small, focused PRs with a clear threat
model note are easiest to review.

## Reporting bugs

Use the bug report issue form. For a suspected vulnerability, follow
[`SECURITY.md`](SECURITY.md) instead of opening a public issue.

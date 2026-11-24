# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
release is tagged.

## [Unreleased]

### Added

- Strict, reusable election definitions via `SVS_ELECTION_FILE` and
  [`examples/election.json`](examples/election.json), with DB-persisted
  title/description/candidates and an immutable candidate fingerprint.
- Atomic `import-voters` CSV command plus
  [`examples/voters.csv`](examples/voters.csv).
- `export --what results|audit` CLI commands and public
  `/export/results.json` / `/export/audit.json` download endpoints. Results
  bundles include the certified tally, integrity summary and signed checkpoint;
  audit bundles include the full HMAC chain. Results remain sealed until close.
- Real Chromium end-to-end test (`scripts/browser_e2e.py`) covering rendered
  CSS, no-JS navigation, custom ballots, receipt verification, sealed results,
  admin close and JSON downloads. A dedicated CI job installs Playwright's
  Chromium and runs it on every push / PR.
- GitHub community polish: issue forms, PR checklist, contributing guide,
  security policy, code of conduct, changelog and Dependabot configuration.
- Replaced the generic gradient dashboard with a civic-paper ledger design
  system: warm paper, ink rules, vermilion stamp accent, serif display type,
  lettered ballot sheets, printable receipts, a progress stepper, sealed
  envelope state, certified-return results and ruled ledger tables.
- [`docs/DESIGN.md`](docs/DESIGN.md) documenting the visual rules, tokens and
  anti-patterns.
- 16 new tests (105 total), including a design regression test, and refreshed
  screenshots (`00-overview.png`, `01`–`12`).

### Changed

- Election metadata is now read from the database on every request, so the UI
  and exports cannot drift from the initialized election definition.
- `make check-all` runs the coverage gate, HTTP E2E and browser E2E;
  `make browser-install` provisions Playwright separately.
- README now documents the civic-ledger design, custom elections,
  import/export, browser CI and the exact production limitations.

### Verification

- `105` unit/integration tests pass; statement coverage is `96%` with a
  `90%` CI gate.
- `scripts/e2e.py` and `scripts/browser_e2e.py` pass locally.
- Runtime remains Python-standard-library-only; all browser tooling is
  development/CI-only.

### Security

- Candidate definitions cannot be changed for an existing database without an
  explicit reset; malformed election files fail loudly.
- Bulk voter imports roll back completely on any duplicate or weak credential.
- JSON exports are `no-store` and never include passwords, receipt secrets or
  ballot choices.

# Security policy

## Scope

SecureVote is a **teaching prototype**. It demonstrates verifiable receipt
checking, anonymous ballot storage and tamper-evident chains using only the
Python standard library. It is **not suitable for real elections**: the server
sees plaintext choices, there is no threshold encryption, coercion resistance,
distributed witness network or professional audit. See
[`README.md`](README.md#threat-model--limitations) and
[`docs/EXTENDING.md`](docs/EXTENDING.md).

Security work on the prototype itself is still welcome.

## Supported versions

| Version | Supported |
| --- | --- |
| Current default branch | ✅ |
| Older tagged releases | ❌ (none yet) |

Fixes are made on the default branch; there is no separate security backport
process.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability.

Use GitHub's **private vulnerability reporting** on the repository
(*Security → Report a vulnerability*) or contact the maintainers privately
through GitHub. Include:

1. A description of the issue and its impact on the stated prototype threat model.
2. Affected commit / version, Python version and OS.
3. Minimal reproduction steps or a proof-of-concept script.
4. Any suggested fix, without including real credentials or personal data.

You should receive an acknowledgement within 7 days. We will coordinate a fix,
add a regression test and disclose the issue after the patch is available.
Please give us reasonable time to respond before public disclosure.

## Out of scope

- Requests to deploy this prototype for binding public elections.
- Missing production features already documented in the threat model
  (end-to-end encryption, receipt-freeness, distributed transparency logs,
  HSM/KMS separation, load/DR testing, formal WCAG audit).
- Findings that require an attacker to already control the single trusted
  server and its HMAC key; this is explicitly assumed honest in the prototype.
- Vulnerabilities in demo credentials or the embedded HTTP preview mode; never
  use either outside a local demo.

## Hardening checklist for experiments

- Terminate TLS; set `SVS_SECURE_COOKIES=1`, `SVS_SAMESITE=strict` and
  `SVS_STRICT_FRAME_POLICY=1`.
- Provide `SVS_SECRET_KEY` from a secret manager; keep it off the DB host.
- Export signed `checkpoint` snapshots to an independent, append-only witness.
- Run `python3 -m secure_vote verify` and `make check-all` after every change.

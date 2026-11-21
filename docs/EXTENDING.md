# From prototype to a real election system

This repository is deliberately honest about what it is **not**: a single trusted
server sees every plaintext choice, and there is no coercion resistance. This
document is the concrete upgrade path. Each section names the gap, the
cryptographic tool that closes it, and the code that would have to change.

## 1. Ballot confidentiality against the server

**Gap.** `service.cast_ballot` receives `choice` in cleartext and writes it to
`ballots.choice`. Anyone with database or process access can read every vote.

**Tool.** Threshold ElGamal / Paillier encryption with distributed trustees.

- Publish an election public key `PK` whose secret key is split among *n*
  trustees with a *t-of-n* threshold.
- The client encrypts the choice under `PK` **before** submission (homomorphic
  or randomized encoding); the server stores only ciphertext.
- Tally by homomorphic addition of ciphertexts, then run a distributed
  decryption ceremony. No single party ever holds the decryption key.
- Each ciphertext needs a NIZK proof that it encodes a valid option (0/1 per
  candidate) and that the voter knows the plaintext — otherwise a malicious
  client can submit `1000` votes for one candidate.

**Code changes.** `config.py` (trustee keys), `service.cast_ballot` (verify NIZK,
store ciphertext), `tally()` (homomorphic sum + threshold decryption), `views`
(ballot client-side encryption — this is where the current "no JS" rule would
have to be relaxed, with a strict, audited, vendored script and a matching CSP
hash), and the entire test suite for ciphertext equality/proofs.

## 2. Eligibility without a linkable voter list

**Gap.** `voters.has_voted` is trusted database state; the voting service knows
which account is voting, and `audit_log.actor` records it.

**Tool.** Anonymous credentials / blind signatures.

- A registrar blindly signs a one-time voting token after checking eligibility.
- The voter later presents the unblinded token with a nullifier derived from it;
  the nullifier prevents double voting without revealing the token's origin.
- Eligibility becomes publicly checkable, and the casting service never sees a
  real identity.

**Code changes.** Replace `voters`/`sessions` with registrar + token issuer,
replace the conditional `UPDATE ... WHERE has_voted = 0` with a nullifier
uniqueness constraint (still inside `BEGIN IMMEDIATE`), and stop logging actor
names in `audit_log`.

## 3. Coercion resistance / receipt-freeness

**Gap.** A voter can show their `nonce` and prove exactly how they voted, which
enables vote buying and coercion.

**Tool.** Re-voting with a fake-credential scheme (Juels–Catalano–Jakobsson),
or a designated-verifier receipt that the voter can simulate.

- Allow multiple ballots per credential; only the last counts, so a coercer
  cannot tell whether a later ballot overwrote the observed one.
- Receipts must be *deniable*: the voter can produce a convincing fake receipt
  for any choice.

**Code changes.** This breaks the current one-person-one-vote transaction and the
`receipt` flow; it is the deepest change in the list and should be designed
before any of the others are implemented.

## 4. Independent, append-only transparency

**Gap.** The bulletin board and audit log are served by the same host that can
rewrite them, and the HMAC key lives next to the database.

**Tool.** Merkle-tree transparency log with external witnesses.

- Every ballot and audit entry becomes a leaf; publish signed tree heads.
- Multiple independent mirrors gossip and cross-sign heads; clients verify
  consistency proofs between heads.
- Move the HMAC key to a KMS/HSM. Sign chain heads with a key that cannot be
  used to rewrite history from the application host.

**Partial step already implemented.** `python3 -m secure_vote checkpoint`
exports an HMAC-signed snapshot of both chain heads, and
`verify --checkpoint PATH` proves the saved file was not edited and that the
chain prefix it describes still exists. Keep those files off-host. It is a
detective control, not a distributed log — but it makes silent history rewrites
detectable today.

**Code changes.** `audit.py` and `verify_ballot_chain` gain Merkle proofs;
`service.create_checkpoint` becomes a signed tree head; add a witness API.

## 5. Operational hardening

| Gap today | Production requirement |
| --- | --- |
| Plain HTTP preview | TLS terminating proxy; `SVS_SECURE_COOKIES=1`, `SVS_SAMESITE=strict`, `SVS_STRICT_FRAME_POLICY=1` |
| Single SQLite file | Replicated, encrypted storage; WAL backups; tested disaster recovery |
| In-memory `RateLimiter` | Shared store (Redis) with per-IP and per-account limits |
| Admin is one account | Multi-person ceremony with threshold authorization for open/close |
| No monitoring | Alert on chain verification failure, state transitions, login spikes |
| No independent audit | Third-party code review, penetration test, accessibility audit, public source + reproducible builds |

## 6. Verification, UX and process

**Already in the repository:**

- `coverage report --fail-under=90`, HTTP lifecycle E2E, CLI/import/export smoke
  tests and a separate real Chromium Playwright job run in
  `.github/workflows/ci.yml`. The browser job checks rendered CSS, tab focus,
  no-JS navigation, custom ballot options, receipt verification, sealed results,
  admin close and JSON downloads.
- `SECURITY.md`, issue/PR templates, a code of conduct, contribution guide and
  changelog provide a basic disclosure and review process.
- Custom election files, immutable candidate fingerprints, atomic voter-roll
  import and signed JSON exports keep configuration and verification data
  portable without adding runtime dependencies.

**Still needed before any production claim:**

- Keyboard-only navigation and screen-reader snapshots inside the browser E2E;
  the current accessibility work covers labels, skip links, focus rings,
  `aria-current`, `aria-label` on result bars and reduced-motion preferences,
  but has not been professionally audited.
- i18n, a formal written threat model, third-party code review, penetration
  testing, load testing and a public WCAG sign-off.

## Ordering recommendation

1. Operational hardening (cheap, no protocol change).
2. Distributed transparency + off-host checkpoints (already started).
3. Threshold encryption with NIZK proofs.
4. Anonymous credentials.
5. Coercion resistance — redesign, not an incremental patch.

Steps 3–5 should be treated as a new system with its own formal security proof,
not as a refactor of this prototype.

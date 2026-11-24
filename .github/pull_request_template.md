## Summary

<!-- What changed, and why? Keep it focused. -->

## Scope

- [ ] Runtime code remains Python-standard-library-only
- [ ] No voter identifier, receipt secret or ballot choice was added to logs / schema
- [ ] Fail-closed behaviour is preserved (chains, CSRF, sealed results, config validation)
- [ ] README / `docs/EXTENDING.md` / examples are updated where needed
- [ ] Screenshots are refreshed if the UI changed
- [ ] `CHANGELOG.md` has an entry for user-visible changes

## Verification

```text
paste the relevant output here, e.g.
Ran 104 tests ... OK
TOTAL ... 96%
[e2e] OK — full lifecycle passed
[browser] OK — real Chromium lifecycle passed
```

- [ ] `python3 -m compileall -q secure_vote tests scripts`
- [ ] `make check`
- [ ] `make check-all` (or explain why Chromium was unavailable)
- [ ] No runtime state (`data/`, `*.db`, `*.key`, `.coverage`) is included

## Security / threat-model note

<!-- Does this change the trusted-server assumption, ballot secrecy, verifiability
or deployment guidance? If not, write "No change". -->

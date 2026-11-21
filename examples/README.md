# Examples

These files are used by tests, CI smoke checks and the real-browser E2E job.

## `election.json`

Set `SVS_ELECTION_FILE=examples/election.json` **before the first `init`**:

```bash
export SVS_ELECTION_FILE=examples/election.json
export SVS_DB=data/campus-election.db
python3 -m secure_vote init
python3 -m secure_vote serve
```

Schema:

| Field | Type | Rules |
| --- | --- | --- |
| `title` | string | 1–120 characters |
| `description` | string | ≤ 500 characters; optional |
| `candidates` | array | 2–20 entries |
| `candidates[].key` | string | Unique, `^[a-z0-9_]{1,32}$`; stored in ballots |
| `candidates[].label` | string | 1–120 characters; displayed on the ballot |
| `candidates[].description` | string | ≤ 200 characters; optional |

The definition is persisted with a keyed fingerprint. To change candidates,
start a new `--db` path or use `reset --yes` (which deletes election data).

## `voters.csv`

Optional header `username,password`, then one row per voter:

```csv
username,password
amina,ExamplePass123!
bennett,ExamplePass123!
```

Import atomically:

```bash
python3 -m secure_vote import-voters examples/voters.csv
```

Every username and password is validated before any account is committed. A
single duplicate, malformed row or weak password rolls back the whole import.
These sample passwords are for local tests only — never reuse them.

"""SQLite persistence: schema, connections and explicit write transactions.

Two deliberate choices make the security properties enforceable rather than
aspirational:

* The ``ballots`` table has **no voter identifier column at all** (and no
  foreign key to ``voters``), so the schema itself prevents the most common
  ballot-secrecy bug: an accidental join between a person and a vote.
* Every multi-step write runs inside ``BEGIN IMMEDIATE``. SQLite then serialises
  writers for us, which is what makes "one person, one vote" race-free.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .config import Config
from .crypto import CANDIDATES_TAG, GENESIS_HASH, digest, hash_password, safe_equals

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
    key         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    ordinal     INTEGER NOT NULL
);

-- Credentials and eligibility only. There is intentionally NO reference to a
-- ballot here, and a single has_voted flag is the only link to participation.
CREATE TABLE IF NOT EXISTS voters (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'voter'
                  CHECK (role IN ('voter', 'admin')),
    has_voted     INTEGER NOT NULL DEFAULT 0 CHECK (has_voted IN (0, 1)),
    created_at    TEXT NOT NULL
);

-- Anonymous ballots. `ballot_hash` is a public commitment;
-- `chain_hash` is a keyed HMAC link to the previous ballot.
CREATE TABLE IF NOT EXISTS ballots (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    ballot_id     TEXT NOT NULL UNIQUE,
    tracking_code TEXT NOT NULL UNIQUE,
    choice        TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    ballot_hash   TEXT NOT NULL,
    chain_hash    TEXT NOT NULL
);

-- Only a hash of the session token is stored: a database dump must not be
-- enough to hijack a live session.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    voter_id    INTEGER NOT NULL REFERENCES voters(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at);

-- Append-only, hash-chained event log. No ballot choices are ever logged.
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""

VALID_STATES = ("setup", "open", "closed")

ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "setup": ("open",),
    "open": ("closed",),
    "closed": (),
}


def utcnow() -> str:
    """Timezone-aware ISO-8601 timestamp with microsecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def epoch_now() -> int:
    return int(time.time())


def connect(config: Config) -> sqlite3.Connection:
    """Open a fresh connection. One connection per request/thread."""
    config.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(config.db_path),
        timeout=10.0,
        isolation_level=None,  # we manage transactions explicitly
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


@contextmanager
def open_db(config: Config) -> Iterator[sqlite3.Connection]:
    """Connection context manager that actually closes the handle on exit.

    ``sqlite3.Connection.__exit__`` only commits/rolls back a transaction, so a
    plain ``with connect(...)`` silently leaks file descriptors.
    """
    conn = connect(config)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def write_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """A serialisable write transaction (BEGIN IMMEDIATE takes the write lock)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_state(conn: sqlite3.Connection) -> str:
    state = get_meta(conn, "election_state", "setup")
    return state if state in VALID_STATES else "setup"


def initialize(
    config: Config,
    *,
    admin_username: str = "admin",
    admin_password: str | None = None,
    initial_state: str = "open",
) -> str | None:
    """Create the schema and seed immutable election data.

    Returns the generated admin password when one had to be created, so the CLI
    can print it exactly once. Idempotent: safe to run on every startup.
    """
    if initial_state not in VALID_STATES:
        raise ValueError(f"invalid initial election state: {initial_state}")

    generated: str | None = None
    with open_db(config) as conn:
        conn.executescript(SCHEMA)
        with write_tx(conn):
            # A ballot definition is immutable once the election exists: silently
            # accepting a different candidate list would invalidate every
            # already-cast ballot.
            fingerprint = digest(
                CANDIDATES_TAG,
                *[f"{c.key}:{c.label}" for c in config.candidates],
            )
            existing = get_meta(conn, "candidate_fingerprint")
            if existing is None:
                set_meta(conn, "candidate_fingerprint", fingerprint)
                set_meta(conn, "election_title", config.election_title)
                set_meta(conn, "election_description", config.election_description)
            elif not safe_equals(existing, fingerprint):
                raise ValueError(
                    "Election candidates changed after the database was created. "
                    "Use a fresh --db path or 'reset --yes' to start a new election."
                )

            for ordinal, candidate in enumerate(config.candidates):
                conn.execute(
                    "INSERT OR IGNORE INTO candidates (key, label, description, ordinal) "
                    "VALUES (?, ?, ?, ?)",
                    (candidate.key, candidate.label, candidate.description, ordinal),
                )
            if get_meta(conn, "election_state") is None:
                set_meta(conn, "election_state", initial_state)
            set_meta(conn, "schema_version", "1")

            existing_admin = conn.execute(
                "SELECT 1 FROM voters WHERE role = 'admin' LIMIT 1"
            ).fetchone()
            if not existing_admin and admin_username:
                if admin_password is None:
                    from .crypto import random_token

                    admin_password = f"Svs-{random_token(12)}!"
                    generated = admin_password
                conn.execute(
                    "INSERT INTO voters (username, password_hash, role, created_at) "
                    "VALUES (?, ?, 'admin', ?)",
                    (
                        admin_username,
                        hash_password(
                            admin_password, iterations=config.pbkdf2_iterations
                        ),
                        utcnow(),
                    ),
                )
    return generated

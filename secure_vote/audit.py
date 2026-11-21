"""Append-only, hash-chained audit log.

Each entry carries an HMAC of its own contents plus the previous entry's HMAC.
Editing, deleting or reordering any historical row therefore invalidates the
whole suffix of the chain, which :func:`verify_audit_chain` detects.
"""

from __future__ import annotations

import sqlite3

from .config import Config
from .crypto import AUDIT_CHAIN_TAG, GENESIS_HASH, mac, safe_equals
from .db import utcnow


def append_audit(
    conn: sqlite3.Connection,
    config: Config,
    actor: str,
    action: str,
    detail: str,
) -> None:
    """Append an entry. Call inside :func:`secure_vote.db.write_tx`.

    ``detail`` must never contain credentials, ballot choices or receipt
    secrets — the log is publicly readable for transparency.
    """
    last = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev_hash = last["entry_hash"] if last else GENESIS_HASH
    ts = utcnow()
    entry_hash = mac(
        config.secret_key, AUDIT_CHAIN_TAG, prev_hash, ts, actor, action, detail
    )
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (ts, actor, action, detail, prev_hash, entry_hash),
    )


def verify_audit_chain(
    conn: sqlite3.Connection, config: Config
) -> tuple[bool, list[str]]:
    """Return ``(is_intact, problems)`` for the entire audit log."""
    problems: list[str] = []
    expected_prev = GENESIS_HASH
    for row in conn.execute(
        "SELECT seq, ts, actor, action, detail, prev_hash, entry_hash "
        "FROM audit_log ORDER BY seq ASC"
    ):
        if not safe_equals(row["prev_hash"], expected_prev):
            problems.append(f"entry {row['seq']}: broken predecessor link")
        recomputed = mac(
            config.secret_key,
            AUDIT_CHAIN_TAG,
            row["prev_hash"],
            row["ts"],
            row["actor"],
            row["action"],
            row["detail"],
        )
        if not safe_equals(recomputed, row["entry_hash"]):
            problems.append(f"entry {row['seq']}: content hash mismatch")
        expected_prev = row["entry_hash"]
    return (not problems, problems)


def read_audit_log(
    conn: sqlite3.Connection, limit: int = 100
) -> list[sqlite3.Row]:
    """Most recent entries first (clamped to a bounded, safe limit)."""
    safe_limit = max(1, min(int(limit), 500))
    return list(
        conn.execute(
            "SELECT seq, ts, actor, action, detail FROM audit_log "
            "ORDER BY seq DESC LIMIT ?",
            (safe_limit,),
        )
    )

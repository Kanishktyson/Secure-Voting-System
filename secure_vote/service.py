"""Election domain logic.

This is the only module that creates ballots or changes election state. Keeping
those operations in one place makes the invariants reviewable:

1. A ballot is accepted only while the election is ``open``.
2. At most one ballot per voter, enforced by a conditional UPDATE inside a
   serialisable transaction (no check-then-act race).
3. Nothing that identifies a voter is written to the ballots table.
4. Every ballot commits to its contents with a public hash and is linked into a
   keyed HMAC hash chain.
5. Every state change appends to the audit log.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from .audit import append_audit, verify_audit_chain
from .config import Candidate, Config
from .crypto import (
    BALLOT_CHAIN_TAG,
    BALLOT_TAG,
    CHECKPOINT_TAG,
    GENESIS_HASH,
    RESULTS_TAG,
    digest,
    dummy_password_check,
    hash_password,
    mac,
    random_token,
    safe_equals,
    verify_password,
)
from .db import (
    ALLOWED_TRANSITIONS,
    epoch_now,
    get_meta,
    get_state,
    set_meta,
    utcnow,
    write_tx,
)

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
SESSION_TAG = "securevote/v1/session"


class VotingError(Exception):
    """Base class for expected, user-facing failures."""


class ValidationError(VotingError):
    """Invalid input."""


class AuthenticationError(VotingError):
    """Bad credentials."""


class PermissionDenied(VotingError):
    """Authenticated but not allowed to perform the operation."""


class ElectionNotOpen(VotingError):
    """Voting is not currently permitted."""


class AlreadyVoted(VotingError):
    """This voter has already cast a ballot."""


class InvalidTransition(VotingError):
    """Illegal election state change."""


@dataclass(frozen=True)
class SessionContext:
    """Everything a handler may know about the current request's identity."""

    token_hash: str
    csrf_token: str
    voter_id: int
    username: str
    role: str
    has_voted: bool

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


@dataclass(frozen=True)
class IntegrityReport:
    """Result of walking a hash chain."""

    ok: bool
    problems: list[str]
    invalid_seqs: frozenset[int]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def validate_username(username: str) -> str:
    cleaned = (username or "").strip().lower()
    if not USERNAME_RE.fullmatch(cleaned):
        raise ValidationError(
            "Username must be 3-32 characters: lowercase letters, digits or underscore."
        )
    return cleaned


def validate_password(password: str) -> str:
    if not isinstance(password, str) or "\x00" in password:
        raise ValidationError("Invalid password.")
    if not (12 <= len(password) <= 128):
        raise ValidationError("Password must be between 12 and 128 characters.")
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise ValidationError("Password must contain at least one letter and one digit.")
    return password


def candidates_from_db(conn: sqlite3.Connection, config: Config) -> list[Candidate]:
    rows = conn.execute(
        "SELECT key, label, description FROM candidates ORDER BY ordinal ASC"
    ).fetchall()
    if not rows:
        return list(config.candidates)
    return [Candidate(r["key"], r["label"], r["description"]) for r in rows]


# ---------------------------------------------------------------------------
# Identity and sessions
# ---------------------------------------------------------------------------


def _insert_voter_locked(
    conn: sqlite3.Connection,
    config: Config,
    username: str,
    password: str,
    role: str = "voter",
) -> tuple[int, str]:
    """Insert one voter and return ``(voter_id, username)``.

    Caller MUST already hold a ``write_tx``. The id is captured before the
    audit insert, otherwise ``last_insert_rowid()`` would return the log row.
    """
    clean_username = validate_username(username)
    clean_password = validate_password(password)
    encoded = hash_password(clean_password, iterations=config.pbkdf2_iterations)
    cursor = conn.execute(
        "INSERT INTO voters (username, password_hash, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (clean_username, encoded, role, utcnow()),
    )
    voter_id = int(cursor.lastrowid)
    append_audit(
        conn, config, clean_username, "voter_registered", f"role={role}"
    )
    return voter_id, clean_username


def register_voter(
    conn: sqlite3.Connection,
    config: Config,
    username: str,
    password: str,
    *,
    role: str = "voter",
) -> int:
    """Create a voter. Usernames are unique (case-insensitively)."""
    if role not in ("voter", "admin"):
        raise ValidationError("Invalid role.")
    try:
        with write_tx(conn):
            voter_id, _ = _insert_voter_locked(conn, config, username, password, role)
            return voter_id
    except sqlite3.IntegrityError as exc:
        raise ValidationError("That username is already registered.") from exc


def import_voters(
    conn: sqlite3.Connection,
    config: Config,
    credentials: list[tuple[str, str]],
) -> list[str]:
    """Atomically import a voter roll. All-or-nothing on any invalid row."""
    if not credentials:
        raise ValidationError("The voter file is empty.")
    try:
        with write_tx(conn):
            return [
                _insert_voter_locked(conn, config, username, password)[1]
                for username, password in credentials
            ]
    except sqlite3.IntegrityError as exc:
        raise ValidationError(
            "A username in the file is already registered; no accounts were added."
        ) from exc


def authenticate(
    conn: sqlite3.Connection, config: Config, username: str, password: str
) -> sqlite3.Row | None:
    """Return the voter row on success, ``None`` otherwise (with equal timing)."""
    clean = (username or "").strip().lower()
    candidate = (password or "")
    row = conn.execute(
        "SELECT * FROM voters WHERE username = ?", (clean,)
    ).fetchone()
    if row is None:
        dummy_password_check(candidate, iterations=config.pbkdf2_iterations)
        return None
    if not verify_password(candidate, row["password_hash"]):
        return None
    return row


def _session_hash(raw_token: str) -> str:
    return digest(SESSION_TAG, raw_token)


def start_session(
    conn: sqlite3.Connection,
    config: Config,
    voter_id: int,
    *,
    previous_token: str | None = None,
) -> tuple[str, SessionContext]:
    """Issue a fresh session, rotating away any previous one (anti-fixation)."""
    raw = random_token(32)
    token_hash = _session_hash(raw)
    csrf = random_token(32)
    expires_at = epoch_now() + config.session_ttl_seconds

    with write_tx(conn):
        voter = conn.execute(
            "SELECT id, username, role, has_voted FROM voters WHERE id = ?",
            (voter_id,),
        ).fetchone()
        if voter is None:
            raise AuthenticationError("Unknown account.")
        if previous_token:
            conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (_session_hash(previous_token),),
            )
        conn.execute(
            "INSERT INTO sessions (token_hash, voter_id, csrf_token, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (token_hash, voter_id, csrf, utcnow(), expires_at),
        )
        append_audit(conn, config, voter["username"], "login", "session issued")

    context = SessionContext(
        token_hash=token_hash,
        csrf_token=csrf,
        voter_id=voter["id"],
        username=voter["username"],
        role=voter["role"],
        has_voted=bool(voter["has_voted"]),
    )
    return raw, context


def get_session(
    conn: sqlite3.Connection, config: Config, raw_token: str | None
) -> SessionContext | None:
    """Resolve a session token, pruning it if expired."""
    if not raw_token:
        return None
    row = conn.execute(
        "SELECT s.token_hash, s.csrf_token, s.expires_at, "
        "       v.id AS voter_id, v.username, v.role, v.has_voted "
        "FROM sessions s JOIN voters v ON v.id = s.voter_id "
        "WHERE s.token_hash = ?",
        (_session_hash(raw_token),),
    ).fetchone()
    if row is None:
        return None
    if row["expires_at"] <= epoch_now():
        with write_tx(conn):
            conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],)
            )
        return None
    return SessionContext(
        token_hash=row["token_hash"],
        csrf_token=row["csrf_token"],
        voter_id=row["voter_id"],
        username=row["username"],
        role=row["role"],
        has_voted=bool(row["has_voted"]),
    )


def end_session(
    conn: sqlite3.Connection,
    config: Config,
    raw_token: str | None,
    actor: str,
) -> None:
    if not raw_token:
        return
    with write_tx(conn):
        conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?", (_session_hash(raw_token),)
        )
        append_audit(conn, config, actor, "logout", "session revoked")


def prune_expired_sessions(conn: sqlite3.Connection) -> int:
    with write_tx(conn):
        cursor = conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ?", (epoch_now(),)
        )
        return cursor.rowcount


# ---------------------------------------------------------------------------
# Voting
# ---------------------------------------------------------------------------


def cast_ballot(
    conn: sqlite3.Connection,
    config: Config,
    ctx: SessionContext,
    choice: str,
) -> dict[str, str]:
    """Atomically record one anonymous ballot and return the voter's receipt.

    The receipt is returned to the caller **once** and deliberately never
    persisted: storing it next to the voter would re-create the voter-to-ballot
    link that the schema exists to prevent.
    """
    if not isinstance(choice, str):
        raise ValidationError("Invalid ballot selection.")

    with write_tx(conn):
        if get_state(conn) != "open":
            raise ElectionNotOpen("Voting is not open.")
        if choice not in config.candidate_keys:
            raise ValidationError("Select one of the listed options.")

        # The conditional UPDATE is the linearisation point. Under concurrent
        # requests only one can change has_voted from 0 to 1.
        updated = conn.execute(
            "UPDATE voters SET has_voted = 1 WHERE id = ? AND has_voted = 0",
            (ctx.voter_id,),
        )
        if updated.rowcount != 1:
            raise AlreadyVoted("This account has already cast a ballot.")

        last = conn.execute(
            "SELECT chain_hash FROM ballots ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["chain_hash"] if last else GENESIS_HASH

        ballot_id = random_token(24)
        tracking_code = random_token(18)
        nonce = random_token(24)
        created_at = utcnow()

        # Public commitment: verifiable by the voter, but NOT brute-forceable by
        # an outsider because the high-entropy nonce is only on the receipt.
        ballot_hash = digest(
            BALLOT_TAG, tracking_code, choice, nonce, created_at
        )
        chain_hash = mac(
            config.secret_key,
            BALLOT_CHAIN_TAG,
            prev_hash,
            ballot_id,
            tracking_code,
            ballot_hash,
        )
        conn.execute(
            "INSERT INTO ballots "
            "(ballot_id, tracking_code, choice, nonce, created_at, "
            " prev_hash, ballot_hash, chain_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ballot_id,
                tracking_code,
                choice,
                nonce,
                created_at,
                prev_hash,
                ballot_hash,
                chain_hash,
            ),
        )
        # Deliberately no choice, nonce or tracking code in the log.
        append_audit(conn, config, ctx.username, "ballot_cast", f"ballot={ballot_id}")

    return {
        "ballot_id": ballot_id,
        "tracking_code": tracking_code,
        "choice": choice,
        "choice_label": config.candidate_label(choice),
        "nonce": nonce,
        "created_at": created_at,
        "ballot_hash": ballot_hash,
    }


def verify_ballot_chain(
    conn: sqlite3.Connection, config: Config
) -> IntegrityReport:
    """Recompute every commitment and every HMAC link in the ballot chain."""
    problems: list[str] = []
    invalid: set[int] = set()
    expected_prev = GENESIS_HASH
    rows = conn.execute(
        "SELECT seq, ballot_id, tracking_code, choice, nonce, created_at, "
        "       prev_hash, ballot_hash, chain_hash "
        "FROM ballots ORDER BY seq ASC"
    ).fetchall()

    for row in rows:
        seq = row["seq"]
        row_problems: list[str] = []

        recomputed_ballot = digest(
            BALLOT_TAG,
            row["tracking_code"],
            row["choice"],
            row["nonce"],
            row["created_at"],
        )
        if not safe_equals(recomputed_ballot, row["ballot_hash"]):
            row_problems.append(f"ballot {seq}: commitment does not match contents")

        if not safe_equals(row["prev_hash"], expected_prev):
            row_problems.append(f"ballot {seq}: broken predecessor link")

        recomputed_chain = mac(
            config.secret_key,
            BALLOT_CHAIN_TAG,
            row["prev_hash"],
            row["ballot_id"],
            row["tracking_code"],
            row["ballot_hash"],
        )
        if not safe_equals(recomputed_chain, row["chain_hash"]):
            row_problems.append(f"ballot {seq}: HMAC chain link mismatch")

        if row_problems:
            invalid.add(seq)
            problems.extend(row_problems)
        expected_prev = row["chain_hash"]

    return IntegrityReport(not problems, problems, frozenset(invalid))


def bulletin_board(
    conn: sqlite3.Connection, config: Config
) -> list[dict[str, Any]]:
    """Public list of tracking codes and commitments.

    Sorted by tracking code rather than insertion order so the board does not
    leak the order in which people voted.
    """
    integrity = verify_ballot_chain(conn, config)
    rows = conn.execute(
        "SELECT seq, tracking_code, ballot_hash FROM ballots ORDER BY tracking_code ASC"
    ).fetchall()
    return [
        {
            "tracking_code": row["tracking_code"],
            "ballot_hash": row["ballot_hash"],
            "chain_ok": row["seq"] not in integrity.invalid_seqs,
        }
        for row in rows
    ]


def verify_receipt(
    conn: sqlite3.Connection, config: Config, fields: dict[str, str]
) -> dict[str, Any]:
    """Verify a saved receipt against the public bulletin board.

    The voter supplies the values printed on their receipt. The server never
    stores them, so a successful match is real evidence that this exact ballot
    is in the count.
    """
    required = ("tracking_code", "choice", "nonce", "created_at")
    values = {key: (fields.get(key) or "").strip() for key in required}
    supplied_hash = (fields.get("ballot_hash") or "").strip()
    result: dict[str, Any] = {
        "found": False,
        "commitment_ok": False,
        "receipt_ok": None,
        "chain_ok": False,
        "verdict": "Not verified",
        "published_hash": None,
    }
    if not all(values.values()):
        result["verdict"] = "Incomplete receipt — all receipt fields are required."
        return result

    recomputed = digest(
        BALLOT_TAG,
        values["tracking_code"],
        values["choice"],
        values["nonce"],
        values["created_at"],
    )
    row = conn.execute(
        "SELECT seq, ballot_hash FROM ballots WHERE tracking_code = ?",
        (values["tracking_code"],),
    ).fetchone()
    if row is None:
        result["verdict"] = "No ballot with that tracking code was found."
        return result

    result["found"] = True
    result["published_hash"] = row["ballot_hash"]
    result["commitment_ok"] = safe_equals(recomputed, row["ballot_hash"])
    if supplied_hash:
        result["receipt_ok"] = safe_equals(supplied_hash, row["ballot_hash"])
    integrity = verify_ballot_chain(conn, config)
    result["chain_ok"] = row["seq"] not in integrity.invalid_seqs

    if result["receipt_ok"] is False:
        result["verdict"] = "The commitment printed on your receipt does not match the published ballot."
    elif result["commitment_ok"] and result["chain_ok"]:
        result["verdict"] = "Verified: your ballot is recorded as cast and intact."
    elif result["commitment_ok"]:
        result["verdict"] = "Ballot found, but the integrity chain reports a problem."
    else:
        result["verdict"] = "Mismatch: these receipt values do not match the published ballot."
    return result


# ---------------------------------------------------------------------------
# Administration / results
# ---------------------------------------------------------------------------


def set_state(
    conn: sqlite3.Connection, config: Config, actor: str, new_state: str
) -> str:
    """Apply a legal election transition and log it."""
    with write_tx(conn):
        current = get_state(conn)
        if new_state not in ALLOWED_TRANSITIONS[current]:
            raise InvalidTransition(
                f"Cannot move from '{current}' to '{new_state}'."
            )
        set_meta(conn, "election_state", new_state)
        append_audit(
            conn, config, actor, "state_change", f"{current}->{new_state}"
        )
    return new_state


def get_stats(conn: sqlite3.Connection) -> dict[str, int | str]:
    voters = conn.execute("SELECT COUNT(*) AS n FROM voters").fetchone()["n"]
    eligible = conn.execute(
        "SELECT COUNT(*) AS n FROM voters WHERE role = 'voter'"
    ).fetchone()["n"]
    ballots = conn.execute("SELECT COUNT(*) AS n FROM ballots").fetchone()["n"]
    voted = conn.execute(
        "SELECT COUNT(*) AS n FROM voters WHERE has_voted = 1"
    ).fetchone()["n"]
    return {
        "state": get_state(conn),
        "registered": voters,
        "eligible": eligible,
        "ballots": ballots,
        "voted": voted,
    }


def get_election_info(
    conn: sqlite3.Connection, config: Config
) -> dict[str, Any]:
    """Public election metadata, read from the DB so it cannot drift from config."""
    return {
        "title": get_meta(conn, "election_title", config.election_title)
        or config.election_title,
        "description": get_meta(
            conn, "election_description", config.election_description
        )
        or "",
        "state": get_state(conn),
        "candidates": [
            {"key": c.key, "label": c.label, "description": c.description}
            for c in candidates_from_db(conn, config)
        ],
    }


def export_results(conn: sqlite3.Connection, config: Config) -> dict[str, Any]:
    """Machine-readable certified results bundle (requires a closed election)."""
    return {
        "format": "securevote/results-v1",
        "generated_at": utcnow(),
        "election": get_election_info(conn, config),
        "results": tally(conn, config),
        "integrity": integrity_summary(conn, config),
        "checkpoint": create_checkpoint(conn, config),
    }


def export_audit(conn: sqlite3.Connection) -> dict[str, Any]:
    """Full audit trail including every chain hash, for offline verification."""
    rows = conn.execute(
        "SELECT seq, ts, actor, action, detail, prev_hash, entry_hash "
        "FROM audit_log ORDER BY seq ASC"
    ).fetchall()
    return {
        "format": "securevote/audit-v1",
        "generated_at": utcnow(),
        "count": len(rows),
        "entries": [dict(row) for row in rows],
    }


def tally(conn: sqlite3.Connection, config: Config) -> dict[str, Any]:
    """Count sealed ballots. Refuses to run before the election is closed."""
    if get_state(conn) != "closed":
        raise ElectionNotOpen("Results are sealed until the election is closed.")

    choices = {c.key: c.label for c in candidates_from_db(conn, config)}
    counts = {key: 0 for key in choices}
    rows = conn.execute(
        "SELECT choice, COUNT(*) AS n FROM ballots GROUP BY choice"
    ).fetchall()
    for row in rows:
        if row["choice"] not in counts:
            raise VotingError("Ballot contains an unknown option.")
        counts[row["choice"]] = row["n"]

    total = sum(counts.values())
    stats = get_stats(conn)
    ballot_integrity = verify_ballot_chain(conn, config)
    audit_ok, audit_problems = verify_audit_chain(conn, config)
    results_digest = digest(
        RESULTS_TAG,
        *[f"{key}:{counts[key]}" for key in sorted(counts)],
        str(total),
    )
    return {
        "counts": counts,
        "labels": choices,
        "total": total,
        "registered": stats["eligible"],
        "voted": stats["voted"],
        "turnout": (total / stats["eligible"] * 100) if stats["eligible"] else 0.0,
        "ballot_chain_ok": ballot_integrity.ok,
        "ballot_chain_problems": ballot_integrity.problems,
        "audit_chain_ok": audit_ok,
        "audit_chain_problems": audit_problems,
        "consistent": total == stats["voted"] == stats["ballots"],
        "results_digest": results_digest,
    }


def integrity_summary(
    conn: sqlite3.Connection, config: Config
) -> dict[str, Any]:
    """Overall integrity status shown on the home and admin pages."""
    ballots = verify_ballot_chain(conn, config)
    audit_ok, audit_problems = verify_audit_chain(conn, config)
    return {
        "ballot_chain_ok": ballots.ok,
        "ballot_problems": ballots.problems,
        "audit_chain_ok": audit_ok,
        "audit_problems": audit_problems,
        "ok": ballots.ok and audit_ok,
    }


# ---------------------------------------------------------------------------
# Externally anchored integrity checkpoints
# ---------------------------------------------------------------------------


def _checkpoint_payload(
    conn: sqlite3.Connection, config: Config
) -> dict[str, Any]:
    last_ballot = conn.execute(
        "SELECT chain_hash FROM ballots ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    last_audit = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    ballot_count = conn.execute("SELECT COUNT(*) AS n FROM ballots").fetchone()["n"]
    audit_count = conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"]
    state = get_state(conn)
    results_digest = tally(conn, config)["results_digest"] if state == "closed" else None
    return {
        "created_at": utcnow(),
        "state": state,
        "ballot_count": ballot_count,
        "ballot_head": last_ballot["chain_hash"] if last_ballot else GENESIS_HASH,
        "audit_count": audit_count,
        "audit_head": last_audit["entry_hash"] if last_audit else GENESIS_HASH,
        "results_digest": results_digest,
    }


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def create_checkpoint(
    conn: sqlite3.Connection, config: Config
) -> dict[str, Any]:
    """Produce a signed snapshot for an independent witness to keep off-host.

    A witness stores this JSON elsewhere. Later, :func:`verify_checkpoint`
    proves the saved file was not edited (HMAC signature) and that the chain
    prefix it describes still exists unmodified. This does not replace a real
    transparency log, but it does make silent history rewrites detectable.
    """
    payload = _checkpoint_payload(conn, config)
    return {
        **payload,
        "signature": mac(config.secret_key, CHECKPOINT_TAG, _canonical(payload)),
    }


def verify_checkpoint(
    conn: sqlite3.Connection, config: Config, checkpoint: Any
) -> tuple[bool, list[str]]:
    """Validate a previously exported checkpoint against the current database."""
    if not isinstance(checkpoint, dict):
        return False, ["Checkpoint must be a JSON object."]
    signature = checkpoint.get("signature")
    if not isinstance(signature, str) or not signature:
        return False, ["Checkpoint is missing its signature."]

    payload = {k: v for k, v in checkpoint.items() if k != "signature"}
    expected = mac(config.secret_key, CHECKPOINT_TAG, _canonical(payload))
    if not safe_equals(expected, signature):
        return False, ["Checkpoint signature is invalid (file altered or key changed)."]

    problems: list[str] = []
    ballots = verify_ballot_chain(conn, config)
    audit_ok, audit_problems = verify_audit_chain(conn, config)
    if not ballots.ok:
        problems.extend(ballots.problems)
    if not audit_ok:
        problems.extend(audit_problems)

    for kind, count_key, head_key, table, hash_column in (
        ("ballot", "ballot_count", "ballot_head", "ballots", "chain_hash"),
        ("audit", "audit_count", "audit_head", "audit_log", "entry_hash"),
    ):
        count = payload.get(count_key)
        if not isinstance(count, int) or count < 1:
            continue
        row = conn.execute(
            f"SELECT {hash_column} AS head FROM {table} WHERE seq = ?", (count,)
        ).fetchone()
        head = payload.get(head_key)
        if row is None or not isinstance(head, str) or not safe_equals(row["head"], head):
            problems.append(f"{kind} {count}: checkpointed head is no longer in the chain")

    if payload.get("state") == "closed" and isinstance(
        payload.get("results_digest"), str
    ):
        current = tally(conn, config)["results_digest"]
        if not safe_equals(current, payload["results_digest"]):
            problems.append("published results digest differs from the checkpoint")

    return (not problems, problems)

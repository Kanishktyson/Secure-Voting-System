"""Shared, dependency-free test helpers."""

from __future__ import annotations

from pathlib import Path

from secure_vote.config import Config
from secure_vote.db import initialize, open_db
from secure_vote.service import authenticate, register_voter, start_session

TEST_PASSWORD = "DemoPass123!"
ADMIN_PASSWORD = "AdminPass123!"


def test_config(root: Path, **overrides) -> Config:
    """Fast, isolated config (low PBKDF2 cost, own DB, own key)."""
    values = dict(
        db_path=root / "election.db",
        key_path=root / "server.key",
        secret_key=b"unit-test-key-0123456789-abcdef",
        pbkdf2_iterations=1_000,
        session_ttl_seconds=1_800,
        max_body_bytes=16_384,
        login_max_failures=5,
        login_window_seconds=300,
        secure_cookies=False,
        strict_frame_policy=False,
        demo=False,
        host="127.0.0.1",
        port=0,
    )
    values.update(overrides)
    return Config(**values)


def seed(
    config: Config,
    voters: tuple[str, ...] = ("alice", "bob"),
    *,
    state: str = "open",
) -> None:
    """Create the DB, an admin and the given voters."""
    initialize(
        config,
        admin_username="admin",
        admin_password=ADMIN_PASSWORD,
        initial_state=state,
    )
    with open_db(config) as conn:
        for name in voters:
            register_voter(conn, config, name, TEST_PASSWORD)


def signed_in_context(config: Config, username: str, password: str = TEST_PASSWORD):
    """Return ``(raw_session_token, SessionContext)`` for a fresh login."""
    with open_db(config) as conn:
        row = authenticate(conn, config, username, password)
        assert row is not None, f"could not authenticate {username}"
        return start_session(conn, config, row["id"])

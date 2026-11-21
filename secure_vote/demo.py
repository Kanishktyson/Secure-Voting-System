"""Idempotent demo seeding. Never used outside ``python -m secure_vote demo``."""

from __future__ import annotations

from typing import Any

from .config import DEMO_ADMIN, DEMO_VOTERS, Config
from .db import get_state, initialize, open_db
from .service import register_voter


def seed_demo(config: Config) -> dict[str, Any]:
    """Create demo accounts if they do not exist; never overwrite real data."""
    initialize(
        config,
        admin_username=DEMO_ADMIN[0],
        admin_password=DEMO_ADMIN[1],
        initial_state="open",
    )
    created: list[str] = []
    with open_db(config) as conn:
        for username, password in DEMO_VOTERS:
            existing = conn.execute(
                "SELECT 1 FROM voters WHERE username = ?", (username,)
            ).fetchone()
            if not existing:
                register_voter(conn, config, username, password)
                created.append(username)
        state = get_state(conn)
    return {
        "created": created,
        "state": state,
        "admin": DEMO_ADMIN,
        "voters": [(name, password) for name, password in DEMO_VOTERS],
    }

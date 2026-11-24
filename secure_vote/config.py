"""Runtime configuration.

Every setting is overridable through environment variables, and every setting
is also injectable in tests via :class:`Config`, so no test ever needs to touch
the real database or global process state.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Candidate:
    """One option on the ballot. ``key`` is stored in the database."""

    key: str
    label: str
    description: str = ""


DEFAULT_CANDIDATES: tuple[Candidate, ...] = (
    Candidate("aurora", "Aurora Alliance", "Fictional party A"),
    Candidate("borealis", "Borealis Coalition", "Fictional party B"),
    Candidate("cascade", "Cascade Movement", "Fictional party C"),
)

DEMO_VOTERS: tuple[tuple[str, str], ...] = (
    ("alice", "DemoPass123!"),
    ("bob", "DemoPass123!"),
    ("carol", "DemoPass123!"),
    ("diana", "DemoPass123!"),
)
DEMO_ADMIN = ("admin", "AdminPass123!")

DEFAULT_ELECTION_TITLE = "General Election"
DEFAULT_ELECTION_DESCRIPTION = (
    "An open, verifiable ballot. Every vote is anonymous and independently checkable."
)
CANDIDATE_KEY_RE = re.compile(r"^[a-z0-9_]{1,32}$")


def load_election_file(path: Path) -> tuple[str, str, tuple[Candidate, ...]]:
    """Load ``title``, ``description`` and ``candidates`` from a JSON file.

    Expected shape::

        {
          "title": "Campus Council Election 2026",
          "description": "Vote for one representative.",
          "candidates": [
            {"key": "aurora", "label": "Aurora Alliance", "description": "..."}
          ]
        }

    Validation is strict and fails loudly: a malformed ballot definition must
    never silently turn into a different election.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read election file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("Election file must contain a JSON object.")

    title = raw.get("title")
    description = raw.get("description", "")
    entries = raw.get("candidates")
    if not isinstance(title, str) or not (1 <= len(title.strip()) <= 120):
        raise ValueError("Election 'title' must be a 1-120 character string.")
    if not isinstance(description, str) or len(description) > 500:
        raise ValueError("Election 'description' must be a string of at most 500 characters.")
    if not isinstance(entries, list) or not (2 <= len(entries) <= 20):
        raise ValueError("Election 'candidates' must be a list of 2 to 20 options.")

    candidates: list[Candidate] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"candidate {index} must be an object.")
        key, label = entry.get("key"), entry.get("label")
        detail = entry.get("description", "")
        if not isinstance(key, str) or not CANDIDATE_KEY_RE.fullmatch(key):
            raise ValueError(f"candidate {index}: 'key' must match [a-z0-9_]{{1,32}}.")
        if key in seen:
            raise ValueError(f"duplicate candidate key: {key}")
        if not isinstance(label, str) or not (1 <= len(label.strip()) <= 120):
            raise ValueError(f"candidate {key}: 'label' must be 1-120 characters.")
        if not isinstance(detail, str) or len(detail) > 200:
            raise ValueError(f"candidate {key}: 'description' must be <= 200 characters.")
        seen.add(key)
        candidates.append(Candidate(key, label.strip(), detail))

    return title.strip(), description, tuple(candidates)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _env_samesite() -> str:
    value = os.environ.get("SVS_SAMESITE", "strict").strip().lower()
    if value not in ("strict", "lax", "none"):
        raise ValueError("SVS_SAMESITE must be one of: strict, lax, none")
    return value


def load_or_create_secret(key_path: Path) -> bytes:
    """Load the server's HMAC key, creating it with 0600 permissions if absent.

    In a real deployment this value must come from a KMS/HSM via
    ``SVS_SECRET_KEY`` and must never live on the same host as the database.
    The file fallback exists only to make local evaluation reproducible.
    """
    from_env = os.environ.get("SVS_SECRET_KEY", "").strip()
    if from_env:
        try:
            key = bytes.fromhex(from_env)
        except ValueError as exc:
            raise ValueError("SVS_SECRET_KEY must be hexadecimal") from exc
        if len(key) < 16:
            raise ValueError("SVS_SECRET_KEY must be at least 16 bytes (32 hex chars)")
        return key

    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        key = key_path.read_bytes()
        if len(key) < 16:
            raise ValueError(f"key file {key_path} is too short")
        return key

    key = secrets.token_bytes(32)
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


@dataclass(frozen=True)
class Config:
    """Immutable, injectable application configuration."""

    db_path: Path
    key_path: Path
    secret_key: bytes
    candidates: tuple[Candidate, ...] = DEFAULT_CANDIDATES
    election_title: str = DEFAULT_ELECTION_TITLE
    election_description: str = DEFAULT_ELECTION_DESCRIPTION
    pbkdf2_iterations: int = 260_000
    session_ttl_seconds: int = 1_800
    max_body_bytes: int = 16_384
    login_max_failures: int = 5
    login_window_seconds: int = 300
    secure_cookies: bool = False
    # strict | lax | none. "none" adds Secure + Partitioned so sessions work in
    # a cross-site embedded preview (e.g. an HTTPS iframe). CSRF protection
    # comes from synchronizer tokens, not from SameSite.
    samesite: str = "strict"
    # Opt-in X-Frame-Options / frame-ancestors. Off by default because the
    # hosted preview is displayed inside an iframe; enable for real deployments.
    strict_frame_policy: bool = False
    demo: bool = False
    host: str = "0.0.0.0"
    port: int = 8_000

    @property
    def candidate_keys(self) -> frozenset[str]:
        return frozenset(c.key for c in self.candidates)

    def candidate_label(self, key: str) -> str:
        for candidate in self.candidates:
            if candidate.key == key:
                return candidate.label
        return "Unknown option"

    @classmethod
    def from_env(cls) -> "Config":
        db_path = Path(os.environ.get("SVS_DB", "data/election.db")).expanduser()
        key_path = Path(
            os.environ.get("SVS_KEY_FILE", str(db_path.parent / "server.key"))
        ).expanduser()
        title, description, candidates = (
            DEFAULT_ELECTION_TITLE,
            DEFAULT_ELECTION_DESCRIPTION,
            DEFAULT_CANDIDATES,
        )
        election_file = os.environ.get("SVS_ELECTION_FILE", "").strip()
        if election_file:
            title, description, candidates = load_election_file(
                Path(election_file).expanduser()
            )
        return cls(
            db_path=db_path,
            key_path=key_path,
            secret_key=load_or_create_secret(key_path),
            candidates=candidates,
            election_title=title,
            election_description=description,
            pbkdf2_iterations=_env_int("SVS_PBKDF2_ITERATIONS", 260_000, minimum=1_000),
            session_ttl_seconds=_env_int("SVS_SESSION_TTL", 1_800, minimum=60),
            max_body_bytes=_env_int("SVS_MAX_BODY_BYTES", 16_384, minimum=1_024),
            login_max_failures=_env_int("SVS_LOGIN_MAX_FAILURES", 5),
            login_window_seconds=_env_int("SVS_LOGIN_WINDOW", 300),
            secure_cookies=_env_bool("SVS_SECURE_COOKIES"),
            samesite=_env_samesite(),
            strict_frame_policy=_env_bool("SVS_STRICT_FRAME_POLICY"),
            demo=_env_bool("SVS_DEMO"),
            host=os.environ.get("SVS_HOST", "0.0.0.0"),
            port=_env_int("PORT", _env_int("SVS_PORT", 8_000, minimum=1), minimum=1),
        )

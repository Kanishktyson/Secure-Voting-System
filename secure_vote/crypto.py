"""Primitive cryptographic helpers.

Everything here uses the standard library. This is deliberate: the prototype
has *no* third-party runtime dependencies, so the code that protects ballots
can be read end-to-end without trusting a supply chain.

Note that these primitives provide **integrity and verifiability**, not
confidentiality against a compromised server. See README.md "Limitations".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Iterable

GENESIS_HASH = "0" * 64  #: initial value of every hash chain

# Domain-separation tags. Prefixing every hash/MAC input with a tag prevents a
# value produced for one purpose being replayed as a value for another.
BALLOT_TAG = "securevote/v1/ballot"
BALLOT_CHAIN_TAG = "securevote/v1/ballot-chain"
AUDIT_CHAIN_TAG = "securevote/v1/audit-chain"
RESULTS_TAG = "securevote/v1/results"
CHECKPOINT_TAG = "securevote/v1/checkpoint"
CANDIDATES_TAG = "securevote/v1/candidates"


def _normalise(part: str | bytes) -> bytes:
    return part.encode("utf-8") if isinstance(part, str) else part


def _pack(parts: Iterable[str | bytes]) -> bytes:
    """Length-prefix every part so concatenations are unambiguous.

    ``("ab", "c")`` and ``("a", "bc")`` must not collide. Each part is encoded
    as a 4-byte big-endian length followed by its bytes.
    """
    out = bytearray()
    for part in parts:
        raw = _normalise(part)
        if len(raw) > 0xFFFFFFFF:  # pragma: no cover - defensive
            raise ValueError("hash input part is too large")
        out.extend(len(raw).to_bytes(4, "big"))
        out.extend(raw)
    return bytes(out)


def digest(*parts: str | bytes) -> str:
    """Unkeyed SHA-256 commitment over length-prefixed parts (hex digest)."""
    return hashlib.sha256(_pack(parts)).hexdigest()


def mac(key: bytes, *parts: str | bytes) -> str:
    """Keyed HMAC-SHA256 over length-prefixed parts (hex digest)."""
    return hmac.new(key, _pack(parts), hashlib.sha256).hexdigest()


def safe_equals(left: str, right: str) -> bool:
    """Constant-time comparison for tokens, hashes and CSRF values."""
    return hmac.compare_digest(_normalise(left), _normalise(right))


def random_token(nbytes: int = 32) -> str:
    """URL-safe, unpadded base64 of ``nbytes`` cryptographically random bytes."""
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def hash_password(password: str, *, iterations: int) -> str:
    """Return a self-describing PBKDF2-HMAC-SHA256 password hash.

    Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``. Storing the
    cost alongside the hash allows future migrations without invalidating
    existing accounts.
    """
    if iterations < 1:
        raise ValueError("iterations must be positive")
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=32
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Verify ``password`` against an encoded hash, always in constant time.

    Malformed or unsupported encodings return ``False`` rather than raising, so
    a corrupt database row can never be turned into an authentication bypass.
    """
    try:
        algorithm, raw_iterations, salt_hex, hash_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(raw_iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        if iterations < 1 or len(salt) < 8 or len(expected) < 16:
            return False
    except (ValueError, AttributeError, TypeError):
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
    )
    return hmac.compare_digest(candidate, expected)


def dummy_password_check(password: str, *, iterations: int) -> None:
    """Burn roughly the same CPU for unknown usernames as for known ones.

    Without this, login timing reveals whether a username is registered.
    """
    salt = b"\x00" * 16
    hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

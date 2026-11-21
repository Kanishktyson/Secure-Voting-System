"""SecureVote: a small, dependency-free, verifiable electronic voting prototype.

The package is intentionally built on the Python standard library only: for a
system that makes security claims, a small and auditable trusted computing base
is a feature, not a limitation.

Modules
-------
config      Runtime configuration (environment driven, testable dataclass).
crypto      Password hashing, keyed MACs, hash commitments and token creation.
db          SQLite schema, connections and explicit write transactions.
audit       Append-only, hash-chained audit log.
service     Election domain logic (the only place ballots are created).
views       Escaped HTML rendering.
app         HTTP server, routing, sessions, CSRF and security headers.
__main__    Command line entry point.
demo        Idempotent demo-data seeding.
"""

__version__ = "1.0.0"

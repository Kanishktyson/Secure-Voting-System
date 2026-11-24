"""Command line entry point: ``python3 -m secure_vote <command>``."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

from .app import make_server
from .config import Config
from .crypto import random_token
from .db import connect, get_state, initialize, open_db
from .demo import seed_demo
from .service import (
    ElectionNotOpen,
    InvalidTransition,
    ValidationError,
    create_checkpoint,
    export_audit,
    export_results,
    get_stats,
    import_voters,
    integrity_summary,
    register_voter,
    set_state,
    tally,
    verify_checkpoint,
)


def _build_parser() -> argparse.ArgumentParser:
    # Global flags live in a shared parent so they work BOTH before and after
    # the subcommand. SUPPRESS stops an absent subparser flag from overwriting a
    # value supplied before the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db", metavar="PATH", default=argparse.SUPPRESS,
        help="SQLite database path (default data/election.db)",
    )
    common.add_argument(
        "--host", default=argparse.SUPPRESS, help="bind host (default 0.0.0.0)"
    )
    common.add_argument(
        "--port", type=int, default=argparse.SUPPRESS, help="bind port (default 8000)"
    )

    parser = argparse.ArgumentParser(
        prog="python3 -m secure_vote",
        description="SecureVote — a verifiable, dependency-free voting prototype.",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", parents=[common], help="create the database and election state")
    init.add_argument("--admin-user", default="admin")
    init.add_argument("--admin-password", help="otherwise a random password is generated and printed once")

    sub.add_parser("serve", parents=[common], help="start the web server (initialises the DB if needed)")
    demo = sub.add_parser("demo", parents=[common], help="seed demo accounts and start the web server")
    demo.add_argument("--reset", action="store_true", help="delete any existing election data first")

    add = sub.add_parser("add-voter", parents=[common], help="register a voter")
    add.add_argument("username")
    add.add_argument("--password", help="otherwise a random password is printed")

    state = sub.add_parser("state", parents=[common], help="show or change the election state")
    state.add_argument("value", nargs="?", choices=["open", "closed"])

    sub.add_parser("tally", parents=[common], help="print certified results (requires a closed election)")
    verify = sub.add_parser("verify", parents=[common], help="verify both hash chains; exit 1 on failure")
    verify.add_argument("--checkpoint", metavar="PATH", help="also validate an exported checkpoint")

    checkpoint = sub.add_parser(
        "checkpoint", parents=[common], help="export a signed chain-head snapshot"
    )
    checkpoint.add_argument("--output", metavar="PATH", help="write to a file instead of stdout")

    export = sub.add_parser("export", parents=[common], help="export results or the full audit trail as JSON")
    export.add_argument("--what", choices=["results", "audit"], default="results")
    export.add_argument("--output", metavar="PATH", help="write to a file instead of stdout")

    imp = sub.add_parser("import-voters", parents=[common], help="atomically import a CSV voter roll")
    imp.add_argument("csv_file", metavar="PATH", help="CSV rows: username,password (header optional)")

    reset = sub.add_parser("reset", parents=[common], help="delete all election data (requires --yes)")
    reset.add_argument("--yes", action="store_true")
    return parser


def _config(args: argparse.Namespace, *, demo: bool = False) -> Config:
    # Feed CLI overrides through the same env-based path so all validation and
    # key handling stays in one place.
    if getattr(args, "db", None):
        os.environ["SVS_DB"] = args.db
    if getattr(args, "host", None):
        os.environ["SVS_HOST"] = args.host
    if getattr(args, "port", None):
        os.environ["PORT"] = str(args.port)
    if demo:
        os.environ["SVS_DEMO"] = "1"
    else:
        os.environ.pop("SVS_DEMO", None)
    return Config.from_env()


def _reset(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            candidate.unlink()


def _serve(config: Config) -> None:
    generated = initialize(config)
    if generated:
        print(f"[SecureVote] Generated admin password (shown once): {generated}", flush=True)
    server = make_server(config)
    probe = connect(config)
    try:
        current_state = get_state(probe)
    finally:
        probe.close()
    print(
        f"[SecureVote] Serving on http://{config.host}:{config.port} "
        f"(db={config.db_path}, state={current_state})",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\n[SecureVote] Shutting down.", flush=True)
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    command = args.command

    if command == "reset":
        config = _config(args)
        if not args.yes:
            print("Refusing to delete election data without --yes.", file=sys.stderr)
            return 2
        _reset(config.db_path)
        print(f"Deleted {config.db_path} (the HMAC key was kept).")
        return 0

    if command == "demo" and args.reset:
        config = _config(args, demo=True)
        _reset(config.db_path)
        print(f"[SecureVote] Reset {config.db_path}", flush=True)
    else:
        config = _config(args, demo=(command == "demo"))

    if command == "init":
        generated = initialize(
            config,
            admin_username=args.admin_user,
            admin_password=args.admin_password,
        )
        print(f"Initialised {config.db_path}")
        if generated:
            print(f"Admin: {args.admin_user} / {generated}  (save this now)")
        else:
            print("Admin account already exists (or a password was supplied).")
        return 0

    if command == "serve":
        _serve(config)
        return 0

    if command == "demo":
        info = seed_demo(config)
        print("[SecureVote] Demo mode", flush=True)
        print(f"  admin  : {info['admin'][0]} / {info['admin'][1]}", flush=True)
        print(f"  voters : {', '.join(name for name, _ in info['voters'])}", flush=True)
        print(f"  password for all voters: {info['voters'][0][1]}", flush=True)
        print(f"  state  : {info['state']}", flush=True)
        print(f"  added  : {', '.join(info['created']) or 'nothing (already seeded)'}", flush=True)
        server = make_server(config)
        print(f"[SecureVote] Serving on http://{config.host}:{config.port}", flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            print("\n[SecureVote] Shutting down.", flush=True)
        finally:
            server.server_close()
        return 0

    # All remaining commands need an existing database.
    generated = initialize(config)
    if generated:
        print(f"Generated admin password (shown once): {generated}")
    with open_db(config) as conn:
        if command == "add-voter":
            password = args.password or f"Voter7-{random_token(12)}!"
            try:
                register_voter(conn, config, args.username, password)
            except ValidationError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            print(f"Registered {args.username.lower()}")
            if not args.password:
                print(f"Generated password (shown once): {password}")
            return 0

        if command == "state":
            if args.value is None:
                print(json.dumps({"state": get_state(conn), **get_stats(conn)}, indent=2))
                return 0
            try:
                new_state = set_state(conn, config, "cli", args.value)
            except InvalidTransition as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            print(f"Election state is now '{new_state}'.")
            return 0

        if command == "tally":
            try:
                print(json.dumps(tally(conn, config), indent=2))
            except ElectionNotOpen as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            return 0

        if command == "checkpoint":
            snapshot = create_checkpoint(conn, config)
            text = json.dumps(snapshot, indent=2, sort_keys=True)
            if args.output:
                Path(args.output).write_text(text + "\n", encoding="utf-8")
                print(f"Wrote checkpoint to {args.output}")
            else:
                print(text)
            return 0

        if command == "export":
            if args.what == "results":
                try:
                    payload = export_results(conn, config)
                except ElectionNotOpen as exc:
                    print(f"Error: {exc}", file=sys.stderr)
                    return 2
            else:
                payload = export_audit(conn)
            text = json.dumps(payload, indent=2)
            if args.output:
                Path(args.output).write_text(text + "\n", encoding="utf-8")
                print(f"Wrote {args.what} export to {args.output}")
            else:
                print(text)
            return 0

        if command == "import-voters":
            try:
                with Path(args.csv_file).open(newline="", encoding="utf-8") as handle:
                    rows = [
                        row
                        for row in csv.reader(handle)
                        if row and any(cell.strip() for cell in row)
                    ]
            except (OSError, UnicodeDecodeError) as exc:
                print(f"Error reading voter file: {exc}", file=sys.stderr)
                return 2
            if not rows:
                print("Error: voter file is empty.", file=sys.stderr)
                return 2
            if rows[0][0].strip().lower() in ("username", "user", "name"):
                rows = rows[1:]
            credentials = []
            for index, row in enumerate(rows, start=1):
                if len(row) < 2:
                    print(
                        f"Error: row {index} needs username,password.",
                        file=sys.stderr,
                    )
                    return 2
                credentials.append((row[0].strip(), row[1].strip()))
            try:
                created = import_voters(conn, config, credentials)
            except ValidationError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            print(f"Imported {len(created)} voter(s): {', '.join(created)}")
            return 0

        if command == "verify":
            summary = integrity_summary(conn, config)
            print(json.dumps(summary, indent=2))
            overall_ok = bool(summary["ok"])
            if args.checkpoint:
                try:
                    saved = json.loads(
                        Path(args.checkpoint).read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError) as exc:
                    print(f"Error reading checkpoint: {exc}", file=sys.stderr)
                    return 2
                cp_ok, cp_problems = verify_checkpoint(conn, config, saved)
                print(
                    json.dumps(
                        {"checkpoint_ok": cp_ok, "checkpoint_problems": cp_problems},
                        indent=2,
                    )
                )
                overall_ok = overall_ok and cp_ok
            print(
                "Integrity OK" if overall_ok else "INTEGRITY FAILURE",
                file=sys.stdout if overall_ok else sys.stderr,
            )
            return 0 if overall_ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

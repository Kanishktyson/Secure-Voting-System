import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_vote import __main__ as cli
from secure_vote.config import Config
from secure_vote.db import open_db


class FakeServer:
    """Stand-in for the real threaded HTTP server in CLI tests."""

    interrupt = False

    def __init__(self):
        self.closed = False
        self.served = False

    def serve_forever(self, poll_interval=0.2):
        self.served = True
        if self.interrupt:
            raise KeyboardInterrupt

    def server_close(self):
        self.closed = True


class InterruptingServer(FakeServer):
    interrupt = True


class _CliBase(unittest.TestCase):
    """Shared isolated environment; not collected as a test case itself."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "election.db"
        clean = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("SVS_") and k != "PORT"
        }
        patcher = patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ["SVS_DB"] = str(self.db)
        os.environ["SVS_PBKDF2_ITERATIONS"] = "1000"

    def cfg(self) -> Config:
        return Config.from_env()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--db", str(self.db), *argv])
        return code, out.getvalue(), err.getvalue()

    def seed(self):
        self.run_cli("init", "--admin-password", "AdminPass123!")

class CliTests(_CliBase):
    # -- init / add-voter --------------------------------------------------

    def test_init_generates_admin_password_once(self):
        code, out, _ = self.run_cli("init")
        self.assertEqual(code, 0)
        self.assertIn("Initialised", out)
        self.assertIn("save this now", out)
        self.assertTrue(self.db.exists())
        with open_db(self.cfg()) as conn:
            roles = [r["role"] for r in conn.execute("SELECT role FROM voters")]
            self.assertEqual(roles, ["admin"])

    def test_init_with_supplied_password_is_idempotent(self):
        self.seed()
        code, out, _ = self.run_cli("init", "--admin-password", "AdminPass123!")
        self.assertEqual(code, 0)
        self.assertIn("already exists", out)
        with open_db(self.cfg()) as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) AS n FROM voters").fetchone()["n"], 1
            )

    def test_add_voter_generated_password_and_duplicate(self):
        self.seed()
        code, out, _ = self.run_cli("add-voter", "alice")
        self.assertEqual(code, 0)
        self.assertIn("Registered alice", out)
        self.assertIn("Generated password (shown once)", out)

        code, _, err = self.run_cli("add-voter", "alice")
        self.assertEqual(code, 2)
        self.assertIn("already registered", err.lower())

        code, out, _ = self.run_cli("add-voter", "bob", "--password", "BobPass1234!")
        self.assertEqual(code, 0)
        self.assertNotIn("Generated password", out)

    def test_implicit_init_prints_generated_admin_password(self):
        code, out, _ = self.run_cli("add-voter", "zoe")
        self.assertEqual(code, 0)
        self.assertIn("Generated admin password (shown once)", out)

    def test_invalid_voter_input_returns_error_code(self):
        self.seed()
        code, _, err = self.run_cli("add-voter", "BAD NAME")
        self.assertEqual(code, 2)
        self.assertIn("Error:", err)

    # -- state / tally / verify -------------------------------------------

    def test_state_show_and_monotonic_transition(self):
        self.seed()
        code, out, _ = self.run_cli("state")
        self.assertEqual(json.loads(out)["state"], "open")

        code, out, _ = self.run_cli("state", "closed")
        self.assertEqual(code, 0)
        self.assertIn("now 'closed'", out)

        code, _, err = self.run_cli("state", "open")
        self.assertEqual(code, 2)
        self.assertIn("Cannot move", err)

    def test_tally_is_sealed_until_closed(self):
        self.seed()
        code, _, err = self.run_cli("tally")
        self.assertEqual(code, 2)
        self.assertIn("sealed", err.lower())
        self.run_cli("state", "closed")
        code, out, _ = self.run_cli("tally")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["total"], 0)

    def test_verify_detects_tampering(self):
        self.seed()
        self.run_cli("add-voter", "alice")
        with open_db(self.cfg()) as conn:
            conn.execute("UPDATE audit_log SET detail = 'tampered' WHERE seq = 1")
        code, out, err = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("INTEGRITY FAILURE", err)
        self.assertIn("content hash mismatch", out)

    # -- checkpoints -------------------------------------------------------

    def test_checkpoint_export_and_verification(self):
        self.seed()
        self.run_cli("add-voter", "alice")
        path = self.root / "checkpoint.json"

        code, out, _ = self.run_cli("checkpoint", "--output", str(path))
        self.assertEqual(code, 0)
        self.assertIn("Wrote checkpoint", out)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("signature", data)
        self.assertEqual(data["ballot_count"], 0)

        code, out, _ = self.run_cli("verify", "--checkpoint", str(path))
        self.assertEqual(code, 0)
        self.assertIn('"checkpoint_ok": true', out)
        self.assertIn("Integrity OK", out)

        code, out, _ = self.run_cli("checkpoint")
        self.assertEqual(json.loads(out)["state"], "open")

    def test_checkpoint_rejects_tampered_file_and_missing_file(self):
        self.seed()
        path = self.root / "checkpoint.json"
        self.run_cli("checkpoint", "--output", str(path))
        data = json.loads(path.read_text(encoding="utf-8"))
        # With no ballots yet, ballot_head is already the genesis hash, so
        # change a different field to make the signature genuinely invalid.
        data["ballot_count"] = 99
        path.write_text(json.dumps(data), encoding="utf-8")
        code, out, err = self.run_cli("verify", "--checkpoint", str(path))
        self.assertEqual(code, 1)
        self.assertIn('"checkpoint_ok": false', out)
        self.assertIn("signature is invalid", out)

        code, _, err = self.run_cli("verify", "--checkpoint", str(self.root / "nope.json"))
        self.assertEqual(code, 2)
        self.assertIn("Error reading checkpoint", err)

    # -- reset -------------------------------------------------------------

    def test_reset_requires_explicit_confirmation(self):
        self.seed()
        code, _, err = self.run_cli("reset")
        self.assertEqual(code, 2)
        self.assertIn("Refusing", err)
        self.assertTrue(self.db.exists())
        code, out, _ = self.run_cli("reset", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("Deleted", out)
        self.assertFalse(self.db.exists())

    # -- serve / demo ------------------------------------------------------

    def test_serve_and_demo_start_and_stop_cleanly(self):
        fake = FakeServer()
        with patch.object(cli, "make_server", return_value=fake) as maker:
            code, out, _ = self.run_cli("serve")
            self.assertEqual(code, 0)
            self.assertIn("Serving on", out)
            self.assertIn("Generated admin password", out)
            self.assertTrue(fake.served and fake.closed)

            code, out, _ = self.run_cli("demo")
            self.assertEqual(code, 0)
            self.assertIn("Demo mode", out)
            self.assertIn("Serving on", out)
            self.assertIn("added", out)

            code, out, _ = self.run_cli("demo", "--reset")
            self.assertEqual(code, 0)
            self.assertIn("Reset", out)
            self.assertEqual(maker.call_count, 3)

    def test_keyboard_interrupt_shuts_down_gracefully(self):
        with patch.object(cli, "make_server", return_value=InterruptingServer()):
            for command in ("serve", "demo"):
                with self.subTest(command=command):
                    code, out, _ = self.run_cli(command)
                    self.assertEqual(code, 0)
                    self.assertIn("Shutting down", out)

    # -- parser ------------------------------------------------------------

    def test_global_flags_work_before_and_after_subcommand(self):
        parser = cli._build_parser()
        before = parser.parse_args(["--db", "/tmp/a.db", "--port", "9001", "verify"])
        after = parser.parse_args(["verify", "--db", "/tmp/a.db", "--port", "9001"])
        self.assertEqual(before.db, after.db)
        self.assertEqual(before.port, after.port)
        self.assertEqual(before.command, after.command)

    def test_unknown_command_is_rejected_by_argparse(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["definitely-not-a-command"])


if __name__ == "__main__":
    unittest.main()


class CliDataTests(_CliBase):
    """Extra CLI cases for export / import."""

    def test_export_results_and_audit(self):
        self.seed()
        # Results are sealed while the election is open.
        code, _, err = self.run_cli("export", "--what", "results")
        self.assertEqual(code, 2)
        self.assertIn("sealed", err.lower())

        self.run_cli("state", "closed")
        path = self.root / "results.json"
        code, out, _ = self.run_cli("export", "--what", "results", "--output", str(path))
        self.assertEqual(code, 0)
        self.assertIn("Wrote results export", out)
        bundle = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(bundle["format"], "securevote/results-v1")
        self.assertEqual(bundle["election"]["state"], "closed")

        code, out, _ = self.run_cli("export", "--what", "audit")
        self.assertEqual(code, 0)
        audit = json.loads(out)
        self.assertEqual(audit["format"], "securevote/audit-v1")
        self.assertGreater(audit["count"], 0)

    def test_import_voters_csv(self):
        self.seed()
        path = self.root / "voters.csv"
        path.write_text(
            "username,password\nzoe,ZoePass1234!\nyan,YanPass1234!\n",
            encoding="utf-8",
        )
        code, out, _ = self.run_cli("import-voters", str(path))
        self.assertEqual(code, 0)
        self.assertIn("Imported 2 voter(s)", out)
        with open_db(self.cfg()) as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) AS n FROM voters").fetchone()["n"], 3
            )

        # Re-importing the same roll fails without adding anyone.
        code, _, err = self.run_cli("import-voters", str(path))
        self.assertEqual(code, 2)
        self.assertIn("already registered", err)

    def test_import_voters_rejects_bad_files(self):
        self.seed()
        missing = self.root / "missing.csv"
        code, _, err = self.run_cli("import-voters", str(missing))
        self.assertEqual(code, 2)
        self.assertIn("Error reading voter file", err)

        empty = self.root / "empty.csv"
        empty.write_text("\n\n", encoding="utf-8")
        code, _, err = self.run_cli("import-voters", str(empty))
        self.assertEqual(code, 2)
        self.assertIn("empty", err.lower())

        short = self.root / "short.csv"
        short.write_text("only_one_column\n", encoding="utf-8")
        code, _, err = self.run_cli("import-voters", str(short))
        self.assertEqual(code, 2)
        self.assertIn("needs username,password", err)

        weak = self.root / "weak.csv"
        weak.write_text("new_user,weak\n", encoding="utf-8")
        code, _, err = self.run_cli("import-voters", str(weak))
        self.assertEqual(code, 2)
        self.assertIn("Error:", err)

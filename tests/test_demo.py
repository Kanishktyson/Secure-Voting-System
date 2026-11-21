import tempfile
import unittest
from pathlib import Path

from secure_vote.db import get_state, open_db
from secure_vote.demo import seed_demo

from support import test_config


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = test_config(Path(self.tmp.name), demo=True)

    def test_seed_is_idempotent(self):
        first = seed_demo(self.config)
        self.assertEqual(first["created"], ["alice", "bob", "carol", "diana"])
        self.assertEqual(first["state"], "open")
        self.assertEqual(first["admin"][0], "admin")
        self.assertEqual(len(first["voters"]), 4)

        second = seed_demo(self.config)
        self.assertEqual(second["created"], [])
        with open_db(self.config) as conn:
            count = conn.execute("SELECT COUNT(*) AS n FROM voters").fetchone()["n"]
            self.assertEqual(count, 5)  # 4 voters + 1 admin
            self.assertEqual(get_state(conn), "open")

    def test_demo_accounts_can_authenticate(self):
        from secure_vote.service import authenticate

        seed_demo(self.config)
        with open_db(self.config) as conn:
            self.assertIsNotNone(
                authenticate(conn, self.config, "alice", "DemoPass123!")
            )
            self.assertIsNotNone(
                authenticate(conn, self.config, "admin", "AdminPass123!")
            )
            self.assertIsNone(
                authenticate(conn, self.config, "alice", "WrongPass123!")
            )


if __name__ == "__main__":
    unittest.main()

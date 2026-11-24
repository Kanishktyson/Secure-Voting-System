import tempfile
import unittest
from pathlib import Path

from secure_vote.db import open_db
from secure_vote.service import (
    cast_ballot,
    create_checkpoint,
    set_state,
    tally,
    verify_checkpoint,
)

from support import seed, signed_in_context, test_config


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = test_config(Path(self.tmp.name))
        seed(self.config, voters=("alice", "bob", "carol"))

    def vote(self, voter: str, choice: str) -> None:
        _, ctx = signed_in_context(self.config, voter)
        with open_db(self.config) as conn:
            cast_ballot(conn, self.config, ctx, choice)

    def test_round_trip_and_required_fields(self):
        self.vote("alice", "aurora")
        with open_db(self.config) as conn:
            snapshot = create_checkpoint(conn, self.config)
            ok, problems = verify_checkpoint(conn, self.config, snapshot)
        self.assertEqual(snapshot["ballot_count"], 1)
        self.assertEqual(snapshot["state"], "open")
        self.assertIsNone(snapshot["results_digest"])
        self.assertEqual(len(snapshot["signature"]), 64)
        self.assertTrue(ok, problems)

    def test_detects_tampering_with_the_saved_file(self):
        self.vote("alice", "aurora")
        with open_db(self.config) as conn:
            snapshot = create_checkpoint(conn, self.config)
        for field, value in (
            ("ballot_head", "0" * 64),
            ("ballot_count", 99),
            ("state", "closed"),
        ):
            with self.subTest(field=field):
                altered = dict(snapshot, **{field: value})
                with open_db(self.config) as conn:
                    ok, problems = verify_checkpoint(conn, self.config, altered)
                self.assertFalse(ok)
                self.assertTrue(any("signature" in p for p in problems))

    def test_detects_history_rewrite(self):
        self.vote("alice", "aurora")
        self.vote("bob", "borealis")
        with open_db(self.config) as conn:
            snapshot = create_checkpoint(conn, self.config)
            conn.execute("UPDATE ballots SET choice = 'cascade' WHERE seq = 1")
            ok, problems = verify_checkpoint(conn, self.config, snapshot)
        self.assertFalse(ok)
        self.assertTrue(any("commitment" in p for p in problems), problems)

    def test_detects_deleted_audit_entry(self):
        self.vote("alice", "aurora")
        with open_db(self.config) as conn:
            snapshot = create_checkpoint(conn, self.config)
            conn.execute("DELETE FROM audit_log WHERE seq = 1")
            ok, problems = verify_checkpoint(conn, self.config, snapshot)
        self.assertFalse(ok)
        self.assertTrue(problems)

    def test_checkpoint_remains_valid_as_new_ballots_arrive(self):
        self.vote("alice", "aurora")
        with open_db(self.config) as conn:
            snapshot = create_checkpoint(conn, self.config)
        self.vote("bob", "borealis")
        with open_db(self.config) as conn:
            ok, problems = verify_checkpoint(conn, self.config, snapshot)
        self.assertTrue(ok, problems)

    def test_closed_election_checkpoint_includes_results_digest(self):
        self.vote("alice", "aurora")
        with open_db(self.config) as conn:
            set_state(conn, self.config, "admin", "closed")
            snapshot = create_checkpoint(conn, self.config)
            digest = tally(conn, self.config)["results_digest"]
        self.assertEqual(snapshot["results_digest"], digest)
        self.assertEqual(snapshot["state"], "closed")

    def test_non_object_checkpoint_is_rejected(self):
        with open_db(self.config) as conn:
            for bad in (None, [], "string", {}, {"signature": ""}):
                with self.subTest(bad=bad):
                    ok, problems = verify_checkpoint(conn, self.config, bad)
                    self.assertFalse(ok)
                    self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main()

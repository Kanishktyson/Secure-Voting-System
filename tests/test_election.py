import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from secure_vote.audit import verify_audit_chain
from secure_vote.config import Candidate
from secure_vote.crypto import BALLOT_TAG, digest
from secure_vote.db import get_state, open_db
from secure_vote.service import (
    AlreadyVoted,
    ElectionNotOpen,
    InvalidTransition,
    ValidationError,
    authenticate,
    bulletin_board,
    candidates_from_db,
    cast_ballot,
    get_session,
    get_stats,
    integrity_summary,
    register_voter,
    set_state,
    start_session,
    tally,
    verify_ballot_chain,
    verify_receipt,
)

from support import ADMIN_PASSWORD, TEST_PASSWORD, seed, signed_in_context, test_config


class ElectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = test_config(Path(self.tmp.name))
        seed(self.config, voters=("alice", "bob", "carol"))

    # -- registration / authentication ------------------------------------

    def test_registration_validates_inputs(self):
        with open_db(self.config) as conn:
            for bad in ("", "ab", "A B", "has spaces", "x" * 40, "drop-table"):
                with self.subTest(username=bad):
                    with self.assertRaises(ValidationError):
                        register_voter(conn, self.config, bad, TEST_PASSWORD)
            for bad in ("short", "alllettersonly", "123456789012"):
                with self.subTest(password=bad):
                    with self.assertRaises(ValidationError):
                        register_voter(conn, self.config, "newperson", bad)

    def test_duplicate_username_rejected_case_insensitively(self):
        with open_db(self.config) as conn:
            with self.assertRaises(ValidationError):
                register_voter(conn, self.config, "ALICE", TEST_PASSWORD)

    def test_password_is_not_stored_in_plaintext(self):
        with open_db(self.config) as conn:
            row = conn.execute(
                "SELECT password_hash FROM voters WHERE username = 'alice'"
            ).fetchone()
            self.assertNotIn(TEST_PASSWORD, row["password_hash"])
            self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))

    def test_authenticate_known_and_unknown_users(self):
        with open_db(self.config) as conn:
            self.assertIsNotNone(authenticate(conn, self.config, "Alice", TEST_PASSWORD))
            self.assertIsNone(authenticate(conn, self.config, "alice", "WrongPass123!"))
            self.assertIsNone(authenticate(conn, self.config, "nobody", TEST_PASSWORD))

    # -- sessions ---------------------------------------------------------

    def test_session_rotation_invalidates_old_token(self):
        first, _ = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            row = authenticate(conn, self.config, "alice", TEST_PASSWORD)
            second, ctx = start_session(conn, self.config, row["id"], previous_token=first)
            self.assertIsNone(get_session(conn, self.config, first))
            self.assertIsNotNone(get_session(conn, self.config, second))
            self.assertEqual(ctx.username, "alice")

    def test_expired_session_is_rejected_and_pruned(self):
        raw, _ = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            conn.execute("UPDATE sessions SET expires_at = 1")
            self.assertIsNone(get_session(conn, self.config, raw))
            remaining = conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"]
            self.assertEqual(remaining, 0)

    def test_only_a_hash_of_the_session_token_is_stored(self):
        raw, _ = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            stored = [r["token_hash"] for r in conn.execute("SELECT token_hash FROM sessions")]
            self.assertEqual(len(stored), 1)
            self.assertNotIn(raw, stored)
            self.assertNotEqual(raw, stored[0])
            self.assertEqual(len(stored[0]), 64)

    # -- ballot secrecy and one-person-one-vote ----------------------------

    def test_ballots_table_has_no_voter_reference(self):
        with open_db(self.config) as conn:
            columns = [r["name"] for r in conn.execute("PRAGMA table_info(ballots)")]
            self.assertNotIn("voter_id", columns)
            self.assertFalse(any("voter" in c for c in columns))
            self.assertEqual(list(conn.execute("PRAGMA foreign_key_list(ballots)")), [])
            voter_columns = [r["name"] for r in conn.execute("PRAGMA table_info(voters)")]
            self.assertFalse(any("ballot" in c for c in voter_columns))

    def test_cast_ballot_and_reject_second_attempt(self):
        _, ctx = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            receipt = cast_ballot(conn, self.config, ctx, "aurora")
            self.assertEqual(receipt["choice_label"], "Aurora Alliance")
            self.assertEqual(len(receipt["ballot_hash"]), 64)
            with self.assertRaises(AlreadyVoted):
                cast_ballot(conn, self.config, ctx, "cascade")
            self.assertEqual(get_stats(conn)["ballots"], 1)

    def test_invalid_choice_and_unknown_option_are_rejected(self):
        _, ctx = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            with self.assertRaises(ValidationError):
                cast_ballot(conn, self.config, ctx, "not-a-party")
            with self.assertRaises(ValidationError):
                cast_ballot(conn, self.config, ctx, "")
            self.assertEqual(get_stats(conn)["ballots"], 0)

    def test_receipt_secrets_never_appear_in_audit_log_or_sessions(self):
        _, ctx = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            receipt = cast_ballot(conn, self.config, ctx, "borealis")
            details = " ".join(
                r["detail"] for r in conn.execute("SELECT detail FROM audit_log")
            )
            self.assertNotIn(receipt["nonce"], details)
            self.assertNotIn(receipt["tracking_code"], details)
            self.assertNotIn(receipt["choice"], details)
            session_columns = [r["name"] for r in conn.execute("PRAGMA table_info(sessions)")]
            self.assertNotIn("nonce", session_columns)
            self.assertNotIn("tracking_code", session_columns)

    def test_concurrent_votes_are_serialised(self):
        _, ctx = signed_in_context(self.config, "alice")
        barrier = threading.Barrier(6)
        outcomes = []
        lock = threading.Lock()

        def attempt():
            barrier.wait()
            try:
                with open_db(self.config) as conn:
                    cast_ballot(conn, self.config, ctx, "aurora")
                result = "ok"
            except AlreadyVoted:
                result = "duplicate"
            except (sqlite3.Error, Exception) as exc:  # pragma: no cover
                result = f"error:{type(exc).__name__}:{exc}"
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=attempt) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertEqual(outcomes.count("duplicate"), 5, outcomes)
        with open_db(self.config) as conn:
            self.assertEqual(get_stats(conn)["ballots"], 1)

    # -- verifiability -----------------------------------------------------

    def test_receipt_commitment_is_recomputable_by_the_voter(self):
        _, ctx = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            receipt = cast_ballot(conn, self.config, ctx, "aurora")
            recomputed = digest(
                BALLOT_TAG,
                receipt["tracking_code"],
                receipt["choice"],
                receipt["nonce"],
                receipt["created_at"],
            )
            self.assertEqual(recomputed, receipt["ballot_hash"])
            published = conn.execute(
                "SELECT ballot_hash FROM ballots WHERE tracking_code = ?",
                (receipt["tracking_code"],),
            ).fetchone()["ballot_hash"]
            self.assertEqual(recomputed, published)

    def test_verify_receipt_positive_and_negative(self):
        _, ctx = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            receipt = cast_ballot(conn, self.config, ctx, "cascade")
            ok = verify_receipt(conn, self.config, receipt)
            self.assertTrue(ok["found"])
            self.assertTrue(ok["commitment_ok"])
            self.assertTrue(ok["chain_ok"])
            self.assertIn("Verified", ok["verdict"])

            wrong_nonce = dict(receipt, nonce="not-the-nonce")
            self.assertFalse(verify_receipt(conn, self.config, wrong_nonce)["commitment_ok"])

            tampered = dict(receipt, ballot_hash="0" * 64)
            bad = verify_receipt(conn, self.config, tampered)
            self.assertFalse(bad["receipt_ok"])
            self.assertNotIn("Verified:", bad["verdict"])

            missing = dict(receipt, tracking_code="unknown-code")
            self.assertFalse(verify_receipt(conn, self.config, missing)["found"])

            incomplete = {"tracking_code": receipt["tracking_code"]}
            self.assertIn("Incomplete", verify_receipt(conn, self.config, incomplete)["verdict"])

    def test_ballot_chain_detects_tampering(self):
        with open_db(self.config) as conn:
            for voter in ("alice", "bob", "carol"):
                _, ctx = signed_in_context(self.config, voter)
                cast_ballot(conn, self.config, ctx, "aurora")
            self.assertTrue(verify_ballot_chain(conn, self.config).ok)

            conn.execute("UPDATE ballots SET choice = 'cascade' WHERE seq = 1")
            report = verify_ballot_chain(conn, self.config)
            self.assertFalse(report.ok)
            self.assertIn(1, report.invalid_seqs)
            self.assertTrue(any("commitment" in p for p in report.problems))

    def test_ballot_chain_detects_deletion_and_forged_link(self):
        with open_db(self.config) as conn:
            for voter in ("alice", "bob", "carol"):
                _, ctx = signed_in_context(self.config, voter)
                cast_ballot(conn, self.config, ctx, "aurora")
            conn.execute("DELETE FROM ballots WHERE seq = 2")
            report = verify_ballot_chain(conn, self.config)
            self.assertFalse(report.ok)
            self.assertTrue(any("predecessor" in p for p in report.problems))

            conn.execute("UPDATE ballots SET chain_hash = ? WHERE seq = 1", ("f" * 64,))
            self.assertFalse(verify_ballot_chain(conn, self.config).ok)

    def test_audit_chain_detects_tampering(self):
        with open_db(self.config) as conn:
            ok, problems = verify_audit_chain(conn, self.config)
            self.assertTrue(ok, problems)
            conn.execute("UPDATE audit_log SET detail = 'tampered' WHERE seq = 1")
            ok, problems = verify_audit_chain(conn, self.config)
            self.assertFalse(ok)
            self.assertTrue(problems)

    def test_bulletin_board_is_sorted_by_tracking_code(self):
        with open_db(self.config) as conn:
            for voter in ("alice", "bob", "carol"):
                _, ctx = signed_in_context(self.config, voter)
                cast_ballot(conn, self.config, ctx, "aurora")
            board = bulletin_board(conn, self.config)
            self.assertEqual(len(board), 3)
            codes = [item["tracking_code"] for item in board]
            self.assertEqual(codes, sorted(codes))
            self.assertTrue(all(item["chain_ok"] for item in board))

    # -- lifecycle and tally ----------------------------------------------

    def test_state_transitions_are_monotonic(self):
        with open_db(self.config) as conn:
            self.assertEqual(get_state(conn), "open")
            self.assertEqual(set_state(conn, self.config, "admin", "closed"), "closed")
            with self.assertRaises(InvalidTransition):
                set_state(conn, self.config, "admin", "open")
            with self.assertRaises(InvalidTransition):
                set_state(conn, self.config, "admin", "setup")

    def test_voting_requires_open_election(self):
        with open_db(self.config) as conn:
            set_state(conn, self.config, "admin", "closed")
            _, ctx = signed_in_context(self.config, "alice")
            with self.assertRaises(ElectionNotOpen):
                cast_ballot(conn, self.config, ctx, "aurora")

    def test_results_are_sealed_until_close(self):
        _, ctx = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            cast_ballot(conn, self.config, ctx, "aurora")
            with self.assertRaises(ElectionNotOpen):
                tally(conn, self.config)

    def test_tally_counts_and_consistency(self):
        with open_db(self.config) as conn:
            for voter, choice in (
                ("alice", "aurora"),
                ("bob", "aurora"),
                ("carol", "borealis"),
            ):
                _, ctx = signed_in_context(self.config, voter)
                cast_ballot(conn, self.config, ctx, choice)
            set_state(conn, self.config, "admin", "closed")
            result = tally(conn, self.config)
            self.assertEqual(result["counts"], {"aurora": 2, "borealis": 1, "cascade": 0})
            self.assertEqual(result["total"], 3)
            self.assertEqual(result["registered"], 3)
            self.assertAlmostEqual(result["turnout"], 100.0)
            self.assertTrue(result["consistent"])
            self.assertTrue(result["ballot_chain_ok"])
            self.assertTrue(result["audit_chain_ok"])
            self.assertEqual(len(result["results_digest"]), 64)
            # A deterministic digest lets anyone reproduce the published count.
            self.assertEqual(result["results_digest"], tally(conn, self.config)["results_digest"])

    def test_integrity_summary(self):
        with open_db(self.config) as conn:
            summary = integrity_summary(conn, self.config)
            self.assertTrue(summary["ok"])
            self.assertEqual(summary["ballot_problems"], [])
            self.assertEqual(summary["audit_problems"], [])

    def test_candidates_read_from_db(self):
        with open_db(self.config) as conn:
            options = candidates_from_db(conn, self.config)
            self.assertEqual([c.key for c in options], ["aurora", "borealis", "cascade"])

    def test_custom_candidates_are_honoured(self):
        custom = (
            Candidate("x", "<script>alert(1)</script>", "HTML must be escaped"),
        )
        other = test_config(Path(self.tmp.name) / "custom", candidates=custom)
        # Separate DB path keeps this test isolated from the shared fixture.
        from support import seed as seed_election

        seed_election(other, voters=())
        _, ctx = signed_in_context(other, "admin", ADMIN_PASSWORD)
        with open_db(other) as conn:
            receipt = cast_ballot(conn, other, ctx, "x")
            self.assertEqual(receipt["choice_label"], "<script>alert(1)</script>")


if __name__ == "__main__":
    unittest.main()


class ElectionDataTests(unittest.TestCase):
    """Election metadata, bulk import and machine-readable exports."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = test_config(Path(self.tmp.name))
        seed(self.config, voters=("alice",))

    def test_election_info_comes_from_the_database(self):
        from secure_vote.db import set_meta
        from secure_vote.service import get_election_info

        with open_db(self.config) as conn:
            set_meta(conn, "election_title", "Board Election")
            info = get_election_info(conn, self.config)
        self.assertEqual(info["title"], "Board Election")
        self.assertEqual(info["state"], "open")
        self.assertEqual(len(info["candidates"]), 3)

    def test_export_audit_includes_chain_hashes(self):
        from secure_vote.service import export_audit

        with open_db(self.config) as conn:
            payload = export_audit(conn)
        self.assertEqual(payload["format"], "securevote/audit-v1")
        self.assertGreater(payload["count"], 0)
        self.assertEqual(len(payload["entries"]), payload["count"])
        self.assertEqual(len(payload["entries"][0]["entry_hash"]), 64)
        self.assertIn("prev_hash", payload["entries"][0])

    def test_export_results_is_sealed_then_complete(self):
        from secure_vote.service import export_results

        _, ctx = signed_in_context(self.config, "alice")
        with open_db(self.config) as conn:
            cast_ballot(conn, self.config, ctx, "aurora")
            with self.assertRaises(ElectionNotOpen):
                export_results(conn, self.config)
            set_state(conn, self.config, "admin", "closed")
            bundle = export_results(conn, self.config)
        self.assertEqual(bundle["format"], "securevote/results-v1")
        self.assertEqual(bundle["results"]["total"], 1)
        self.assertTrue(bundle["integrity"]["ok"])
        self.assertIn("signature", bundle["checkpoint"])
        self.assertEqual(bundle["election"]["state"], "closed")

    def test_import_voters_is_atomic(self):
        from secure_vote.service import import_voters

        with open_db(self.config) as conn:
            created = import_voters(
                conn,
                self.config,
                [("zoe", "ZoePass1234!"), ("yan", "YanPass1234!")],
            )
            self.assertEqual(created, ["zoe", "yan"])
            count = conn.execute("SELECT COUNT(*) AS n FROM voters").fetchone()["n"]
            self.assertEqual(count, 4)  # admin + alice + 2 imported

            with self.assertRaises(ValidationError):
                import_voters(
                    conn,
                    self.config,
                    [("new_person", "NewPass1234!"), ("alice", "DupPass1234!")],
                )
            count_after = conn.execute("SELECT COUNT(*) AS n FROM voters").fetchone()["n"]
            self.assertEqual(count_after, 4, "failed import must roll back entirely")

    def test_import_voters_rejects_bad_rows_and_empty_roll(self):
        from secure_vote.service import import_voters

        with open_db(self.config) as conn:
            with self.assertRaises(ValidationError):
                import_voters(conn, self.config, [])
            with self.assertRaises(ValidationError):
                import_voters(conn, self.config, [("ok_user", "weak")])
            self.assertEqual(
                conn.execute("SELECT COUNT(*) AS n FROM voters").fetchone()["n"], 2
            )

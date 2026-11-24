import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_vote import config as C

from support import test_config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Give every test a clean SVS_* / PORT environment and restore it after.
        clean = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("SVS_") and k != "PORT"
        }
        patcher = patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_defaults(self):
        os.environ["SVS_DB"] = str(self.root / "election.db")
        cfg = C.Config.from_env()
        self.assertEqual(cfg.db_path, self.root / "election.db")
        self.assertEqual(cfg.key_path, self.root / "server.key")
        self.assertEqual(cfg.pbkdf2_iterations, 260_000)
        self.assertEqual(cfg.session_ttl_seconds, 1_800)
        self.assertEqual(cfg.samesite, "strict")
        self.assertFalse(cfg.secure_cookies)
        self.assertFalse(cfg.strict_frame_policy)
        self.assertFalse(cfg.demo)
        self.assertEqual(cfg.host, "0.0.0.0")
        self.assertEqual(cfg.port, 8_000)
        self.assertTrue((self.root / "server.key").exists())

    def test_all_overrides_and_port_precedence(self):
        os.environ.update(
            {
                "SVS_DB": str(self.root / "custom.db"),
                "SVS_KEY_FILE": str(self.root / "custom.key"),
                "SVS_PBKDF2_ITERATIONS": "4200",
                "SVS_SESSION_TTL": "900",
                "SVS_MAX_BODY_BYTES": "2048",
                "SVS_LOGIN_MAX_FAILURES": "3",
                "SVS_LOGIN_WINDOW": "120",
                "SVS_SECURE_COOKIES": "true",
                "SVS_SAMESITE": "LAX",
                "SVS_STRICT_FRAME_POLICY": "1",
                "SVS_DEMO": "yes",
                "SVS_HOST": "127.0.0.1",
                "SVS_PORT": "7000",
                "PORT": "9123",
            }
        )
        cfg = C.Config.from_env()
        self.assertEqual(cfg.db_path, self.root / "custom.db")
        self.assertEqual(cfg.key_path, self.root / "custom.key")
        self.assertEqual(cfg.pbkdf2_iterations, 4_200)
        self.assertEqual(cfg.session_ttl_seconds, 900)
        self.assertEqual(cfg.max_body_bytes, 2_048)
        self.assertEqual(cfg.login_max_failures, 3)
        self.assertEqual(cfg.login_window_seconds, 120)
        self.assertTrue(cfg.secure_cookies)
        self.assertEqual(cfg.samesite, "lax")
        self.assertTrue(cfg.strict_frame_policy)
        self.assertTrue(cfg.demo)
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 9_123)  # PORT wins over SVS_PORT

    def test_invalid_values_fail_loudly(self):
        os.environ["SVS_DB"] = str(self.root / "e.db")
        cases = (
            ("SVS_PBKDF2_ITERATIONS", "not-a-number"),
            ("SVS_SESSION_TTL", "10"),
            ("SVS_MAX_BODY_BYTES", "0"),
            ("SVS_SAMESITE", "sometimes"),
        )
        for key, value in cases:
            with self.subTest(key=key):
                os.environ[key] = value
                with self.assertRaises(ValueError):
                    C.Config.from_env()
                del os.environ[key]

    def test_bool_helper(self):
        for raw in ("1", "true", "YES", "on"):
            os.environ["FLAG"] = raw
            self.assertTrue(C._env_bool("FLAG", False), raw)
        for raw in ("0", "false", "no", "", "off"):
            os.environ["FLAG"] = raw
            self.assertFalse(C._env_bool("FLAG", True), raw)
        del os.environ["FLAG"]
        self.assertTrue(C._env_bool("MISSING_FLAG", True))
        self.assertFalse(C._env_bool("MISSING_FLAG", False))

    def test_int_helper_minimum_and_default(self):
        self.assertEqual(C._env_int("MISSING_INT", 42), 42)
        os.environ["N"] = "7"
        self.assertEqual(C._env_int("N", 42, minimum=5), 7)
        with self.assertRaises(ValueError):
            C._env_int("N", 42, minimum=10)

    def test_secret_file_is_created_with_0600_and_is_stable(self):
        path = self.root / "server.key"
        key = C.load_or_create_secret(path)
        self.assertEqual(len(key), 32)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(C.load_or_create_secret(path), key)

    def test_secret_from_env_hex(self):
        hexkey = "ab" * 20
        os.environ["SVS_SECRET_KEY"] = f"  {hexkey}  "
        self.assertEqual(C.load_or_create_secret(self.root / "unused.key"), bytes.fromhex(hexkey))
        self.assertFalse((self.root / "unused.key").exists())

    def test_bad_env_secret_rejected(self):
        key_path = self.root / "k"
        for raw in ("zz", "aabb", "ab" * 8):
            with self.subTest(raw=raw[:12]):
                os.environ["SVS_SECRET_KEY"] = raw
                with self.assertRaises(ValueError):
                    C.load_or_create_secret(key_path)

    def test_short_existing_key_rejected(self):
        key_path = self.root / "k"
        key_path.write_bytes(b"too short")
        with self.assertRaises(ValueError):
            C.load_or_create_secret(key_path)

    def test_candidate_helpers(self):
        cfg = test_config(self.root)
        self.assertEqual(cfg.candidate_keys, {"aurora", "borealis", "cascade"})
        self.assertEqual(cfg.candidate_label("aurora"), "Aurora Alliance")
        self.assertEqual(cfg.candidate_label("unknown"), "Unknown option")

    def test_bundled_example_election_file_is_valid(self):
        example = Path(__file__).resolve().parents[1] / "examples" / "election.json"
        title, description, candidates = C.load_election_file(example)
        self.assertEqual(title, "Campus Council Election 2026")
        self.assertTrue(description)
        self.assertEqual(len(candidates), 4)
        self.assertEqual(candidates[0].key, "atlas")

    def test_election_file_is_loaded_from_env(self):
        path = self.root / "election.json"
        path.write_text(
            json.dumps(
                {
                    "title": "Board Election",
                    "description": "Pick one director.",
                    "candidates": [
                        {"key": "red", "label": "Red List"},
                        {"key": "blue", "label": "Blue List", "description": "A slate"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        os.environ["SVS_DB"] = str(self.root / "election.db")
        os.environ["SVS_ELECTION_FILE"] = str(path)
        cfg = C.Config.from_env()
        self.assertEqual(cfg.election_title, "Board Election")
        self.assertEqual(cfg.election_description, "Pick one director.")
        self.assertEqual(cfg.candidate_keys, {"red", "blue"})
        self.assertEqual(cfg.candidate_label("red"), "Red List")

    def test_election_file_rejects_malformed_definitions(self):
        path = self.root / "bad.json"
        valid = {
            "title": "Election",
            "candidates": [
                {"key": "a", "label": "A"},
                {"key": "b", "label": "B"},
            ],
        }
        cases = (
            "{not json",
            "[]",
            json.dumps({**valid, "title": ""}),
            json.dumps({**valid, "title": "x" * 200}),
            json.dumps({**valid, "description": 42}),
            json.dumps({**valid, "candidates": [{"key": "a", "label": "A"}]}),
            json.dumps(
                {
                    **valid,
                    "candidates": [
                        {"key": "a", "label": "A"},
                        {"key": "a", "label": "B"},
                    ],
                }
            ),
            json.dumps(
                {
                    **valid,
                    "candidates": [
                        {"key": "BAD KEY", "label": "A"},
                        {"key": "b", "label": "B"},
                    ],
                }
            ),
            json.dumps(
                {
                    **valid,
                    "candidates": [
                        {"key": "a", "label": ""},
                        {"key": "b", "label": "B"},
                    ],
                }
            ),
        )
        for raw in cases:
            with self.subTest(raw=raw[:40]):
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises(ValueError):
                    C.load_election_file(path)
        with self.assertRaises(ValueError):
            C.load_election_file(self.root / "missing.json")

    def test_candidate_definition_is_immutable_after_init(self):
        from secure_vote.db import initialize

        from support import test_config

        first = test_config(self.root / "immutable")
        initialize(first, admin_password="AdminPass123!")
        changed = test_config(
            self.root / "immutable",
            candidates=(C.Candidate("x", "X"), C.Candidate("y", "Y")),
        )
        with self.assertRaisesRegex(ValueError, "candidates changed"):
            initialize(changed)


if __name__ == "__main__":
    unittest.main()

import unittest

from secure_vote import crypto


class CryptoTests(unittest.TestCase):
    def test_password_round_trip(self):
        encoded = crypto.hash_password("correct horse battery", iterations=2_000)
        self.assertTrue(crypto.verify_password("correct horse battery", encoded))
        self.assertIn("pbkdf2_sha256", encoded)
        self.assertIn("$2000$", encoded)

    def test_wrong_password_rejected(self):
        encoded = crypto.hash_password("DemoPass123!", iterations=1_000)
        self.assertFalse(crypto.verify_password("demopass123!", encoded))
        self.assertFalse(crypto.verify_password("", encoded))

    def test_salts_are_unique(self):
        first = crypto.hash_password("DemoPass123!", iterations=1_000)
        second = crypto.hash_password("DemoPass123!", iterations=1_000)
        self.assertNotEqual(first, second)
        self.assertNotIn("DemoPass123!", first)

    def test_malformed_hashes_fail_closed(self):
        for encoded in (
            "",
            "garbage",
            "md5$1000$aa$bb",
            "pbkdf2_sha256$abc$aa$bb",
            "pbkdf2_sha256$1000$zz$bb",
            "pbkdf2_sha256$0$aa$bb",
            None,
        ):
            with self.subTest(encoded=encoded):
                self.assertFalse(crypto.verify_password("whatever", encoded))

    def test_digest_length_prefixing_prevents_ambiguity(self):
        self.assertNotEqual(crypto.digest("ab", "c"), crypto.digest("a", "bc"))
        self.assertEqual(len(crypto.digest("x")), 64)

    def test_mac_is_key_dependent_and_stable(self):
        self.assertEqual(crypto.mac(b"key-one", "a", "b"), crypto.mac(b"key-one", "a", "b"))
        self.assertNotEqual(crypto.mac(b"key-one", "a", "b"), crypto.mac(b"key-two", "a", "b"))

    def test_domain_tags_separate_purposes(self):
        self.assertNotEqual(
            crypto.digest(crypto.BALLOT_TAG, "same", "data"),
            crypto.digest(crypto.RESULTS_TAG, "same", "data"),
        )

    def test_random_tokens(self):
        tokens = {crypto.random_token() for _ in range(50)}
        self.assertEqual(len(tokens), 50)
        for token in tokens:
            self.assertNotIn("=", token)
            self.assertNotIn("/", token)
            self.assertNotIn("+", token)

    def test_safe_equals(self):
        self.assertTrue(crypto.safe_equals("abc", "abc"))
        self.assertFalse(crypto.safe_equals("abc", "abd"))
        self.assertFalse(crypto.safe_equals("abc", "ab"))

    def test_dummy_password_check_runs(self):
        crypto.dummy_password_check("anything", iterations=1_000)


if __name__ == "__main__":
    unittest.main()

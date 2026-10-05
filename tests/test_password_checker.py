import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from password_checker import analyze, entropy_bits, is_common, has_sequence, has_repeats


class TestChecker(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(analyze("password")["label"], "Very Weak")

    def test_leetspeak_common_detected(self):
        self.assertTrue(is_common("P@ssw0rd"))

    def test_sequence_and_repeat(self):
        self.assertTrue(has_sequence("xx123xx"))
        self.assertTrue(has_sequence("QWErty"))
        self.assertTrue(has_repeats("aaab"))

    def test_entropy_grows_with_length(self):
        self.assertGreater(entropy_bits("Abcd1234!xyz"), entropy_bits("Abcd1!"))

    def test_strong_password(self):
        self.assertGreaterEqual(analyze("v7#Kp9!zQm2@Lx8$")["score"], 3)

    def test_common_word_with_suffix_is_weak(self):
        self.assertLessEqual(analyze("P@ssw0rd123")["score"], 2)

    def test_empty_entropy(self):
        self.assertEqual(entropy_bits(""), 0.0)


if __name__ == "__main__":
    unittest.main()

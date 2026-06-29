import unittest

from app import should_flag_deepfake


class DeepfakeLogicTests(unittest.TestCase):
    def test_flags_high_score_as_suspicious(self):
        self.assertTrue(should_flag_deepfake(40))

    def test_flags_multi_face_composites_even_at_mid_score(self):
        self.assertTrue(should_flag_deepfake(35, face_count=2))

    def test_keeps_low_score_safe(self):
        self.assertFalse(should_flag_deepfake(30))


if __name__ == "__main__":
    unittest.main()

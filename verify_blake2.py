"""Known-answer and edge-case checks for the pure-Python BLAKE2 demos.

Run with ``python3 verify_blake2.py``. The fixed vectors guard against a
shared implementation mistake; Python's standard-library hashlib supplies an
independent reference for parameter combinations and padding boundaries.
"""

import hashlib
import unittest

from blake2b_demo import blake2b, blake2b_hex
from blake2s_demo import blake2s, blake2s_hex


class Blake2KnownAnswerTests(unittest.TestCase):
    def test_empty_and_abc_known_vectors(self):
        self.assertEqual(
            blake2b_hex(b""),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
            "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        )
        self.assertEqual(
            blake2s_hex(b""),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        )
        self.assertEqual(
            blake2b_hex(b"abc"),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d"
            "17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        )
        self.assertEqual(
            blake2s_hex(b"abc"),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        )


class Blake2ReferenceComparisonTests(unittest.TestCase):
    def test_boundary_lengths_against_hashlib(self):
        lengths = [0, 1, 3, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024]
        for message_length in lengths:
            message_data = bytes((index * 37 + 11) & 0xFF for index in range(message_length))
            with self.subTest(message_length=message_length):
                self.assertEqual(blake2b(message_data), hashlib.blake2b(message_data).digest())
                self.assertEqual(blake2s(message_data), hashlib.blake2s(message_data).digest())

    def test_digest_sizes_and_keys_against_hashlib(self):
        message_data = bytes(range(256))
        for digest_size in (1, 2, 16, 31, 32, 48, 63, 64):
            if digest_size <= 64:
                self.assertEqual(
                    blake2b(message_data, digest_size=digest_size),
                    hashlib.blake2b(message_data, digest_size=digest_size).digest(),
                )
            if digest_size <= 32:
                self.assertEqual(
                    blake2s(message_data, digest_size=digest_size),
                    hashlib.blake2s(message_data, digest_size=digest_size).digest(),
                )

        for key_length in (1, 31, 32, 63, 64):
            key_data = bytes(range(key_length))
            self.assertEqual(
                blake2b(message_data, key=key_data), hashlib.blake2b(message_data, key=key_data).digest()
            )
            if key_length <= 32:
                self.assertEqual(
                    blake2s(message_data, key=key_data), hashlib.blake2s(message_data, key=key_data).digest()
                )

    def test_key_block_and_exact_block_boundaries(self):
        # Key blocks are input blocks. Empty keyed input makes that key block final.
        for message_length in (0, 1, 63, 64, 65, 127, 128, 129, 255, 256):
            message_data = b"m" * message_length
            for key_length in (1, 16, 32):
                key_data = bytes(range(key_length))
                self.assertEqual(
                    blake2s(message_data, key=key_data),
                    hashlib.blake2s(message_data, key=key_data).digest(),
                    ("BLAKE2s", message_length, key_length),
                )
            for key_length in (1, 32, 64):
                key_data = bytes(range(key_length))
                self.assertEqual(
                    blake2b(message_data, key=key_data),
                    hashlib.blake2b(message_data, key=key_data).digest(),
                    ("BLAKE2b", message_length, key_length),
                )

    def test_text_and_mutable_byte_inputs(self):
        text = "密码学 🔐 BLAKE2"
        encoded_text = text.encode("utf-8")
        self.assertEqual(blake2b(text), hashlib.blake2b(encoded_text).digest())
        self.assertEqual(blake2s(text), hashlib.blake2s(encoded_text).digest())
        self.assertEqual(blake2b(bytearray(encoded_text)), hashlib.blake2b(encoded_text).digest())
        self.assertEqual(blake2s(bytearray(encoded_text)), hashlib.blake2s(encoded_text).digest())
        self.assertEqual(blake2b_hex(text), blake2b(text).hex())
        self.assertEqual(blake2s_hex(text), blake2s(text).hex())

    def test_sha_comparisons_are_distinct_hashes(self):
        for message_data in (b"", b"abc", b"The quick brown fox jumps over the lazy dog"):
            self.assertNotEqual(blake2b(message_data), hashlib.sha512(message_data).digest())
            self.assertNotEqual(blake2s(message_data), hashlib.sha256(message_data).digest())


class Blake2ValidationTests(unittest.TestCase):
    def test_digest_size_validation(self):
        for bad_size in (0, -1, 65, 1.5, "32", True):
            with self.subTest(algorithm="BLAKE2b", digest_size=bad_size):
                with self.assertRaises((TypeError, ValueError)):
                    blake2b(b"message", digest_size=bad_size)
            if isinstance(bad_size, int) and not isinstance(bad_size, bool):
                with self.subTest(algorithm="BLAKE2s", digest_size=bad_size):
                    with self.assertRaises(ValueError):
                        blake2s(b"message", digest_size=bad_size)
            else:
                with self.assertRaises(TypeError):
                    blake2s(b"message", digest_size=bad_size)

    def test_key_and_message_type_validation(self):
        with self.assertRaises(TypeError):
            blake2b(123)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            blake2s(123)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            blake2b(b"message", key="secret")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            blake2s(b"message", key="secret")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            blake2b(b"message", key=bytes(65))
        with self.assertRaises(ValueError):
            blake2s(b"message", key=bytes(33))


if __name__ == "__main__":
    unittest.main(verbosity=2)

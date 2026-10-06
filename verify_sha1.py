"""Verification Suite for Pure Python SHA-1 Implementation.

This module validates the SHA-1 implementation in sha1_demo.py against:
  1. RFC 3174 Section 7.3 official test vectors (Tests 1, 2, 3, 4).
  2. Wikipedia SHA-1 test vectors (including empty string and pangrams).
  3. Padding boundary edge cases (lengths 0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 512, 1000).
  4. Multi-byte UTF-8 string hashing.
  5. Component-level unit checks for rotation, message expansion, and type validation.
  6. Cross-verification against Python standard library hashlib.sha1.

Usage:
  python verify_sha1.py
"""

import sys
import hashlib
from typing import List, Tuple

from sha1_demo import (
    sha1,
    sha1_hex,
    pad_message,
    expand_message_schedule,
    left_rotate,
    f_func,
    get_k,
)


def verify_rfc3174_test_vectors():
    """Validates the 4 official test vectors from RFC 3174 Section 7.3."""
    print("=" * 70)
    print("1. VERIFYING RFC 3174 SECTION 7.3 TEST SUITE")
    print("=" * 70)

    # RFC 3174 Section 7.3 test cases
    test_cases: List[Tuple[str, bytes, str]] = [
        (
            "Test 1: 'abc'",
            b"abc",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        (
            "Test 2: 56-byte string",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        (
            "Test 3: 1,000,000 repetitions of 'a'",
            b"a" * 1000000,
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
        ),
        (
            "Test 4: 10 blocks of 64 bytes (640 bytes total)",
            (b"01234567" * 8) * 10,
            "dea356a2cddd90c7a7ecedc5ebb563934f460452",
        ),
    ]

    all_passed = True
    for label, msg, expected_hex in test_cases:
        actual_hex = sha1_hex(msg)
        if actual_hex == expected_hex:
            print(f"  [PASS] {label}")
            print(f"         Digest: {actual_hex}")
        else:
            print(f"  [FAIL] {label}")
            print(f"         Expected: {expected_hex}")
            print(f"         Actual:   {actual_hex}")
            all_passed = False

    assert all_passed, "One or more RFC 3174 test vectors failed!"
    print("--> All RFC 3174 test vectors PASSED!\n")


def verify_wikipedia_test_vectors():
    """Validates the test vectors listed in the Wikipedia SHA-1 article."""
    print("=" * 70)
    print("2. VERIFYING WIKIPEDIA SHA-1 ARTICLE TEST VECTORS")
    print("=" * 70)

    wiki_vectors: List[Tuple[str, str]] = [
        (
            "",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        ),
        (
            "The quick brown fox jumps over the lazy cog",
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
        ),
    ]

    all_passed = True
    for text, expected_hex in wiki_vectors:
        actual_hex = sha1_hex(text)
        if actual_hex == expected_hex:
            print(f"  [PASS] SHA-1({text!r:45s}) == {expected_hex}")
        else:
            print(f"  [FAIL] SHA-1({text!r})")
            print(f"         Expected: {expected_hex}")
            print(f"         Actual:   {actual_hex}")
            all_passed = False

    assert all_passed, "One or more Wikipedia test vectors failed!"
    print("--> All Wikipedia test vectors PASSED!\n")


def verify_padding_and_boundaries():
    """Tests message boundary lengths and padding block alignment."""
    print("=" * 70)
    print("3. VERIFYING PADDING & BLOCK BOUNDARY EDGE CASES")
    print("=" * 70)

    # Boundary lengths:
    # 55 bytes: padding is 0x80 + 8-byte length = 64 bytes (1 block)
    # 56 bytes: padding needs another block -> 128 bytes (2 blocks)
    # 64 bytes: full block -> padding is 0x80 + 55 zeros + 8 length = 128 bytes (2 blocks)
    boundary_lengths = [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 512, 1000]

    all_passed = True
    for length in boundary_lengths:
        sample = b"Y" * length
        padded = pad_message(sample)

        # 1. Padded length must be a multiple of 64 bytes (512 bits)
        assert len(padded) % 64 == 0, f"Padded length {len(padded)} not multiple of 64"

        # 2. Check 64-bit big-endian length at end of padding
        bit_len = int.from_bytes(padded[-8:], 'big')
        expected_bit_len = (length * 8) & 0xFFFFFFFFFFFFFFFF
        assert bit_len == expected_bit_len, f"Bit length mismatch: got {bit_len}, expected {expected_bit_len}"

        # 3. Check hash equality against hashlib.sha1
        actual = sha1_hex(sample)
        expected = hashlib.sha1(sample).hexdigest()
        if actual != expected:
            print(f"  [FAIL] Length {length:4d} bytes: got {actual}, expected {expected}")
            all_passed = False
        else:
            print(f"  [PASS] Length {length:4d} bytes (padded to {len(padded):4d} bytes, {len(padded)//64} blocks): match")

    assert all_passed, "Padding / boundary tests failed!"
    print("--> All boundary edge cases PASSED!\n")


def verify_utf8_strings():
    """Verifies multi-byte UTF-8 string encoding and hashing."""
    print("=" * 70)
    print("4. VERIFYING MULTI-BYTE UTF-8 STRINGS")
    print("=" * 70)

    strings = [
        "你好，世界！",
        "SHA-1 安全哈希算法纯 Python 实现",
        "Cryptographic Hash Functions: MD5 vs SHA-1 vs SHA-256",
        "Emoji test: 🔒🔑🛡️🚀",
    ]

    for s in strings:
        actual = sha1_hex(s)
        expected = hashlib.sha1(s.encode('utf-8')).hexdigest()
        assert actual == expected, f"Mismatch on {s!r}: {actual} != {expected}"
        print(f"  [PASS] SHA-1({s!r}) == {actual}")

    print("--> All UTF-8 strings PASSED!\n")


def verify_unit_components():
    """Verifies unit behavior of circular rotations, message expansion, and input validation."""
    print("=" * 70)
    print("5. VERIFYING UNIT COMPONENTS & INPUT VALIDATION")
    print("=" * 70)

    # 1. Circular left rotate
    assert left_rotate(0x80000001, 1) == 0x00000003, "left_rotate failed bit carry"
    assert left_rotate(0x12345678, 5) == 0x468ACF02, "left_rotate failed 5-bit shift"
    assert left_rotate(0x12345678, 30) == 0x048D159E, "left_rotate failed 30-bit shift"
    print("  [PASS] Circular left shifts (A <<< 5, B <<< 30) verified.")

    # 2. Message schedule expansion length
    sample_chunk = b"\x00" * 64
    w = expand_message_schedule(sample_chunk)
    assert len(w) == 80, f"Expected 80 words in schedule, got {len(w)}"
    print("  [PASS] expand_message_schedule correctly generates 80 32-bit words.")

    # 3. Round function output bounds
    for t in (0, 20, 40, 60):
        val = f_func(t, 0x12345678, 0x9ABCDEF0, 0x13579BDF)
        assert 0 <= val <= 0xFFFFFFFF
    print("  [PASS] Round functions f_t conform to 32-bit unsigned bounds.")

    # 4. Input type validation
    invalid_inputs = [12345, None, ["a", "b"], {"key": "val"}]
    for bad in invalid_inputs:
        try:
            sha1(bad)  # type: ignore
            raise AssertionError(f"Expected TypeError for {type(bad).__name__}")
        except TypeError as e:
            print(f"  [PASS] Invalid type {type(bad).__name__} correctly rejected: {e}")

    print("--> All unit components and input validation checks PASSED!\n")


def main():
    print("=" * 70)
    print("RUNNING COMPREHENSIVE SHA-1 VERIFICATION SUITE")
    print("=" * 70 + "\n")

    verify_rfc3174_test_vectors()
    verify_wikipedia_test_vectors()
    verify_padding_and_boundaries()
    verify_utf8_strings()
    verify_unit_components()

    print("=" * 70)
    print("SUMMARY: ALL SHA-1 VERIFICATION TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()

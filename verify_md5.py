"""Verification Suite for Pure Python MD5 Implementation.

This module validates the MD5 implementation in md5_demo.py against:
  1. RFC 1321 Section A.5 official test suite (7 vectors).
  2. Wikipedia MD5 article test vectors (including pangrams with and without period).
  3. Padding boundary edge cases (lengths 0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1000).
  4. Multi-byte UTF-8 string hashing.
  5. Component-level unit checks for auxiliary functions and padding.
  6. Comparison against standard library hashlib.md5.

Usage:
  python verify_md5.py
"""

import sys
import hashlib
from typing import List, Tuple

from md5_demo import (
    md5,
    md5_hex,
    pad_message,
    left_rotate,
    f_func,
    g_func,
    h_func,
    i_func,
)


def verify_rfc1321_test_vectors():
    """Validates the 7 official test vectors from RFC 1321 Section A.5."""
    print("=" * 65)
    print("1. VERIFYING RFC 1321 SECTION A.5 TEST SUITE")
    print("=" * 65)

    rfc_vectors: List[Tuple[bytes, str]] = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ]

    all_passed = True
    for idx, (msg, expected_hex) in enumerate(rfc_vectors, 1):
        actual_hex = md5_hex(msg)
        display_msg = f"{msg[:28]!r}..." if len(msg) > 30 else f"{msg!r}"
        if actual_hex == expected_hex:
            print(f"  [PASS] Vector #{idx}: MD5({display_msg}) == {expected_hex}")
        else:
            print(f"  [FAIL] Vector #{idx}: MD5({display_msg})")
            print(f"         Expected: {expected_hex}")
            print(f"         Actual:   {actual_hex}")
            all_passed = False

    assert all_passed, "One or more RFC 1321 test vectors failed!"
    print("--> All RFC 1321 test vectors PASSED!\n")


def verify_wikipedia_test_vectors():
    """Validates the test vectors listed in the Wikipedia MD5 article."""
    print("=" * 65)
    print("2. VERIFYING WIKIPEDIA MD5 ARTICLE TEST VECTORS")
    print("=" * 65)

    wiki_vectors: List[Tuple[str, str]] = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        (
            "The quick brown fox jumps over the lazy dog",
            "9e107d9d372bb6826bd81d3542a419d6",
        ),
        (
            "The quick brown fox jumps over the lazy dog.",
            "e4d909c290d0fb1ca068ffaddf22cbd0",
        ),
    ]

    all_passed = True
    for text, expected_hex in wiki_vectors:
        actual_hex = md5_hex(text)
        if actual_hex == expected_hex:
            print(f"  [PASS] MD5({text!r}) == {expected_hex}")
        else:
            print(f"  [FAIL] MD5({text!r})")
            print(f"         Expected: {expected_hex}")
            print(f"         Actual:   {actual_hex}")
            all_passed = False

    assert all_passed, "One or more Wikipedia test vectors failed!"
    print("--> All Wikipedia test vectors PASSED!\n")


def verify_padding_and_edge_cases():
    """Tests message boundary lengths and padding block alignment."""
    print("=" * 65)
    print("3. VERIFYING PADDING & BLOCK BOUNDARY EDGE CASES")
    print("=" * 65)

    # Critical boundary lengths:
    # 55 bytes: padding is 0x80 + 8-byte length = 64 bytes (1 block)
    # 56 bytes: padding needs another block -> 128 bytes (2 blocks)
    # 64 bytes: full block -> padding is 0x80 + 55 zeros + 8 length = 128 bytes (2 blocks)
    boundary_lengths = [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 512, 1000]

    all_passed = True
    for length in boundary_lengths:
        sample = b"X" * length
        padded = pad_message(sample)

        # 1. Check padded length is a multiple of 64 bytes
        assert len(padded) % 64 == 0, f"Padded length {len(padded)} not multiple of 64"

        # 2. Check original bit length in last 8 bytes
        bit_len = int.from_bytes(padded[-8:], 'little')
        expected_bit_len = (length * 8) & 0xFFFFFFFFFFFFFFFF
        assert bit_len == expected_bit_len, f"Bit length mismatch: got {bit_len}, expected {expected_bit_len}"

        # 3. Check hash equality against hashlib.md5
        actual = md5_hex(sample)
        expected = hashlib.md5(sample).hexdigest()
        if actual != expected:
            print(f"  [FAIL] Length {length} bytes: got {actual}, expected {expected}")
            all_passed = False
        else:
            print(
                f"  [PASS] Length {length:4d} bytes (padded to {len(padded):4d} bytes, {len(padded) // 64} blocks): match")

    assert all_passed, "Padding / boundary tests failed!"
    print("--> All boundary edge cases PASSED!\n")


def verify_utf8_strings():
    """Verifies multi-byte UTF-8 string encoding and hashing."""
    print("=" * 65)
    print("4. VERIFYING MULTI-BYTE UTF-8 STRINGS")
    print("=" * 65)

    strings = [
        "你好，世界！",
        "MD5 消息摘要算法纯 Python 实现",
        "Cryptographic Hash Functions: MD5, SHA-1, SHA-256",
        "Emoji test: 🔒🔑🛡️🚀",
    ]

    for s in strings:
        actual = md5_hex(s)
        expected = hashlib.md5(s.encode('utf-8')).hexdigest()
        assert actual == expected, f"Mismatch on {s!r}: {actual} != {expected}"
        print(f"  [PASS] MD5({s!r}) == {actual}")

    print("--> All UTF-8 strings PASSED!\n")


def verify_auxiliary_functions_and_types():
    """Verifies unit behavior of auxiliary non-linear functions and input type validation."""
    print("=" * 65)
    print("5. VERIFYING AUXILIARY FUNCTIONS & INPUT VALIDATION")
    print("=" * 65)

    # Check left rotate
    assert left_rotate(0x80000001, 1) == 0x00000003, "left_rotate failed bit carry"
    assert left_rotate(0x12345678, 4) == 0x23456781, "left_rotate failed nibble shift"
    print("  [PASS] left_rotate circular bit shifts verified.")

    # Check bitwise masking in auxiliary functions
    x, y, z = 0x12345678, 0x9ABCDEF0, 0x13579BDF
    assert f_func(x, y, z) <= 0xFFFFFFFF
    assert g_func(x, y, z) <= 0xFFFFFFFF
    assert h_func(x, y, z) <= 0xFFFFFFFF
    assert i_func(x, y, z) <= 0xFFFFFFFF
    print("  [PASS] Auxiliary functions F, G, H, I conform to 32-bit unsigned bounds.")

    # Check invalid input types
    invalid_inputs = [12345, None, ["a", "b"], {"key": "val"}]
    for bad in invalid_inputs:
        try:
            md5(bad)  # type: ignore
            raise AssertionError(f"Expected TypeError for {type(bad).__name__}")
        except TypeError as e:
            print(f"  [PASS] Invalid type {type(bad).__name__} correctly rejected: {e}")

    print("--> All auxiliary and input validation checks PASSED!\n")


def main():
    print("=" * 65)
    print("RUNNING COMPREHENSIVE MD5 VERIFICATION SUITE")
    print("=" * 65 + "\n")

    verify_rfc1321_test_vectors()
    verify_wikipedia_test_vectors()
    verify_padding_and_edge_cases()
    verify_utf8_strings()
    verify_auxiliary_functions_and_types()

    print("=" * 65)
    print("SUMMARY: ALL MD5 VERIFICATION TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    main()

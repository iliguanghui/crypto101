"""Verification Suite for Pure Python SHA-2 Family (SHA-224, SHA-256, SHA-384, SHA-512).

This module comprehensively validates the implementations in:
  - sha256_demo.py (SHA-224, SHA-256)
  - sha512_demo.py (SHA-384, SHA-512)

Test Coverage:
  1. RFC 6234 Section 8.5 official test vectors (TEST1, TEST2_1, TEST2_2, TEST3, TEST4).
  2. Wikipedia SHA-2 test vectors (empty string, pangrams, 1-bit flip avalanche effect).
  3. Padding boundary edge cases:
       - 512-bit block boundaries (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128 bytes).
       - 1024-bit block boundaries (0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 256 bytes).
  4. Multi-byte UTF-8 string encoding verification.
  5. Component-level unit checks (rotations, sigma functions, schedule expansion, padding).
  6. Cross-verification against Python standard library hashlib (sha224, sha256, sha384, sha512).

Usage:
  python verify_sha2.py
"""

import hashlib
import sys
from typing import Callable, Dict, List, Tuple

from sha256_demo import (
    INIT_H_224,
    INIT_H_256,
    K_TABLE_256,
    big_sigma0_32,
    big_sigma1_32,
    ch32,
    expand_message_schedule_32,
    maj32,
    pad_message_512,
    rotr32,
    sha224,
    sha224_hex,
    sha256,
    sha256_hex,
    small_sigma0_32,
    small_sigma1_32,
)
from sha512_demo import (
    INIT_H_384,
    INIT_H_512,
    K_TABLE_512,
    big_sigma0_64,
    big_sigma1_64,
    ch64,
    expand_message_schedule_64,
    maj64,
    pad_message_1024,
    rotr64,
    sha384,
    sha384_hex,
    sha512,
    sha512_hex,
    small_sigma0_64,
    small_sigma1_64,
)


def verify_rfc6234_test_vectors():
    """Validates official test vectors from RFC 6234 Section 8.5 across all 4 algorithms."""
    print("=" * 72)
    print("1. VERIFYING RFC 6234 OFFICIAL TEST SUITE")
    print("=" * 72)

    # Patterns defined in RFC 6234 Section 8.5
    test1 = b"abc"
    test2_1 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    test2_2 = (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    )
    test3 = b"a" * 1000000
    test4 = (b"01234567" * 8) * 10

    test_matrix: List[Tuple[str, Callable[[bytes], str], List[Tuple[str, bytes, str]]]] = [
        (
            "SHA-224",
            sha224_hex,
            [
                ("TEST1 ('abc')", test1, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
                ("TEST2_1 (56 bytes)", test2_1, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"),
                ("TEST2_2 (112 bytes)", test2_2, "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"),
                ("TEST3 (1,000,000 'a's)", test3, "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"),
                ("TEST4 (640 bytes)", test4, "567f69f168cd7844e65259ce658fe7aadfa25216e68eca0eb7ab8262"),
            ],
        ),
        (
            "SHA-256",
            sha256_hex,
            [
                ("TEST1 ('abc')", test1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                ("TEST2_1 (56 bytes)", test2_1, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
                ("TEST2_2 (112 bytes)", test2_2, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
                ("TEST3 (1,000,000 'a's)", test3, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
                ("TEST4 (640 bytes)", test4, "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5"),
            ],
        ),
        (
            "SHA-384",
            sha384_hex,
            [
                ("TEST1 ('abc')", test1, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
                ("TEST2_1 (56 bytes)", test2_1, "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"),
                ("TEST2_2 (112 bytes)", test2_2, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"),
                ("TEST3 (1,000,000 'a's)", test3, "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"),
                ("TEST4 (640 bytes)", test4, "2fc64a4f500ddb6828f6a3430b8dd72a368eb7f3a8322a70bc84275b9c0b3ab00d27a5cc3c2d224aa6b61a0d79fb4596"),
            ],
        ),
        (
            "SHA-512",
            sha512_hex,
            [
                ("TEST1 ('abc')", test1, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
                ("TEST2_1 (56 bytes)", test2_1, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"),
                ("TEST2_2 (112 bytes)", test2_2, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
                ("TEST3 (1,000,000 'a's)", test3, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"),
                ("TEST4 (640 bytes)", test4, "89d05ba632c699c31231ded4ffc127d5a894dad412c0e024db872d1abd2ba8141a0f85072a9be1e2aa04cf33c765cb510813a39cd5a84c4acaa64d3f3fb7bae9"),
            ],
        ),
    ]

    all_passed = True
    for algo_name, hash_fn, cases in test_matrix:
        print(f"\n--- Testing {algo_name} ---")
        for label, msg, expected in cases:
            actual = hash_fn(msg)
            if actual == expected:
                print(f"  [PASS] {label}")
            else:
                print(f"  [FAIL] {label}")
                print(f"         Expected: {expected}")
                print(f"         Actual:   {actual}")
                all_passed = False

    assert all_passed, "One or more RFC 6234 test vectors failed!"
    print("\n--> All RFC 6234 official test vectors PASSED!\n")


def verify_wikipedia_test_vectors():
    """Validates the test vectors and avalanche effect examples from Wikipedia."""
    print("=" * 72)
    print("2. VERIFYING WIKIPEDIA SHA-2 ARTICLE TEST VECTORS")
    print("=" * 72)

    wiki_cases = [
        (
            "Empty string ('')",
            "",
            {
                "SHA-224": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
                "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "SHA-384": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                "SHA-512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            },
        ),
        (
            "Pangram ('The quick brown fox jumps over the lazy dog')",
            "The quick brown fox jumps over the lazy dog",
            {
                "SHA-224": "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
                "SHA-256": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
                "SHA-384": "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
                "SHA-512": "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
            },
        ),
        (
            "Wikipedia Avalanche (added period '.'): 'The quick brown fox jumps over the lazy dog.'",
            "The quick brown fox jumps over the lazy dog.",
            {
                "SHA-224": "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
                "SHA-256": "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
                "SHA-384": "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7",
                "SHA-512": "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
            },
        ),
        (
            "1-bit flip ('The quick brown fox jumps over the lazy cog')",
            "The quick brown fox jumps over the lazy cog",
            {
                "SHA-224": "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b",
                "SHA-256": "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be",
                "SHA-384": "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b",
                "SHA-512": "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045",
            },
        ),
    ]

    all_passed = True
    func_map = {
        "SHA-224": sha224_hex,
        "SHA-256": sha256_hex,
        "SHA-384": sha384_hex,
        "SHA-512": sha512_hex,
    }

    for label, text, expected_dict in wiki_cases:
        print(f"\n--- Testing {label} ---")
        for algo, expected_hex in expected_dict.items():
            actual_hex = func_map[algo](text)
            if actual_hex == expected_hex:
                print(f"  [PASS] {algo}: {actual_hex[:32]}...")
            else:
                print(f"  [FAIL] {algo}")
                print(f"         Expected: {expected_hex}")
                print(f"         Actual:   {actual_hex}")
                all_passed = False

    assert all_passed, "One or more Wikipedia test vectors failed!"
    print("\n--> All Wikipedia test vectors PASSED!\n")


def verify_padding_boundary_cases():
    """Tests critical padding boundary edge cases across block sizes."""
    print("=" * 72)
    print("3. VERIFYING PADDING BOUNDARIES (512-BIT & 1024-BIT BLOCKS)")
    print("=" * 72)

    # 32-bit block (64 bytes): critical boundaries are around 56 and 64
    lengths_32 = [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 128]
    # 64-bit block (128 bytes): critical boundaries are around 112 and 128
    lengths_64 = [0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 241, 256]

    all_passed = True

    print("Checking 512-bit block padding boundaries (SHA-224 & SHA-256):")
    for length in lengths_32:
        msg = b"B" * length
        # Pad message check
        padded = pad_message_512(msg)
        assert len(padded) % 64 == 0, f"Padded length {len(padded)} not multiple of 64"
        assert padded[length] == 0x80, f"Padding does not start with 0x80"
        bit_len = int.from_bytes(padded[-8:], "big")
        assert bit_len == length * 8, f"Bit length field mismatch: {bit_len} != {length * 8}"

        # Hash check against hashlib
        expected_256 = hashlib.sha256(msg).hexdigest()
        actual_256 = sha256_hex(msg)
        expected_224 = hashlib.sha224(msg).hexdigest()
        actual_224 = sha224_hex(msg)
        if expected_256 != actual_256 or expected_224 != actual_224:
            print(f"  [FAIL] Length {length} bytes")
            all_passed = False
        else:
            print(f"  [PASS] Length {length:3d} bytes -> Padded to {len(padded):3d} bytes ({len(padded)//64} blocks)")

    print("\nChecking 1024-bit block padding boundaries (SHA-384 & SHA-512):")
    for length in lengths_64:
        msg = b"C" * length
        padded = pad_message_1024(msg)
        assert len(padded) % 128 == 0, f"Padded length {len(padded)} not multiple of 128"
        assert padded[length] == 0x80, f"Padding does not start with 0x80"
        bit_len = int.from_bytes(padded[-16:], "big")
        assert bit_len == length * 8, f"Bit length field mismatch: {bit_len} != {length * 8}"

        expected_512 = hashlib.sha512(msg).hexdigest()
        actual_512 = sha512_hex(msg)
        expected_384 = hashlib.sha384(msg).hexdigest()
        actual_384 = sha384_hex(msg)
        if expected_512 != actual_512 or expected_384 != actual_384:
            print(f"  [FAIL] Length {length} bytes")
            all_passed = False
        else:
            print(f"  [PASS] Length {length:3d} bytes -> Padded to {len(padded):3d} bytes ({len(padded)//128} blocks)")

    assert all_passed, "Padding boundary verification failed!"
    print("\n--> All padding boundary edge cases PASSED!\n")


def verify_utf8_and_data_types():
    """Tests diverse data types (str, bytes, bytearray) and UTF-8 multi-byte characters."""
    print("=" * 72)
    print("4. VERIFYING UTF-8 AND DATA TYPE HANDLING")
    print("=" * 72)

    samples = [
        "密码学101: 纯Python实现SHA-2哈希函数家族",
        "🔐 Secure Hashing Algorithm 2 (SHA-224, SHA-256, SHA-384, SHA-512) 🚀",
        "Привет, мир! Γειά σου Κόσμε! こんにちは世界！",
    ]

    all_passed = True
    for sample in samples:
        str_val = sample
        bytes_val = sample.encode("utf-8")
        bytearray_val = bytearray(bytes_val)

        # Cross-test types
        h_str = sha256_hex(str_val)
        h_bytes = sha256_hex(bytes_val)
        h_bytearray = sha256_hex(bytearray_val)
        h_expected = hashlib.sha256(bytes_val).hexdigest()

        if h_str == h_bytes == h_bytearray == h_expected:
            print(f"  [PASS] SHA-256 type equivalence for: {sample[:35]}...")
        else:
            print(f"  [FAIL] Type mismatch for: {sample}")
            all_passed = False

        # Test SHA-512
        h512_str = sha512_hex(str_val)
        h512_expected = hashlib.sha512(bytes_val).hexdigest()
        if h512_str == h512_expected:
            print(f"  [PASS] SHA-512 type equivalence for: {sample[:35]}...")
        else:
            print(f"  [FAIL] SHA-512 mismatch for: {sample}")
            all_passed = False

    assert all_passed, "UTF-8 / Data type verification failed!"
    print("\n--> All UTF-8 and data type handling tests PASSED!\n")


def verify_component_units():
    """Unit tests for low-level primitive functions (rotations, sigma functions, schedule expansion)."""
    print("=" * 72)
    print("5. VERIFYING LOW-LEVEL PRIMITIVE FUNCTIONS")
    print("=" * 72)

    # 1. 32-bit and 64-bit circular rotations
    x32 = 0x12345678
    assert rotr32(x32, 0) == x32
    assert rotr32(x32, 4) == 0x81234567
    assert rotr32(x32, 32) == x32
    print("  [PASS] rotr32 correctness verified.")

    x64 = 0x123456789ABCDEF0
    assert rotr64(x64, 0) == x64
    assert rotr64(x64, 4) == 0x0123456789ABCDEF
    assert rotr64(x64, 64) == x64
    print("  [PASS] rotr64 correctness verified.")

    # 2. Logic functions
    assert ch32(0xFFFFFFFF, 0xAAAAAAAA, 0x55555555) == 0xAAAAAAAA
    assert ch32(0x00000000, 0xAAAAAAAA, 0x55555555) == 0x55555555
    assert ch64(0xFFFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555) == 0xAAAAAAAAAAAAAAAA
    assert maj32(0xF0F0F0F0, 0xCCCCCCCC, 0xAAAAAAAA) == 0xE8E8E8E8
    assert maj64(0xF0F0F0F0F0F0F0F0, 0xCCCCCCCCCCCCCCCC, 0xAAAAAAAAAAAAAAAA) == 0xE8E8E8E8E8E8E8E8
    print("  [PASS] Bitwise logic functions (ch, maj) verified.")

    # 3. Schedule expansion dimensions
    block_512 = b"\x00" * 64
    w_32 = expand_message_schedule_32(block_512)
    assert len(w_32) == 64, f"Expected 64 words for 32-bit schedule, got {len(w_32)}"
    print("  [PASS] expand_message_schedule_32 produces exactly 64 words.")

    block_1024 = b"\x00" * 128
    w_64 = expand_message_schedule_64(block_1024)
    assert len(w_64) == 80, f"Expected 80 words for 64-bit schedule, got {len(w_64)}"
    print("  [PASS] expand_message_schedule_64 produces exactly 80 words.")

    # 4. Digest length check
    assert len(sha224(b"")) == 28, "SHA-224 digest must be 28 bytes"
    assert len(sha256(b"")) == 32, "SHA-256 digest must be 32 bytes"
    assert len(sha384(b"")) == 48, "SHA-384 digest must be 48 bytes"
    assert len(sha512(b"")) == 64, "SHA-512 digest must be 64 bytes"
    print("  [PASS] Output digest lengths verified (28, 32, 48, 64 bytes).")

    print("\n--> All low-level primitive unit tests PASSED!\n")


def verify_cross_hashlib_bulk():
    """Performs bulk cross-verification against Python hashlib on randomized message lengths."""
    print("=" * 72)
    print("6. BULK CROSS-VERIFICATION AGAINST PYTHON HASHLIB")
    print("=" * 72)

    import random
    rng = random.Random(42)  # Deterministic seed

    all_passed = True
    test_counts = 50
    for idx in range(test_counts):
        size = rng.randint(0, 1500)
        random_payload = bytes(rng.getrandbits(8) for _ in range(size))

        if sha224_hex(random_payload) != hashlib.sha224(random_payload).hexdigest():
            print(f"  [FAIL] SHA-224 failed for random size {size}")
            all_passed = False
            break

        if sha256_hex(random_payload) != hashlib.sha256(random_payload).hexdigest():
            print(f"  [FAIL] SHA-256 failed for random size {size}")
            all_passed = False
            break

        if sha384_hex(random_payload) != hashlib.sha384(random_payload).hexdigest():
            print(f"  [FAIL] SHA-384 failed for random size {size}")
            all_passed = False
            break

        if sha512_hex(random_payload) != hashlib.sha512(random_payload).hexdigest():
            print(f"  [FAIL] SHA-512 failed for random size {size}")
            all_passed = False
            break

    assert all_passed, "Bulk cross-verification against hashlib failed!"
    print(f"  [PASS] {test_counts} random payloads (lengths 0..1500 bytes) matched hashlib across all 4 algorithms.")
    print("\n--> Bulk cross-verification PASSED!\n")


def main():
    print("#" * 72)
    print("# COMPREHENSIVE SHA-2 TEST SUITE (SHA-224, SHA-256, SHA-384, SHA-512)")
    print("#" * 72)
    print()

    try:
        verify_rfc6234_test_vectors()
        verify_wikipedia_test_vectors()
        verify_padding_boundary_cases()
        verify_utf8_and_data_types()
        verify_component_units()
        verify_cross_hashlib_bulk()

        print("=" * 72)
        print("ALL SHA-2 SUITE VERIFICATIONS COMPLETED SUCCESSFULLY! [100% PASS]")
        print("=" * 72)
    except AssertionError as err:
        print(f"\n[FATAL ERROR] Test suite aborted: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

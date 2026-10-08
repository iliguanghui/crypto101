"""Verification Suite for Pure Python SHA-3 and SHAKE Implementation (NIST FIPS PUB 202).

This module comprehensively validates the implementation in sha3_demo.py against:
  1. NIST FIPS PUB 202 official test vectors for all 4 fixed-length hash algorithms:
       - SHA3-224, SHA3-256, SHA3-384, SHA3-512.
  2. NIST FIPS PUB 202 official test vectors for extendable-output functions:
       - SHAKE128, SHAKE256.
  3. Wikipedia SHA-3 article test vectors (empty string, pangrams, avalanche effect).
  4. Sponge multi-rate padding (pad10*1) boundary edge cases:
       - Critical boundary: pad_len = 1 (delimiters 0x86 and 0x9F).
       - Critical boundary: message length equal to multiple of rate r (extra full block).
  5. Arbitrary long-length squeezing across multiple Keccak-f[1600] blocks (SHAKE).
  6. Multi-byte UTF-8 character string hashing.
  7. Component-level unit checks (theta, rho, pi, chi, iota, state conversions).
  8. Bulk cross-verification against Python standard library hashlib.

Usage:
  python verify_sha3.py
"""

import hashlib
import sys

from sha3_demo import (
    KECCAK_L,
    LANE_WIDTH_BITS,
    LFSR_PERIOD,
    MASK_64,
    NUM_ROUNDS,
    RC,
    RHO_OFFSETS,
    STATE_GRID_DIM,
    STATE_WIDTH_BYTES,
    bytes_to_state,
    compute_rho_offsets,
    compute_round_constant,
    rc_lfsr,
    pad10star1,
    rotl64,
    sha3_224,
    sha3_224_hex,
    sha3_256,
    sha3_256_hex,
    sha3_384,
    sha3_384_hex,
    sha3_512,
    sha3_512_hex,
    shake128,
    shake128_hex,
    shake256,
    shake256_hex,
    state_to_bytes,
    step_chi,
    step_iota,
    step_pi,
    step_rho,
    step_theta,
)


def verify_nist_fips202_fixed_vectors():
    """Validates official NIST FIPS 202 test vectors across all 4 fixed-length hash functions."""
    print("=" * 72)
    print("1. VERIFYING NIST FIPS 202 OFFICIAL FIXED-LENGTH TEST VECTORS")
    print("=" * 72)

    test_vectors = [
        ("Empty String ('')", b""),
        ("Single Char ('a')", b"a"),
        ("Three Chars ('abc')", b"abc"),
        (
            "Medium 56-byte message",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        ),
        (
            "Long 112-byte message",
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
        ),
        ("1,000 repetitions of 'a'", b"a" * 1000),
    ]

    all_passed = True
    for label, msg in test_vectors:
        print(f"\n--- Testing: {label} ---")
        for algo_name, my_fn, ref_fn in [
            ("SHA3-224", sha3_224_hex, hashlib.sha3_224),
            ("SHA3-256", sha3_256_hex, hashlib.sha3_256),
            ("SHA3-384", sha3_384_hex, hashlib.sha3_384),
            ("SHA3-512", sha3_512_hex, hashlib.sha3_512),
        ]:
            actual = my_fn(msg)
            expected = ref_fn(msg).hexdigest()
            if actual == expected:
                print(f"  [PASS] {algo_name}: {actual[:24]}...")
            else:
                print(f"  [FAIL] {algo_name}")
                print(f"         Expected: {expected}")
                print(f"         Actual:   {actual}")
                all_passed = False

    assert all_passed, "One or more NIST FIPS 202 fixed-length test vectors failed!"
    print("\n--> All NIST FIPS 202 fixed-length test vectors PASSED!\n")


def verify_nist_fips202_shake_vectors():
    """Validates official NIST FIPS 202 test vectors for SHAKE128 and SHAKE256 XOFs."""
    print("=" * 72)
    print("2. VERIFYING NIST FIPS 202 SHAKE EXTENDABLE-OUTPUT FUNCTIONS (XOFs)")
    print("=" * 72)

    test_cases = [
        ("Empty String", b"", [16, 32, 64, 128]),
        ("Three Chars ('abc')", b"abc", [32, 64, 136, 168, 200, 500]),
        ("Long String (1000 'a')", b"a" * 1000, [32, 64, 256, 1024]),
    ]

    all_passed = True
    for label, msg, length_list in test_cases:
        print(f"\n--- Testing: {label} ---")
        for out_len in length_list:
            # SHAKE128
            act_128 = shake128_hex(msg, output_bytes=out_len)
            exp_128 = hashlib.shake_128(msg).hexdigest(out_len)
            if act_128 == exp_128:
                print(f"  [PASS] SHAKE128 (length={out_len:4d} bytes): {act_128[:20]}...")
            else:
                print(f"  [FAIL] SHAKE128 (length={out_len})")
                all_passed = False

            # SHAKE256
            act_256 = shake256_hex(msg, output_bytes=out_len)
            exp_256 = hashlib.shake_256(msg).hexdigest(out_len)
            if act_256 == exp_256:
                print(f"  [PASS] SHAKE256 (length={out_len:4d} bytes): {act_256[:20]}...")
            else:
                print(f"  [FAIL] SHAKE256 (length={out_len})")
                all_passed = False

    assert all_passed, "One or more SHAKE test vectors failed!"
    print("\n--> All SHAKE XOF test vectors PASSED!\n")


def verify_wikipedia_test_vectors():
    """Validates the test vectors and avalanche examples listed in the Wikipedia SHA-3 article."""
    print("=" * 72)
    print("3. VERIFYING WIKIPEDIA SHA-3 ARTICLE TEST VECTORS")
    print("=" * 72)

    wiki_cases = [
        (
            "Empty string ('')",
            "",
            {
                "SHA3-224": "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
                "SHA3-256": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                "SHA3-384": "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
                "SHA3-512": "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            },
        ),
        (
            "Pangram ('The quick brown fox jumps over the lazy dog')",
            "The quick brown fox jumps over the lazy dog",
            {
                "SHA3-224": "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795",
                "SHA3-256": "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
                "SHA3-384": "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
                "SHA3-512": "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
            },
        ),
        (
            "Wikipedia Avalanche (added period '.'): 'The quick brown fox jumps over the lazy dog.'",
            "The quick brown fox jumps over the lazy dog.",
            {
                "SHA3-224": "2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0",
                "SHA3-256": "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
                "SHA3-384": "1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9",
                "SHA3-512": "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8",
            },
        ),
    ]

    all_passed = True
    func_map = {
        "SHA3-224": sha3_224_hex,
        "SHA3-256": sha3_256_hex,
        "SHA3-384": sha3_384_hex,
        "SHA3-512": sha3_512_hex,
    }

    for label, text, expected_dict in wiki_cases:
        print(f"\n--- Testing {label} ---")
        for algo, expected_hex in expected_dict.items():
            actual_hex = func_map[algo](text)
            if actual_hex == expected_hex:
                print(f"  [PASS] {algo}: {actual_hex[:24]}...")
            else:
                print(f"  [FAIL] {algo}")
                print(f"         Expected: {expected_hex}")
                print(f"         Actual:   {actual_hex}")
                all_passed = False

    assert all_passed, "One or more Wikipedia test vectors failed!"
    print("\n--> All Wikipedia test vectors PASSED!\n")


def verify_sponge_padding_boundaries():
    """Validates critical sponge multi-rate padding (pad10*1) boundary edge cases."""
    print("=" * 72)
    print("4. VERIFYING SPONGE PADDING (pad10*1) BOUNDARY EDGE CASES")
    print("=" * 72)

    all_passed = True

    # 1. SHA3-256 (rate = 136 bytes):
    # Boundary 1: pad_len = 1 byte (length = 135 mod 136) -> first byte is 0x06 | 0x80 = 0x86
    # Boundary 2: message is exact multiple of rate (length = 136, 272) -> must append full 136-byte block
    test_lens_256 = [0, 1, 134, 135, 136, 137, 271, 272, 273]
    print("Checking SHA3-256 rate boundaries (r = 136 bytes):")
    for length in test_lens_256:
        msg = b"X" * length
        pad = pad10star1(length, 136, 0x06)
        total_len = length + len(pad)
        assert total_len % 136 == 0, f"Total length {total_len} not multiple of 136"

        if length % 136 == 135:
            # 1-byte padding case: delimiter combined with 0x80
            assert len(pad) == 1, f"Expected 1 byte padding, got {len(pad)}"
            assert pad[0] == 0x86, f"Expected 0x86, got 0x{pad[0]:02x}"
        elif length % 136 == 0:
            # Exact block boundary: full rate_bytes padding added
            assert len(pad) == 136, f"Expected 136 bytes padding, got {len(pad)}"
            assert pad[0] == 0x06 and pad[-1] == 0x80

        act = sha3_256_hex(msg)
        exp = hashlib.sha3_256(msg).hexdigest()
        if act == exp:
            print(f"  [PASS] Length {length:3d} bytes (padding: {len(pad):3d} bytes) -> match")
        else:
            print(f"  [FAIL] Length {length} bytes mismatch")
            all_passed = False

    # 2. SHAKE128 (rate = 168 bytes):
    # Boundary: pad_len = 1 byte (length = 167 mod 168) -> first byte is 0x1F | 0x80 = 0x9F
    test_lens_shake = [0, 1, 166, 167, 168, 169, 335, 336]
    print("\nChecking SHAKE128 rate boundaries (r = 168 bytes):")
    for length in test_lens_shake:
        msg = b"Y" * length
        pad = pad10star1(length, 168, 0x1F)
        total_len = length + len(pad)
        assert total_len % 168 == 0

        if length % 168 == 167:
            assert len(pad) == 1
            assert pad[0] == 0x9F, f"Expected 0x9F, got 0x{pad[0]:02x}"

        act = shake128_hex(msg, output_bytes=32)
        exp = hashlib.shake_128(msg).hexdigest(32)
        if act == exp:
            print(f"  [PASS] Length {length:3d} bytes (padding: {len(pad):3d} bytes) -> match")
        else:
            print(f"  [FAIL] Length {length} bytes mismatch")
            all_passed = False

    assert all_passed, "Sponge padding boundary verification failed!"
    print("\n--> All sponge padding boundary edge cases PASSED!\n")


def verify_utf8_and_data_types():
    """Validates diverse data types (str, bytes, bytearray) and UTF-8 multi-byte characters."""
    print("=" * 72)
    print("5. VERIFYING UTF-8 AND DATA TYPE HANDLING")
    print("=" * 72)

    samples = [
        "密码学101: 纯Python实现SHA-3与SHAKE海绵结构函数家族",
        "🔐 Secure Hash Algorithm 3 (Keccak-f[1600] Permutation) 🚀",
        "Привет, мир! Γειά σου Κόσμε! こんにちは世界！",
    ]

    all_passed = True
    for sample in samples:
        str_val = sample
        bytes_val = sample.encode("utf-8")
        bytearray_val = bytearray(bytes_val)

        # SHA3-256 type equivalence
        h_str = sha3_256_hex(str_val)
        h_bytes = sha3_256_hex(bytes_val)
        h_bytearray = sha3_256_hex(bytearray_val)
        h_exp = hashlib.sha3_256(bytes_val).hexdigest()

        if h_str == h_bytes == h_bytearray == h_exp:
            print(f"  [PASS] SHA3-256 type equivalence for: {sample[:35]}...")
        else:
            print(f"  [FAIL] Type mismatch for: {sample}")
            all_passed = False

        # SHAKE128 type equivalence
        s_str = shake128_hex(str_val, output_bytes=48)
        s_bytes = shake128_hex(bytes_val, output_bytes=48)
        s_exp = hashlib.shake_128(bytes_val).hexdigest(48)
        if s_str == s_bytes == s_exp:
            print(f"  [PASS] SHAKE128 type equivalence for: {sample[:35]}...")
        else:
            print(f"  [FAIL] SHAKE128 mismatch for: {sample}")
            all_passed = False

    assert all_passed, "UTF-8 / Data type verification failed!"
    print("\n--> All UTF-8 and data type handling tests PASSED!\n")


def verify_component_units():
    """Unit tests for low-level primitive functions (rotations, step mappings, conversions)."""
    print("=" * 72)
    print("6. VERIFYING LOW-LEVEL PRIMITIVE STEPS (θ, ρ, π, χ, ι)")
    print("=" * 72)

    # 1. rotl64
    x = 0x123456789ABCDEF0
    assert rotl64(x, 0) == x
    assert rotl64(x, LANE_WIDTH_BITS) == x
    assert rotl64(x, 4) == (((x << 4) | (x >> (LANE_WIDTH_BITS - 4))) & MASK_64)
    print("  [PASS] rotl64 circular shift verified.")

    # 2. State serialization round-trip
    test_bytes = bytes(range(STATE_WIDTH_BYTES))
    st = bytes_to_state(test_bytes)
    assert len(st) == STATE_GRID_DIM and all(len(col) == STATE_GRID_DIM for col in st)
    recovered_bytes = state_to_bytes(st)
    assert test_bytes == recovered_bytes, "State conversion round-trip failed"
    print("  [PASS] bytes_to_state <-> state_to_bytes 200-byte round-trip verified.")

    # 3. All-zero state invariance through theta, rho, pi, chi
    zero_state = [[0] * STATE_GRID_DIM for _ in range(STATE_GRID_DIM)]
    assert step_theta(zero_state) == zero_state
    assert step_rho(zero_state) == zero_state
    assert step_pi(zero_state) == zero_state
    assert step_chi(zero_state) == zero_state
    print("  [PASS] Zero state invariance through theta, rho, pi, chi verified.")

    # 4. iota injects correct round constant into lane (0, 0)
    for r in range(NUM_ROUNDS):
        iota_st = step_iota(zero_state, r)
        assert iota_st[0][0] == RC[r], f"Round constant mismatch at round {r}"
        assert all(iota_st[x][y] == 0 for x in range(STATE_GRID_DIM) for y in range(STATE_GRID_DIM) if (x, y) != (0, 0))
    print("  [PASS] iota correctly injects all 24 round constants RC[0..23].")

    # 4b. LFSR Round Constant Generation (FIPS 202 Algorithm 5 & 6)
    ref_rc = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    assert rc_lfsr(0) == 1
    assert rc_lfsr(LFSR_PERIOD) == 1
    for r in range(NUM_ROUNDS):
        assert compute_round_constant(r, l=KECCAK_L) == ref_rc[r], f"Computed RC mismatch at round {r}"
        assert RC[r] == ref_rc[r], f"Dynamic RC list mismatch at round {r}"
    print("  [PASS] LFSR rc(t) (Alg 5) and RC[0..23] (Alg 6) dynamic computation verified.")

    # 4c. RHO Offsets Generation (FIPS 202 Algorithm 2)
    ref_rho = [
        [ 0, 36,  3, 41, 18],
        [ 1, 44, 10, 45,  2],
        [62,  6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39,  8, 14],
    ]
    assert compute_rho_offsets() == ref_rho
    assert RHO_OFFSETS == ref_rho
    print("  [PASS] RHO offsets (Alg 2) dynamic computation verified.")

    # 5. Digest lengths check
    assert len(sha3_224(b"")) == 28
    assert len(sha3_256(b"")) == 32
    assert len(sha3_384(b"")) == 48
    assert len(sha3_512(b"")) == 64
    assert len(shake128(b"", output_bytes=10)) == 10
    assert len(shake256(b"", output_bytes=100)) == 100
    print("  [PASS] Output digest lengths verified for all 6 functions.")

    print("\n--> All low-level primitive unit tests PASSED!\n")


def verify_cross_hashlib_bulk():
    """Bulk cross-verification against Python hashlib on randomized payloads."""
    print("=" * 72)
    print("7. BULK CROSS-VERIFICATION AGAINST PYTHON HASHLIB")
    print("=" * 72)

    import random
    rng = random.Random(42)  # Deterministic seed

    all_passed = True
    test_count = 50
    for idx in range(test_count):
        size = rng.randint(0, 1500)
        payload = bytes(rng.getrandbits(8) for _ in range(size))

        if sha3_224_hex(payload) != hashlib.sha3_224(payload).hexdigest():
            print(f"  [FAIL] SHA3-224 mismatch on size {size}")
            all_passed = False
            break

        if sha3_256_hex(payload) != hashlib.sha3_256(payload).hexdigest():
            print(f"  [FAIL] SHA3-256 mismatch on size {size}")
            all_passed = False
            break

        if sha3_384_hex(payload) != hashlib.sha3_384(payload).hexdigest():
            print(f"  [FAIL] SHA3-384 mismatch on size {size}")
            all_passed = False
            break

        if sha3_512_hex(payload) != hashlib.sha3_512(payload).hexdigest():
            print(f"  [FAIL] SHA3-512 mismatch on size {size}")
            all_passed = False
            break

        shake128_len = rng.randint(1, 300)
        if shake128_hex(payload, output_bytes=shake128_len) != hashlib.shake_128(payload).hexdigest(shake128_len):
            print(f"  [FAIL] SHAKE128 mismatch on size {size}, out_len {shake128_len}")
            all_passed = False
            break

        shake256_len = rng.randint(1, 300)
        if shake256_hex(payload, output_bytes=shake256_len) != hashlib.shake_256(payload).hexdigest(shake256_len):
            print(f"  [FAIL] SHAKE256 mismatch on size {size}, out_len {shake256_len}")
            all_passed = False
            break

    assert all_passed, "Bulk cross-verification against hashlib failed!"
    print(f"  [PASS] {test_count} random payloads (lengths 0..1500 bytes) matched hashlib across all 6 algorithms.")
    print("\n--> Bulk cross-verification PASSED!\n")


def main():
    print("#" * 72)
    print("# COMPREHENSIVE SHA-3 & SHAKE TEST SUITE (NIST FIPS PUB 202)")
    print("#" * 72)
    print()

    try:
        verify_nist_fips202_fixed_vectors()
        verify_nist_fips202_shake_vectors()
        verify_wikipedia_test_vectors()
        verify_sponge_padding_boundaries()
        verify_utf8_and_data_types()
        verify_component_units()
        verify_cross_hashlib_bulk()

        print("=" * 72)
        print("ALL SHA-3 & SHAKE SUITE VERIFICATIONS COMPLETED! [100% PASS]")
        print("=" * 72)
    except AssertionError as err:
        print(f"\n[FATAL ERROR] Test suite aborted: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

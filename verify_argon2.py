"""Verify RFC 9106 Argon2 Test Vectors (Argon2d, Argon2i, Argon2id).

Uses standardized snake_case parameter and variable names:
  password, salt, parallelism, tag_length, memory_size_kb, iterations,
  version, key, associated_data, hash_type.

Run: python verify_argon2.py
Source: https://www.rfc-editor.org/info/rfc9106/
"""

import sys
from argon2_demo import (
    ARGON2_D,
    ARGON2_I,
    ARGON2_ID,
    ARGON2_VERSION_13,
    argon2,
    argon2d,
    argon2i,
    argon2id,
    vl_hash,
    to_le32,
    to_le64,
)

def format_rfc_hex(hex_str: str, bytes_per_line: int = 8, indent: str = "    ") -> str:
    """Formats a continuous hex string into RFC 9106 style lines."""
    bytes_list = [hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]
    lines = []
    for i in range(0, len(bytes_list), bytes_per_line):
        lines.append(indent + " ".join(bytes_list[i:i + bytes_per_line]))
    return "\n".join(lines)


def run_verification():
    # Common test parameters from RFC 9106 Section 5 using snake_case names
    password = b'\x01' * 32
    salt = b'\x02' * 16
    key = b'\x03' * 8
    associated_data = b'\x04' * 12
    parallelism = 4
    tag_length = 32
    memory_size_kb = 32
    iterations = 3

    test_cases = [
        {
            "name": "Argon2d",
            "hash_type": ARGON2_D,
            "section": "5.1",
            "expected_tag": (
                "51 2b 39 1b 6f 11 62 97\n"
                "53 71 d3 09 19 73 42 94\n"
                "f8 68 e3 be 39 84 f3 c1\n"
                "a1 3a 4d b9 fa be 4a cb"
            ),
        },
        {
            "name": "Argon2i",
            "hash_type": ARGON2_I,
            "section": "5.2",
            "expected_tag": (
                "c8 14 d9 d1 dc 7f 37 aa\n"
                "13 f0 d7 7f 24 94 bd a1\n"
                "c8 de 6b 01 6d d3 88 d2\n"
                "99 52 a4 c4 67 2b 6c e8"
            ),
        },
        {
            "name": "Argon2id",
            "hash_type": ARGON2_ID,
            "section": "5.3",
            "expected_tag": (
                "0d 64 0d f5 8d 78 76 6c\n"
                "08 c0 37 a3 4a 8b 53 c9\n"
                "d0 1e f0 45 2d 75 b6 5e\n"
                "b5 25 20 e9 6b 01 e6 59"
            ),
        },
    ]

    all_passed = True
    for tc in test_cases:
        print("=" * 64)
        print(f"Testing {tc['name']} (RFC 9106 Section {tc['section']})")
        print("=" * 64)

        actual_tag = argon2(
            password=password,
            salt=salt,
            parallelism=parallelism,
            tag_length=tag_length,
            memory_size_kb=memory_size_kb,
            iterations=iterations,
            version=ARGON2_VERSION_13,
            key=key,
            associated_data=associated_data,
            hash_type=tc["hash_type"],
            verbose=True,
        )

        expected_tag_clean = tc["expected_tag"].replace(" ", "").replace("\n", "")
        actual_tag_hex = actual_tag.hex()

        print("\nActual Tag:\n" + format_rfc_hex(actual_tag_hex))
        print("Expected Tag:\n" + tc["expected_tag"])

        if actual_tag_hex == expected_tag_clean:
            print(f"PASS: {tc['name']} tag matches RFC 9106 test vector perfectly!\n")
        else:
            print(f"FAIL: {tc['name']} tag mismatch!\n")
            all_passed = False

    if all_passed:
        print("=" * 64)
        print("SUMMARY: All 3 variants (Argon2d, Argon2i, Argon2id) PASSED!")
        print("=" * 64)
    else:
        sys.exit(1)


def verify_input_validation():
    """Tests that invalid input parameters are rejected per RFC 9106 Section 3.1."""
    print("\n" + "=" * 64)
    print("TESTING INPUT VALIDATION (RFC 9106 Section 3.1)")
    print("=" * 64)

    valid_kwargs = {
        "password": b"password",
        "salt": b"somesalt12345678",
        "parallelism": 2,
        "tag_length": 32,
        "memory_size_kb": 64,  # >= 8 * 2 = 16
        "iterations": 1,
        "version": ARGON2_VERSION_13,
        "key": b"",
        "associated_data": b"",
        "hash_type": ARGON2_ID,
    }

    test_cases = [
        ("Password not bytes", {**valid_kwargs, "password": "not bytes"}, TypeError),
        ("Salt not bytes", {**valid_kwargs, "salt": 12345}, TypeError),
        ("Parallelism zero", {**valid_kwargs, "parallelism": 0}, ValueError),
        ("Parallelism too large (> 2^24-1)", {**valid_kwargs, "parallelism": 2**24}, ValueError),
        ("Tag length too short (< 4)", {**valid_kwargs, "tag_length": 3}, ValueError),
        ("Memory size too small (< 8*p)", {**valid_kwargs, "parallelism": 4, "memory_size_kb": 31}, ValueError),
        ("Iterations zero (< 1)", {**valid_kwargs, "iterations": 0}, ValueError),
        ("Invalid version (!= 0x13)", {**valid_kwargs, "version": 0x10}, ValueError),
        ("Invalid hash type", {**valid_kwargs, "hash_type": 5}, ValueError),
        ("Secret key not bytes", {**valid_kwargs, "key": "string_key"}, TypeError),
        ("Associated data not bytes", {**valid_kwargs, "associated_data": 42}, TypeError),
    ]

    for label, kwargs, expected_exc in test_cases:
        try:
            argon2(**kwargs)
            raise AssertionError(f"FAIL: {label} did not raise {expected_exc.__name__}")
        except expected_exc as e:
            print(f"PASS: {label} correctly rejected with {expected_exc.__name__}: {e}")

    print("=" * 64)
    print("ALL INPUT VALIDATION TESTS PASSED!")
    print("=" * 64)


def verify_api_consistency():
    """Verifies that all API interfaces use snake_case and strictly reject camelCase."""
    print("\n" + "=" * 64)
    print("TESTING SNAKE_CASE API & CAMELCASE REJECTION")
    print("=" * 64)

    # 1. Snake_case helpers check
    assert to_le32(1) == b'\x01\x00\x00\x00', "to_le32 failed"
    assert to_le64(1) == b'\x01\x00\x00\x00\x00\x00\x00\x00', "to_le64 failed"
    h_out = vl_hash(b"test_msg", digest_size=16)
    assert len(h_out) == 16, "vl_hash digest_size failed"
    print("PASS: Snake_case primitive helpers verified.")

    # 2. Strict rejection of camelCase parameter names
    pw = b"password"
    salt = b"salt_16_bytes_ok"

    camelcase_tests = [
        ("tagLength", {"tagLength": 16}),
        ("memorySizeKB", {"memorySizeKB": 32}),
        ("hashType", {"hashType": ARGON2_ID}),
        ("associatedData", {"associatedData": b""}),
    ]

    for param_name, bad_kwarg in camelcase_tests:
        try:
            argon2(pw, salt, **bad_kwarg)
            raise AssertionError(f"FAIL: camelCase '{param_name}' was unexpectedly accepted!")
        except TypeError as e:
            print(f"PASS: camelCase '{param_name}' rejected with TypeError: {e}")

    # Also test vl_hash rejecting digestSize
    try:
        vl_hash(b"test", digestSize=16)  # type: ignore
        raise AssertionError("FAIL: camelCase 'digestSize' was unexpectedly accepted in vl_hash!")
    except TypeError as e:
        print(f"PASS: camelCase 'digestSize' in vl_hash rejected with TypeError: {e}")

    # 3. Convenience wrappers check
    pw = b"test_pass"
    salt = b"test_salt_123456"
    assert argon2d(pw, salt, memory_size_kb=32, iterations=1, parallelism=2) == argon2(pw, salt, memory_size_kb=32, iterations=1, parallelism=2, hash_type=ARGON2_D)
    assert argon2i(pw, salt, memory_size_kb=32, iterations=1, parallelism=2) == argon2(pw, salt, memory_size_kb=32, iterations=1, parallelism=2, hash_type=ARGON2_I)
    assert argon2id(pw, salt, memory_size_kb=32, iterations=1, parallelism=2) == argon2(pw, salt, memory_size_kb=32, iterations=1, parallelism=2, hash_type=ARGON2_ID)
    print("PASS: Convenience wrappers (argon2d, argon2i, argon2id) match argon2().")

    print("=" * 64)
    print("ALL API CONSISTENCY & SNAKE_CASE TESTS PASSED!")
    print("=" * 64)


if __name__ == "__main__":
    run_verification()
    verify_input_validation()
    verify_api_consistency()

"""Compare the RSA-PSS demo with cryptography, using plain functions.
Run: venv/bin/python verify_rsa_pss.py
Both sides use SHA-256, MGF1-SHA-256 and exactly 32 salt bytes.
"""

import random
import sys
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from rsa_pss_demo import rsa_pss_sign, rsa_pss_verify, pss_hash, generate_key, PUBLIC_EXPONENT, apply_mask, SALT_BYTES, validate_key

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_BYTES)


def check_equal(actual: object, expected: object, case: str) -> None:
    if actual != expected:
        raise AssertionError(f"{case}: expected {expected!r}, got {actual!r}")


def check_both_directions(message: bytes, private_key: rsa.RSAPrivateKey, case: str) -> None:
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    ours = rsa_pss_sign(message, numbers.n, private_key.private_numbers().d)
    check_equal(len(ours), (numbers.n.bit_length() + 7) // 8, case + " signature length")
    # Random salts differ, so compare verification outcomes, not signature bytes.
    public_key.verify(ours, message, PSS, hashes.SHA256())
    theirs = private_key.sign(message, PSS, hashes.SHA256())
    check_equal(rsa_pss_verify(message, theirs, numbers.n, numbers.e), True, case)
    check_equal(rsa_pss_verify(message, ours, numbers.n, numbers.e), True, case + " own signature")


def verify_messages(private_key: rsa.RSAPrivateKey) -> None:
    generator = random.Random(2024)  # Reproducible messages, fresh keys and salts.
    lengths = list(range(130)) + [255, 256, 257, 511, 512, 513, 4096]
    lengths += [generator.randrange(2049) for _ in range(50)]
    for index, length in enumerate(lengths):
        message = bytes(generator.getrandbits(8) for _ in range(length))
        check_both_directions(message, private_key, f"message {index}, length {length}")
    for message in (bytes(256), b"\xff" * 256, b"\x00Hello\x00", "密码学 🔐".encode("utf-8")):
        check_both_directions(message, private_key, "structured message")
    print(f"[PASS] {len(lengths) + 4} messages, both signing directions")


def verify_rejections(private_key: rsa.RSAPrivateKey) -> None:
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    message = b"Signature rejection checks"
    signature = private_key.sign(message, PSS, hashes.SHA256())

    def reject(candidate: bytes, data: bytes, case: str) -> None:
        check_equal(rsa_pss_verify(data, candidate, numbers.n, numbers.e), False, case)
        try:
            public_key.verify(candidate, data, PSS, hashes.SHA256())
        except InvalidSignature:
            return
        raise AssertionError(case + ": library accepted invalid signature")

    for index in range(len(signature)):
        altered = bytearray(signature)
        altered[index] ^= 1
        reject(bytes(altered), message, f"tampered byte {index}")
    for candidate in (b"", signature[:-1], signature + b"\x00",
                      bytes(len(signature)), numbers.n.to_bytes(len(signature), "big")):
        reject(candidate, message, "invalid signature length or value")
    reject(signature, message + b"!", "changed message")
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    reject(wrong_key.sign(message, PSS, hashes.SHA256()), message, "wrong key")
    for salt_length in (0, 20):
        other_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length)
        reject(private_key.sign(message, other_padding, hashes.SHA256()), message, "wrong salt length")
    print("[PASS] Tampering, wrong message/key/parameters, malformed signatures")


def verify_helpers() -> None:
    # Check the small hashing/masking helpers independently with library SHA-256.
    def digest(data: bytes) -> bytes:
        context = hashes.Hash(hashes.SHA256())
        context.update(data)
        return context.finalize()

    message, salt = b"helper example", bytes(range(32))
    check_equal(pss_hash(message, salt), digest(bytes(8) + digest(message) + salt), "PSS hash")
    for length in (0, 1, 31, 32, 33, 64, 223):
        source = b"MGF1 example"
        mask = b"".join(digest(source + counter.to_bytes(4, "big"))
                        for counter in range((length + 31) // 32))[:length]
        data = bytes(index % 256 for index in range(length))
        check_equal(apply_mask(data, source), bytearray(a ^ b for a, b in zip(data, mask)),
                    f"mask length {length}")
    print("[PASS] Hash and mask helpers")


def expect_value_error(operation: Callable[[], object]) -> None:
    try:
        operation()
    except ValueError:
        return
    raise AssertionError("Expected ValueError")


def verify_key_validation(private_key: rsa.RSAPrivateKey) -> None:
    numbers = private_key.private_numbers()
    modulus = numbers.public_numbers.n
    check_equal(validate_key(modulus, numbers.public_numbers.e), None, "valid public key")
    check_equal(validate_key(modulus, numbers.d), None, "valid private key")
    invalid_values = [(0, 3), (1, 3), (-3, 3), (modulus - 1, 3)]
    invalid_values += [(modulus, exponent) for exponent in (-3, 0, 1, 2, modulus, modulus + 2)]
    invalid_types = [(True, 3), (str(modulus), 3), (3.0, 3),
                     (modulus, True), (modulus, "3"), (modulus, 3.0)]
    for cases, error_type in ((invalid_values, ValueError), (invalid_types, TypeError)):
        for candidate_modulus, candidate_exponent in cases:
            # Exercise the public entry points, not just the validator.
            for operation in (
                    lambda: validate_key(candidate_modulus, candidate_exponent),
                    lambda: rsa_pss_sign(b"", candidate_modulus, candidate_exponent),
                    lambda: rsa_pss_verify(b"", b"", candidate_modulus, candidate_exponent)):
                try:
                    operation()
                except error_type:
                    continue
                raise AssertionError(f"Expected {error_type.__name__} for invalid PSS key")
    print("[PASS] PSS key component types, parity and ranges")


def verify_key_edges() -> None:
    # A 2049-bit modulus makes the encoded message one byte shorter than
    # the signature: exercise the RFC's modBits-1 rule explicitly.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2049)
    check_both_directions(b"uneven modulus width", key, "2049-bit key")
    modulus, private_exponent = generate_key()
    signature = rsa_pss_sign(b"demo key", modulus, private_exponent)
    rsa.RSAPublicNumbers(PUBLIC_EXPONENT, modulus).public_key().verify(
        signature, b"demo key", PSS, hashes.SHA256())
    expect_value_error(lambda: rsa_pss_sign(b"", 1, 3))
    expect_value_error(lambda: rsa_pss_sign(b"", 3233, 2753))
    expect_value_error(lambda: rsa_pss_verify(b"", b"", modulus, 1))
    print("[PASS] Generated key, 2049-bit key, invalid key arguments")


def main() -> None:
    verify_helpers()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verify_key_validation(private_key)
    verify_messages(private_key)
    verify_rejections(private_key)
    verify_key_edges()
    print("[PASS] All RSA-PSS checks completed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.exit(f"[FAIL] {type(error).__name__}: {error}")

"""Verify RSA-2048/OAEP against cryptography. Run: python verify_rsa_oaep.py"""

import random
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from rsa_oaep_demo import PUBLIC_EXPONENT, generate_key, rsa_decrypt, rsa_encrypt, validate_key

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"")
MAX_MESSAGE_BYTES = 190  # 256-byte modulus minus two SHA-256 digests and two marker bytes.


def check_both_directions(message: bytes, private_key: rsa.RSAPrivateKey,
                          private_exponent: int, case: str) -> None:
    public_key = private_key.public_key()
    modulus = public_key.public_numbers().n
    # Each implementation draws its own OAEP seed; compare recovered messages.
    ours = rsa_encrypt(message, modulus, PUBLIC_EXPONENT)
    if len(ours) != 256 or private_key.decrypt(ours, OAEP) != message:
        raise AssertionError(f"{case}: library failed to recover our message")
    theirs = public_key.encrypt(message, OAEP)
    if rsa_decrypt(theirs, modulus, private_exponent) != message:
        raise AssertionError(f"{case}: demo failed to recover the library's message")


def verify_random_messages(private_key: rsa.RSAPrivateKey, private_exponent: int) -> None:
    generator = random.Random(2024)  # Reproduce messages; keys and seeds stay fresh.
    lengths = list(range(MAX_MESSAGE_BYTES + 1))
    lengths += [generator.randrange(MAX_MESSAGE_BYTES + 1) for _ in range(50)]
    for case, length in enumerate(lengths):
        message = bytes(generator.getrandbits(8) for _ in range(length))
        check_both_directions(message, private_key, private_exponent, f"case {case}, length {length}")


def verify_structured_messages(private_key: rsa.RSAPrivateKey, private_exponent: int) -> None:
    for message in (b"\x00Hello, RSA!", bytes(MAX_MESSAGE_BYTES),
                    b"\xff" * MAX_MESSAGE_BYTES, "密码学 🔐".encode("utf-8")):
        check_both_directions(message, private_key, private_exponent, f"prefix {message[:8]!r}")


def verify_generated_key() -> None:
    modulus, private_exponent = generate_key()
    if modulus.bit_length() != 2048:
        raise AssertionError("Expected a 2048-bit modulus")
    public_key = rsa.RSAPublicNumbers(PUBLIC_EXPONENT, modulus).public_key()
    message = b"Use the demo's own key"
    if rsa_decrypt(public_key.encrypt(message, OAEP), modulus, private_exponent) != message:
        raise AssertionError("Generated key failed to decrypt the library's ciphertext")


def expect_value_error(operation: Callable[[], bytes], case: str) -> None:
    try:
        operation()
    except ValueError:
        return
    raise AssertionError(f"{case}: expected ValueError")


def verify_invalid_inputs(modulus: int, private_exponent: int) -> None:
    expect_value_error(lambda: rsa_encrypt(bytes(MAX_MESSAGE_BYTES + 1), modulus, PUBLIC_EXPONENT),
                       "oversized message")
    for ciphertext in (bytes(255), bytes(257), modulus.to_bytes(256, "big"), bytes(256)):
        expect_value_error(lambda: rsa_decrypt(ciphertext, modulus, private_exponent),
                           f"invalid ciphertext: length {len(ciphertext)}, prefix {ciphertext[:2]!r}")


def verify_labels(private_key: rsa.RSAPrivateKey) -> None:
    numbers = private_key.private_numbers()
    modulus = numbers.public_numbers.n
    for label in (b"", b"application context", b"\x00\xff\x00", bytes(range(256))):
        scheme = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                              algorithm=hashes.SHA256(), label=label)
        for message in (b"", b"\x00label test", bytes(MAX_MESSAGE_BYTES)):
            ours = rsa_encrypt(message, modulus, PUBLIC_EXPONENT, label=label)
            if private_key.decrypt(ours, scheme) != message:
                raise AssertionError("Library failed to decrypt with matching label")
            theirs = private_key.public_key().encrypt(message, scheme)
            if rsa_decrypt(theirs, modulus, numbers.d, label=label) != message:
                raise AssertionError("Demo failed to decrypt with matching label")
            expect_value_error(lambda: rsa_decrypt(theirs, modulus, numbers.d, label=label + b"!"),
                               "mismatched label")
        # An omitted label is equivalent to an explicitly empty one.
        if not label and rsa_decrypt(theirs, modulus, numbers.d) != message:
            raise AssertionError("Default label differs from empty label")
    for label in (None, "context", bytearray(b"context"), 123):
        for operation in (lambda: rsa_encrypt(b"", modulus, PUBLIC_EXPONENT, label=label),
                          lambda: rsa_decrypt(bytes(256), modulus, numbers.d, label=label)):
            try:
                operation()
            except TypeError:
                continue
            raise AssertionError("Expected TypeError for non-bytes label")
    print("[PASS] OAEP label interoperability, mismatches, default and invalid types")


def verify_key_validation(private_key: rsa.RSAPrivateKey) -> None:
    numbers = private_key.private_numbers()
    modulus = numbers.public_numbers.n
    for exponent in (numbers.public_numbers.e, numbers.d):
        if validate_key(modulus, exponent) is not None:
            raise AssertionError("validate_key must return None")
    invalid_values = [(0, 3), (1, 3), (-3, 3), (modulus - 1, 3), (3233, 17)]
    invalid_values += [(modulus, exponent) for exponent in (-3, 0, 1, 2, modulus, modulus + 2)]
    invalid_types = [(True, 3), (str(modulus), 3), (3.0, 3),
                     (modulus, True), (modulus, "3"), (modulus, 3.0)]
    for cases, error_type in ((invalid_values, ValueError), (invalid_types, TypeError)):
        for candidate_modulus, candidate_exponent in cases:
            for operation in (
                    lambda: validate_key(candidate_modulus, candidate_exponent),
                    lambda: rsa_encrypt(b"", candidate_modulus, candidate_exponent),
                    lambda: rsa_decrypt(bytes(256), candidate_modulus, candidate_exponent)):
                try:
                    operation()
                except error_type:
                    continue
                raise AssertionError(f"Expected {error_type.__name__} for invalid OAEP key")
    print("[PASS] OAEP key component types, parity, ranges and minimum size")


def main() -> None:
    private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=2048)
    private_exponent = private_key.private_numbers().d
    verify_key_validation(private_key)
    verify_labels(private_key)
    verify_random_messages(private_key, private_exponent)
    verify_structured_messages(private_key, private_exponent)
    verify_generated_key()
    verify_invalid_inputs(private_key.public_key().public_numbers().n, private_exponent)
    print("[PASS] RSA-OAEP: random messages, structured messages, generated key, and invalid inputs")


if __name__ == "__main__":
    main()

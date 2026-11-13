"""Verify RSA-2048/OAEP against cryptography. Run: python verify_rsa_oaep.py"""

import random
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from rsa_textbook_demo import PUBLIC_EXPONENT, generate_key, rsa_decrypt, rsa_encrypt

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


def main() -> None:
    private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=2048)
    private_exponent = private_key.private_numbers().d
    verify_random_messages(private_key, private_exponent)
    verify_structured_messages(private_key, private_exponent)
    verify_generated_key()
    verify_invalid_inputs(private_key.public_key().public_numbers().n, private_exponent)
    print("[PASS] RSA-OAEP: random messages, structured messages, generated key, and invalid inputs")


if __name__ == "__main__":
    main()

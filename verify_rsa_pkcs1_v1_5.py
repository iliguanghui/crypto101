"""Verify both PKCS#1 v1.5 demos with plain functions and cryptography.

Run: venv/bin/python verify_rsa_pkcs1_v1_5.py
Only this verification script needs the third-party cryptography library.
Reference: https://www.rfc-editor.org/rfc/rfc8017.html (sections 7.2 and 8.2).
"""

import random
import sys
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import rsa_pkcs1_v1_5_encryption_demo as encryption
import rsa_pkcs1_v1_5_signature_demo as signature
from rsa_oaep_demo import PUBLIC_EXPONENT


def check_equal(actual: object, expected: object, case: str) -> None:
    if actual != expected:
        raise AssertionError(f"{case}: expected {expected!r}, got {actual!r}")


def expect_error(operation: Callable[[], object], error_type: type,
                 case: str, message: str = "") -> None:
    try:
        operation()
    except error_type as error:
        if message:
            check_equal(str(error), message, case)
        return
    raise AssertionError(case + f": expected {error_type.__name__}")


def check_encryption(message: bytes, private_key: rsa.RSAPrivateKey) -> None:
    numbers = private_key.private_numbers()
    modulus, exponent = numbers.public_numbers.n, numbers.public_numbers.e
    width = (modulus.bit_length() + 7) // 8
    ours = encryption.rsa_encrypt(message, modulus, exponent)
    check_equal(len(ours), width, "ciphertext width")
    # Encryption uses random padding: ciphertext bytes need not match.
    check_equal(private_key.decrypt(ours, padding.PKCS1v15()), message, "library decrypt")
    theirs = private_key.public_key().encrypt(message, padding.PKCS1v15())
    check_equal(encryption.rsa_decrypt(theirs, modulus, numbers.d), message, "demo decrypt")
    check_equal(encryption.rsa_decrypt(ours, modulus, numbers.d), message, "round trip")
    encoded = pow(int.from_bytes(ours, "big"), numbers.d, modulus).to_bytes(width, "big")
    delimiter = width - len(message) - 1
    check_equal(encoded[:2], b"\x00\x02", "encryption markers")
    check_equal(encoded[delimiter:], b"\x00" + message, "delimiter and message")
    check_equal(len(encoded[2:delimiter]) >= 8, True, "minimum padding")
    check_equal(all(encoded[2:delimiter]), True, "nonzero padding")


def check_signature(message: bytes, private_key: rsa.RSAPrivateKey) -> None:
    numbers = private_key.private_numbers()
    modulus, exponent = numbers.public_numbers.n, numbers.public_numbers.e
    ours = signature.rsa_sign(message, modulus, numbers.d)
    theirs = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    # Unlike PSS, this signature scheme is deterministic; compare exact bytes.
    check_equal(ours, theirs, "exact library signature")
    check_equal(len(ours), (modulus.bit_length() + 7) // 8, "signature width")
    private_key.public_key().verify(ours, message, padding.PKCS1v15(), hashes.SHA256())
    check_equal(signature.rsa_verify(message, theirs, modulus, exponent), True, "demo verify")


def verify_messages(encryption_key: rsa.RSAPrivateKey,
                    signing_key: rsa.RSAPrivateKey) -> None:
    generator = random.Random(2024)  # Repeatable messages, independently generated keys.
    maximum = (encryption_key.key_size + 7) // 8 - 11
    lengths = list(range(maximum + 1)) + [generator.randrange(maximum + 1) for _ in range(50)]
    for length in lengths:
        message = bytes(generator.getrandbits(8) for _ in range(length))
        check_encryption(message, encryption_key)
        check_signature(message, signing_key)
    for message in (bytes(maximum), b"\xff" * maximum, b"\x00Hello\x00", "密码学 🔐".encode()):
        check_encryption(message, encryption_key)
        check_signature(message, signing_key)
    for length in (256, 511, 512, 513, 4096):
        check_signature(bytes(generator.getrandbits(8) for _ in range(length)), signing_key)
    numbers = encryption_key.public_key().public_numbers()
    expect_error(lambda: encryption.rsa_encrypt(bytes(maximum + 1), numbers.n, numbers.e),
                 ValueError, "oversize plaintext")
    print(f"[PASS] {len(lengths) + 4} messages for both schemes; 5 longer signed messages")


def verify_encryption_rejections(private_key: rsa.RSAPrivateKey) -> None:
    numbers = private_key.private_numbers()
    modulus, exponent = numbers.public_numbers.n, numbers.public_numbers.e
    width = (modulus.bit_length() + 7) // 8
    # Construct specific invalid encodings, then apply RSAEP. Arbitrary ciphertext
    # mutations are unsuitable: encryption alone does not authenticate messages.
    malformed = [b"\x00\x01" + b"\xff" * (width - 3) + b"\x00",
                 b"\x01\x02" + b"\xff" * (width - 3) + b"\x00",
                 b"\x00\x02" + b"\xff" * (width - 2)]
    for padding_length in range(8):
        malformed.append(b"\x00\x02" + b"\xff" * padding_length + b"\x00"
                         + b"M" * (width - padding_length - 3))
    candidates = [b"", bytes(width - 1), bytes(width + 1), bytes(width),
                  modulus.to_bytes(width, "big"), b"\xff" * width]
    candidates += [pow(int.from_bytes(encoded, "big"), exponent, modulus).to_bytes(width, "big")
                   for encoded in malformed]
    for candidate in candidates:
        expect_error(lambda: encryption.rsa_decrypt(candidate, modulus, numbers.d),
                     ValueError, "invalid ciphertext", "Decryption error")
    # Some library backends use implicit rejection (returning synthetic plaintext)
    # for bad v1.5 padding, so their exception behavior is not our oracle here.
    print("[PASS] Encryption length, range, marker, delimiter and short-padding rejection")


def verify_signature_rejections(private_key: rsa.RSAPrivateKey) -> None:
    numbers = private_key.private_numbers()
    modulus, exponent = numbers.public_numbers.n, numbers.public_numbers.e
    width = (modulus.bit_length() + 7) // 8
    message = b"Check the entire signature encoding"
    valid = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def reject(candidate: bytes, data: bytes = message) -> None:
        check_equal(signature.rsa_verify(data, candidate, modulus, exponent), False, "reject signature")
        expect_error(lambda: private_key.public_key().verify(
            candidate, data, padding.PKCS1v15(), hashes.SHA256()), InvalidSignature, "library rejects")

    for candidate in (b"", valid[:-1], valid + b"\x00", bytes(width),
                      modulus.to_bytes(width, "big"), b"\xff" * width):
        reject(candidate)
    reject(valid, message + b"!")
    other_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=2048)
    reject(other_key.sign(message, padding.PKCS1v15(), hashes.SHA256()))
    reject(private_key.sign(message, padding.PKCS1v15(), hashes.SHA384()))
    # Corrupt every encoded byte, including FF padding, DER and digest, and
    # use our test private key to make signatures recovering those exact blocks.
    encoded = signature.encode_message(message, width)
    for index in range(width):
        altered = bytearray(encoded)
        altered[index] ^= 1
        reject(pow(int.from_bytes(altered, "big"), numbers.d, modulus).to_bytes(width, "big"))
    print("[PASS] Every encoding byte, wrong message/key/hash, signature length and range")


def verify_helpers(private_key: rsa.RSAPrivateKey) -> None:
    # Fixed, independently specified SHA-256('abc') and DER encoding.
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420"
                                "ba7816bf8f01cfea414140de5dae2223"
                                "b00361a396177a9cb410ff61f20015ad")
    for width in (62, 63, 128, 256, 257):
        expected = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
        check_equal(signature.encode_message(b"abc", width), expected, "known encoding")
    for width in (-1, 0, 61):
        expect_error(lambda: signature.encode_message(b"", width), ValueError, "short encoding")
    for width in (True, 62.0, "62"):
        expect_error(lambda: signature.encode_message(b"", width), TypeError, "width type")
    numbers = private_key.private_numbers()
    modulus, exponent = numbers.public_numbers.n, numbers.public_numbers.e
    for module in (encryption, signature):
        check_equal(module.validate_key(modulus, exponent), None, "validation returns None")
        for bad_modulus, bad_exponent in ((1, 3), (0, 3), (-3, 3), (modulus - 1, 3),
                                          (modulus, 1), (modulus, 2), (modulus, modulus)):
            expect_error(lambda: module.validate_key(bad_modulus, bad_exponent), ValueError, "invalid key")
        for bad_modulus, bad_exponent in ((True, 3), (modulus, True), ("123", 3), (modulus, 3.0)):
            expect_error(lambda: module.validate_key(bad_modulus, bad_exponent), TypeError, "key type")
    for data in ("abc", bytearray(b"abc"), None, 123):
        for operation in (lambda: encryption.rsa_encrypt(data, modulus, exponent),
                          lambda: encryption.rsa_decrypt(data, modulus, numbers.d),
                          lambda: signature.encode_message(data, 256),
                          lambda: signature.rsa_sign(data, modulus, numbers.d),
                          lambda: signature.rsa_verify(data, bytes(256), modulus, exponent),
                          lambda: signature.rsa_verify(b"abc", data, modulus, exponent)):
            expect_error(operation, TypeError, "input type")
    expect_error(lambda: encryption.validate_key(3233, 17), ValueError, "tiny encryption modulus")
    expect_error(lambda: signature.rsa_sign(b"", 3233, 2753), ValueError, "tiny signing modulus")
    check_equal(signature.rsa_verify(b"", bytes(2), 3233, 17), False, "tiny verification modulus")
    print("[PASS] Known encoding, minimum size, input types and key validation")


def main() -> None:
    encryption_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=2048)
    signing_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=2048)
    verify_helpers(signing_key)
    verify_messages(encryption_key, signing_key)
    verify_encryption_rejections(encryption_key)
    verify_signature_rejections(signing_key)
    # Non-byte-aligned modulus sizes exercise ceiling division in both schemes.
    for size in (1024, 2049):
        check_encryption(b"key size edge", rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=size))
        check_signature(b"key size edge", rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=size))
    print("[PASS] 1024-bit and 2049-bit key interoperability")
    print("[PASS] All RSA-PKCS1-v1_5 checks completed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.exit(f"[FAIL] {type(error).__name__}: {error}")

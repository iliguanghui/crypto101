"""Educational RSASSA-PSS: SHA-256, MGF1-SHA-256, and a 32-byte salt.
RFC 8017 sections 8.1, 9.1, and B.2.1: https://www.rfc-editor.org/rfc/rfc8017.html
Run: python3 rsa_pss_demo.py

Uses standard-library SHA-256 and the repository's RSA key generator and MGF1.
Python's private exponentiation is not constant-time.
"""
from hashlib import sha256
from hmac import compare_digest
from secrets import token_bytes

from rsa_oaep_demo import PUBLIC_EXPONENT, generate_key, mgf1

HASH_BYTES = sha256().digest_size
SALT_BYTES = HASH_BYTES
TRAILER = b"\xbc"


def validate_key(modulus: int, exponent: int) -> None:
    """Check component ranges, not full RSA key validity or PSS encoding size."""
    # Full validation needs the prime factors; encoding size is checked below
    # using PSS's modBits - 1 rule rather than OAEP's modulus-byte rule.
    if type(modulus) is not int or type(exponent) is not int:
        raise TypeError("RSA modulus and exponent must be integers")
    if modulus <= 1 or modulus % 2 == 0:
        raise ValueError("RSA modulus must be odd and greater than one")
    if not 1 < exponent < modulus or exponent % 2 == 0:
        raise ValueError("RSA exponent must be odd and satisfy 1 < exponent < modulus")


def apply_mask(data: bytes, source: bytes) -> bytearray:
    mask = mgf1(source, len(data))
    return bytearray(v ^ m for v, m in zip(data, mask))


def pss_hash(message: bytes, salt: bytes) -> bytes:
    # The eight zero bytes are part of the RFC format, even for an empty message.
    return sha256(bytes(8) + sha256(message).digest() + salt).digest()


def rsa_pss_sign(message: bytes, modulus: int, private_exponent: int,
                 verbose: bool = False) -> bytes:
    """Encode the message with a fresh salt, then apply the private exponent."""
    validate_key(modulus, private_exponent)
    # Use one fewer bit than the modulus so the encoded integer is always < n.
    encoded_bits = modulus.bit_length() - 1
    width = (encoded_bits + 7) // 8
    padding_length = width - HASH_BYTES - SALT_BYTES - 2
    if padding_length < 0:
        raise ValueError("Modulus too short for SHA-256 and a 32-byte salt")
    salt = token_bytes(SALT_BYTES)
    digest = pss_hash(message, salt)
    data = bytes(padding_length) + b"\x01" + salt
    masked = apply_mask(data, digest)
    masked[0] &= 0xff >> (8 * width - encoded_bits)
    encoded = bytes(masked) + digest + TRAILER
    if verbose:
        print("Salt:", salt.hex())
        print("PSS hash:", digest.hex())
        print("Encoded message (masked data || hash || bc):", encoded.hex())
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, modulus)
    return signature.to_bytes((modulus.bit_length() + 7) // 8, "big")


def rsa_pss_verify(message: bytes, signature: bytes, modulus: int, public_exponent: int) -> bool:
    """Recover the encoding with the public key and check it against the message."""
    validate_key(modulus, public_exponent)
    encoded_bits = modulus.bit_length() - 1
    width = (encoded_bits + 7) // 8
    padding_length = width - HASH_BYTES - SALT_BYTES - 2
    if padding_length < 0 or len(signature) != (modulus.bit_length() + 7) // 8:
        return False
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        return False
    recovered = pow(value, public_exponent, modulus)
    # This also rejects any nonzero unused high bits before unmasking.
    if recovered.bit_length() > encoded_bits:
        return False
    encoded = recovered.to_bytes(width, "big")
    if encoded[-1:] != TRAILER:
        return False
    digest = encoded[-HASH_BYTES - 1:-1]
    data = apply_mask(encoded[:-HASH_BYTES - 1], digest)
    # Signing discarded the high mask bits; discard them again after XOR.
    data[0] &= 0xff >> (8 * width - encoded_bits)
    if not compare_digest(data[:padding_length + 1], bytes(padding_length) + b"\x01"):
        return False
    salt = bytes(data[-SALT_BYTES:]) if SALT_BYTES else b""
    return compare_digest(pss_hash(message, salt), digest)


def main() -> None:
    modulus, private_exponent = generate_key()
    message = b"Hello, RSA-PSS!"
    signature = rsa_pss_sign(message, modulus, private_exponent, verbose=True)
    print("Signature:", signature.hex())
    print("Original message verifies:", rsa_pss_verify(message, signature, modulus, PUBLIC_EXPONENT))
    print("Changed message verifies:", rsa_pss_verify(message + b"!", signature, modulus, PUBLIC_EXPONENT))


if __name__ == "__main__":
    main()

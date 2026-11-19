"""RSASSA-PKCS1-v1_5 with SHA-256, using only the Python standard library.

Reference: https://www.rfc-editor.org/rfc/rfc8017.html#section-8.2
Encoding: RFC 8017 section 9.2.
Run: python3 rsa_pkcs1_v1_5_signature_demo.py

This is the SIGNATURE scheme, distinct from RSAES-PKCS1-v1_5 encryption.
Signatures are deterministic: there is no salt or random padding.
Educational only: Python's private exponentiation is not constant-time.
"""

from hashlib import sha256
from hmac import compare_digest

from rsa_oaep_demo import PUBLIC_EXPONENT, generate_key

# DER DigestInfo prefix: identifies SHA-256 and a following 32-byte digest.
# It includes the hash algorithm identifier, NULL parameters, and the
# OCTET STRING header. Unlike PSS, this encoding carries a hash identifier.
DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
HASH_BYTES = sha256().digest_size
MIN_PADDING_BYTES = 8


def validate_key(modulus: int, exponent: int) -> None:
    """Check component ranges; cannot prove key validity without the factors."""
    if type(modulus) is not int or type(exponent) is not int:
        raise TypeError("RSA modulus and exponent must be integers")
    if modulus <= 1 or modulus % 2 == 0:
        raise ValueError("RSA modulus must be odd and greater than one")
    if not 1 < exponent < modulus or exponent % 2 == 0:
        raise ValueError("RSA exponent must be odd and satisfy 1 < exponent < modulus")


def encode_message(message: bytes, width: int, verbose: bool = False) -> bytes:
    """EMSA-PKCS1-v1_5: produce exactly width bytes for the RSA operation."""
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    if type(width) is not int:
        raise TypeError("Encoding width must be an integer")
    digest = sha256(message).digest()
    digest_info = DIGEST_INFO_PREFIX + digest
    padding_length = width - len(digest_info) - 3
    if padding_length < MIN_PADDING_BYTES:
        raise ValueError("RSA modulus too short for SHA-256 signature encoding")
    # 00 keeps the integer below n. 01 denotes signature encoding.
    # PS is all FF, unlike encryption's random nonzero padding after 00 02.
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    if verbose:
        print("Message hash:", digest.hex())
        print("DigestInfo (DER):", digest_info.hex())
        print("FF padding length:", padding_length)
        print("Encoded message (00 || 01 || PS || 00 || DigestInfo):", encoded.hex())
    return encoded


def rsa_sign(message: bytes, modulus: int, private_exponent: int,
             verbose: bool = False) -> bytes:
    """RSASP1: raise the encoded message integer to d modulo n."""
    validate_key(modulus, private_exponent)
    width = (modulus.bit_length() + 7) // 8
    encoded = encode_message(message, width, verbose)
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, modulus)
    # Fixed-width conversion preserves leading zero bytes in the signature.
    return signature.to_bytes(width, "big")


def rsa_verify(message: bytes, signature: bytes, modulus: int,
               public_exponent: int, verbose: bool = False) -> bool:
    """Return False for invalid signatures; raise for invalid API arguments."""
    validate_key(modulus, public_exponent)
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise TypeError("Message and signature must be bytes")
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width or width < len(DIGEST_INFO_PREFIX) + HASH_BYTES + 11:
        return False
    representative = int.from_bytes(signature, "big")
    if representative >= modulus:
        return False
    recovered = pow(representative, public_exponent, modulus).to_bytes(width, "big")
    expected = encode_message(message, width, verbose)
    if verbose:
        print("Recovered encoding:", recovered.hex())
    # Compare the ENTIRE encoding, including padding, DER identifier, and digest.
    # Searching for just the hash could accept malformed signatures.
    return compare_digest(recovered, expected)


def main() -> None:
    # Reuse the generator, not a key pair assigned to OAEP or PSS.
    modulus, private_exponent = generate_key()
    message = b"Hello, RSASSA-PKCS1-v1_5!"
    print("Public modulus:", hex(modulus))
    print("Public exponent:", PUBLIC_EXPONENT)
    print("Message:", message)
    signature = rsa_sign(message, modulus, private_exponent, verbose=True)
    print("Signature:", signature.hex())
    print("Original message verifies:",
          rsa_verify(message, signature, modulus, PUBLIC_EXPONENT, verbose=True))
    print("Changed message verifies:",
          rsa_verify(message + b"!", signature, modulus, PUBLIC_EXPONENT))


if __name__ == "__main__":
    main()

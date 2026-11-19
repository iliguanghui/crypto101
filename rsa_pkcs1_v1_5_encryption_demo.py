"""RSAES-PKCS1-v1_5 encryption teaching demo (not the signature scheme).

Reference: https://www.rfc-editor.org/rfc/rfc8017.html#section-7.2
Run: python3 rsa_pkcs1_v1_5_encryption_demo.py

Uses only Python's standard library and the existing RSA key generator.
RSA needs no AES block cipher. Encoding is 00 || 02 || PS || 00 || message,
where PS contains at least eight independently chosen nonzero random bytes.

Educational only: Python exponentiation and padding checks are not constant-
time. Uniform error text alone does not prevent padding-oracle attacks.
Verbose output exposes the encoded plaintext. Use only demonstration keys.
"""

from secrets import randbelow

from rsa_oaep_demo import PUBLIC_EXPONENT, generate_key


def validate_key(modulus: int, exponent: int) -> None:
    """Raise on invalid component ranges; this is not full RSA key validation."""
    if type(modulus) is not int or type(exponent) is not int:
        raise TypeError("RSA modulus and exponent must be integers")
    if modulus <= 1 or modulus % 2 == 0:
        raise ValueError("RSA modulus must be odd and greater than one")
    if not 1 < exponent < modulus or exponent % 2 == 0:
        raise ValueError("RSA exponent must be odd and satisfy 1 < exponent < modulus")
    width = (modulus.bit_length() + 7) // 8
    # Unlike the OAEP helper, this scheme requires only 11 encoding bytes.
    # This is a format minimum, not a secure RSA key size.
    if width < 11:
        raise ValueError("Modulus too short for PKCS1-v1_5 encoding")


def rsa_encrypt(message: bytes, modulus: int, public_exponent: int,
                verbose: bool = False) -> bytes:
    """Encode one message and apply RSAEP: c = m**e mod n."""
    validate_key(modulus, public_exponent)
    width = (modulus.bit_length() + 7) // 8
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    if len(message) > width - 11:
        raise ValueError("Message too long")
    # Three marker bytes plus at least eight padding bytes leave k-11 bytes
    # for the message: 245 bytes for RSA-2048. Empty messages are valid.
    padding_length = width - len(message) - 3
    padding = bytes(1 + randbelow(255) for _ in range(padding_length))
    encoded = b"\x00\x02" + padding + b"\x00" + message
    # Big-endian conversion is OS2IP. The initial 00 ensures m < n.
    representative = int.from_bytes(encoded, "big")
    if verbose:
        print("Random nonzero padding:", padding.hex())
        print("Encoded message (00 || 02 || PS || 00 || M):", encoded.hex())
        print("Message representative:", representative)
    ciphertext = pow(representative, public_exponent, modulus)
    # I2OSP preserves leading zeros and always returns exactly k bytes.
    return ciphertext.to_bytes(width, "big")


def rsa_decrypt(ciphertext: bytes, modulus: int, private_exponent: int,
                verbose: bool = False) -> bytes:
    """Apply RSADP and remove encoding; reject malformed ciphertexts uniformly."""
    validate_key(modulus, private_exponent)
    width = (modulus.bit_length() + 7) // 8
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    if len(ciphertext) != width:
        raise ValueError("Decryption error")
    representative = int.from_bytes(ciphertext, "big")
    if representative >= modulus:
        raise ValueError("Decryption error")
    encoded = pow(representative, private_exponent, modulus).to_bytes(width, "big")
    # The FIRST zero after 02 terminates PS: bytes before it must be nonzero.
    # Index >= 10 means PS has at least eight bytes; -1 means no delimiter.
    delimiter = encoded.find(b"\x00", 2)
    if encoded[:2] != b"\x00\x02" or delimiter < 10:
        raise ValueError("Decryption error")
    if verbose:
        print("Recovered encoding:", encoded.hex())
        print("Padding length:", delimiter - 2)
    # Zeros inside the original message are retained.
    return encoded[delimiter + 1:]


def main() -> None:
    # A fresh key pair dedicated to this scheme; do not share an OAEP/PSS key.
    modulus, private_exponent = generate_key()
    print("Public modulus:", hex(modulus))
    print("Public exponent:", PUBLIC_EXPONENT)
    message = b"Hello, RSA-PKCS1-v1.5!"
    print("Plaintext:", message)
    for attempt in (1, 2):
        print(f"Encryption {attempt} with fresh random padding:")
        ciphertext = rsa_encrypt(message, modulus, PUBLIC_EXPONENT, verbose=True)
        print("Ciphertext:", ciphertext.hex())
        recovered = rsa_decrypt(ciphertext, modulus, private_exponent, verbose=True)
        print("Recovered plaintext:", recovered)
        print("Round trip successful:", recovered == message)


if __name__ == "__main__":
    main()

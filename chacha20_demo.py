"""ChaCha20 teaching demo: python chacha20_demo.py"""

import secrets

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    raise SystemExit("Install dependencies: python -m pip install -r requirements.txt")


def chacha20(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt or decrypt one complete message, starting at counter zero."""
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("Expected a 32-byte key and an 8-byte nonce")
    # This API uses original ChaCha20: 64-bit counter + 64-bit nonce.
    # The IETF variant instead uses a 32-bit counter + 96-bit nonce.
    full_nonce = (0).to_bytes(8, "little") + nonce
    cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
    context = cipher.encryptor()  # XOR with the keystream works both ways.
    return context.update(data) + context.finalize()


def main():
    # Edit these lines to encrypt your own text.
    text = """Hello, ChaCha20!
This is the second line.
你好，这是第三行。"""
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(8)
    plaintext = text.encode("utf-8")

    # Process all lines together; do not restart the stream for each line.
    ciphertext = chacha20(plaintext, key, nonce)
    recovered = chacha20(ciphertext, key, nonce)

    # Encrypting zeros reveals the keystream, for demonstration only.
    keystream = chacha20(bytes(len(plaintext)), key, nonce)
    assert ciphertext == bytes(p ^ s for p, s in zip(plaintext, keystream))
    assert recovered == plaintext

    print("ChaCha20: 256-bit key, 20 rounds, 64-byte keystream blocks.")
    print("Demo key (hex):", key.hex())
    print("Nonce (hex):", nonce.hex())
    print("Initial block counter: 0")
    print("Keystream (hex):", keystream.hex())
    print("Ciphertext = plaintext XOR keystream (hex):", ciphertext.hex())
    print("Decrypted text:\n" + recovered.decode("utf-8"))
    print("No padding: plaintext and ciphertext are both", len(ciphertext), "bytes.")
    print("Teaching output only: keep real keys and keystreams secret.")
    print("Never reuse a key/nonce pair to encrypt different messages.")
    print("Raw ChaCha20 does not detect tampering; use ChaCha20-Poly1305 in applications.")


if __name__ == "__main__":
    main()

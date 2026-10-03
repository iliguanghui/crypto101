"""Simple RC4 teaching demo. Run with: python rc4_demo.py"""

import secrets


def rc4(data: bytes, key: bytes) -> bytes:
    """Encrypt or decrypt bytes using RC4 (educational use only)."""
    if not 1 <= len(key) <= 256:
        raise ValueError("RC4 keys must contain 1 to 256 bytes")

    # Key-scheduling algorithm: shuffle the 256-byte state using the key.
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]

    # Generate a keystream and XOR it with the input bytes.
    i = j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        stream_byte = state[(state[i] + state[j]) % 256]
        output.append(byte ^ stream_byte)
    return bytes(output)


def main():
    # Edit these lines to encrypt your own text.
    text = """Hello, RC4!
This is the second line.
你好，这是第三行。"""
    key = secrets.token_bytes(16)

    # Encrypt all lines together so the keystream continues across newlines.
    encrypted = rc4(text.encode("utf-8"), key)
    decrypted = rc4(encrypted, key).decode("utf-8")

    print("RC4 teaching demo: RC4 is insecure for real-world use.")
    print("Demo key (hex):", key.hex())
    print("Ciphertext (hex):", encrypted.hex())
    print("Decrypted text:\n" + decrypted)
    print("Decrypt Success? ", decrypted == text)


if __name__ == "__main__":
    main()

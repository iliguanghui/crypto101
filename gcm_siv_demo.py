"""AES-GCM-SIV teaching demo. Run: python3 gcm_siv_demo.py
References: https://www.rfc-editor.org/rfc/rfc8452.html
            https://en.wikipedia.org/wiki/AES-GCM-SIV

GCM encrypts first and hashes AAD and ciphertext with GHASH. GCM-SIV
hashes AAD and plaintext with POLYVAL first, then uses the tag to start CTR.
Encryption therefore needs two passes. Accidental nonce reuse in GCM can
repeat the keystream and compromise authentication. GCM-SIV tolerates reuse
better, but identical inputs under the same key and nonce reveal equality.
Use fresh nonces. Verbose traces expose secrets and are for learning only.
"""

from hmac import compare_digest
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ByteInput = Union[bytes, bytearray]
BLOCK_BYTES = TAG_BYTES = 16
NONCE_BYTES = 12
MAX_DATA_BYTES = 1 << 36  # Separate limits for plaintext and associated data.
FIELD_POLYNOMIAL = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1


def byte_input(value: ByteInput) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("Expected bytes or bytearray")
    return bytes(value)


def aes_block(key: bytes, block: bytes) -> bytes:
    """Use ECB only to obtain one AES block encryption; GCM handles chaining."""
    if len(block) != BLOCK_BYTES:
        raise ValueError("AES requires exactly 16 bytes")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def derive_keys(key: ByteInput, nonce: bytes, verbose: bool) -> Tuple[bytes, bytes]:
    key = byte_input(key)
    if len(key) not in (16, 32) or len(nonce) != NONCE_BYTES:
        raise ValueError("Expected a 16- or 32-byte key and a 12-byte nonce")
    material = bytearray()
    # Keep the first eight bytes from each AES output. Four outputs supply
    # AES-128; AES-256 needs two more for its longer encryption key.
    for counter in range((16 + len(key)) // 8):
        block = counter.to_bytes(4, "little") + nonce
        material.extend(aes_block(key, block)[:8])
    auth_key, encryption_key = bytes(material[:16]), bytes(material[16:])
    if verbose:
        print("Record authentication key:", auth_key.hex())
        print("Record encryption key:", encryption_key.hex())
    return auth_key, encryption_key


def polyval_dot(first: int, second: int) -> int:
    """POLYVAL's dot product is field multiplication followed by x**(-128)."""
    product = 0
    # Bit i represents x**i. From i=127 down to 0 we need second times
    # x**(-1), x**(-2), ..., x**(-128). Divide by x once per iteration.
    for bit in range(127, -1, -1):
        if second & 1:
            second ^= FIELD_POLYNOMIAL  # Cancel the constant term before division.
        second >>= 1
        if first & (1 << bit):
            product ^= second
    return product


def authentication_tag(auth_key: bytes, encryption_key: bytes, nonce: bytes,
                       aad: bytes, plaintext: bytes, verbose: bool) -> bytes:
    # Pad each field separately; record the two original BIT lengths.
    blocks = (aad + bytes(-len(aad) % BLOCK_BYTES)
              + plaintext + bytes(-len(plaintext) % BLOCK_BYTES)
              + (8 * len(aad)).to_bytes(8, "little")
              + (8 * len(plaintext)).to_bytes(8, "little"))
    accumulator = 0
    multiplier = int.from_bytes(auth_key, "little")
    for offset in range(0, len(blocks), BLOCK_BYTES):
        block = blocks[offset:offset + BLOCK_BYTES]
        accumulator = polyval_dot(accumulator ^ int.from_bytes(block, "little"), multiplier)
        if verbose:
            print(f"POLYVAL block {block.hex()} -> {accumulator.to_bytes(16, 'little').hex()}")

    tag_input = bytearray(accumulator.to_bytes(BLOCK_BYTES, "little"))
    for index, value in enumerate(nonce):
        tag_input[index] ^= value
    tag_input[-1] &= 0x7f  # Clear the bit that CTR sets on its starting block.
    tag = aes_block(encryption_key, bytes(tag_input))
    if verbose:
        print("Tag input:", tag_input.hex())
        print("Synthetic IV (tag):", tag.hex())
    return tag


def counter_transform(key: bytes, tag: bytes, data: bytes, verbose: bool) -> bytes:
    counter = bytearray(tag)
    counter[-1] |= 0x80
    output = bytearray()
    for offset in range(0, len(data), BLOCK_BYTES):
        stream = aes_block(key, bytes(counter))
        fragment = data[offset:offset + BLOCK_BYTES]
        output.extend(value ^ mask for value, mask in zip(fragment, stream))
        if verbose:
            print(f"CTR block {counter.hex()} -> keystream {stream.hex()}")
        # Use the starting counter first, then increment its FIRST four bytes.
        word = (int.from_bytes(counter[:4], "little") + 1) % (1 << 32)
        counter[:4] = word.to_bytes(4, "little")
    return bytes(output)


def gcm_siv_encrypt(key: ByteInput, nonce: ByteInput, plaintext: ByteInput,
                    associated_data: ByteInput = b"", verbose: bool = False) -> bytes:
    """Return ciphertext followed by the full 16-byte authentication tag."""
    nonce, plaintext, aad = map(byte_input, (nonce, plaintext, associated_data))
    if max(len(plaintext), len(aad)) > MAX_DATA_BYTES:
        raise ValueError("Plaintext or associated data too long")
    auth_key, encryption_key = derive_keys(key, nonce, verbose)
    tag = authentication_tag(auth_key, encryption_key, nonce, aad, plaintext, verbose)
    return counter_transform(encryption_key, tag, plaintext, verbose) + tag


def gcm_siv_decrypt(key: ByteInput, nonce: ByteInput, ciphertext_and_tag: ByteInput,
                    associated_data: ByteInput = b"") -> bytes:
    nonce, packet, aad = map(byte_input, (nonce, ciphertext_and_tag, associated_data))
    if not TAG_BYTES <= len(packet) <= MAX_DATA_BYTES + TAG_BYTES or len(aad) > MAX_DATA_BYTES:
        raise ValueError("Invalid packet or associated data length")
    auth_key, encryption_key = derive_keys(key, nonce, False)
    ciphertext, tag = packet[:-TAG_BYTES], packet[-TAG_BYTES:]
    # The tag depends on plaintext. Keep the candidate private until it verifies.
    plaintext = counter_transform(encryption_key, tag, ciphertext, False)
    expected = authentication_tag(auth_key, encryption_key, nonce, aad, plaintext, False)
    if not compare_digest(tag, expected):
        raise ValueError("AES-GCM-SIV authentication failed")
    return plaintext


def main() -> None:
    # RFC 8452, Appendix C.1: both AAD and plaintext end in partial blocks.
    key = bytes.fromhex("f901cfe8a69615a93fdf7a98cad48179")
    nonce = bytes.fromhex("6245709fb18853f68d833640")
    plaintext = bytes.fromhex("e42a3c02c25b64869e146d7b233987bd"
                              "dfc240871d")
    aad = bytes.fromhex("7576f7028ec6eb5ea7e298342a94d4b2"
                        "02b370ef9768ec6561c4fe6b7e7296fa"
                        "859c21")
    print("Plaintext:", plaintext.hex())
    print("AAD:", aad.hex())
    packet = gcm_siv_encrypt(key, nonce, plaintext, aad, verbose=True)
    print("Ciphertext || tag:", packet.hex())
    print("Authenticated plaintext:", gcm_siv_decrypt(key, nonce, packet, aad).hex())


if __name__ == "__main__":
    main()

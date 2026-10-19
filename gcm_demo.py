"""AES-GCM teaching implementation: CTR encryption plus GHASH authentication.

References:
  https://en.wikipedia.org/wiki/Galois/Counter_Mode
  https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
  https://doi.org/10.6028/NIST.SP.800-38D

Only AES block encryption uses cryptography (already in requirements.txt).
GHASH, finite-field multiplication, counter handling, and tag formation use
Python integers and bytes. No speed or memory optimizations are attempted.

K = AES key; IV = nonce; A = associated data (authenticated, not encrypted);
P = plaintext; C = ciphertext; H = AES_K(0^128); J0 = initial counter
(called Y0 in the original proposal); T = authentication tag.

Workflow: derive H and J0, encrypt P using counters inc32(J0), inc32^2(J0),
..., then compute T = AES_K(J0) XOR GHASH(H, A, C). Authentication covers
ciphertext, so decryption can verify the tag before decrypting.

This one-shot, byte-oriented API returns C || T. It uses full 128-bit tags
only. Send the nonce and AAD separately; never reuse a nonce with the same
key. Verbose mode exposes intermediate values for learning with demo keys.

Usage:
  python3 -m pip install -r requirements.txt
  python3 gcm_demo.py                 # Public specification test case 2
  python3 gcm_demo.py --text hello    # Fresh key and nonce, UTF-8 input
  python3 gcm_demo.py --self-test
"""

import argparse
import secrets
from hmac import compare_digest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_BYTES = 16  # AES block size: 128 bits for all key sizes.
VALID_KEY_LENGTHS_BYTES = (16, 24, 32)  # K: AES-128/192/256.
TAG_BYTES = 16  # T: fixed 128-bit tag in this simple API.
DEFAULT_NONCE_BYTES = 12  # IV: recommended 96-bit nonce.
MAX_LENGTH_BYTES = ((1 << 64) - 1) // 8  # A/IV bit lengths fit in 64 bits.
MAX_PLAINTEXT_BYTES = (1 << 36) - 32  # P: at most 2**39 - 256 bits (SP 800-38D).
# GHASH field polynomial x^128 + x^7 + x^2 + x + 1, in GCM's bit ordering.
REDUCTION_POLYNOMIAL = 0xE1000000000000000000000000000000


def byte_input(value, name):
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray")
    return bytes(value)


def xor_bytes(first, second):
    if len(first) != len(second):
        raise ValueError("XOR operands must have equal lengths")
    return bytes(left ^ right for left, right in zip(first, second))


def aes_block(key, block):
    """Use ECB only to obtain one AES block encryption; GCM handles chaining."""
    if len(block) != BLOCK_BYTES:
        raise ValueError("AES requires exactly 16 bytes")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def field_multiply(first, second):
    """Multiply two 128-bit integers in GHASH's GF(2**128).

    This is polynomial arithmetic: addition is XOR, not integer addition.
    Following Algorithm 1, first is X and second is Y: shifted starts at X,
    and each bit of Y selects whether to XOR shifted into the product.
    GCM reads coefficients from the most significant bit first. Consequently
    the encoded multiplicative identity is 1 << 127, and multiplication by
    x shifts right, reducing with 0xe1... when a low bit falls off.
    """
    product = 0
    shifted = first
    for bit_index in range(128):
        if second & (1 << (127 - bit_index)):
            product ^= shifted
        low_bit = shifted & 1
        shifted >>= 1
        if low_bit:
            shifted ^= REDUCTION_POLYNOMIAL
    return product


def zero_pad(data):
    """Pad a partial block with zeros; aligned and empty data add no block."""
    return data + bytes((-len(data)) % BLOCK_BYTES)


def ghash(hash_key, associated_data, ciphertext, verbose=False):
    """GHASH: process padded AAD, padded ciphertext, then their BIT lengths.

    AAD and ciphertext must be padded separately. The final 16-byte block
    contains two big-endian 64-bit lengths, excluding all padding bytes.
    """
    length_block = ((len(associated_data) * 8).to_bytes(8, "big")
                    + (len(ciphertext) * 8).to_bytes(8, "big"))
    formatted = zero_pad(associated_data) + zero_pad(ciphertext) + length_block
    multiplier = int.from_bytes(hash_key, "big")
    accumulator = 0
    for offset in range(0, len(formatted), BLOCK_BYTES):
        block = formatted[offset:offset + BLOCK_BYTES]
        accumulator = field_multiply(accumulator ^ int.from_bytes(block, "big"), multiplier)
        if verbose:
            print(f"GHASH block {offset // BLOCK_BYTES + 1}: {block.hex()} -> {accumulator:032x}")
    return accumulator.to_bytes(BLOCK_BYTES, "big")


def initial_counter(hash_key, nonce, verbose=False):
    """96-bit IV: append 0^31 || 1. Otherwise hash the padded IV and its length."""
    if len(nonce) == DEFAULT_NONCE_BYTES:
        return nonce + b"\x00\x00\x00\x01"
    if verbose:
        print("Deriving J0 by GHASH of the non-96-bit IV:")
    # Empty AAD makes the final length block 0^64 || len(IV), as required.
    return ghash(hash_key, b"", nonce, verbose)


def increment_counter(counter):
    """Increment only the rightmost 32 bits, modulo 2**32; keep the prefix."""
    low_word = (int.from_bytes(counter[-4:], "big") + 1) & 0xFFFFFFFF
    return counter[:-4] + low_word.to_bytes(4, "big")


def counter_transform(key, initial, data, verbose=False):
    """Encrypt or decrypt by XOR; no ciphertext padding is transmitted."""
    output = bytearray()
    counter = initial
    for offset in range(0, len(data), BLOCK_BYTES):
        counter = increment_counter(counter)  # J0 itself is reserved for the tag.
        stream = aes_block(key, counter)
        fragment = data[offset:offset + BLOCK_BYTES]
        transformed = xor_bytes(fragment, stream[:len(fragment)])
        output.extend(transformed)
        if verbose:
            print(
                f"CTR {offset // BLOCK_BYTES + 1}: counter={counter.hex()} stream={stream.hex()} output={transformed.hex()}")
    return bytes(output)


def validate_inputs(key, nonce, data, associated_data):
    key = byte_input(key, "key")
    nonce = byte_input(nonce, "nonce")
    data = byte_input(data, "data")
    associated_data = byte_input(associated_data, "associated_data")
    if len(key) not in VALID_KEY_LENGTHS_BYTES:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if not 1 <= len(nonce) <= MAX_LENGTH_BYTES:
        raise ValueError("Nonce must be nonempty and shorter than 2**64 bits")
    if len(associated_data) > MAX_LENGTH_BYTES:
        raise ValueError("AAD must be shorter than 2**64 bits")
    return key, nonce, data, associated_data


def check_payload_length(length):
    if length > MAX_PLAINTEXT_BYTES:
        raise ValueError("GCM payload exceeds 2**39 - 256 bits")


def authentication_tag(key, hash_key, initial, associated_data, ciphertext, verbose=False):
    hashed = ghash(hash_key, associated_data, ciphertext, verbose)
    mask = aes_block(key, initial)
    tag = xor_bytes(hashed, mask)
    if verbose:
        print("AES_K(J0) =", mask.hex())
        print("Tag = GHASH XOR AES_K(J0) =", tag.hex())
    return tag


def gcm_encrypt(key, nonce, plaintext, associated_data=b"", verbose=False):
    """Return ciphertext || 16-byte tag; caller ensures nonce uniqueness."""
    key, nonce, plaintext, associated_data = validate_inputs(key, nonce, plaintext, associated_data)
    check_payload_length(len(plaintext))
    hash_key = aes_block(key, bytes(BLOCK_BYTES))
    initial = initial_counter(hash_key, nonce, verbose)
    if verbose:
        print("H =", hash_key.hex())
        print("J0 =", initial.hex())
    ciphertext = counter_transform(key, initial, plaintext, verbose)
    tag = authentication_tag(key, hash_key, initial, associated_data, ciphertext, verbose)
    return ciphertext + tag


def gcm_decrypt(key, nonce, ciphertext_and_tag, associated_data=b""):
    """Authenticate first; return plaintext or raise ValueError without output."""
    key, nonce, packet, associated_data = validate_inputs(key, nonce, ciphertext_and_tag, associated_data)
    if len(packet) < TAG_BYTES:
        raise ValueError("GCM authentication failed")
    ciphertext, received_tag = packet[:-TAG_BYTES], packet[-TAG_BYTES:]
    check_payload_length(len(ciphertext))
    hash_key = aes_block(key, bytes(BLOCK_BYTES))
    initial = initial_counter(hash_key, nonce)
    expected_tag = authentication_tag(key, hash_key, initial, associated_data, ciphertext)
    if not compare_digest(expected_tag, received_tag):
        raise ValueError("GCM authentication failed")
    return counter_transform(key, initial, ciphertext)


def self_test():
    """Fixed proposal vectors and independent library comparisons; no network."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def check(actual, expected):
        if actual != expected:
            raise AssertionError(f"Got {actual!r}; expected {expected!r}")

    def rejects(operation):
        try:
            operation()
        except (ValueError, TypeError):
            return
        raise AssertionError("Invalid input accepted")

    # Proposal test cases 1 and 2: empty plaintext and one all-zero block.
    check(gcm_encrypt(bytes(16), bytes(12), b"").hex(), "58e2fccefa7e3061367f1d57a4e7455a")
    check(gcm_encrypt(bytes(16), bytes(12), bytes(16)).hex(),
          "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    message = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    # Proposal test cases 4 and 5: AAD, a partial last block, 96/64-bit IVs.
    for nonce_hex, expected_hex in (
            ("cafebabefacedbaddecaf888",
             "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
             "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"),
            ("cafebabefacedbad",
             "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
             "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f45983612d2e79e3b0785561be14aaca2fccb"),
    ):
        nonce, expected = bytes.fromhex(nonce_hex), bytes.fromhex(expected_hex)
        check(gcm_encrypt(key, nonce, message, aad), expected)
        check(gcm_decrypt(key, nonce, expected, aad), message)
    comparisons = 0
    for key_size in VALID_KEY_LENGTHS_BYTES:
        key = bytes(range(key_size))
        for nonce_size in (8, 12, 13, 16, 60, 128):
            for length in (0, 1, 15, 16, 17, 31, 32, 33):
                for aad_length in (0, 1, 15, 16, 17):
                    nonce = bytes([length, aad_length]) + bytes(nonce_size - 2)
                    message, aad = bytes(range(length)), bytes(range(aad_length))
                    result = gcm_encrypt(key, nonce, message, aad)
                    check(result, AESGCM(key).encrypt(nonce, message, aad))
                    check(gcm_decrypt(key, nonce, result, aad), message)
                    comparisons += 1
    # Counter wrap must not increment any of the preceding 96 bits.
    check(increment_counter(b"\x12" * 12 + b"\xff" * 4), b"\x12" * 12 + bytes(4))
    check(field_multiply(1 << 127, 12345), 12345)
    check(field_multiply(0, 12345), 0)
    key, nonce, message, aad = bytes(16), bytes(12), b"hello", b"header"
    result = gcm_encrypt(key, nonce, message, aad)
    check(gcm_encrypt(bytearray(key), bytearray(nonce), bytearray(message), bytearray(aad)), result)
    for index in (0, len(result) - 1):
        tampered = bytearray(result)
        tampered[index] ^= 1
        rejects(lambda: gcm_decrypt(key, nonce, tampered, aad))
    rejects(lambda: gcm_decrypt(key, nonce, result, b"changed"))
    rejects(lambda: gcm_decrypt(key, b"\x01" + nonce[1:], result, aad))
    rejects(lambda: gcm_decrypt(b"\x01" + key[1:], nonce, result, aad))
    rejects(lambda: gcm_decrypt(key, nonce, result[:-1], aad))
    rejects(lambda: gcm_decrypt(key, nonce, bytes(15), aad))
    rejects(lambda: gcm_encrypt(bytes(15), nonce, b""))
    rejects(lambda: gcm_encrypt(key, b"", b""))
    rejects(lambda: gcm_encrypt(key, nonce, "text"))
    check_payload_length(MAX_PLAINTEXT_BYTES)
    rejects(lambda: check_payload_length(MAX_PLAINTEXT_BYTES + 1))
    print(f"PASS: four published vectors, {comparisons} library comparisons, counter wrap and rejection checks.")


def main():
    parser = argparse.ArgumentParser(description="AES-GCM demo with intermediate values")
    parser.add_argument("--text", help="UTF-8 text; default is public specification test case 2")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        return
    if arguments.text is None:
        print("Public specification test case 2:")
        key, nonce, message, aad = bytes(16), bytes(12), bytes(16), b""
    else:
        key, nonce = secrets.token_bytes(16), secrets.token_bytes(DEFAULT_NONCE_BYTES)
        message, aad = arguments.text.encode("utf-8"), b"demo header"
    print("Demo key =", key.hex())
    print("Nonce =", nonce.hex())
    print("AAD =", aad.hex())
    print("Plaintext =", message.hex())
    packet = gcm_encrypt(key, nonce, message, aad, verbose=True)
    print("Ciphertext || tag =", packet.hex())
    print("Authenticated plaintext =", gcm_decrypt(key, nonce, packet, aad).hex())


if __name__ == "__main__":
    main()

"""AES-CCM: explicit CBC-MAC + counter mode, with library AES block encryption.

References:
  https://en.wikipedia.org/wiki/CCM_mode
  https://en.wikipedia.org/wiki/Authenticated_encryption
  https://www.rfc-editor.org/info/rfc3610/ (Sections 2 and 8)

Only the AES primitive uses cryptography, already in requirements.txt.
CCM formatting, padding, CBC-MAC, and CTR are implemented below with bytes
and integers. The library's AESCCM is used only as a self-test reference.

AEAD encrypts the plaintext and authenticates both plaintext and associated
data (AAD). AAD, such as a packet header, remains visible. Our wire output
is ciphertext || tag; transport the nonce and AAD separately.

Parameters: AES key 16/24/32 bytes; nonce 7..13 bytes; tag 4/6/8/10/12/14/16
bytes. L = 15 - len(nonce) encodes the message length in bytes. The message
must be shorter than 2**(8*L) bytes. Never reuse a nonce with the same key.
The receiver must agree on tag length. Only byte-aligned inputs are supported.

Usage:
  python3 -m pip install -r requirements.txt
  python3 ccm_demo.py                # Trace public RFC 3610 packet vector 1
  python3 ccm_demo.py --text hello   # Fresh key and nonce for this demo run
  python3 ccm_demo.py --self-test
"""

import argparse
import secrets
from hmac import compare_digest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RFC 3610 Sections 2 and 2.1: parameter symbols and their allowed ranges.
BLOCK_BYTES = 16  # AES block size is always 128 bits, for every AES key size.

# M: authentication tag length in BYTES, encoded in B0 as M' = (M - 2) // 2.
# Both sender and receiver must use the same M.
VALID_TAG_LENGTHS_BYTES = (4, 6, 8, 10, 12, 14, 16)
DEFAULT_TAG_LENGTH_BYTES = 16

# L: number of bytes encoding the plaintext length and the counter.
# Allowed values are 2..8, encoded in the flags as L' = L - 1.
# A message may contain 0 through 2**(8*L) - 1 bytes.
MIN_LENGTH_FIELD_BYTES = 2
MAX_LENGTH_FIELD_BYTES = 8

# N: the nonce BYTE STRING, not its length. Its length must be 15 - L.
# One byte of each AES block holds flags, leaving 15 for nonce + length/counter.
# Thus nonce lengths are 7..13 bytes. N must be unique for each use of a key K.
NONCE_AND_LENGTH_BYTES = BLOCK_BYTES - 1
MIN_NONCE_LENGTH_BYTES = NONCE_AND_LENGTH_BYTES - MAX_LENGTH_FIELD_BYTES  # 7
MAX_NONCE_LENGTH_BYTES = NONCE_AND_LENGTH_BYTES - MIN_LENGTH_FIELD_BYTES  # 13

# K: the secret AES key BYTE STRING. RFC 3610 leaves key sizes to the cipher;
# AES permits 16, 24, or 32 bytes (128, 192, or 256 bits), independently of L/M.
VALID_AES_KEY_LENGTHS_BYTES = (16, 24, 32)

# N and K themselves are supplied per call, rather than stored as global secrets.
# Associated data length is 0..2**64 - 1 bytes (RFC 3610 Section 2.1).
MAX_ASSOCIATED_DATA_BYTES = (1 << 64) - 1


def byte_input(value, name):
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray")
    return bytes(value)


def xor_bytes(first, second):
    """XOR equally sized byte strings, including a short final CTR fragment."""
    if len(first) != len(second):
        raise ValueError("XOR operands must have equal lengths")
    return bytes(left ^ right for left, right in zip(first, second))


def aes_block(key, block):
    """ECB supplies one AES encryption; CCM implements its own chaining."""
    if len(block) != BLOCK_BYTES:
        raise ValueError("AES requires a 16-byte block")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def validate_inputs(key, nonce, data, associated_data, tag_length):
    key = byte_input(key, "key")
    nonce = byte_input(nonce, "nonce")
    data = byte_input(data, "data")
    associated_data = byte_input(associated_data, "associated_data")
    if len(key) not in VALID_AES_KEY_LENGTHS_BYTES:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if not MIN_NONCE_LENGTH_BYTES <= len(nonce) <= MAX_NONCE_LENGTH_BYTES:
        raise ValueError("CCM nonce must be 7..13 bytes")
    if type(tag_length) is not int or tag_length not in VALID_TAG_LENGTHS_BYTES:
        raise ValueError("CCM tag length must be 4, 6, 8, 10, 12, 14, or 16 bytes")
    if len(associated_data) > MAX_ASSOCIATED_DATA_BYTES:
        raise ValueError("AAD must be shorter than 2**64 bytes")
    return key, nonce, data, associated_data


def check_message_length(length, nonce):
    if length >= 1 << (8 * (NONCE_AND_LENGTH_BYTES - len(nonce))):
        raise ValueError("Message is too long for this nonce length")


def encode_aad_length(length):
    """RFC 3610 uses three encodings; the first boundary is 0xFF00, not 65536."""
    if not 0 < length <= MAX_ASSOCIATED_DATA_BYTES:
        raise ValueError("Encoded AAD length must be in 1..2**64-1")
    if length < (2 ** 16 - 2 ** 8):
        return length.to_bytes(2, "big")
    if length < 1 << 32:
        return b"\xff\xfe" + length.to_bytes(4, "big")
    return b"\xff\xff" + length.to_bytes(8, "big")


def zero_pad(data):
    """Pad only a partial block; empty or aligned input adds no extra block."""
    return data + bytes((-len(data)) % BLOCK_BYTES)


def authentication_tag(key, nonce, plaintext, associated_data, tag_length, verbose=False):
    """Format B0 || padded AAD || padded plaintext and compute CBC-MAC.

    B0 encodes AAD presence, tag length, nonce, and plaintext length. This
    structured input is essential; plain CBC-MAC on arbitrary messages is
    not a substitute. CCM does not use CMAC subkeys or 0x80 padding.
    """
    length_bytes = NONCE_AND_LENGTH_BYTES - len(nonce)
    flags = (0x40 if associated_data else 0) | (((tag_length - 2) // 2) << 3) | (length_bytes - 1)
    first_block = bytes([flags]) + nonce + len(plaintext).to_bytes(length_bytes, "big")
    encoded_aad = (zero_pad(encode_aad_length(len(associated_data)) + associated_data)
                   if associated_data else b"")
    formatted = first_block + encoded_aad + zero_pad(plaintext)
    state = bytes(BLOCK_BYTES)  # initialization vector is all zeros when calculating CBC-MAC
    for offset in range(0, len(formatted), BLOCK_BYTES):
        block = formatted[offset:offset + BLOCK_BYTES]
        aes_input = xor_bytes(state, block)
        state = aes_block(key, aes_input)
        if verbose:
            print(f"B{offset // BLOCK_BYTES}={block.hex()} XOR={aes_input.hex()} MAC={state.hex()}")
    tag = state[:tag_length]
    if verbose:
        print("Unmasked tag T =", tag.hex())
    return tag


def counter_stream(key, nonce, counter, verbose=False):
    """Counter zero masks the tag; counters 1, 2, ... encrypt the payload."""
    length_bytes = NONCE_AND_LENGTH_BYTES - len(nonce)
    counter_block = bytes([length_bytes - 1]) + nonce + counter.to_bytes(length_bytes, "big")
    stream = aes_block(key, counter_block)
    if verbose:
        print(f"A{counter}={counter_block.hex()} S{counter}={stream.hex()}")
    return stream


def counter_transform(key, nonce, data, verbose=False):
    """XOR with CTR keystream; encryption and decryption are the same operation."""
    output = bytearray()
    for offset in range(0, len(data), BLOCK_BYTES):
        fragment = data[offset:offset + BLOCK_BYTES]
        stream = counter_stream(key, nonce, offset // BLOCK_BYTES + 1, verbose)
        output.extend(xor_bytes(fragment, stream[:len(fragment)]))
    return bytes(output)


def ccm_encrypt(key, nonce, plaintext, associated_data=b"", tag_length=DEFAULT_TAG_LENGTH_BYTES, verbose=False):
    """Return ciphertext || tag. The caller supplies a unique nonce per key."""
    key, nonce, plaintext, associated_data = validate_inputs(
        key, nonce, plaintext, associated_data, tag_length)
    check_message_length(len(plaintext), nonce)
    tag = authentication_tag(key, nonce, plaintext, associated_data, tag_length, verbose)
    ciphertext = counter_transform(key, nonce, plaintext, verbose)
    masked_tag = xor_bytes(tag, counter_stream(key, nonce, 0, verbose)[:tag_length])
    if verbose:
        print("Ciphertext =", ciphertext.hex())
        print("Masked tag =", masked_tag.hex())
    return ciphertext + masked_tag


def ccm_decrypt(key, nonce, ciphertext_and_tag, associated_data=b"", tag_length=DEFAULT_TAG_LENGTH_BYTES):
    """Return plaintext only after authentication; raise ValueError on failure.

    CCM must decrypt internally to recompute its MAC. Do not print or return
    this candidate plaintext before comparing the full configured tag.
    """
    key, nonce, packet, associated_data = validate_inputs(
        key, nonce, ciphertext_and_tag, associated_data, tag_length)
    if len(packet) < tag_length:
        raise ValueError("CCM authentication failed")
    ciphertext, received_tag = packet[:-tag_length], packet[-tag_length:]
    check_message_length(len(ciphertext), nonce)
    plaintext = counter_transform(key, nonce, ciphertext)
    tag = authentication_tag(key, nonce, plaintext, associated_data, tag_length)
    expected_tag = xor_bytes(tag, counter_stream(key, nonce, 0)[:tag_length])
    if not compare_digest(expected_tag, received_tag):
        raise ValueError("CCM authentication failed")
    return plaintext


def self_test():
    """RFC 3610 vector 1 plus independent library comparisons and rejection tests."""
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    def check(actual, expected):
        if actual != expected:
            raise AssertionError(f"Got {actual!r}; expected {expected!r}")

    def rejects(operation):
        try:
            operation()
        except (ValueError, TypeError):
            return
        raise AssertionError("Invalid input accepted")

    key = bytes(range(0xC0, 0xD0))
    nonce = bytes.fromhex("00000003020100a0a1a2a3a4a5")
    aad, message = bytes(range(8)), bytes(range(8, 31))
    expected = bytes.fromhex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
    check(ccm_encrypt(key, nonce, message, aad, 8), expected)
    check(ccm_decrypt(key, nonce, expected, aad, 8), message)
    # Every supported key, nonce, and tag length; empty and partial/full blocks.
    for key_size in (16, 24, 32):
        test_key = bytes(range(key_size))
        for nonce_size in range(7, 14):
            for tag_length in range(4, 17, 2):
                reference = AESCCM(test_key, tag_length)
                for length in (0, 1, 15, 16, 17, 31, 32):
                    test_nonce = bytes([length, tag_length]) + bytes(nonce_size - 2)
                    plaintext = bytes(range(length))
                    associated = bytes(range(length % 17))
                    result = ccm_encrypt(test_key, test_nonce, plaintext, associated, tag_length)
                    check(result, reference.encrypt(test_nonce, plaintext, associated))
                    check(ccm_decrypt(test_key, test_nonce, result, associated, tag_length), plaintext)
    for aad_length in (0xFEFF, 0xFF00):
        associated = bytes(aad_length)
        check(ccm_encrypt(key, nonce, b"abc", associated), AESCCM(key).encrypt(nonce, b"abc", associated))
    check(encode_aad_length(1 << 32), b"\xff\xff" + (1 << 32).to_bytes(8, "big"))
    check(encode_aad_length((1 << 64) - 1), b"\xff\xff" + b"\xff" * 8)
    for index in (0, len(expected) - 1):
        modified = bytearray(expected)
        modified[index] ^= 1
        rejects(lambda: ccm_decrypt(key, nonce, modified, aad, 8))
    rejects(lambda: ccm_decrypt(key, nonce, expected, aad + b"x", 8))
    rejects(lambda: ccm_decrypt(key, nonce[:-1] + b"x", expected, aad, 8))
    rejects(lambda: ccm_decrypt(bytes(16), nonce, expected, aad, 8))
    rejects(lambda: ccm_decrypt(key, nonce, b"", aad, 8))
    rejects(lambda: ccm_encrypt(key, nonce, bytes(65536)))
    for bad_nonce in (bytes(6), bytes(14)):
        rejects(lambda: ccm_encrypt(key, bad_nonce, b""))
    for bad_tag in (0, 3, 5, 18, 8.0, True):
        rejects(lambda: ccm_encrypt(key, nonce, b"", tag_length=bad_tag))
    rejects(lambda: ccm_encrypt(bytes(15), nonce, b""))
    rejects(lambda: ccm_encrypt(key, nonce, "text"))
    check(ccm_encrypt(bytearray(key), bytearray(nonce), bytearray(message), bytearray(aad), 8), expected)
    print("PASS: RFC 3610 vector 1, 1029 parameter/boundary cases, AAD lengths, tampering and validation.")


def main():
    parser = argparse.ArgumentParser(description="AES-CCM teaching demo with intermediate values")
    parser.add_argument("--text", help="UTF-8 message; default is RFC 3610 packet vector 1")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        return
    if arguments.text is None:
        print("Public RFC 3610 test vector 1:")
        key, nonce = bytes(range(0xC0, 0xD0)), bytes.fromhex("00000003020100a0a1a2a3a4a5")
        associated_data, message = bytes(range(8)), bytes(range(8, 31))
    else:
        key, nonce = secrets.token_bytes(16), secrets.token_bytes(13)
        associated_data, message = b"demo header", arguments.text.encode("utf-8")
    print("Demo key =", key.hex())
    print("Nonce =", nonce.hex())
    print("AAD =", associated_data.hex())
    print("Plaintext =", message.hex())
    packet = ccm_encrypt(key, nonce, message, associated_data, tag_length=8, verbose=True)
    print("Ciphertext || tag =", packet.hex())
    recovered = ccm_decrypt(key, nonce, packet, associated_data, tag_length=8)
    print("Authenticated plaintext =", recovered.hex())


if __name__ == "__main__":
    main()

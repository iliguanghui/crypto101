"""AES-CMAC (OMAC1), with explicit CMAC steps and library AES encryption.

References:
  https://en.wikipedia.org/wiki/One-key_MAC
  https://www.rfc-editor.org/rfc/rfc4493.html
  https://doi.org/10.6028/NIST.FIPS.197-upd1 (AES)

AES is supplied by cryptography, as in cbc_mac_demo.py. The CMAC subkey,
padding, and chaining operations below use basic Python types.

CMAC authenticates a message with a secret key; it does not encrypt it.
AES always encrypts 16-byte blocks, with a 16-, 24-, or 32-byte key.
CMAC starts with a zero chaining value and derives two final-block subkeys:
  L = AES(key, zero_block), K1 = double(L), K2 = double(K1).
A nonempty complete last block is XORed with K1. Otherwise append 0x80 and
zeros to the last fragment (including an empty message), then XOR with K2.
Chain the blocks with AES(key, previous_state XOR block); the last result
is the 16-byte tag. These final-block rules allow variable-length messages.

This byte-oriented, one-shot teaching implementation prints key-derived
intermediates only when verbose=True. The demo uses a public test key.

Usage:
  python3 -m pip install -r requirements.txt
  python3 cmac_demo.py                  # Trace RFC 4493's one-block example
  python3 cmac_demo.py --text "hello"   # UTF-8 text, using the public test key
  python3 cmac_demo.py --self-test      # Published vectors and edge cases
"""

import secrets
import argparse
from hmac import compare_digest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_BYTES = 16


def byte_input(value, name):
    """Avoid bytes(integer), which would silently create that many zeros."""
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray")
    return bytes(value)


def xor_blocks(first, second):
    """XOR corresponding bytes of two complete AES blocks."""
    if len(first) != BLOCK_BYTES or len(second) != BLOCK_BYTES:
        raise ValueError("XOR requires two 16-byte blocks")
    return bytes(left ^ right for left, right in zip(first, second))


def aes_encrypt_block(key, block):
    """Encrypt one block through the same AES library used by cbc_mac_demo.py."""
    key = byte_input(key, "key")
    block = byte_input(block, "block")
    if len(block) != BLOCK_BYTES:
        raise ValueError("AES requires a 16-byte block")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def double_block(block):
    """CMAC multiplication by x in GF(2**128), not AES's 8-bit field.

    Shift the entire block left once, discarding overflow. If its original
    top bit was 1, XOR 0x87 into the low byte for polynomial reduction.
    """
    if len(block) != BLOCK_BYTES:
        raise ValueError("CMAC doubling requires a 16-byte block")
    value = int.from_bytes(block, "big")
    doubled = (value << 1) & ((1 << 128) - 1)
    if value >> 127:
        doubled ^= 0x87
    return doubled.to_bytes(BLOCK_BYTES, "big")


def cmac(key, message, verbose=False):
    """Return a full 16-byte AES-CMAC tag for byte input, including empty input."""
    message = byte_input(message, "message")
    key = byte_input(key, "key")
    # ECB supplies individual AES block encryptions; CMAC chaining is done below.
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encrypted_zero = encryptor.update(bytes(BLOCK_BYTES))
    subkey_one = double_block(encrypted_zero)
    subkey_two = double_block(subkey_one)
    block_count = max(1, (len(message) + BLOCK_BYTES - 1) // BLOCK_BYTES)
    last_fragment = message[(block_count - 1) * BLOCK_BYTES:]
    complete_last_block = len(last_fragment) == BLOCK_BYTES
    if complete_last_block:
        prepared_last = last_fragment
        last_block = xor_blocks(prepared_last, subkey_one)
    else:
        # Bit padding 10*; this is not PKCS#7. Empty input follows this path.
        prepared_last = last_fragment + b"\x80" + bytes(15 - len(last_fragment))
        last_block = xor_blocks(prepared_last, subkey_two)
    if verbose:
        print("L  =", encrypted_zero.hex())
        print("K1 =", subkey_one.hex())
        print("K2 =", subkey_two.hex())
        print("Last block:", "complete, use K1" if complete_last_block else "padded, use K2")
        print("Last block before subkey XOR =", prepared_last.hex())
        print("Last block after subkey XOR  =", last_block.hex())
    state = bytes(BLOCK_BYTES)  # CMAC's initial chaining value is always zero.
    for block_index in range(block_count):
        block = (last_block if block_index == block_count - 1 else
                 message[block_index * BLOCK_BYTES:(block_index + 1) * BLOCK_BYTES])
        aes_input = xor_blocks(state, block)
        state = encryptor.update(aes_input)
        if verbose:
            print(f"Block {block_index + 1}: AES input={aes_input.hex()} output={state.hex()}")
    encryptor.finalize()  # Every input was a complete block; no bytes remain.
    return state


def verify_cmac(key, message, tag):
    """Verify a full-length tag using the standard library comparison helper."""
    tag = byte_input(tag, "tag")
    expected = cmac(key, message)
    return compare_digest(expected, tag)


def self_test():
    """Published AES examples and every RFC 4493 Section 4 CMAC example."""

    def check(actual, expected, label):
        if actual != expected:
            raise AssertionError(f"{label}: got {actual!r}, expected {expected!r}")

    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    # FIPS 197 examples for AES-128/192/256.
    for key_size, expected in (
            (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (32, "8ea2b7ca516745bfeafc49904b496089"),
    ):
        check(aes_encrypt_block(bytes(range(key_size)), plaintext).hex(), expected, "AES")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    message = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710")
    encrypted_zero = aes_encrypt_block(key, bytes(16))
    check(encrypted_zero.hex(), "7df76b0c1ab899b33e42f047b91b546f", "L")
    check(double_block(encrypted_zero).hex(), "fbeed618357133667c85e08f7236a8de", "K1")
    check(double_block(double_block(encrypted_zero)).hex(),
          "f7ddac306ae266ccf90bc11ee46d513b", "K2")
    for length, expected in (
            (0, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ):
        check(cmac(key, message[:length]).hex(), expected, f"CMAC length {length}")
    for length in (0, 1, 15, 16, 17, 31, 32, 33):
        payload = bytes(range(length))
        tag = cmac(key, payload)
        check(cmac(bytearray(key), bytearray(payload)), tag, "bytearray")
        check(verify_cmac(key, payload, tag), True, "valid tag")
        check(verify_cmac(key, payload + b"\x00", tag), False, "changed message")
        check(verify_cmac(key, payload, bytes([tag[0] ^ 1]) + tag[1:]), False, "changed tag")
        check(verify_cmac(key, payload, tag[:8]), False, "truncated tag")
    for bad_key in (b"", bytes(15), bytes(17), bytes(33)):
        try:
            cmac(bad_key, b"")
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid key accepted")
    print("PASS: AES-128/192/256, RFC 4493 subkeys and four CMAC vectors, edge cases.")


def main():
    parser = argparse.ArgumentParser(description="AES-CMAC teaching demo using library AES")
    parser.add_argument("--text", default="The quick brown fox jumps over the lazy dog",
                        help="UTF-8 message; default is RFC 4493's one-block example")
    parser.add_argument("--self-test", action="store_true", help="Check published vectors")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        return
    key = secrets.token_bytes(16)  # 只有认证方知道密钥
    message = arguments.text.encode("utf-8")
    print("Public example key =", key.hex())
    print("Message =", message.hex())
    tag = cmac(key, message, verbose=True)
    print("CMAC =", tag.hex())
    print("Verification =", verify_cmac(key, message, tag))


if __name__ == "__main__":
    main()

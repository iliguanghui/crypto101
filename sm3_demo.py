"""SM3 cryptographic hash algorithm in pure Python (GM/T 0004).

Reference:
  http://www.gmbz.org.cn/upload/2024-11-18/1731899426565012428.pdf
  Published 2012-03-21; English translation dated 2024-10-30.

Architecture overview:
  1. Encode text as UTF-8, then append a 1 bit, zeros, and the original bit
     length. The padded message contains complete 64-byte (512-bit) blocks.
  2. Start with eight fixed 32-bit words, called the initialization vector.
  3. Expand each block's 16 words into 68 words W and 64 derived words W'.
  4. Run 64 compression rounds, then XOR the result with the incoming state.
  5. Serialize the final eight words in big-endian order: a 32-byte digest.

Comparison with SHA-256:
  Both use 32-bit words, 64-byte blocks, 64 rounds, and big-endian length
  padding. SM3 uses different initial values, two round constants, its P0/P1
  transformations, and two message schedules. Its final state combination
  uses XOR, whereas SHA-256 adds words modulo 2**32.

Scope:
  This simple one-shot API accepts bytes, bytearray, or UTF-8 text. The
  specification also defines non-byte-aligned bit strings; those are outside
  this byte-oriented API. Message lengths must be less than 2**64 bits.
  No third-party libraries or library hash implementations are used here.

Usage:
  python3 sm3_demo.py --text abc
  python3 sm3_demo.py --text abc --verbose
  python3 verify_sm3.py
"""

import argparse
from typing import List, Tuple, Union

# Section 4.1: these are public constants, not a secret key or random nonce.
INITIAL_VECTOR = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)
WORD_BITS = 32
MASK_32 = (1 << WORD_BITS) - 1
BLOCK_BYTES = 64
ROUND_COUNT = 64


# ============================================================================
# Word operations (Sections 4.2-4.4)
# ============================================================================

def rotate_left(value: int, distance: int) -> int:
    """Rotate within a 32-bit word, wrapping high bits around to the low end."""
    value &= MASK_32
    # Round indexes reach 63; rotating by 32 has the same effect as by zero.
    distance %= WORD_BITS
    return ((value << distance) | (value >> (WORD_BITS - distance))) & MASK_32


def permutation_zero(value: int) -> int:
    """P0: spread bits within a compression-round result using rotations 9, 17."""
    return value ^ rotate_left(value, 9) ^ rotate_left(value, 17)


def permutation_one(value: int) -> int:
    """P1: mix bits during message expansion using rotations 15, 23."""
    return value ^ rotate_left(value, 15) ^ rotate_left(value, 23)


def boolean_ff(first: int, second: int, third: int, round_index: int) -> int:
    """FF: XOR for rounds 0..15; bitwise majority for rounds 16..63."""
    if round_index < 16:
        return first ^ second ^ third
    return (first & second) | (first & third) | (second & third)


def boolean_gg(first: int, second: int, third: int, round_index: int) -> int:
    """GG: XOR initially; later each bit of first selects second or third."""
    if round_index < 16:
        return first ^ second ^ third
    # Python's ~ creates a negative integer; mask it to a 32-bit complement.
    return (first & second) | ((~first & MASK_32) & third)


# ============================================================================
# Padding and message expansion (Sections 5.2 and 5.3.2)
# ============================================================================

def pad_message(message: bytes) -> bytes:
    """Append 1, then zeros, then the original length as 64 big-endian bits.

    A byte-aligned message uses 0x80 for the first padding byte. There must be
    eight bytes left for the length: 55 input bytes fit in one block, whereas
    56 require two. An empty message and an exact block both need padding.
    """
    bit_length = len(message) * 8
    if bit_length >= (1 << 64):
        raise ValueError("SM3 message length must be less than 2**64 bits")
    zero_bytes = (56 - (len(message) + 1)) % BLOCK_BYTES
    return message + b"\x80" + bytes(zero_bytes) + bit_length.to_bytes(8, "big")


def expand_message(block: bytes) -> Tuple[List[int], List[int]]:
    """Return the 68 W words and 64 W' words needed for one block."""
    if len(block) != BLOCK_BYTES:
        raise ValueError("SM3 compression blocks must contain exactly 64 bytes")
    # Example: bytes 61 62 63 80 become the integer 0x61626380.
    expanded_words = [int.from_bytes(block[offset:offset + 4], "big")
                      for offset in range(0, BLOCK_BYTES, 4)]
    for word_index in range(16, 68):
        mixed_word = (expanded_words[word_index - 16]
                      ^ expanded_words[word_index - 9]
                      ^ rotate_left(expanded_words[word_index - 3], 15))
        expanded_words.append(
            permutation_one(mixed_word)
            ^ rotate_left(expanded_words[word_index - 13], 7)
            ^ expanded_words[word_index - 6]
        )
    derived_words = [expanded_words[index] ^ expanded_words[index + 4]
                     for index in range(ROUND_COUNT)]
    return expanded_words, derived_words


# ============================================================================
# Compression (Section 5.3.3)
# ============================================================================


def compress_block(hash_state: List[int], block: bytes, verbose: bool = False) -> List[int]:
    """Fold one block into the eight-word state without modifying the input."""
    expanded_words, derived_words = expand_message(block)
    working_state = hash_state[:]
    register_a, register_b, register_c, register_d = working_state[:4]
    register_e, register_f, register_g, register_h = working_state[4:]
    for round_index in range(ROUND_COUNT):
        round_constant = 0x79CC4519 if round_index < 16 else 0x7A879D8A
        # Mask before rotation: Python addition must emulate modulo 2**32.
        sum_one = rotate_left(
            (rotate_left(register_a, 12) + register_e + rotate_left(round_constant, round_index)) & MASK_32, 7
        )
        sum_two = sum_one ^ rotate_left(register_a, 12)
        temporary_one = (boolean_ff(register_a, register_b, register_c, round_index)
                         + register_d + sum_two + derived_words[round_index]) & MASK_32
        temporary_two = (boolean_gg(register_e, register_f, register_g, round_index)
                         + register_h + sum_one + expanded_words[round_index]) & MASK_32

        register_d = register_c
        register_c = rotate_left(register_b, 9)
        register_b = register_a
        register_a = temporary_one
        register_h = register_g
        register_g = rotate_left(register_f, 19)
        register_f = register_e
        register_e = permutation_zero(temporary_two)
        working_state = [register_a, register_b, register_c, register_d, register_e, register_f, register_g, register_h]
        if verbose:
            print(f"  Round {round_index:02d}: " + " ".join(f"{word:08x}" for word in working_state))
    # Feed forward with XOR. Retain the incoming state until all rounds finish.
    return [previous ^ current for previous, current in zip(hash_state, working_state)]


def sm3(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Hash a complete message and return 32 bytes; text uses UTF-8 encoding."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    elif isinstance(message, (bytes, bytearray)):
        message = bytes(message)
    else:
        raise TypeError("message must be bytes, bytearray, or str")
    padded_message = pad_message(message)
    hash_state = list(INITIAL_VECTOR)
    if verbose:
        print(f"Input: {len(message)} bytes; padded: {len(padded_message)} bytes")
        print("Round register order: A B C D E F G H")
    for offset in range(0, len(padded_message), BLOCK_BYTES):
        if verbose:
            print(f"Block {offset // BLOCK_BYTES}:")
        hash_state = compress_block(hash_state, padded_message[offset:offset + BLOCK_BYTES], verbose)
    # Eight 32-bit words give 256 bits; preserve big-endian order throughout.
    return b"".join(word.to_bytes(4, "big") for word in hash_state)


def sm3_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Return the same digest as 64 lowercase hexadecimal characters."""
    return sm3(message, verbose=verbose).hex()


def main() -> None:
    parser = argparse.ArgumentParser(description="Pure-Python SM3 teaching demo (GM/T 0004).")
    parser.add_argument("--text", default="abc", help="UTF-8 text to hash")
    parser.add_argument("--verbose", action="store_true", help="Show all round register values")
    arguments = parser.parse_args()
    print(f"Message: {arguments.text!r}")
    print(f"SM3: {sm3_hex(arguments.text, verbose=arguments.verbose)}")


if __name__ == "__main__":
    main()

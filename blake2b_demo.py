"""BLAKE2b: an educational hash and keyed-hash implementation in pure Python.

References:
  - RFC 7693: https://www.rfc-editor.org/rfc/rfc7693.html
    Sections 2.5-2.7: parameters, initial values, and message schedule.
    Sections 3.1-3.3: mixing, compression, and complete hashing procedure.
  - Wikipedia: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2

Architecture Overview:
  1. A word is an integer restricted to 64 bits; a block contains 16 words
     (128 bytes). The persistent hash state contains eight words.
  2. Initialize the state using fixed constants and the chosen digest/key sizes.
     These sizes affect the computation from the beginning.
  3. If a key is supplied, place it in a zero-filled first block. This enables
     message authentication: the digest depends on both the key and message.
  4. Compress each block into the state using 12 rounds. Each round performs
     eight G operations, mixing four working words and two message words each.
  5. Mark the final block explicitly. Fill any unused bytes with zeros, while
     keeping a separate count of the actual input bytes processed.
  6. Serialize the eight state words in little-endian order and take the
     requested number of digest bytes (1..64).

Comparison with SHA-512:
  - Both use 64-bit words, 128-byte blocks, and the same eight IV constants.
    BLAKE2b additionally mixes its digest/key parameters into the initial state.
  - BLAKE2b reads words and writes digests in little-endian order (lowest byte
    first); SHA-512 uses big-endian order (highest byte first).
  - BLAKE2b permutes the original 16 message words with the SIGMA table.
    SHA-512 expands those 16 words into a 80-word message schedule.
  - BLAKE2b has 12 rounds of addition, XOR, and rotation mixing, with
    rotations (32, 24, 16, 63). SHA-512 has 80 differently structured
    rounds using choice, majority, sigma functions, and round constants.
    Round counts across these different constructions are not security scores.
  - BLAKE2b uses a byte counter and final-block flag with zero filling.
    SHA-512 appends a 1 bit, zeros, and a bit-length field to its message.
  - BLAKE2b supports variable digest lengths and direct keyed hashing.
    SHA-512 has a fixed digest length; HMAC supplies keyed authentication.

Scope:
  This is the sequential mode specified by RFC 7693, including optional keying.
  Tree hashing, salt, and personalization are not implemented. Each function
  call hashes a complete message; there is no incremental update interface.
  The implementation favors clarity over speed and uses Python integers and
  byte strings. Python does not provide constant-time execution for this code.

Usage:
  python3 blake2b_demo.py
  python3 blake2b_demo.py --text "abc" --length 64
  python3 verify_blake2.py
"""

import argparse
import hashlib  # Used only for the SHA comparison in main(), not the BLAKE2 core.
from typing import List, Union

# ==============================================================================
# Fixed algorithm parameters and constants (RFC 7693, Section 2)
# ==============================================================================

# Python integers can grow without limit. This mask keeps only the lowest
# word-sized bits, implementing addition modulo 2**64.
MASK_64 = (1 << 64) - 1
WORD_BYTES = 8
BLOCK_BYTES = 128
WORD_COUNT = 8  # Persistent chaining state; compression uses 16 working words.
ROUND_COUNT = 12
MAX_DIGEST_BYTES = 64
MAX_KEY_BYTES = 64
MAX_INPUT_BYTES = 1 << 128

# The IV is public and fixed: it is neither a secret key nor a random nonce.
# Copy it before hashing so one call cannot change another call's starting state.
# Same numerical initialization words as SHA-512 (RFC 7693, Section 2.6).
INITIAL_VECTOR = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]

# Message word indexes for rounds 0..9. BLAKE2b repeats rounds 0 and 1.
# Each row is a permutation of indexes 0..15, not a list of message values.
# For example, schedule[0] == 14 selects the fifteenth word of this block.
MESSAGE_SCHEDULE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]


# ==============================================================================
# Word rotation and the G mixing operation (RFC 7693, Section 3.1)
# ==============================================================================

def rotate_right_64(value: int, rotation: int) -> int:
    """Move bits right, wrapping the bits that fall off back to the left.

    For an 8-bit illustration, rotating 00000001 right by 1 gives 10000000.
    Here the word is 64 bits wide. Internal callers supply a word-sized
    nonnegative value and one of the fixed BLAKE2b rotation amounts.
    """
    # The two shifts form the wrapped result; masking discards excess high bits.
    return ((value >> rotation) | (value << (64 - rotation))) & MASK_64


def mix_words(
        working_state: List[int], first: int, second: int, third: int, fourth: int,
        message_first: int, message_second: int,
) -> None:
    """Mix four selected working words with two words from the message block.

    first, second, third, and fourth are indexes into working_state. They
    correspond to a, b, c, and d in the RFC. message_first and message_second
    are actual word values. The supplied list is modified in place.

    G uses addition, rotation, and XOR (often called ARX). Addition introduces
    carries between bit positions; XOR combines bits; rotation moves bits to
    new positions. Together they spread the influence of the input words.
    """
    # First half: inject the first message word, then propagate the changes.
    working_state[first] = (working_state[first] + working_state[second] + message_first) & MASK_64
    working_state[fourth] = rotate_right_64(working_state[fourth] ^ working_state[first], 32)
    working_state[third] = (working_state[third] + working_state[fourth]) & MASK_64
    working_state[second] = rotate_right_64(working_state[second] ^ working_state[third], 24)
    # Second half: inject the second message word with different rotations.
    working_state[first] = (working_state[first] + working_state[second] + message_second) & MASK_64
    working_state[fourth] = rotate_right_64(working_state[fourth] ^ working_state[first], 16)
    working_state[third] = (working_state[third] + working_state[fourth]) & MASK_64
    working_state[second] = rotate_right_64(working_state[second] ^ working_state[third], 63)


# ==============================================================================
# Compression: combine one block with the running state (RFC 7693, Section 3.2)
# ==============================================================================

def compress_block(
        hash_state: List[int], block: bytes, byte_count: int, is_final_block: bool,
) -> None:
    """Update hash_state using a block, a cumulative byte count, and a final flag.

    Compression here means folding a block into the fixed-size hash state;
    it does not produce a file that can later be decompressed. The caller
    supplies eight state words and a block padded to 128 bytes.
    byte_count includes the current block's real input bytes, excludes final
    message padding, and includes a full padded key block when a key is used.
    """
    # 1. Decode 16 little-endian words. For example, bytes 01 02 03 04 begin
    # a word whose low 32 bits are 0x04030201.
    message_words = [
        int.from_bytes(block[offset:offset + WORD_BYTES], "little")
        for offset in range(0, BLOCK_BYTES, WORD_BYTES)
    ]
    # 2. Build a temporary 4x4 grid of words, stored as one flat list:
    #       0   1   2   3      <- running hash state
    #       4   5   6   7      <- running hash state
    #       8   9  10  11      <- fixed IV
    #      12  13  14  15      <- IV, modified by counter and final flag
    working_state = hash_state[:] + INITIAL_VECTOR[:]
    # Split the 128-bit cumulative byte count into two 64-bit words.
    working_state[12] ^= byte_count & MASK_64
    working_state[13] ^= (byte_count >> 64) & MASK_64
    # Invert word 14 for the last block, making final compression distinct.
    if is_final_block:
        working_state[14] ^= MASK_64

    # 3. Each round mixes four columns, then four diagonals of the grid.
    for round_index in range(ROUND_COUNT):
        schedule = MESSAGE_SCHEDULE[round_index % len(MESSAGE_SCHEDULE)]
        # Column phase: each call touches one vertical group of four words.
        mix_words(working_state, 0, 4, 8, 12, message_words[schedule[0]], message_words[schedule[1]])
        mix_words(working_state, 1, 5, 9, 13, message_words[schedule[2]], message_words[schedule[3]])
        mix_words(working_state, 2, 6, 10, 14, message_words[schedule[4]], message_words[schedule[5]])
        mix_words(working_state, 3, 7, 11, 15, message_words[schedule[6]], message_words[schedule[7]])
        # Diagonal phase: connect words from different columns.
        mix_words(working_state, 0, 5, 10, 15, message_words[schedule[8]], message_words[schedule[9]])
        mix_words(working_state, 1, 6, 11, 12, message_words[schedule[10]], message_words[schedule[11]])
        mix_words(working_state, 2, 7, 8, 13, message_words[schedule[12]], message_words[schedule[13]])
        mix_words(working_state, 3, 4, 9, 14, message_words[schedule[14]], message_words[schedule[15]])

    # 4. Feed forward: XOR both working halves into the previous hash state.
    # This updated state becomes the starting state for the next block.
    for word_index in range(WORD_COUNT):
        hash_state[word_index] ^= working_state[word_index] ^ working_state[word_index + WORD_COUNT]


# ==============================================================================
# Complete-message hashing and output encoding (RFC 7693, Section 3.3)
# ==============================================================================

def _message_bytes(message: Union[bytes, bytearray, str]) -> bytes:
    """Encode text as UTF-8 or copy byte input into an immutable byte string.

    Lengths throughout the algorithm count encoded bytes, not characters.
    """
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, (bytes, bytearray)):
        return bytes(message)
    raise TypeError("message must be bytes, bytearray, or str")


def blake2b(
        message: Union[bytes, bytearray, str], digest_size: int = MAX_DIGEST_BYTES,
        key: Union[bytes, bytearray] = b"",
) -> bytes:
    """Return a BLAKE2b digest; optionally use a key for keyed hashing.

    Digest sizes from 1 to 64 bytes and keys from 0 to 64 bytes are supported.
    ``str`` messages are encoded as UTF-8. The digest size is part of the
    BLAKE2 parameter block, so shorter digests are not truncated BLAKE2b-512.
    """
    # 1. Normalize input and reject parameters outside this variant's limits.
    message_data = _message_bytes(message)
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes or bytearray")
    key_data = bytes(key)
    if isinstance(digest_size, bool) or not isinstance(digest_size, int):
        raise TypeError("digest_size must be an integer")
    if not 1 <= digest_size <= MAX_DIGEST_BYTES:
        raise ValueError("digest_size must be between 1 and 64 bytes")
    if len(key_data) > MAX_KEY_BYTES:
        raise ValueError("key must not exceed 64 bytes")
    if len(message_data) >= MAX_INPUT_BYTES:
        raise ValueError("message exceeds the BLAKE2b input length limit")

    # 2. Initialize with the parameter word p[0] = 0x0101kknn:
    #      nn = digest length, kk = key length (each occupies one byte).
    # The next two bytes select fanout=1 and depth=1: sequential hashing.
    # All other parameter words are zero, so only hash_state[0] changes.
    # Shifting key length left by 8 puts it in its own byte; XOR combines
    # these non-overlapping fields and then injects them into the IV.
    hash_state = INITIAL_VECTOR[:]
    hash_state[0] ^= 0x01010000 ^ (len(key_data) << 8) ^ digest_size

    # 3. A nonempty key occupies a separate, zero-filled first block.
    # Its FULL block length counts toward the byte counter. The original key
    # length is already encoded in the parameter word above.
    pending_data = (key_data + bytes(BLOCK_BYTES - len(key_data)) if key_data else b"") + message_data
    is_empty_unkeyed_input = not pending_data
    if is_empty_unkeyed_input:
        pending_data = b"\x00" * BLOCK_BYTES  # Empty unkeyed input still has one final block.

    # 4. Process all blocks except the final one. The strict > is essential:
    # an exactly full last block must receive the final flag, and does not
    # require an extra padding block. If only a key block exists, it is final.
    total_bytes = 0
    while len(pending_data) > BLOCK_BYTES:
        block = pending_data[:BLOCK_BYTES]
        pending_data = pending_data[BLOCK_BYTES:]
        total_bytes += BLOCK_BYTES
        compress_block(hash_state, block, total_bytes, False)

    # 5. Finalize with zero filling and the final flag. A short message block
    # contributes only its actual length to the counter. Empty unkeyed input
    # uses a zero-filled compression block with byte_count=0.
    # No 0x80 byte or encoded bit-length field is appended as in SHA-2.
    final_byte_count = 0 if is_empty_unkeyed_input else len(pending_data)
    total_bytes += final_byte_count
    final_block = pending_data + bytes(BLOCK_BYTES - final_byte_count)
    compress_block(hash_state, final_block, total_bytes, True)

    # 6. Serialize low bytes first and keep the requested digest length.
    # The same length influenced initialization, so requesting 16 bytes is
    # a different hash computation from taking 16 bytes of the default digest.
    return b"".join(word.to_bytes(WORD_BYTES, "little") for word in hash_state)[:digest_size]


def blake2b_hex(
        message: Union[bytes, bytearray, str], digest_size: int = MAX_DIGEST_BYTES,
        key: Union[bytes, bytearray] = b"",
) -> str:
    """Return the digest as readable hex: two characters for every byte.

    This changes only the display format; it performs the same BLAKE2b hash.
    """
    return blake2b(message, digest_size=digest_size, key=key).hex()


# ==============================================================================
# Command-line demonstration
# ==============================================================================

def main() -> None:
    """Hash UTF-8 text and display the corresponding SHA-2 digest for comparison."""
    parser = argparse.ArgumentParser(description="Pure-Python BLAKE2b teaching demo.")
    parser.add_argument("--text", default="The quick brown fox jumps over the lazy dog", help="Text to hash")
    parser.add_argument("--length", type=int, default=64, help="Digest length in bytes (1..64)")
    arguments = parser.parse_args()
    print(f"Message : {arguments.text!r}")
    print(f"BLAKE2b : {blake2b_hex(arguments.text, digest_size=arguments.length)}")
    print(f"SHA-512 : {hashlib.sha512(arguments.text.encode('utf-8')).hexdigest()}")
    print("BLAKE2b and SHA-512 use different constructions; the comparison is illustrative.")


if __name__ == "__main__":
    main()

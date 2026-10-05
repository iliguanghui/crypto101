"""MD5 (Message-Digest Algorithm 5) Implementation in Pure Python.

This module provides a clean, dependency-free reference implementation of the
MD5 algorithm following the specification in RFC 1321 and the pseudo-code on Wikipedia:
  - RFC 1321: https://www.rfc-editor.org/info/rfc1321/
  - Wikipedia: https://en.wikipedia.org/wiki/MD5#Algorithm

Key Design Goals:
  - Intuitive and readable: closely follows RFC 1321 and Wikipedia pseudo-code.
  - Primitive types only: uses standard Python integers, bytes, and bytearrays.
  - Step-by-step modular encapsulation: padding, auxiliary non-linear functions,
    block compression, and digest serialization.
  - Standard snake_case naming throughout.
  - Educational intermediate output tracing (verbose mode).
  - Bit-for-bit compatibility with RFC 1321 and Wikipedia test vectors.

Usage:
  python md5_demo.py
  python verify_md5.py
"""

import math
import argparse
from typing import List, Tuple, Union

# ==============================================================================
# Constants (RFC 1321 Section 3.3, 3.4 & Wikipedia)
# ==============================================================================

# 32-bit and 64-bit integer masks
MASK_32: int = 0xFFFFFFFF
MASK_64: int = 0xFFFFFFFFFFFFFFFF

# Initial state variables (RFC 1321 Section 3.3 / Wikipedia)
# Represented in 32-bit unsigned integers:
#   word A: 0x67452301
#   word B: 0xefcdab89
#   word C: 0x98badcfe
#   word D: 0x10325476
INIT_A: int = 0x67452301
INIT_B: int = 0xEFCDAB89
INIT_C: int = 0x98BADCFE
INIT_D: int = 0x10325476

# Per-round shift amounts s[0..63] (RFC 1321 Section 3.4 / Wikipedia)
# 4 rounds of 16 operations each
SHIFT_AMOUNTS: List[int] = [
    # Round 1 (operations 0..15)
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    # Round 2 (operations 16..31)
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    # Round 3 (operations 32..47)
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    # Round 4 (operations 48..63)
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

# Table K of 64 elements derived from the sine function (RFC 1321 Table T):
#   K[i] = floor(2^32 * abs(sin(i + 1))) for i = 0..63 (where i+1 is in radians)
K_TABLE: List[int] = [
    int(math.floor(2 ** 32 * abs(math.sin(i + 1)))) for i in range(64)
]


# ==============================================================================
# Bitwise and Auxiliary Functions (RFC 1321 Section 3.4)
# ==============================================================================

def left_rotate(x: int, c: int) -> int:
    """Performs a 32-bit circular left shift: (x <<< c)."""
    x = x & MASK_32
    return ((x << c) | (x >> (32 - c))) & MASK_32


def f_func(x: int, y: int, z: int) -> int:
    """Round 1 auxiliary function: (X AND Y) OR (NOT X AND Z).

    In each bit position, F acts as a conditional: if X then Y else Z.
    """
    return ((x & y) | (~x & z)) & MASK_32


def g_func(x: int, y: int, z: int) -> int:
    """Round 2 auxiliary function: (X AND Z) OR (Y AND NOT Z).

    In each bit position, G acts as a conditional: if Z then X else Y.
    """
    return ((x & z) | (y & ~z)) & MASK_32


def h_func(x: int, y: int, z: int) -> int:
    """Round 3 auxiliary function: X XOR Y XOR Z.

    Bitwise parity function.
    """
    return (x ^ y ^ z) & MASK_32


def i_func(x: int, y: int, z: int) -> int:
    """Round 4 auxiliary function: Y XOR (X OR NOT Z)."""
    # Note: in Python, ~z must be masked to 32 bits to prevent negative sign extension
    not_z = z ^ MASK_32
    return (y ^ (x | not_z)) & MASK_32


# ==============================================================================
# Message Padding (RFC 1321 Section 3.1 & 3.2)
# ==============================================================================

def pad_message(message: bytes, verbose: bool = False) -> bytes:
    """Pads the input message according to RFC 1321 Step 1 and Step 2.

    Step 1. Append Padding Bits:
      The message is extended ("padded") so that its length in bits is
      congruent to 448, modulo 512 (i.e. length in bytes congruent to 56 mod 64).
      A single '1' bit is appended, followed by '0' bits.

    Step 2. Append Length:
      A 64-bit representation of the original message length in bits is
      appended as two 32-bit words in little-endian byte order.

    Returns:
      Padded byte string whose length is an exact multiple of 64 bytes (512 bits).
    """
    original_byte_length = len(message)
    original_bit_length = (original_byte_length * 8) & MASK_64

    # Copy message into a mutable bytearray
    padded = bytearray(message)

    # Append '1' bit: in byte format, 1 followed by seven 0 bits is 0x80
    padded.append(0x80)

    # Append '0' bytes until length in bytes is 56 mod 64 (448 mod 512 bits)
    while len(padded) % 64 != 56:
        padded.append(0x00)

    # Append original length in bits as a 64-bit unsigned integer in little-endian
    padded.extend(original_bit_length.to_bytes(8, 'little'))

    if verbose:
        num_blocks = len(padded) // 64
        padding_bytes_added = len(padded) - original_byte_length
        print("\n--- Message Padding ---")
        print(f"Original Length: {original_byte_length} bytes ({original_byte_length * 8} bits)")
        print(
            f"Padding Added  : {padding_bytes_added} bytes (0x80 + {padding_bytes_added - 9} zero bytes + 8 bytes length)")
        print(f"Padded Length  : {len(padded)} bytes ({num_blocks} 512-bit block{'s' if num_blocks > 1 else ''})")

    return bytes(padded)


# ==============================================================================
# Compression Function: Process 512-Bit Block (RFC 1321 Section 3.4)
# ==============================================================================

def process_block(
        block: bytes,
        state: Tuple[int, int, int, int],
        block_index: int = 0,
        verbose: bool = False,
) -> Tuple[int, int, int, int]:
    """Processes a single 512-bit (64-byte) block and updates the 4 state registers.

    Following Wikipedia pseudo-code and RFC 1321 Section 3.4:
      1. Break 64-byte chunk into sixteen 32-bit words M[0..15] in little-endian.
      2. Initialize working registers (A, B, C, D) from state (a0, b0, c0, d0).
      3. Execute 64 steps across 4 rounds:
           - Round 1 (steps  0..15): F = (B & C) | (~B & D),        g = i
           - Round 2 (steps 16..31): F = (B & D) | (C & ~D),        g = (5*i + 1) mod 16
           - Round 3 (steps 32..47): F = B ^ C ^ D,                 g = (3*i + 5) mod 16
           - Round 4 (steps 48..63): F = C ^ (B | ~D),              g = (7*i) mod 16
         Register rotation:
           temp = B + left_rotate((A + F + K[i] + M[g]) mod 2^32, s[i])
           (A, B, C, D) = (D, temp, B, C)
      4. Add working registers back to state accumulator (modulo 2^32).

    Returns:
      Updated (a0, b0, c0, d0) tuple of 32-bit unsigned integers.
    """
    if len(block) != 64:
        raise ValueError(f"Block size must be exactly 64 bytes, got {len(block)}")

    a0, b0, c0, d0 = state

    # Step 1: Decode sixteen 32-bit little-endian words M[0..15]
    M: List[int] = [
        int.from_bytes(block[j * 4: (j + 1) * 4], 'little') for j in range(16)
    ]

    if verbose:
        print(f"\n{'=' * 65}")
        print(f"Processing Block #{block_index} (Offset: {block_index * 64}..{block_index * 64 + 64} bytes)")
        print(f"{'=' * 65}")
        print(f"State entering block: A=0x{a0:08x}, B=0x{b0:08x}, C=0x{c0:08x}, D=0x{d0:08x}")
        print("16 32-bit words M[0..15] (Little-Endian):")
        for row in range(4):
            indices = range(row * 4, row * 4 + 4)
            row_str = "  ".join(f"M[{idx:02d}]=0x{M[idx]:08x}" for idx in indices)
            print(f"  {row_str}")

    # Step 2: Initialize working registers
    A, B, C, D = a0, b0, c0, d0

    # Step 3: Main 64-step loop across 4 rounds
    for i in range(64):
        if 0 <= i <= 15:
            # Round 1
            f_val = f_func(B, C, D)
            g = i
        elif 16 <= i <= 31:
            # Round 2
            g_val = g_func(B, C, D)
            f_val = g_val
            g = (5 * i + 1) % 16
        elif 32 <= i <= 47:
            # Round 3
            h_val = h_func(B, C, D)
            f_val = h_val
            g = (3 * i + 5) % 16
        else:
            # Round 4
            i_val = i_func(B, C, D)
            f_val = i_val
            g = (7 * i) % 16

        # Core update operation
        # temp = (A + F + K[i] + M[g]) mod 2^32
        temp = (A + f_val + K_TABLE[i] + M[g]) & MASK_32
        rotated = left_rotate(temp, SHIFT_AMOUNTS[i])
        new_b = (B + rotated) & MASK_32

        # Rotate registers: (A, B, C, D) <- (D, new_b, B, C)
        A = D
        D = C
        C = B
        B = new_b

        # Output intermediate progress after each 16-step round
        if verbose and i in (15, 31, 47, 63):
            round_num = (i // 16) + 1
            print(
                f"  After Round {round_num} (step {i + 1:02d}/64): A=0x{A:08x}, B=0x{B:08x}, C=0x{C:08x}, D=0x{D:08x}")

    # Step 4: Add chunk results to accumulator (modulo 2^32)
    a0 = (a0 + A) & MASK_32
    b0 = (b0 + B) & MASK_32
    c0 = (c0 + C) & MASK_32
    d0 = (d0 + D) & MASK_32

    if verbose:
        print(f"State after block #{block_index} addition: A=0x{a0:08x}, B=0x{b0:08x}, C=0x{c0:08x}, D=0x{d0:08x}")

    return a0, b0, c0, d0


# ==============================================================================
# Top-Level MD5 Functions
# ==============================================================================

def md5(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 128-bit (16-byte) MD5 message digest of the input.

    Parameters:
      - message: The message to hash (bytes, bytearray, or UTF-8 str).
      - verbose: If True, prints step-by-step intermediate state values to console.

    Returns:
      16-byte MD5 digest in standard little-endian order.
    """
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    elif isinstance(message, (bytes, bytearray)):
        message_bytes = bytes(message)
    else:
        raise TypeError(f"message must be bytes, bytearray, or str, got {type(message).__name__}")

    if verbose:
        print("=" * 65)
        print("MD5 MESSAGE DIGEST COMPUTATION")
        print("=" * 65)
        sample = message_bytes[:32]
        # sample_str = sample.decode('utf-8', errors='replace')
        print(f"Input ({len(message_bytes)} bytes): {sample!r}{'...' if len(message_bytes) > 32 else ''}")

    # 1. Pad message
    padded = pad_message(message_bytes, verbose=verbose)

    # 2. Initialize state registers (A, B, C, D)
    state = (INIT_A, INIT_B, INIT_C, INIT_D)

    # 3. Process successive 512-bit (64-byte) chunks
    num_blocks = len(padded) // 64
    for block_index in range(num_blocks):
        block = padded[block_index * 64: (block_index + 1) * 64]
        state = process_block(block, state, block_index=block_index, verbose=verbose)

    # 4. Serialize final state as 16 bytes in little-endian order (RFC 1321 Section 3.5)
    a0, b0, c0, d0 = state
    digest = (
            a0.to_bytes(4, 'little')
            + b0.to_bytes(4, 'little')
            + c0.to_bytes(4, 'little')
            + d0.to_bytes(4, 'little')
    )

    if verbose:
        print("\n" + "=" * 65)
        print("FINAL RESULT")
        print("=" * 65)
        print(f"Accumulator words: a0=0x{a0:08x}, b0=0x{b0:08x}, c0=0x{c0:08x}, d0=0x{d0:08x}")
        print(f"Digest (hex)     : {digest.hex()}")
        print("=" * 65)

    return digest


def md5_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes the MD5 message digest and returns it as a 32-character lowercase hex string."""
    return md5(message, verbose=verbose).hex()


# ==============================================================================
# Standalone Demonstration
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Pure Python MD5 Reference Implementation (RFC 1321).")
    parser.add_argument("--text", type=str, default=None, help="Text to hash with MD5.")
    parser.add_argument("--verbose", action="store_true", help="Print intermediate values.")
    args = parser.parse_args()

    if args.text is not None:
        text_bytes = args.text.encode('utf-8')
        print(f"Hashing input text: {args.text!r}")
        digest = md5_hex(text_bytes, verbose=True)
        print(f"\nResult: MD5({args.text!r}) = {digest}")
        return

    # Default educational demo
    demo_text = "The quick brown fox jumps over the lazy dog"
    print("=" * 65)
    print("EDUCATIONAL MD5 DEMONSTRATION")
    print(f"Message: {demo_text!r}")
    print("=" * 65)

    digest_hex = md5_hex(demo_text, verbose=True)
    print(f"MD5({demo_text!r}) = {digest_hex}")

    print("\n" + "=" * 65)
    print("RFC 1321 & WIKIPEDIA STANDARD EXAMPLES")
    print("=" * 65)
    examples = [
        "",
        "a",
        "abc",
        "message digest",
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy dog.",
    ]
    for ex in examples:
        h = md5_hex(ex, verbose=False)
        print(f"MD5({ex!r:45s}) = {h}")


if __name__ == "__main__":
    main()

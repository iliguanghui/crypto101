"""SHA-1 (Secure Hash Algorithm 1) Implementation in Pure Python.

This module provides a clean, dependency-free reference implementation of the
SHA-1 algorithm following RFC 3174 and the Wikipedia specification:
  - RFC 3174: https://www.rfc-editor.org/info/rfc3174/
  - Wikipedia: https://en.wikipedia.org/wiki/SHA-1#Algorithm
  - FIPS PUB 180-1: Secure Hash Standard

Key Design Goals:
  - Intuitive and readable: matches RFC 3174 and Wikipedia pseudo-code.
  - Primitive types only: uses standard Python integers, bytes, and bytearrays.
  - Modular encapsulation: separates padding, message expansion, round functions,
    and block compression.
  - Standard snake_case naming throughout.
  - Educational commentary contrasting SHA-1 with its predecessor MD5.
  - Educational intermediate output tracing (verbose mode).
  - Bit-for-bit compatibility with RFC 3174 and Wikipedia test vectors.

Usage:
  python sha1_demo.py
  python sha1_demo.py --text "The quick brown fox jumps over the lazy dog"
  python verify_sha1.py
"""

import argparse
from typing import List, Tuple, Union

# ==============================================================================
# Constants (RFC 3174 Section 5, 6.1 & Wikipedia)
# ==============================================================================

# 32-bit and 64-bit integer masks
MASK_32: int = 0xFFFFFFFF
MASK_64: int = 0xFFFFFFFFFFFFFFFF

# Initial 32-bit hash values (RFC 3174 Section 6.1)
# [Difference from MD5]:
#   - MD5 uses 4 32-bit state words (128 bits total): A, B, C, D.
#   - SHA-1 uses 5 32-bit state words (160 bits total): H0, H1, H2, H3, H4.
#   - Note that H0..H3 are identical to MD5's initial values, and H4 was added
#     to provide an extra 32 bits of security margin.
INIT_H0: int = 0x67452301
INIT_H1: int = 0xEFCDAB89
INIT_H2: int = 0x98BADCFE
INIT_H3: int = 0x10325476
INIT_H4: int = 0xC3D2E1F0

# Round constants K_t (RFC 3174 Section 5)
# [Difference from MD5]:
#   - MD5 uses 64 distinct constants derived from abs(sin(i+1)).
#   - SHA-1 uses only 4 constants total (one per 20-step round), derived from
#     the fractional parts of sqrt(2), sqrt(3), sqrt(5), and sqrt(10).
K_ROUND_1: int = 0x5A827999  # Steps  0..19: floor(2^30 * sqrt(2))
K_ROUND_2: int = 0x6ED9EBA1  # Steps 20..39: floor(2^30 * sqrt(3))
K_ROUND_3: int = 0x8F1BBCDC  # Steps 40..59: floor(2^30 * sqrt(5))
K_ROUND_4: int = 0xCA62C1D6  # Steps 60..79: floor(2^30 * sqrt(10))


# ==============================================================================
# Bitwise and Non-Linear Auxiliary Functions (RFC 3174 Section 5)
# ==============================================================================

def left_rotate(x: int, c: int) -> int:
    """Performs a 32-bit circular left shift: (x <<< c).

    [Difference from MD5]:
      - In MD5, the rotation amount changes at every step using a 64-item table.
      - In SHA-1, rotation amounts in the main loop are strictly fixed:
        always (A <<< 5) and (B <<< 30).
    """
    x = x & MASK_32
    return ((x << c) | (x >> (32 - c))) & MASK_32


def f_func(t: int, b: int, c: int, d: int) -> int:
    """Computes the round non-linear function f_t(B, C, D) for step t in 0..79.

    [Difference from MD5]:
      - MD5 has 4 rounds of 16 steps (64 steps total).
      - SHA-1 has 4 rounds of 20 steps (80 steps total).
      - Round 1 (0..19):  (B & C) | (~B & D)             [Choice / Ch function, same as MD5 round 1]
      - Round 2 (20..39): B ^ C ^ D                      [Parity function, same as MD5 round 3]
      - Round 3 (40..59): (B & C) | (B & D) | (C & D)    [Majority / Maj function]
      - Round 4 (60..79): B ^ C ^ D                      [Parity function, reuses Round 2]
    """
    if 0 <= t <= 19:
        # Round 1: Choice function
        return ((b & c) | (~b & d)) & MASK_32
    elif 20 <= t <= 39:
        # Round 2: Parity function
        return (b ^ c ^ d) & MASK_32
    elif 40 <= t <= 59:
        # Round 3: Majority function
        return ((b & c) | (b & d) | (c & d)) & MASK_32
    elif 60 <= t <= 79:
        # Round 4: Parity function
        return (b ^ c ^ d) & MASK_32
    else:
        raise ValueError(f"Step t must be between 0 and 79, got {t}")


def get_k(t: int) -> int:
    """Returns the round constant K_t for step t in 0..79."""
    if 0 <= t <= 19:
        return K_ROUND_1
    elif 20 <= t <= 39:
        return K_ROUND_2
    elif 40 <= t <= 59:
        return K_ROUND_3
    elif 60 <= t <= 79:
        return K_ROUND_4
    else:
        raise ValueError(f"Step t must be between 0 and 79, got {t}")


# ==============================================================================
# Message Padding (RFC 3174 Section 4)
# ==============================================================================

def pad_message(message: bytes, verbose: bool = False) -> bytes:
    """Pads the input message according to RFC 3174 Section 4.

    Padding Procedure:
      1. Append a single '1' bit (represented by the byte 0x80).
      2. Append '0' bytes until the message length in bytes is congruent to
         56 modulo 64 (i.e. length in bits is congruent to 448 mod 512).
      3. Append the 64-bit original message length in bits as a BIG-ENDIAN integer.

    [Difference from MD5]:
      - In MD5, the 64-bit length is appended in LITTLE-ENDIAN order.
      - In SHA-1, the 64-bit length is appended in BIG-ENDIAN order.
    """
    original_byte_length = len(message)
    original_bit_length = (original_byte_length * 8) & MASK_64

    padded = bytearray(message)

    # Append '1' bit (0x80 = 10000000 in binary)
    padded.append(0x80)

    # Append '0' bytes until length in bytes is 56 mod 64 (448 mod 512 bits)
    while len(padded) % 64 != 56:
        padded.append(0x00)

    # Append 64-bit original bit length in BIG-ENDIAN order
    padded.extend(original_bit_length.to_bytes(8, 'big'))

    if verbose:
        num_blocks = len(padded) // 64
        padding_bytes_added = len(padded) - original_byte_length
        print("\n--- Message Padding ---")
        print(f"Original Length: {original_byte_length} bytes ({original_byte_length * 8} bits)")
        print(f"Padding Added  : {padding_bytes_added} bytes (0x80 + {padding_bytes_added - 9} zero bytes + 8 bytes length)")
        print(f"Length Encoding: Big-Endian 64-bit integer (0x{original_bit_length:016x})")
        print(f"Padded Length  : {len(padded)} bytes ({num_blocks} 512-bit block{'s' if num_blocks > 1 else ''})")

    return bytes(padded)


# ==============================================================================
# Message Schedule Expansion (RFC 3174 Section 6.1)
# ==============================================================================

def expand_message_schedule(chunk: bytes, verbose: bool = False) -> List[int]:
    """Expands a 64-byte (512-bit) chunk into 80 32-bit words W[0..79].

    RFC 3174 Section 6.1:
      - Words 0..15: Decoded directly from chunk as 16 32-bit BIG-ENDIAN integers.
      - Words 16..79: Generated via linear feedback recurrence:
          W[t] = (W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16]) <<< 1

    [Difference from MD5]:
      - MD5 has NO message schedule expansion. It keeps only the original 16 words
        and uses irregular modular permutation formulas (e.g. (5*i + 1) mod 16)
        to scramble access across rounds.
      - SHA-1 expands the 16 words into 80 words upfront, which allows the main loop
        to simply read W[t] sequentially without index shuffling.
      - [Note on SHA-0 vs SHA-1]: SHA-0 used W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16] without
        the 1-bit left circular shift. NSA introduced the 1-bit shift in SHA-1 to fix
        an unpublished differential cryptanalysis weakness.
    """
    if len(chunk) != 64:
        raise ValueError(f"Chunk must be 64 bytes, got {len(chunk)}")

    # Step 1: Decode first 16 words from chunk in BIG-ENDIAN
    w: List[int] = [
        int.from_bytes(chunk[j * 4 : (j + 1) * 4], 'big') for j in range(16)
    ]

    # Step 2: Expand to 80 words
    for t in range(16, 80):
        val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]
        w.append(left_rotate(val, 1))

    if verbose:
        print("16 Input Words W[0..15] (Big-Endian):")
        for row in range(4):
            indices = range(row * 4, row * 4 + 4)
            row_str = "  ".join(f"W[{idx:02d}]=0x{w[idx]:08x}" for idx in indices)
            print(f"  {row_str}")
        print(f"Expanded Message Schedule W[16..79] generated ({len(w)} words total).")
        print(f"  Sample: W[16]=0x{w[16]:08x}, W[40]=0x{w[40]:08x}, W[79]=0x{w[79]:08x}")

    return w


# ==============================================================================
# Block Compression Function (RFC 3174 Section 6.1)
# ==============================================================================

def process_block(
    block: bytes,
    state: Tuple[int, int, int, int, int],
    block_index: int = 0,
    verbose: bool = False,
) -> Tuple[int, int, int, int, int]:
    """Processes a single 512-bit (64-byte) block and updates the 5 state registers.

    Following RFC 3174 Section 6.1 (Method 1) and Wikipedia pseudo-code:
      1. Expand block into 80-word message schedule W[0..79].
      2. Initialize working variables (A, B, C, D, E) from current state (H0..H4).
      3. For t from 0 to 79:
           temp = ((A <<< 5) + f_t(B, C, D) + E + W[t] + K_t) mod 2^32
           E = D
           D = C
           C = B <<< 30
           B = A
           A = temp
      4. Add working variables back into accumulator state (modulo 2^32).

    [Difference from MD5]:
      - MD5 updates 4 working registers with asymmetric addition into B:
          temp = (A + f + K[i] + M[g])
          B = B + left_rotate(temp, s[i])
      - SHA-1 updates 5 working registers with a clean Feistel-like shift pipeline:
          E <- D <- C <- (B <<< 30) <- A <- temp
    """
    if len(block) != 64:
        raise ValueError(f"Block size must be exactly 64 bytes, got {len(block)}")

    h0, h1, h2, h3, h4 = state

    if verbose:
        print(f"\n{'=' * 70}")
        print(f"Processing Block #{block_index} (Offset: {block_index * 64}..{block_index * 64 + 64} bytes)")
        print(f"{'=' * 70}")
        print(
            f"State entering block: H0=0x{h0:08x}, H1=0x{h1:08x}, H2=0x{h2:08x}, H3=0x{h3:08x}, H4=0x{h4:08x}"
        )

    # Step 1: Expand message schedule
    w = expand_message_schedule(block, verbose=verbose)

    # Step 2: Initialize working variables
    a, b, c, d, e = h0, h1, h2, h3, h4

    # Step 3: 80-step main compression loop
    for t in range(80):
        f_val = f_func(t, b, c, d)
        k_val = get_k(t)

        temp = (left_rotate(a, 5) + f_val + e + k_val + w[t]) & MASK_32
        e = d
        d = c
        c = left_rotate(b, 30)
        b = a
        a = temp

        # Intermediate progress output after each 20-step round
        if verbose and t in (19, 39, 59, 79):
            round_num = (t // 20) + 1
            print(
                f"  After Round {round_num} (step {t + 1:02d}/80): "
                f"A=0x{a:08x}, B=0x{b:08x}, C=0x{c:08x}, D=0x{d:08x}, E=0x{e:08x}"
            )

    # Step 4: Add chunk results to accumulator (modulo 2^32)
    h0 = (h0 + a) & MASK_32
    h1 = (h1 + b) & MASK_32
    h2 = (h2 + c) & MASK_32
    h3 = (h3 + d) & MASK_32
    h4 = (h4 + e) & MASK_32

    if verbose:
        print(
            f"State after block #{block_index} addition: "
            f"H0=0x{h0:08x}, H1=0x{h1:08x}, H2=0x{h2:08x}, H3=0x{h3:08x}, H4=0x{h4:08x}"
        )

    return h0, h1, h2, h3, h4


# ==============================================================================
# Top-Level SHA-1 Functions
# ==============================================================================

def sha1(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 160-bit (20-byte) SHA-1 message digest of the input message.

    Parameters:
      - message: The message to hash (bytes, bytearray, or UTF-8 str).
      - verbose: If True, prints step-by-step intermediate state values to console.

    Returns:
      20-byte SHA-1 digest in standard BIG-ENDIAN order.
    """
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    elif isinstance(message, (bytes, bytearray)):
        message_bytes = bytes(message)
    else:
        raise TypeError(f"message must be bytes, bytearray, or str, got {type(message).__name__}")

    if verbose:
        print("=" * 70)
        print("SHA-1 MESSAGE DIGEST COMPUTATION")
        print("=" * 70)
        sample = message_bytes[:32]
        print(f"Input ({len(message_bytes)} bytes): {sample!r}{'...' if len(message_bytes) > 32 else ''}")

    # 1. Pad message
    padded = pad_message(message_bytes, verbose=verbose)

    # 2. Initialize 160-bit state (H0..H4)
    state = (INIT_H0, INIT_H1, INIT_H2, INIT_H3, INIT_H4)

    # 3. Process successive 512-bit (64-byte) chunks
    num_blocks = len(padded) // 64
    for block_index in range(num_blocks):
        block = padded[block_index * 64 : (block_index + 1) * 64]
        state = process_block(block, state, block_index=block_index, verbose=verbose)

    # 4. Serialize final state as 20 bytes in BIG-ENDIAN order (RFC 3174 Section 6.1)
    # [Difference from MD5]:
    #   MD5 serializes (A, B, C, D) as 16 bytes in little-endian.
    #   SHA-1 serializes (H0, H1, H2, H3, H4) as 20 bytes in big-endian.
    h0, h1, h2, h3, h4 = state
    digest = (
        h0.to_bytes(4, 'big')
        + h1.to_bytes(4, 'big')
        + h2.to_bytes(4, 'big')
        + h3.to_bytes(4, 'big')
        + h4.to_bytes(4, 'big')
    )

    if verbose:
        print("\n" + "=" * 70)
        print("FINAL RESULT")
        print("=" * 70)
        print(
            f"Accumulator words: H0=0x{h0:08x}, H1=0x{h1:08x}, H2=0x{h2:08x}, H3=0x{h3:08x}, H4=0x{h4:08x}"
        )
        print(f"Digest (hex)     : {digest.hex()}")
        print(f"Digest Length    : {len(digest)} bytes (160 bits)")
        print("=" * 70)

    return digest


def sha1_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes the SHA-1 message digest and returns it as a 40-character lowercase hex string."""
    return sha1(message, verbose=verbose).hex()


# ==============================================================================
# Standalone Demonstration
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Pure Python SHA-1 Reference Implementation (RFC 3174).")
    parser.add_argument("--text", type=str, default=None, help="Text to hash with SHA-1.")
    parser.add_argument("--verbose", action="store_true", help="Print intermediate calculation values.")
    args = parser.parse_args()

    if args.text is not None:
        text_bytes = args.text.encode('utf-8')
        print(f"Hashing input text: {args.text!r}")
        digest = sha1_hex(text_bytes, verbose=True)
        print(f"\nResult: SHA-1({args.text!r}) = {digest}")
        return

    # Default educational demo
    demo_text = "The quick brown fox jumps over the lazy dog"
    print("=" * 70)
    print("EDUCATIONAL SHA-1 DEMONSTRATION")
    print(f"Message: {demo_text!r}")
    print("=" * 70)

    digest_hex = sha1_hex(demo_text, verbose=True)
    print(f"SHA-1({demo_text!r}) = {digest_hex}")

    print("\n" + "=" * 70)
    print("RFC 3174 & WIKIPEDIA STANDARD EXAMPLES")
    print("=" * 70)
    examples = [
        "",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy cog",
    ]
    for ex in examples:
        h = sha1_hex(ex, verbose=False)
        print(f"SHA-1({ex!r:58s}) = {h}")


if __name__ == "__main__":
    main()

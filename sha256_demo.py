"""SHA-256 and SHA-224 (SHA-2 32-bit Word Family) Implementation in Pure Python.

This module provides a clean, dependency-free reference implementation of the
SHA-256 and SHA-224 cryptographic hash algorithms specified in FIPS PUB 180-4
and RFC 6234:
  - RFC 6234: https://www.rfc-editor.org/info/rfc6234/
  - Wikipedia: https://en.wikipedia.org/wiki/SHA-2

Architecture Overview:
  SHA-256 and SHA-224 share the exact same 32-bit core compression function:
    - 512-bit (64-byte) block size.
    - 64 rounds of non-linear mixing.
    - 64 32-bit round constants derived from the cube roots of the first 64 primes.
    - Big-endian byte ordering throughout.
  The only differences between SHA-256 and SHA-224 are:
    1. Initial hash values: SHA-224 uses a different initial state H^(0).
    2. Output truncation: SHA-224 truncates the final 256-bit state to 224 bits
       (dropping the 8th word H7).

Architectural Comparison with SHA-1 (when implementing SHA-256):
  1. Internal State:
     - SHA-1: 160 bits (5 32-bit words: A, B, C, D, E).
     - SHA-256: 256 bits (8 32-bit words: A, B, C, D, E, F, G, H).
  2. Number of Rounds:
     - SHA-1: 80 rounds (4 rounds of 20 steps).
     - SHA-256: 64 rounds.
  3. Message Expansion:
     - SHA-1: Linear expansion using only XOR and 1-bit rotation:
         W[t] = (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]) <<< 1
     - SHA-256: Non-linear expansion using sigma functions with right rotations and shifts:
         W[t] = (small_sigma1(W[t-2]) + W[t-7] + small_sigma0(W[t-15]) + W[t-16]) mod 2^32
  4. Round Step Updates:
     - SHA-1: Updates only ONE register per step (A <- temp, while others shift).
     - SHA-256: Computes TWO temporary variables (T1, T2) and updates TWO registers per step:
         e <- (d + T1) mod 2^32
         a <- (T1 + T2) mod 2^32
  5. Round Constants:
     - SHA-1: Only 4 constants total (one per 20-step quarter).
     - SHA-256: 64 distinct 32-bit constants (one per step, cube roots of primes).
  6. Collision Security:
     - SHA-1: Broken (theoretical ~2^63, practical collisions found in 2017 SHAttered).
     - SHA-256: 128-bit collision resistance, widely trusted standard worldwide.

Architectural Comparison with SHA-256 (when implementing SHA-224):
  1. Core Engine: 100% identical compression function, padding, and round constants.
  2. Initial Hash State: SHA-224 uses different initial constants (fractional parts of
     the square roots of the 9th through 16th primes: 23, 29, 31, 37, 41, 43, 47, 53).
  3. Output Size: SHA-256 outputs all 8 words (32 bytes / 256 bits).
     SHA-224 truncates the final state to the first 7 words H0..H6 (28 bytes / 224 bits),
     discarding H7.
  4. Length Extension Attack Immunity:
     Because SHA-224 discards 32 bits of internal state in the output, an attacker
     cannot directly reconstruct the full internal state to perform a standard
     length-extension attack, making SHA-224 naturally resistant.

Usage:
  python sha256_demo.py
  python sha256_demo.py --text "The quick brown fox jumps over the lazy dog"
  python verify_sha2.py
"""

import argparse
from typing import List, Tuple, Union

# ==============================================================================
# Constants (RFC 6234 Section 5.1 & 6.1, FIPS PUB 180-4)
# ==============================================================================

MASK_32: int = 0xFFFFFFFF
MASK_64: int = 0xFFFFFFFFFFFFFFFF

# SHA-256 Initial Hash State H^(0) (RFC 6234 Section 6.1):
# First 32 bits of the fractional parts of the square roots of the first 8 primes (2..19).
INIT_H_256: Tuple[int, ...] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

# SHA-224 Initial Hash State H^(0) (RFC 6234 Section 6.1):
# Second 32 bits of the fractional parts of the square roots of the 9th..16th primes (23..53).
INIT_H_224: Tuple[int, ...] = (
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
)

# SHA-256 / SHA-224 Round Constants K[0..63] (RFC 6234 Section 5.1):
# First 32 bits of the fractional parts of the cube roots of the first 64 prime numbers (2..311).
K_TABLE_256: List[int] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


# ==============================================================================
# Bitwise and Non-Linear Auxiliary Functions (RFC 6234 Section 5.1)
# ==============================================================================

def rotr32(x: int, n: int) -> int:
    """32-bit circular right shift: (x >>> n)."""
    x = x & MASK_32
    return ((x >> n) | (x << (32 - n))) & MASK_32


def ch32(x: int, y: int, z: int) -> int:
    """Choice function: Ch(x, y, z) = (x AND y) XOR (NOT x AND z).

    In each bit position, if x is 1, chooses y; if x is 0, chooses z.
    Same logical function as in MD5 and SHA-1.
    """
    return ((x & y) ^ ((~x & MASK_32) & z)) & MASK_32


def maj32(x: int, y: int, z: int) -> int:
    """Majority function: Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z).

    Outputs 1 if at least two of the three bits are 1. Same as SHA-1 Round 3.
    """
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK_32


def big_sigma0_32(x: int) -> int:
    """Upper-case Sigma 0 for SHA-256: ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x).

    Provides diffusion across the working variable 'a'.
    """
    return (rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)) & MASK_32


def big_sigma1_32(x: int) -> int:
    """Upper-case Sigma 1 for SHA-256: ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x).

    Provides diffusion across the working variable 'e'.
    """
    return (rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)) & MASK_32


def small_sigma0_32(x: int) -> int:
    """Lower-case sigma 0 for SHA-256 message expansion:
    ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x).

    Notice the last term is a logical right shift (SHR), not circular rotation.
    This injects asymmetry into the message schedule.
    """
    return (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)) & MASK_32


def small_sigma1_32(x: int) -> int:
    """Lower-case sigma 1 for SHA-256 message expansion:
    ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x).

    Notice the last term is a logical right shift (SHR), not circular rotation.
    """
    return (rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)) & MASK_32


# ==============================================================================
# Message Padding (512-bit Block Family: RFC 6234 Section 4.1)
# ==============================================================================

def pad_message_512(message: bytes, verbose: bool = False) -> bytes:
    """Pads message for 512-bit block hashes (SHA-224 and SHA-256).

    Procedure:
      1. Append a single '1' bit (0x80 byte).
      2. Append '0' bytes until length in bytes is 56 mod 64 (448 mod 512 bits).
      3. Append 64-bit original message bit length in BIG-ENDIAN byte order.
    """
    original_byte_length = len(message)
    original_bit_length = (original_byte_length * 8) & MASK_64

    padded = bytearray(message)
    padded.append(0x80)

    while len(padded) % 64 != 56:
        padded.append(0x00)

    padded.extend(original_bit_length.to_bytes(8, 'big'))

    if verbose:
        num_blocks = len(padded) // 64
        padding_bytes_added = len(padded) - original_byte_length
        print("\n--- Message Padding (512-bit Block) ---")
        print(f"Original Length: {original_byte_length} bytes ({original_byte_length * 8} bits)")
        print(f"Padding Added  : {padding_bytes_added} bytes (0x80 + {padding_bytes_added - 9} zero bytes + 8 bytes length)")
        print(f"Length Field   : Big-Endian 64-bit integer (0x{original_bit_length:016x})")
        print(f"Padded Length  : {len(padded)} bytes ({num_blocks} 512-bit block{'s' if num_blocks > 1 else ''})")

    return bytes(padded)


# ==============================================================================
# Message Schedule Expansion (RFC 6234 Section 6.2)
# ==============================================================================

def expand_message_schedule_32(chunk: bytes, verbose: bool = False) -> List[int]:
    """Expands a 64-byte (512-bit) chunk into 64 32-bit words W[0..63].

    Procedure:
      - W[0..15]: 16 32-bit big-endian integers decoded directly from chunk.
      - W[16..63]: Generated via non-linear recurrence:
          W[t] = (small_sigma1(W[t-2]) + W[t-7] + small_sigma0(W[t-15]) + W[t-16]) mod 2^32

    [Comparison with SHA-1]:
      SHA-1 used a simple linear XOR recurrence: W[t] = (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]) <<< 1.
      SHA-256 uses modular addition plus non-linear sigma functions with right shifts,
      making the schedule substantially more resistant to differential cryptanalysis.
    """
    if len(chunk) != 64:
        raise ValueError(f"Chunk must be 64 bytes, got {len(chunk)}")

    w: List[int] = [
        int.from_bytes(chunk[j * 4 : (j + 1) * 4], 'big') for j in range(16)
    ]

    for t in range(16, 64):
        s0 = small_sigma0_32(w[t - 15])
        s1 = small_sigma1_32(w[t - 2])
        w_val = (s1 + w[t - 7] + s0 + w[t - 16]) & MASK_32
        w.append(w_val)

    if verbose:
        print("16 Input Words W[0..15] (Big-Endian):")
        for row in range(4):
            indices = range(row * 4, row * 4 + 4)
            row_str = "  ".join(f"W[{idx:02d}]=0x{w[idx]:08x}" for idx in indices)
            print(f"  {row_str}")
        print(f"Expanded Message Schedule W[16..63] generated (64 words total).")
        print(f"  Sample: W[16]=0x{w[16]:08x}, W[32]=0x{w[32]:08x}, W[63]=0x{w[63]:08x}")

    return w


# ==============================================================================
# Block Compression Function (RFC 6234 Section 6.2)
# ==============================================================================

def process_block_256(
    block: bytes,
    state: Tuple[int, ...],
    block_index: int = 0,
    verbose: bool = False,
) -> Tuple[int, ...]:
    """Processes a single 512-bit (64-byte) block and updates 8 32-bit state registers.

    Procedure (RFC 6234 Section 6.2):
      1. Expand block into 64-word schedule W[0..63].
      2. Initialize working registers (a, b, c, d, e, f, g, h) from state.
      3. For t from 0 to 63:
           T1 = (h + big_sigma1(e) + Ch(e, f, g) + K[t] + W[t]) mod 2^32
           T2 = (big_sigma0(a) + Maj(a, b, c)) mod 2^32
           h = g
           g = f
           f = e
           e = (d + T1) mod 2^32
           d = c
           c = b
           b = a
           a = (T1 + T2) mod 2^32
      4. Add working registers back to state accumulator (modulo 2^32).

    [Comparison with SHA-1]:
      SHA-1 only updated ONE register (A <- temp), while B, C, D, E simply shifted.
      SHA-256 updates TWO registers per step: e <- (d + T1) and a <- (T1 + T2),
      providing twice the diffusion speed per round.
    """
    if len(block) != 64:
        raise ValueError(f"Block size must be 64 bytes, got {len(block)}")

    h0, h1, h2, h3, h4, h5, h6, h7 = state

    if verbose:
        print(f"\n{'=' * 72}")
        print(f"Processing Block #{block_index} (Offset: {block_index * 64}..{block_index * 64 + 64} bytes)")
        print(f"{'=' * 72}")
        print(f"State entering block:")
        print(f"  H0=0x{h0:08x}, H1=0x{h1:08x}, H2=0x{h2:08x}, H3=0x{h3:08x}")
        print(f"  H4=0x{h4:08x}, H5=0x{h5:08x}, H6=0x{h6:08x}, H7=0x{h7:08x}")

    w = expand_message_schedule_32(block, verbose=verbose)

    a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

    for t in range(64):
        s1 = big_sigma1_32(e)
        ch_val = ch32(e, f, g)
        t1 = (h + s1 + ch_val + K_TABLE_256[t] + w[t]) & MASK_32

        s0 = big_sigma0_32(a)
        maj_val = maj32(a, b, c)
        t2 = (s0 + maj_val) & MASK_32

        h = g
        g = f
        f = e
        e = (d + t1) & MASK_32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK_32

        if verbose and t in (15, 31, 47, 63):
            round_quarter = (t // 16) + 1
            print(f"  After Step {t + 1:02d}/64 (Quarter {round_quarter}):")
            print(f"    a=0x{a:08x}, b=0x{b:08x}, c=0x{c:08x}, d=0x{d:08x}")
            print(f"    e=0x{e:08x}, f=0x{f:08x}, g=0x{g:08x}, h=0x{h:08x}")

    h0 = (h0 + a) & MASK_32
    h1 = (h1 + b) & MASK_32
    h2 = (h2 + c) & MASK_32
    h3 = (h3 + d) & MASK_32
    h4 = (h4 + e) & MASK_32
    h5 = (h5 + f) & MASK_32
    h6 = (h6 + g) & MASK_32
    h7 = (h7 + h) & MASK_32

    if verbose:
        print(f"State after block #{block_index} addition:")
        print(f"  H0=0x{h0:08x}, H1=0x{h1:08x}, H2=0x{h2:08x}, H3=0x{h3:08x}")
        print(f"  H4=0x{h4:08x}, H5=0x{h5:08x}, H6=0x{h6:08x}, H7=0x{h7:08x}")

    return h0, h1, h2, h3, h4, h5, h6, h7


# ==============================================================================
# Generic Engine for 32-bit SHA-2 Family
# ==============================================================================

def sha256_base(
    message: Union[bytes, bytearray, str],
    init_state: Tuple[int, ...],
    output_words: int,
    algo_name: str,
    verbose: bool = False,
) -> bytes:
    """Common driver engine for SHA-256 (8 words output) and SHA-224 (7 words output)."""
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    elif isinstance(message, (bytes, bytearray)):
        message_bytes = bytes(message)
    else:
        raise TypeError(f"message must be bytes, bytearray, or str, got {type(message).__name__}")

    if verbose:
        print("=" * 72)
        print(f"{algo_name} MESSAGE DIGEST COMPUTATION")
        print("=" * 72)
        sample = message_bytes[:32]
        print(f"Input ({len(message_bytes)} bytes): {sample!r}{'...' if len(message_bytes) > 32 else ''}")

    # 1. Pad message to 512-bit block boundary
    padded = pad_message_512(message_bytes, verbose=verbose)

    # 2. Initialize 8-word 32-bit state
    state = init_state

    # 3. Process successive 512-bit (64-byte) blocks
    num_blocks = len(padded) // 64
    for block_index in range(num_blocks):
        block = padded[block_index * 64 : (block_index + 1) * 64]
        state = process_block_256(block, state, block_index=block_index, verbose=verbose)

    # 4. Serialize specified number of words in big-endian order
    digest = b''.join(w.to_bytes(4, 'big') for w in state[:output_words])

    if verbose:
        print("\n" + "=" * 72)
        print(f"FINAL RESULT ({algo_name})")
        print("=" * 72)
        print(f"Digest (hex) : {digest.hex()}")
        print(f"Digest Length: {len(digest)} bytes ({len(digest) * 8} bits)")
        if output_words == 7:
            print("Truncation   : Retained first 7 words (H0..H6), dropped H7 per SHA-224 spec.")
        print("=" * 72)

    return digest


# ==============================================================================
# Public API: SHA-256 and SHA-224 Functions
# ==============================================================================

def sha256(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 256-bit (32-byte) SHA-256 message digest."""
    return sha256_base(
        message=message,
        init_state=INIT_H_256,
        output_words=8,
        algo_name="SHA-256",
        verbose=verbose,
    )


def sha256_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes the SHA-256 message digest as a 64-character lowercase hex string."""
    return sha256(message, verbose=verbose).hex()


def sha224(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 224-bit (28-byte) SHA-224 message digest."""
    return sha256_base(
        message=message,
        init_state=INIT_H_224,
        output_words=7,
        algo_name="SHA-224",
        verbose=verbose,
    )


def sha224_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes the SHA-224 message digest as a 56-character lowercase hex string."""
    return sha224(message, verbose=verbose).hex()


# ==============================================================================
# Standalone Demonstration
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Pure Python SHA-256 and SHA-224 Reference Implementation (RFC 6234).")
    parser.add_argument("--text", type=str, default=None, help="Text to hash with SHA-256 and SHA-224.")
    parser.add_argument("--verbose", action="store_true", help="Print intermediate calculation values.")
    args = parser.parse_args()

    if args.text is not None:
        text_bytes = args.text.encode('utf-8')
        print(f"Input text: {args.text!r}")
        d256 = sha256_hex(text_bytes, verbose=True)
        d224 = sha224_hex(text_bytes, verbose=False)
        print(f"\nResult:")
        print(f"  SHA-256: {d256}")
        print(f"  SHA-224: {d224}")
        return

    # Default educational demo
    demo_text = "The quick brown fox jumps over the lazy dog"
    print("=" * 72)
    print("EDUCATIONAL SHA-256 & SHA-224 DEMONSTRATION")
    print(f"Message: {demo_text!r}")
    print("=" * 72)

    # Detailed verbose run of SHA-256
    sha256_hex(demo_text, verbose=True)

    print("\n" + "=" * 72)
    print("STANDARD EXAMPLES (SHA-256 & SHA-224)")
    print("=" * 72)
    examples = [
        "",
        "abc",
        "The quick brown fox jumps over the lazy dog",
    ]
    for ex in examples:
        h256 = sha256_hex(ex, verbose=False)
        h224 = sha224_hex(ex, verbose=False)
        print(f"Message: {ex!r}")
        print(f"  SHA-256: {h256}")
        print(f"  SHA-224: {h224}")


if __name__ == "__main__":
    main()

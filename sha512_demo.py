"""SHA-512 and SHA-384 (SHA-2 64-bit Word Family) Implementation in Pure Python.

This module provides a clean, dependency-free reference implementation of the
SHA-512 and SHA-384 cryptographic hash algorithms specified in FIPS PUB 180-4
and RFC 6234:
  - RFC 6234: https://www.rfc-editor.org/info/rfc6234/
  - Wikipedia: https://en.wikipedia.org/wiki/SHA-2

Architecture Overview:
  SHA-512 and SHA-384 share the exact same 64-bit core compression function:
    - 1024-bit (128-byte) block size.
    - 80 rounds of non-linear mixing.
    - 80 64-bit round constants derived from the cube roots of the first 80 primes.
    - 128-bit big-endian length field appended during padding.
    - Big-endian byte ordering throughout.
  The only differences between SHA-512 and SHA-384 are:
    1. Initial hash values: SHA-384 uses a different initial state H^(0).
    2. Output truncation: SHA-384 truncates the final 512-bit state to 384 bits
       (dropping the 7th and 8th words H6 and H7).

Architectural Comparison with SHA-256 (when implementing SHA-512):
  1. Word Size & Arithmetic:
     - SHA-256 operates on 32-bit words (modulo 2^32 arithmetic).
     - SHA-512 operates on 64-bit words (modulo 2^64 arithmetic).
  2. Block Size:
     - SHA-256 block size is 512 bits (64 bytes, 16 32-bit words).
     - SHA-512 block size is 1024 bits (128 bytes, 16 64-bit words).
  3. Number of Rounds:
     - SHA-256 has 64 rounds (64 32-bit constants K[0..63]).
     - SHA-512 has 80 rounds (80 64-bit constants K[0..79]).
  4. Message Expansion and Schedule Size:
     - SHA-256 expands 16 32-bit words into 64 words W[0..63].
     - SHA-512 expands 16 64-bit words into 80 words W[0..79].
  5. Sigma Function Rotation Constants:
     - SHA-256:
         BSIG0(2, 13, 22), BSIG1(6, 11, 25)
         SSIG0(7, 18, shr 3), SSIG1(17, 19, shr 10)
     - SHA-512:
         BSIG0(28, 34, 39), BSIG1(14, 18, 41)
         SSIG0(1, 8, shr 7), SSIG1(19, 61, shr 6)
  6. Message Length Field in Padding:
     - SHA-256 appends a 64-bit (8-byte) big-endian length integer (up to 2^64 - 1 bits).
     - SHA-512 appends a 128-bit (16-byte) big-endian length integer (up to 2^128 - 1 bits).
  7. Computational Efficiency:
     - On modern 64-bit CPUs, SHA-512 hashes 128 bytes in 80 rounds (0.625 rounds/byte),
       compared to SHA-256 hashing 64 bytes in 64 rounds (1.0 rounds/byte). Hence,
       SHA-512 is frequently faster in hardware than SHA-256 for large payloads.
  8. Security Level:
     - SHA-256 provides 128-bit collision resistance (256-bit digest).
     - SHA-512 provides 256-bit collision resistance (512-bit digest).

Architectural Comparison with SHA-512 (when implementing SHA-384):
  1. Core Engine: 100% identical compression function, padding (1024-bit blocks with
     128-bit length), and 80 round constants.
  2. Initial Hash State: SHA-384 uses different initial constants (the first 64 bits
     of the fractional parts of the square roots of the 9th through 16th primes:
     23, 29, 31, 37, 41, 43, 47, 53).
  3. Output Size: SHA-512 outputs all 8 words (64 bytes / 512 bits).
     SHA-384 truncates the final state to the first 6 words H0..H5 (48 bytes / 384 bits),
     discarding H6 and H7.
  4. Length Extension Attack Immunity:
     Because SHA-384 drops 128 bits of internal state (H6 and H7) from its final output,
     an attacker cannot determine the full 512-bit internal state from the digest.
     Therefore, SHA-384 is naturally immune to length extension attacks without needing HMAC.
  5. Collision Security:
     SHA-384 provides 192-bit collision resistance.

Usage:
  python sha512_demo.py
  python sha512_demo.py --text "The quick brown fox jumps over the lazy dog"
  python verify_sha2.py
"""

import argparse
from typing import List, Tuple, Union

# ==============================================================================
# Constants (RFC 6234 Section 5.2 & 6.3, FIPS PUB 180-4)
# ==============================================================================

MASK_64: int = 0xFFFFFFFFFFFFFFFF
MASK_128: int = (1 << 128) - 1

# SHA-512 Initial Hash State H^(0) (RFC 6234 Section 6.3):
# First 64 bits of the fractional parts of the square roots of the first 8 primes (2..19).
INIT_H_512: Tuple[int, ...] = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

# SHA-384 Initial Hash State H^(0) (RFC 6234 Section 6.3):
# First 64 bits of the fractional parts of the square roots of the 9th..16th primes (23..53).
INIT_H_384: Tuple[int, ...] = (
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
)

# SHA-512 / SHA-384 Round Constants K[0..79] (RFC 6234 Section 5.2):
# First 64 bits of the fractional parts of the cube roots of the first 80 prime numbers (2..409).
K_TABLE_512: List[int] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
]


# ==============================================================================
# Bitwise and Non-Linear Auxiliary Functions (RFC 6234 Section 5.2)
# ==============================================================================

def rotr64(x: int, n: int) -> int:
    """64-bit circular right shift: (x >>> n)."""
    x = x & MASK_64
    return ((x >> n) | (x << (64 - n))) & MASK_64


def ch64(x: int, y: int, z: int) -> int:
    """Choice function: Ch(x, y, z) = (x AND y) XOR (NOT x AND z).

    In each bit position, if x is 1, chooses y; if x is 0, chooses z.
    Same bitwise logic as in SHA-256, but operating on 64-bit registers.
    """
    return ((x & y) ^ ((~x & MASK_64) & z)) & MASK_64


def maj64(x: int, y: int, z: int) -> int:
    """Majority function: Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z).

    Outputs 1 if at least two of the three bits are 1.
    Same bitwise logic as in SHA-256, operating on 64-bit registers.
    """
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK_64


def big_sigma0_64(x: int) -> int:
    """Upper-case Sigma 0 for SHA-512: ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x).

    Provides diffusion across the working variable 'a'.
    [Comparison with SHA-256]:
      SHA-256 uses rotations by (2, 13, 22). SHA-512 uses (28, 34, 39) for 64-bit diffusion.
    """
    return (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39)) & MASK_64


def big_sigma1_64(x: int) -> int:
    """Upper-case Sigma 1 for SHA-512: ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x).

    Provides diffusion across the working variable 'e'.
    [Comparison with SHA-256]:
      SHA-256 uses rotations by (6, 11, 25). SHA-512 uses (14, 18, 41) for 64-bit diffusion.
    """
    return (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41)) & MASK_64


def small_sigma0_64(x: int) -> int:
    """Lower-case sigma 0 for SHA-512 message expansion:
    ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x).

    Notice the last term is a logical right shift (SHR), not circular rotation.
    [Comparison with SHA-256]:
      SHA-256 uses ROTR^7, ROTR^18, SHR^3. SHA-512 uses ROTR^1, ROTR^8, SHR^7.
    """
    return (rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)) & MASK_64


def small_sigma1_64(x: int) -> int:
    """Lower-case sigma 1 for SHA-512 message expansion:
    ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x).

    Notice the last term is a logical right shift (SHR), not circular rotation.
    [Comparison with SHA-256]:
      SHA-256 uses ROTR^17, ROTR^19, SHR^10. SHA-512 uses ROTR^19, ROTR^61, SHR^6.
    """
    return (rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6)) & MASK_64


# ==============================================================================
# Message Padding (1024-bit Block Family: RFC 6234 Section 4.2)
# ==============================================================================

def pad_message_1024(message: bytes, verbose: bool = False) -> bytes:
    """Pads message for 1024-bit block hashes (SHA-384 and SHA-512).

    Procedure (RFC 6234 Section 4.2):
      1. Append a single '1' bit (0x80 byte).
      2. Append '0' bytes until length in bytes is 112 mod 128 (896 mod 1024 bits).
      3. Append 128-bit original message bit length in BIG-ENDIAN byte order (16 bytes).

    [Comparison with SHA-256]:
      - SHA-256 pads to 56 mod 64 bytes (448 mod 512 bits) and appends an 8-byte (64-bit) length.
      - SHA-512 pads to 112 mod 128 bytes (896 mod 1024 bits) and appends a 16-byte (128-bit) length.
    """
    original_byte_length = len(message)
    original_bit_length = (original_byte_length * 8) & MASK_128

    padded = bytearray(message)
    padded.append(0x80)

    while len(padded) % 128 != 112:
        padded.append(0x00)

    padded.extend(original_bit_length.to_bytes(16, 'big'))

    if verbose:
        num_blocks = len(padded) // 128
        padding_bytes_added = len(padded) - original_byte_length
        print("\n--- Message Padding (1024-bit Block) ---")
        print(f"Original Length: {original_byte_length} bytes ({original_byte_length * 8} bits)")
        print(f"Padding Added  : {padding_bytes_added} bytes (0x80 + {padding_bytes_added - 17} zero bytes + 16 bytes length)")
        print(f"Length Field   : Big-Endian 128-bit integer (0x{original_bit_length:032x})")
        print(f"Padded Length  : {len(padded)} bytes ({num_blocks} 1024-bit block{'s' if num_blocks > 1 else ''})")

    return bytes(padded)


# ==============================================================================
# Message Schedule Expansion (RFC 6234 Section 6.4)
# ==============================================================================

def expand_message_schedule_64(chunk: bytes, verbose: bool = False) -> List[int]:
    """Expands a 128-byte (1024-bit) chunk into 80 64-bit words W[0..79].

    Procedure:
      - W[0..15]: 16 64-bit big-endian integers decoded directly from chunk.
      - W[16..79]: Generated via non-linear recurrence:
          W[t] = (small_sigma1(W[t-2]) + W[t-7] + small_sigma0(W[t-15]) + W[t-16]) mod 2^64

    [Comparison with SHA-256]:
      SHA-256 expanded to 64 32-bit words. SHA-512 expands to 80 64-bit words,
      accommodating 80 compression rounds.
    """
    if len(chunk) != 128:
        raise ValueError(f"Chunk must be 128 bytes, got {len(chunk)}")

    w: List[int] = [
        int.from_bytes(chunk[j * 8 : (j + 1) * 8], 'big') for j in range(16)
    ]

    for t in range(16, 80):
        s0 = small_sigma0_64(w[t - 15])
        s1 = small_sigma1_64(w[t - 2])
        w_val = (s1 + w[t - 7] + s0 + w[t - 16]) & MASK_64
        w.append(w_val)

    if verbose:
        print("16 Input Words W[0..15] (Big-Endian, 64-bit):")
        for row in range(4):
            indices = range(row * 4, row * 4 + 4)
            row_str = "  ".join(f"W[{idx:02d}]=0x{w[idx]:016x}" for idx in indices)
            print(f"  {row_str}")
        print(f"Expanded Message Schedule W[16..79] generated (80 words total).")
        print(f"  Sample: W[16]=0x{w[16]:016x}, W[40]=0x{w[40]:016x}, W[79]=0x{w[79]:016x}")

    return w


# ==============================================================================
# Block Compression Function (RFC 6234 Section 6.4)
# ==============================================================================

def process_block_512(
    block: bytes,
    state: Tuple[int, ...],
    block_index: int = 0,
    verbose: bool = False,
) -> Tuple[int, ...]:
    """Processes a single 1024-bit (128-byte) block and updates 8 64-bit state registers.

    Procedure (RFC 6234 Section 6.4):
      1. Expand block into 80-word schedule W[0..79].
      2. Initialize working registers (a, b, c, d, e, f, g, h) from state.
      3. For t from 0 to 79:
           T1 = (h + big_sigma1(e) + Ch(e, f, g) + K[t] + W[t]) mod 2^64
           T2 = (big_sigma0(a) + Maj(a, b, c)) mod 2^64
           h = g
           g = f
           f = e
           e = (d + T1) mod 2^64
           d = c
           c = b
           b = a
           a = (T1 + T2) mod 2^64
      4. Add working registers back to state accumulator (modulo 2^64).

    [Comparison with SHA-256]:
      - Operates over 80 rounds instead of 64 rounds.
      - Uses 64-bit registers throughout instead of 32-bit registers.
      - Exact same dual-accumulator structure (T1 and T2 updating e and a).
    """
    if len(block) != 128:
        raise ValueError(f"Block size must be 128 bytes, got {len(block)}")

    h0, h1, h2, h3, h4, h5, h6, h7 = state

    if verbose:
        print(f"\n{'=' * 72}")
        print(f"Processing Block #{block_index} (Offset: {block_index * 128}..{block_index * 128 + 128} bytes)")
        print(f"{'=' * 72}")
        print(f"State entering block:")
        print(f"  H0=0x{h0:016x}, H1=0x{h1:016x}")
        print(f"  H2=0x{h2:016x}, H3=0x{h3:016x}")
        print(f"  H4=0x{h4:016x}, H5=0x{h5:016x}")
        print(f"  H6=0x{h6:016x}, H7=0x{h7:016x}")

    w = expand_message_schedule_64(block, verbose=verbose)

    a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

    for t in range(80):
        s1 = big_sigma1_64(e)
        ch_val = ch64(e, f, g)
        t1 = (h + s1 + ch_val + K_TABLE_512[t] + w[t]) & MASK_64

        s0 = big_sigma0_64(a)
        maj_val = maj64(a, b, c)
        t2 = (s0 + maj_val) & MASK_64

        h = g
        g = f
        f = e
        e = (d + t1) & MASK_64
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK_64

        if verbose and t in (19, 39, 59, 79):
            round_quarter = (t // 20) + 1
            print(f"  After Step {t + 1:02d}/80 (Quarter {round_quarter}):")
            print(f"    a=0x{a:016x}, b=0x{b:016x}, c=0x{c:016x}, d=0x{d:016x}")
            print(f"    e=0x{e:016x}, f=0x{f:016x}, g=0x{g:016x}, h=0x{h:016x}")

    h0 = (h0 + a) & MASK_64
    h1 = (h1 + b) & MASK_64
    h2 = (h2 + c) & MASK_64
    h3 = (h3 + d) & MASK_64
    h4 = (h4 + e) & MASK_64
    h5 = (h5 + f) & MASK_64
    h6 = (h6 + g) & MASK_64
    h7 = (h7 + h) & MASK_64

    if verbose:
        print(f"State after block #{block_index} addition:")
        print(f"  H0=0x{h0:016x}, H1=0x{h1:016x}")
        print(f"  H2=0x{h2:016x}, H3=0x{h3:016x}")
        print(f"  H4=0x{h4:016x}, H5=0x{h5:016x}")
        print(f"  H6=0x{h6:016x}, H7=0x{h7:016x}")

    return h0, h1, h2, h3, h4, h5, h6, h7


# ==============================================================================
# Generic Engine for 64-bit SHA-2 Family
# ==============================================================================

def sha512_base(
    message: Union[bytes, bytearray, str],
    init_state: Tuple[int, ...],
    output_words: int,
    algo_name: str,
    verbose: bool = False,
) -> bytes:
    """Common driver engine for SHA-512 (8 words output) and SHA-384 (6 words output)."""
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

    # 1. Pad message to 1024-bit block boundary
    padded = pad_message_1024(message_bytes, verbose=verbose)

    # 2. Initialize 8-word 64-bit state
    state = init_state

    # 3. Process successive 1024-bit (128-byte) blocks
    num_blocks = len(padded) // 128
    for block_index in range(num_blocks):
        block = padded[block_index * 128 : (block_index + 1) * 128]
        state = process_block_512(block, state, block_index=block_index, verbose=verbose)

    # 4. Serialize specified number of words in big-endian order
    digest = b''.join(w.to_bytes(8, 'big') for w in state[:output_words])

    if verbose:
        print("\n" + "=" * 72)
        print(f"FINAL RESULT ({algo_name})")
        print("=" * 72)
        print(f"Digest (hex) : {digest.hex()}")
        print(f"Digest Length: {len(digest)} bytes ({len(digest) * 8} bits)")
        if output_words == 6:
            print("Truncation   : Retained first 6 words (H0..H5), dropped H6..H7 per SHA-384 spec.")
        print("=" * 72)

    return digest


# ==============================================================================
# Public API: SHA-512 and SHA-384 Functions
# ==============================================================================

def sha512(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 512-bit (64-byte) SHA-512 message digest."""
    return sha512_base(
        message=message,
        init_state=INIT_H_512,
        output_words=8,
        algo_name="SHA-512",
        verbose=verbose,
    )


def sha512_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes the SHA-512 message digest as a 128-character lowercase hex string."""
    return sha512(message, verbose=verbose).hex()


def sha384(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 384-bit (48-byte) SHA-384 message digest."""
    return sha512_base(
        message=message,
        init_state=INIT_H_384,
        output_words=6,
        algo_name="SHA-384",
        verbose=verbose,
    )


def sha384_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes the SHA-384 message digest as a 96-character lowercase hex string."""
    return sha384(message, verbose=verbose).hex()


# ==============================================================================
# Standalone Demonstration
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Pure Python SHA-512 and SHA-384 Reference Implementation (RFC 6234).")
    parser.add_argument("--text", type=str, default=None, help="Text to hash with SHA-512 and SHA-384.")
    parser.add_argument("--verbose", action="store_true", help="Print intermediate calculation values.")
    args = parser.parse_args()

    if args.text is not None:
        text_bytes = args.text.encode('utf-8')
        print(f"Input text: {args.text!r}")
        d512 = sha512_hex(text_bytes, verbose=True)
        d384 = sha384_hex(text_bytes, verbose=False)
        print(f"\nResult:")
        print(f"  SHA-512: {d512}")
        print(f"  SHA-384: {d384}")
        return

    # Default educational demo
    demo_text = "The quick brown fox jumps over the lazy dog"
    print("=" * 72)
    print("EDUCATIONAL SHA-512 & SHA-384 DEMONSTRATION")
    print(f"Message: {demo_text!r}")
    print("=" * 72)

    # Detailed verbose run of SHA-512
    sha512_hex(demo_text, verbose=True)

    print("\n" + "=" * 72)
    print("STANDARD EXAMPLES (SHA-512 & SHA-384)")
    print("=" * 72)
    examples = [
        "",
        "abc",
        "The quick brown fox jumps over the lazy dog",
    ]
    for ex in examples:
        h512 = sha512_hex(ex, verbose=False)
        h384 = sha384_hex(ex, verbose=False)
        print(f"Message: {ex!r}")
        print(f"  SHA-512: {h512}")
        print(f"  SHA-384: {h384}")


if __name__ == "__main__":
    main()

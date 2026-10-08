"""SHA-3 and SHAKE (Keccak Permutation-Based Family) Implementation in Pure Python.

This module provides a clean, dependency-free reference implementation of the
SHA-3 cryptographic hash algorithms and SHAKE extendable-output functions (XOFs)
specified in NIST FIPS PUB 202:
  - FIPS PUB 202: https://csrc.nist.gov/pubs/fips/202/final
  - The Keccak reference: https://keccak.team/files/Keccak-reference-3.0.pdf
  - Wikipedia: https://en.wikipedia.org/wiki/SHA-3

Supported Functions:
  - Fixed-length Hash Functions:
      * SHA3-224 (rate = 1152 bits, capacity =  448 bits, output =  28 bytes / 224 bits)
      * SHA3-256 (rate = 1088 bits, capacity =  512 bits, output =  32 bytes / 256 bits)
      * SHA3-384 (rate =  832 bits, capacity =  768 bits, output =  48 bytes / 384 bits)
      * SHA3-512 (rate =  576 bits, capacity = 1024 bits, output =  64 bytes / 512 bits)
  - Extendable-Output Functions (XOFs):
      * SHAKE128 (rate = 1344 bits, capacity =  256 bits, arbitrary output length)
      * SHAKE256 (rate = 1088 bits, capacity =  512 bits, arbitrary output length)

Architecture Overview:
  1. The Sponge Construction (FIPS 202 Section 4):
     - Total internal state width b = r + c = 1600 bits (25 64-bit words / 200 bytes).
     - Rate (r): The block size absorbed and squeezed per permutation call.
     - Capacity (c): The hidden portion of the state providing security (collision resistance c/2).
     - Phase 1 - Absorbing: Input blocks of r bits are XORed into the state, interleaved with Keccak-f[1600].
     - Phase 2 - Squeezing: Output blocks of r bits are read from the state, interleaved with Keccak-f[1600].
     - Natural immunity to Length-Extension Attacks: Because the capacity c is never revealed,
       an attacker cannot reconstruct the full internal state from the digest.

  2. The Keccak-f[1600] Permutation (FIPS 202 Section 3):
     The state is viewed as a 5x5 array of 64-bit lanes A[x][y], x,y in {0..4}.
     24 rounds, each comprising 5 modular steps:
       - theta (θ): Column parity mixing (linear diffusion).
       - rho (ρ): Intra-lane bit rotations by precomputed offsets.
       - pi (π): Coordinate lane transposition ((x, y) -> (y, (2x + 3y) mod 5)).
       - chi (χ): Non-linear row mapping: A[x] ^= (~A[x+1]) & A[x+2] (the ONLY non-linear step!).
       - iota (ι): Injects round constant RC[ir] into lane A[0][0] to break symmetry.

  3. Domain Separation and Multi-rate Padding (pad10*1):
     - Byte ordering: LITTLE-ENDIAN throughout (unlike SHA-1/SHA-2 which used Big-Endian).
     - Delimiter suffix bits (appended before pad10*1):
       * SHA3-224, 256, 384, 512: append bits '01' -> first padding byte is 0x06.
       * SHAKE128, SHAKE256:      append bits '1111' -> first padding byte is 0x1F.
       * (Historical note: raw Keccak submission used 0x01; NIST added 0x06/0x1F for domain separation).

Usage:
  python sha3_demo.py
  python sha3_demo.py --algo sha3-256 --text "The quick brown fox jumps over the lazy dog"
  python sha3_demo.py --algo shake128 --text "abc" --length 64
  python verify_sha3.py
"""

import argparse
from typing import List, Tuple, Union

# ==============================================================================
# Keccak-f[1600] Architecture & Algorithmic Constants (NIST FIPS PUB 202)
# ==============================================================================

# Core lane and permutation parameters (FIPS PUB 202 Section 3.1 & 3.3):
KECCAK_L: int = 6  # Exponent l in lane width w = 2^l (FIPS 202 Section 3.1.2)
L: int = KECCAK_L  # FIPS 202 standard symbol alias

LANE_WIDTH_BITS: int = 1 << KECCAK_L  # Lane word size w = 2^6 = 64 bits (FIPS 202 Section 3.1.2)
W: int = LANE_WIDTH_BITS  # FIPS 202 standard symbol alias
LANE_WIDTH_BYTES: int = LANE_WIDTH_BITS // 8  # 8 bytes per 64-bit lane word

# Number of rounds nr = 12 + 2*l = 12 + 12 = 24 for Keccak-f[1600] (FIPS 202 Section 3.4):
NUM_ROUNDS: int = 12 + 2 * KECCAK_L
ROUNDS: int = NUM_ROUNDS  # Specification alias

MASK_64: int = (1 << 64) - 1  # 0xFFFFFFFFFFFFFFFF (64-bit bitmask)

# 5x5 State Matrix Geometry (FIPS 202 Section 3.1.2):
STATE_GRID_DIM: int = 5  # State matrix dimension (5x5 array of lanes)
GRID_DIM: int = STATE_GRID_DIM  # Matrix dimension alias
NUM_LANES: int = STATE_GRID_DIM * STATE_GRID_DIM  # 25 total 64-bit lanes
STATE_WIDTH_BITS: int = NUM_LANES * LANE_WIDTH_BITS  # b = 1600 bits total state width
STATE_WIDTH_BYTES: int = STATE_WIDTH_BITS // 8  # 200 bytes total state width

# LFSR parameters for Round Constant generation (FIPS 202 Section 3.2.5, Algorithm 5):
LFSR_PERIOD: int = 255  # Period of the degree-8 LFSR (2^8 - 1)
ROUND_CONSTANT_BITS_PER_ROUND: int = KECCAK_L + 1  # 7 LFSR bits per round (j in 0..l)

# Domain separation delimiters (FIPS 202 Section 6 & Appendix B.2):
DELIMITER_SHA3: int = 0x06  # Suffix byte for SHA-3 fixed-length hash functions ('01' + '1')
DELIMITER_SHAKE: int = 0x1F  # Suffix byte for SHAKE extendable-output functions ('1111' + '1')
PAD_CLOSING_BYTE: int = 0x80  # Terminating bit '1' in pad10*1 multi-rate padding

# Standard Sponge parameters for SHA-3 fixed-length hash functions (FIPS 202 Table 2):
SHA3_224_CAPACITY_BITS: int = (2 * 224)
SHA3_224_RATE_BITS: int = STATE_WIDTH_BITS - SHA3_224_CAPACITY_BITS
SHA3_224_DIGEST_BYTES: int = 28

SHA3_256_CAPACITY_BITS: int = (2 * 256)
SHA3_256_RATE_BITS: int = STATE_WIDTH_BITS - SHA3_256_CAPACITY_BITS
SHA3_256_DIGEST_BYTES: int = 32

SHA3_384_CAPACITY_BITS: int = (2 * 384)
SHA3_384_RATE_BITS: int = STATE_WIDTH_BITS - SHA3_384_CAPACITY_BITS
SHA3_384_DIGEST_BYTES: int = 48

SHA3_512_CAPACITY_BITS: int = (2 * 512)
SHA3_512_RATE_BITS: int = STATE_WIDTH_BITS - SHA3_512_CAPACITY_BITS
SHA3_512_DIGEST_BYTES: int = 64

# Standard Sponge parameters for SHAKE extendable-output functions (FIPS 202 Table 3):
SHAKE128_CAPACITY_BITS: int = (2 * 128)
SHAKE128_RATE_BITS: int = STATE_WIDTH_BITS - SHAKE128_CAPACITY_BITS
SHAKE128_DEFAULT_BYTES: int = 32

SHAKE256_CAPACITY_BITS: int = (2 * 256)
SHAKE256_RATE_BITS: int = STATE_WIDTH_BITS - SHAKE256_CAPACITY_BITS
SHAKE256_DEFAULT_BYTES: int = 64


# ==============================================================================
# Round Constants Generation (FIPS PUB 202 Section 3.2.5, Algorithm 5 & 6)
# ==============================================================================

def rc_lfsr(t: int) -> int:
    """Algorithm 5: rc(t) - Generates a round constant bit using an 8-bit LFSR (FIPS 202 Section 3.2.5).

    The LFSR is defined over the primitive polynomial x^8 + x^6 + x^5 + x^4 + 1.
    Steps (FIPS 202 Section 3.2.5, Algorithm 5):
      1. If t mod 255 == 0, return 1.
      2. Let R = 10000000 (8 bits: R[0]=1, R[1..7]=0).
      3. For i from 1 to (t mod 255):
         a. R = 0 || R (prepend 0, creating a 9-bit register)
         b. R[0] ^= R[8]
         c. R[4] ^= R[8]
         d. R[5] ^= R[8]
         e. R[6] ^= R[8]
         f. R = Trunc_8(R) (keep first 8 bits R[0..7])
      4. Return R[0].
    """
    if t % LFSR_PERIOD == 0:
        return 1

    # Step 2: Let R = 10000000
    R = [1, 0, 0, 0, 0, 0, 0, 0]

    # Step 3: For i from 1 to t mod 255
    for _ in range(1, (t % LFSR_PERIOD) + 1):
        # 3a: R = 0 || R (list of length 9: R_new[0]=0, R_new[1..8]=R[0..7])
        R_new = [0] + R
        # 3b-e: Feedback taps from R[8]
        feedback = R_new[8]
        R_new[0] ^= feedback
        R_new[4] ^= feedback
        R_new[5] ^= feedback
        R_new[6] ^= feedback
        # 3f: Trunc_8(R)
        R = R_new[:8]

    # Step 4: Return R[0]
    return R[0]


def compute_round_constant(round_index: int, l: int = KECCAK_L) -> int:
    """Computes a 64-bit round constant word RC[round_index] (FIPS 202 Algorithm 6, Steps 2-3).

    For Keccak-f[1600], lane width w = 64 = 2^l (where l = 6).
    Round constant bits are placed at bit positions 2^j - 1:
      For j in 0..l (0..6):
        RC[2^j - 1] = rc(j + (l + 1) * round_index)
    Bit positions: 2^0 - 1 = 0, 2^1 - 1 = 1, 2^2 - 1 = 3, 2^3 - 1 = 7,
                   2^4 - 1 = 15, 2^5 - 1 = 31, 2^6 - 1 = 63.
    """
    rc_word = 0
    for j in range(l + 1):
        bit = rc_lfsr(j + ROUND_CONSTANT_BITS_PER_ROUND * round_index)
        if bit:
            bit_position = (1 << j) - 1
            rc_word |= (1 << bit_position)
    return rc_word


# 24 Round Constants RC[0..23] for Keccak-f[1600] (FIPS 202 Section 3.2.5):
# Computed dynamically per FIPS 202 Algorithm 5 & Algorithm 6.
#
# Precomputed reference values kept as comment for verification:
# RC: List[int] = [
#     0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
#     0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
#     0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
#     0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
#     0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
#     0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
# ]
RC: List[int] = [compute_round_constant(i, l=KECCAK_L) for i in range(NUM_ROUNDS)]


# ==============================================================================
# 5x5 Rotation Offsets Generation (FIPS PUB 202 Section 3.2.2, Algorithm 2)
# ==============================================================================

def compute_rho_offsets() -> List[List[int]]:
    """Computes the 5x5 rotation offsets matrix per FIPS 202 Algorithm 2 (Section 3.2.2)."""
    offsets = [[0] * STATE_GRID_DIM for _ in range(STATE_GRID_DIM)]
    x, y = 1, 0
    for t in range(NUM_ROUNDS):
        offsets[x][y] = ((t + 1) * (t + 2) // 2) % LANE_WIDTH_BITS
        x, y = y, (2 * x + 3 * y) % STATE_GRID_DIM
    return offsets


# 5x5 Rotation Offsets RHO[x][y] for Keccak-f[1600] (FIPS 202 Section 3.2.2, Algorithm 2):
# Computed dynamically per FIPS 202 Algorithm 2.
#
# Precomputed reference values kept as comment for verification:
# RHO_OFFSETS: List[List[int]] = [
#     [ 0, 36,  3, 41, 18],  # x = 0, y = 0..4
#     [ 1, 44, 10, 45,  2],  # x = 1, y = 0..4
#     [62,  6, 43, 15, 61],  # x = 2, y = 0..4
#     [28, 55, 25, 21, 56],  # x = 3, y = 0..4
#     [27, 20, 39,  8, 14],  # x = 4, y = 0..4
# ]
RHO_OFFSETS: List[List[int]] = compute_rho_offsets()


# ==============================================================================
# Helper Functions: Bitwise Rotations and State Conversions
# ==============================================================================

def rotl64(x: int, n: int) -> int:
    """64-bit circular left shift: (x <<< n)."""
    n = n % LANE_WIDTH_BITS
    return ((x << n) | (x >> (LANE_WIDTH_BITS - n))) & MASK_64


def bytes_to_state(data: bytes) -> List[List[int]]:
    """Converts 200 bytes into a 5x5 64-bit lane matrix using Little-Endian order.

    Lane indexing convention (FIPS 202 Section 3.1.2):
      Lane A[x][y] corresponds to word index (x + 5*y) in the linear 25-word array.
    """
    if len(data) != STATE_WIDTH_BYTES:
        raise ValueError(f"State data must be exactly {STATE_WIDTH_BYTES} bytes, got {len(data)}")

    state = [[0] * STATE_GRID_DIM for _ in range(STATE_GRID_DIM)]
    for lane_idx in range(NUM_LANES):
        x = lane_idx % STATE_GRID_DIM
        y = lane_idx // STATE_GRID_DIM
        start_byte = lane_idx * LANE_WIDTH_BYTES
        end_byte = start_byte + LANE_WIDTH_BYTES
        lane_bytes = data[start_byte:end_byte]
        state[x][y] = int.from_bytes(lane_bytes, 'little')
    return state


def state_to_bytes(state: List[List[int]]) -> bytes:
    """Serializes a 5x5 64-bit lane matrix into 200 bytes using Little-Endian order."""
    output = bytearray(STATE_WIDTH_BYTES)
    for lane_idx in range(NUM_LANES):
        x = lane_idx % STATE_GRID_DIM
        y = lane_idx // STATE_GRID_DIM
        start_byte = lane_idx * LANE_WIDTH_BYTES
        end_byte = start_byte + LANE_WIDTH_BYTES
        output[start_byte:end_byte] = state[x][y].to_bytes(LANE_WIDTH_BYTES, 'little')
    return bytes(output)


def print_state_matrix(state: List[List[int]], label: str = ""):
    """Prints the 5x5 state matrix in an intuitive grid."""
    if label:
        print(f"  {label}:")
    for y in range(STATE_GRID_DIM):
        row_str = " ".join(f"A[{x},{y}]=0x{state[x][y]:016x}" for x in range(STATE_GRID_DIM))
        print(f"    {row_str}")


# ==============================================================================
# The Five Step Mappings of Keccak-f[1600] (FIPS 202 Section 3.2)
# ==============================================================================

def step_theta(state: List[List[int]]) -> List[List[int]]:
    """Step 1: theta (θ) - Column parity mixing (FIPS 202 Section 3.2.1, Algorithm 1).

    For each column x, computes column parity C[x] = XOR_{y=0..4}(A[x][y]).
    Then diffuses D[x] = C[(x-1) mod 5] XOR ROTL(C[(x+1) mod 5], 1) across all lanes.
    This provides high-order linear branch diffusion across sheets.
    """
    C = [
        state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
        for x in range(STATE_GRID_DIM)
    ]
    D = [
        C[(x - 1) % STATE_GRID_DIM] ^ rotl64(C[(x + 1) % STATE_GRID_DIM], 1)
        for x in range(STATE_GRID_DIM)
    ]
    return [[state[x][y] ^ D[x] for y in range(STATE_GRID_DIM)] for x in range(STATE_GRID_DIM)]


def step_rho(state: List[List[int]]) -> List[List[int]]:
    """Step 2: rho (ρ) - Intra-lane bit rotations (FIPS 202 Section 3.2.2, Algorithm 2).

    Rotates each lane A[x][y] left by a fixed triangular offset RHO_OFFSETS[x][y].
    Provides diffusion within each 64-bit word across bit slices.
    """
    return [
        [rotl64(state[x][y], RHO_OFFSETS[x][y]) for y in range(STATE_GRID_DIM)]
        for x in range(STATE_GRID_DIM)
    ]


def step_pi(state: List[List[int]]) -> List[List[int]]:
    """Step 3: pi (π) - Coordinate lane transposition (FIPS 202 Section 3.2.3, Algorithm 3).

    Rearranges lane coordinates via matrix transformation:
      A'[y][(2x + 3y) mod 5] = A[x][y].
    Permutes lanes between columns and rows, preventing localization of active bits.
    """
    permuted = [[0] * STATE_GRID_DIM for _ in range(STATE_GRID_DIM)]
    for x in range(STATE_GRID_DIM):
        for y in range(STATE_GRID_DIM):
            permuted[y][(2 * x + 3 * y) % STATE_GRID_DIM] = state[x][y]
    return permuted


def step_chi(state: List[List[int]]) -> List[List[int]]:
    """Step 4: chi (χ) - Non-linear row mapping (FIPS 202 Section 3.2.4, Algorithm 4).

    A'[x][y] = A[x][y] XOR ((NOT A[(x+1) mod 5][y]) AND A[(x+2) mod 5][y]).
    This is the ONLY non-linear step in the entire Keccak permutation!
    Acts as five parallel 5-bit algebraic S-boxes along each row y.
    """
    result = [[0] * STATE_GRID_DIM for _ in range(STATE_GRID_DIM)]
    for y in range(STATE_GRID_DIM):
        for x in range(STATE_GRID_DIM):
            not_next = (~state[(x + 1) % STATE_GRID_DIM][y]) & MASK_64
            next_next = state[(x + 2) % STATE_GRID_DIM][y]
            result[x][y] = state[x][y] ^ (not_next & next_next)
    return result


def step_iota(state: List[List[int]], round_index: int) -> List[List[int]]:
    """Step 5: iota (ι) - Round constant injection (FIPS 202 Section 3.2.5, Algorithm 6).

    A'[0][0] = A[0][0] XOR RC[round_index].
    Note: In FIPS 202 Section 3.2.5, Algorithm 5 defines rc(t) (the LFSR-based round
    constant bit generator), while Algorithm 6 defines the iota step mapping itself,
    which injects RC[round_index] into the origin lane A[0][0] to break round symmetry.
    """
    result = [row[:] for row in state]
    result[0][0] ^= RC[round_index]
    return result


def keccak_p1600_round(
        state: List[List[int]],
        round_index: int,
        verbose: bool = False,
) -> List[List[int]]:
    """Executes a single round of Keccak-p[1600]: iota o chi o pi o rho o theta."""
    # 1. theta
    st = step_theta(state)
    # 2. rho
    st = step_rho(st)
    # 3. pi
    st = step_pi(st)
    # 4. chi
    st = step_chi(st)
    # 5. iota
    st = step_iota(st, round_index)

    if verbose:
        last_coord = STATE_GRID_DIM - 1
        print(f"  --- End of Round {round_index:02d}/{NUM_ROUNDS - 1} ---")
        print(
            f"    A[0][0]=0x{st[0][0]:016x}, A[1][0]=0x{st[1][0]:016x}, A[{last_coord}][{last_coord}]=0x{st[last_coord][last_coord]:016x}")

    return st


def keccak_f1600(state: List[List[int]], verbose: bool = False) -> List[List[int]]:
    """The full 24-round Keccak-f[1600] permutation (FIPS 202 Section 3.3, Algorithm 7)."""
    current = [row[:] for row in state]
    for r in range(NUM_ROUNDS):
        # Print intermediate details on first and last round when verbose
        round_verbose = verbose and (r == 0 or r == NUM_ROUNDS - 1)
        current = keccak_p1600_round(current, r, verbose=round_verbose)
    return current


# ==============================================================================
# Multi-Rate Padding pad10*1 (FIPS 202 Section 5.1, Algorithm 9 & Appendix B)
# ==============================================================================

def pad10star1(
        message_len: int,
        rate_bytes: int,
        delimiter: int,
        verbose: bool = False,
) -> bytes:
    """Generates the multi-rate padding bytes (pad10*1, FIPS 202 Algorithm 9) with domain separator.

    Procedure (FIPS 202 Section 5.1, Algorithm 9 & Appendix B.2):
      1. Suffix delimiter (e.g., DELIMITER_SHA3 or DELIMITER_SHAKE) is appended.
      2. Zero or more 0x00 bytes are inserted.
      3. The final byte has PAD_CLOSING_BYTE (0x80) appended (representing the closing '1' bit).
      If rate_bytes - (len % rate_bytes) == 1, delimiter and 0x80 are combined: (delimiter | PAD_CLOSING_BYTE).
    """
    rem = message_len % rate_bytes
    pad_len = rate_bytes - rem

    if pad_len == 1:
        padding = bytes([delimiter | PAD_CLOSING_BYTE])
    elif pad_len == 2:
        padding = bytes([delimiter, PAD_CLOSING_BYTE])
    else:
        padding = bytes([delimiter]) + (b'\x00' * (pad_len - 2)) + bytes([PAD_CLOSING_BYTE])

    if verbose:
        print("\n--- Sponge Padding (pad10*1) ---")
        print(f"Original Length: {message_len} bytes")
        print(f"Block Rate     : {rate_bytes} bytes ({rate_bytes * 8} bits)")
        print(f"Padding Added  : {len(padding)} bytes (First: 0x{padding[0]:02x}, Last: 0x{padding[-1]:02x})")
        print(
            f"Total Padded   : {message_len + len(padding)} bytes ({(message_len + len(padding)) // rate_bytes} block(s))")

    return padding


# ==============================================================================
# The Sponge Construction Engine (FIPS 202 Section 4)
# ==============================================================================

def keccak_sponge(
        message: Union[bytes, bytearray, str],
        rate_bits: int,
        capacity_bits: int,
        delimiter: int,
        output_bytes: int,
        algo_name: str,
        verbose: bool = False,
) -> bytes:
    """Generic Sponge driver for all SHA-3 and SHAKE functions (FIPS 202 Section 4, Algorithm 8).

    Parameters:
      message: Input message bytes, bytearray, or UTF-8 string.
      rate_bits: Block size r in bits (must be divisible by 8).
      capacity_bits: Capacity c in bits (r + c = STATE_WIDTH_BITS).
      delimiter: Suffix byte (DELIMITER_SHA3 or DELIMITER_SHAKE).
      output_bytes: Desired digest length d in bytes.
      algo_name: Human-readable algorithm name for logging.
      verbose: Output intermediate computation steps to console.
    """
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    elif isinstance(message, (bytes, bytearray)):
        message_bytes = bytes(message)
    else:
        raise TypeError(f"message must be bytes, bytearray, or str, got {type(message).__name__}")

    if rate_bits + capacity_bits != STATE_WIDTH_BITS or rate_bits % 8 != 0:
        raise ValueError(
            f"Invalid rate/capacity parameters: r={rate_bits}, c={capacity_bits} "
            f"(must sum to {STATE_WIDTH_BITS} bits)"
        )

    rate_bytes = rate_bits // 8

    if verbose:
        print("=" * 72)
        print(f"{algo_name} SPONGE COMPUTATION")
        print("=" * 72)
        sample = message_bytes[:32]
        print(f"Input ({len(message_bytes)} bytes): {sample!r}{'...' if len(message_bytes) > 32 else ''}")
        print(f"Sponge Parameters: Rate r = {rate_bits} bits ({rate_bytes} bytes), Capacity c = {capacity_bits} bits")
        print(f"Domain Suffix: 0x{delimiter:02x}, Output Requested: {output_bytes} bytes ({output_bytes * 8} bits)")

    # 1. Padding with domain delimiter
    padding = pad10star1(len(message_bytes), rate_bytes, delimiter, verbose=verbose)
    padded_message = message_bytes + padding
    num_blocks = len(padded_message) // rate_bytes

    # 2. State Initialization: 5x5 lanes initialized to zero
    state = [[0] * STATE_GRID_DIM for _ in range(STATE_GRID_DIM)]

    # 3. Absorbing Phase: XOR each block of r bytes into state, then permute
    if verbose:
        print(f"\n--- Absorbing Phase ({num_blocks} Block{'s' if num_blocks > 1 else ''}) ---")

    for block_idx in range(num_blocks):
        block = padded_message[block_idx * rate_bytes: (block_idx + 1) * rate_bytes]
        num_lanes = rate_bytes // LANE_WIDTH_BYTES

        # XOR block into the first (rate_bytes // LANE_WIDTH_BYTES) lanes in Little-Endian
        for lane_idx in range(num_lanes):
            x = lane_idx % STATE_GRID_DIM
            y = lane_idx // STATE_GRID_DIM
            start_byte = lane_idx * LANE_WIDTH_BYTES
            end_byte = start_byte + LANE_WIDTH_BYTES
            val = int.from_bytes(block[start_byte:end_byte], 'little')
            state[x][y] ^= val

        if verbose:
            print(f"Absorbing Block #{block_idx}: XORed {rate_bytes} bytes into state. Running Keccak-f[1600]...")

        state = keccak_f1600(state, verbose=verbose)

    # 4. Squeezing Phase: Extract r bytes at a time until output_bytes reached
    if verbose:
        print(f"\n--- Squeezing Phase (Target: {output_bytes} bytes) ---")

    output = bytearray()
    squeeze_block = 0
    while len(output) < output_bytes:
        # Serialize state to STATE_WIDTH_BYTES bytes
        state_bytes = state_to_bytes(state)
        needed = output_bytes - len(output)
        take_bytes = min(needed, rate_bytes)
        output.extend(state_bytes[:take_bytes])

        if verbose:
            print(
                f"Squeeze #{squeeze_block}: Extracted {take_bytes} bytes (Total so far: {len(output)}/{output_bytes} bytes)")
        squeeze_block += 1

        if len(output) < output_bytes:
            if verbose:
                print("More output requested: Permuting state for next squeeze block...")
            state = keccak_f1600(state, verbose=verbose)

    digest = bytes(output)

    if verbose:
        print("\n" + "=" * 72)
        print(f"FINAL RESULT ({algo_name})")
        print("=" * 72)
        print(f"Digest (hex) : {digest.hex()}")
        print(f"Digest Length: {len(digest)} bytes ({len(digest) * 8} bits)")
        print("=" * 72)

    return digest


# ==============================================================================
# Public API: SHA-3 Fixed-Length Hash Functions (FIPS 202 Section 6)
# ==============================================================================

def sha3_224(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 224-bit (28-byte) SHA3-224 message digest (FIPS 202)."""
    return keccak_sponge(
        message=message,
        rate_bits=SHA3_224_RATE_BITS,
        capacity_bits=SHA3_224_CAPACITY_BITS,
        delimiter=DELIMITER_SHA3,
        output_bytes=SHA3_224_DIGEST_BYTES,
        algo_name="SHA3-224",
        verbose=verbose,
    )


def sha3_224_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes SHA3-224 digest as a 56-character lowercase hex string."""
    return sha3_224(message, verbose=verbose).hex()


def sha3_256(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 256-bit (32-byte) SHA3-256 message digest (FIPS 202)."""
    return keccak_sponge(
        message=message,
        rate_bits=SHA3_256_RATE_BITS,
        capacity_bits=SHA3_256_CAPACITY_BITS,
        delimiter=DELIMITER_SHA3,
        output_bytes=SHA3_256_DIGEST_BYTES,
        algo_name="SHA3-256",
        verbose=verbose,
    )


def sha3_256_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes SHA3-256 digest as a 64-character lowercase hex string."""
    return sha3_256(message, verbose=verbose).hex()


def sha3_384(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 384-bit (48-byte) SHA3-384 message digest (FIPS 202)."""
    return keccak_sponge(
        message=message,
        rate_bits=SHA3_384_RATE_BITS,
        capacity_bits=SHA3_384_CAPACITY_BITS,
        delimiter=DELIMITER_SHA3,
        output_bytes=SHA3_384_DIGEST_BYTES,
        algo_name="SHA3-384",
        verbose=verbose,
    )


def sha3_384_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes SHA3-384 digest as a 96-character lowercase hex string."""
    return sha3_384(message, verbose=verbose).hex()


def sha3_512(message: Union[bytes, bytearray, str], verbose: bool = False) -> bytes:
    """Computes the 512-bit (64-byte) SHA3-512 message digest (FIPS 202)."""
    return keccak_sponge(
        message=message,
        rate_bits=SHA3_512_RATE_BITS,
        capacity_bits=SHA3_512_CAPACITY_BITS,
        delimiter=DELIMITER_SHA3,
        output_bytes=SHA3_512_DIGEST_BYTES,
        algo_name="SHA3-512",
        verbose=verbose,
    )


def sha3_512_hex(message: Union[bytes, bytearray, str], verbose: bool = False) -> str:
    """Computes SHA3-512 digest as a 128-character lowercase hex string."""
    return sha3_512(message, verbose=verbose).hex()


# ==============================================================================
# Public API: SHAKE Extendable-Output Functions (XOFs) (FIPS 202 Section 6.2)
# ==============================================================================

def shake128(
        message: Union[bytes, bytearray, str],
        output_bytes: int = SHAKE128_DEFAULT_BYTES,
        verbose: bool = False,
) -> bytes:
    """Computes arbitrary-length output using SHAKE128 XOF (FIPS 202)."""
    return keccak_sponge(
        message=message,
        rate_bits=SHAKE128_RATE_BITS,
        capacity_bits=SHAKE128_CAPACITY_BITS,
        delimiter=DELIMITER_SHAKE,
        output_bytes=output_bytes,
        algo_name="SHAKE128",
        verbose=verbose,
    )


def shake128_hex(
        message: Union[bytes, bytearray, str],
        output_bytes: int = SHAKE128_DEFAULT_BYTES,
        verbose: bool = False,
) -> str:
    """Computes SHAKE128 output as a lowercase hex string."""
    return shake128(message, output_bytes=output_bytes, verbose=verbose).hex()


def shake256(
        message: Union[bytes, bytearray, str],
        output_bytes: int = SHAKE256_DEFAULT_BYTES,
        verbose: bool = False,
) -> bytes:
    """Computes arbitrary-length output using SHAKE256 XOF (FIPS 202)."""
    return keccak_sponge(
        message=message,
        rate_bits=SHAKE256_RATE_BITS,
        capacity_bits=SHAKE256_CAPACITY_BITS,
        delimiter=DELIMITER_SHAKE,
        output_bytes=output_bytes,
        algo_name="SHAKE256",
        verbose=verbose,
    )


def shake256_hex(
        message: Union[bytes, bytearray, str],
        output_bytes: int = SHAKE256_DEFAULT_BYTES,
        verbose: bool = False,
) -> str:
    """Computes SHAKE256 output as a lowercase hex string."""
    return shake256(message, output_bytes=output_bytes, verbose=verbose).hex()


# ==============================================================================
# Standalone Demonstration
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Pure Python SHA-3 and SHAKE Reference Implementation (NIST FIPS PUB 202)."
    )
    parser.add_argument(
        "--algo",
        type=str,
        default="sha3-256",
        choices=["sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256"],
        help="Algorithm choice (default: sha3-256)",
    )
    parser.add_argument("--text", type=str, default=None, help="Text to hash.")
    parser.add_argument("--length", type=int, default=32, help="Output length in bytes for SHAKE (default: 32)")
    parser.add_argument("--verbose", action="store_true", help="Print intermediate sponge and permutation steps.")
    args = parser.parse_args()

    algo_func = {
        "sha3-224": lambda m, v: sha3_224_hex(m, verbose=v),
        "sha3-256": lambda m, v: sha3_256_hex(m, verbose=v),
        "sha3-384": lambda m, v: sha3_384_hex(m, verbose=v),
        "sha3-512": lambda m, v: sha3_512_hex(m, verbose=v),
        "shake128": lambda m, v: shake128_hex(m, output_bytes=args.length, verbose=v),
        "shake256": lambda m, v: shake256_hex(m, output_bytes=args.length, verbose=v),
    }[args.algo]

    if args.text is not None:
        digest = algo_func(args.text, args.verbose)
        print(f"Algorithm: {args.algo.upper()}")
        print(f"Message  : {args.text!r}")
        print(f"Digest   : {digest}")
        return

    # Default educational demo
    demo_text = "The quick brown fox jumps over the lazy dog"
    print("=" * 72)
    print("EDUCATIONAL SHA-3 & SHAKE DEMONSTRATION (NIST FIPS PUB 202)")
    print(f"Message: {demo_text!r}")
    print("=" * 72)

    # Detailed verbose execution of SHA3-256
    sha3_256_hex(demo_text, verbose=True)

    print("\n" + "=" * 72)
    print("ALL 6 ALGORITHMS ON STANDARD TEST PHRASE")
    print("=" * 72)
    print(f"SHA3-224 : {sha3_224_hex(demo_text)}")
    print(f"SHA3-256 : {sha3_256_hex(demo_text)}")
    print(f"SHA3-384 : {sha3_384_hex(demo_text)}")
    print(f"SHA3-512 : {sha3_512_hex(demo_text)}")
    print(f"SHAKE128 (32 bytes): {shake128_hex(demo_text, output_bytes=32)}")
    print(f"SHAKE256 (64 bytes): {shake256_hex(demo_text, output_bytes=64)}")


if __name__ == "__main__":
    main()

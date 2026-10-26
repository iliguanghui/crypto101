"""FIPS PUB 46-3 Data Encryption Standard (DES), in pure Python.

References:
  https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25
  https://en.wikipedia.org/wiki/Data_Encryption_Standard
  https://en.wikipedia.org/wiki/DES_supplementary_material

Parameters: block size = 64 bits (8 bytes); key size = 64 bits (8 bytes) on input,
of which 56 bits are the effective cryptographic key and 8 bits (bits 8, 16, 24,
32, 40, 48, 56, 64) are odd-parity bits discarded by Permuted Choice 1 (PC-1).
Structure: 16-round balanced Feistel network operating on two 32-bit half-blocks
(L and R), using sixteen 48-bit round subkeys (K1..K16) derived from the key schedule.

Because DES uses a Feistel structure, the round function F(R, K) does NOT need to
be invertible for the cipher itself to be invertible. Encryption and decryption use
the exact same circuit and algorithm: only the order of the 16 subkeys is reversed
(K1..K16 for encryption, K16..K1 for decryption).

Compared with AES (FIPS 197): DES is a 64-bit Feistel network designed in the 1970s
for hardware gate efficiency (heavy use of wire-crossing bit permutations), whereas
AES is a 128-bit Substitution-Permutation Network (SPN) operating on byte matrices
over GF(2^8). Because a 56-bit key space (2^56 ≈ 7.2 * 10^16 keys) is vulnerable to
brute-force search on modern hardware, raw single-DES is obsolete for security and
was superseded by Triple DES (3DES) and AES. Furthermore, table-lookup S-boxes and
bit-by-bit list operations in Python are not constant-time and are for educational
demonstration only. Verbose output exposes secret key state: use only with demo keys.

Run: python des_demo.py
"""

# --- Cryptographic Permutation & Substitution Tables (FIPS 46-3) ---
# NOTE on DES Bit Numbering Convention:
# Unlike modern little-endian or 0-indexed specifications, FIPS 46-3 numbers bits
# starting at 1 from the Most Significant Bit (MSB, leftmost) to 64 at the Least
# Significant Bit (LSB, rightmost). All tables below follow this 1-indexed convention:
# e.g., a value of 58 in IP means "the 1st output bit comes from the 58th input bit".

# Initial Permutation (IP) table (64 bits -> 64 bits).
# Rearranges the 64 input bits before entering the Feistel network.
# It has no cryptographic significance; in the 1970s, it served to route bits from
# an 8-bit hardware bus into two 32-bit shift registers (even bits to L0, odd bits to R0).
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Final Permutation (FP / IP^-1) table (64 bits -> 64 bits).
# Exact mathematical inverse of IP: FP(IP(x)) == x. Applied after the 16th round
# and the final 32-bit half-block swap so that encryption and decryption remain symmetric.
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# Expansion function (E) table (32 bits -> 48 bits).
# Splits the 32-bit right half (R) into eight 4-bit nibbles and expands each to 6 bits
# by duplicating the boundary bits of adjacent nibbles (notice how bits 4 & 5, 8 & 9,
# ..., 32 & 1 appear twice). This provides the "avalanche effect" by allowing one bit in R
# to influence two adjacent S-boxes in the same round.
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# Permutation (P) table inside the Feistel function (32 bits -> 32 bits).
# Provides "diffusion" (in Claude Shannon's confusion-diffusion paradigm) by spreading
# the 4 output bits of each S-box across 4 different S-boxes in the next round
# (specifically, 2 bits affect middle bits and 2 bits affect outer/row bits in the next round).
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

# Permuted Choice 1 (PC-1) table (64 bits -> 56 bits).
# Extracts the 56 effective key bits from the 64-bit input key, discarding every 8th bit
# (bits 8, 16, 24, 32, 40, 48, 56, 64, which were historically used for odd-parity checking).
# The first 28 entries form C0, and the last 28 entries form D0.
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# Permuted Choice 2 (PC-2) table (56 bits -> 48 bits).
# Compression permutation that selects and permutes 48 bits from the 56-bit concatenated
# key register (C_i || D_i) to produce each round's 48-bit subkey K_i.
# Specifically, the first 24 bits come from C_i (bits 1..28, omitting 9, 18, 22, 25)
# and the last 24 bits come from D_i (bits 29..56, omitting 35, 38, 43, 54).
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]

# Key Schedule Shift Table (16 rounds).
# Number of circular left shifts applied independently to the 28-bit C and D registers
# in each round (1..16). Notice that rounds 1, 2, 9, and 16 shift by 1 bit, while all
# other rounds shift by 2 bits. The sum of all shifts is 1*4 + 2*12 = 28, meaning that
# after Round 16, C16 == C0 and D16 == D0 (convenient for hardware decryption).
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 8 Substitution boxes (S-boxes): S1..S8, each mapping 6 input bits to 4 output bits.
# The S-boxes are the ONLY non-linear component in DES and provide "confusion": without
# them, the entire cipher would be a linear system of XORs and bit permutations over GF(2)
# that could be broken trivially with Gaussian elimination on a single known plaintext.
# IBM and the NSA designed these specific tables to resist Differential Cryptanalysis
# (which was known privately to IBM/NSA in 1974, 15 years before its public discovery).
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


# --- Primitive Bit-Level Helper Functions (Operating on lists of 0/1 ints) ---

def hex_to_bits(hex_str):
    """Convert a hexadecimal string into a big-endian list of integer bits (0 or 1).

    Each hex character represents 4 bits (1 nibble). Index 0 of the returned list
    corresponds to DES bit 1 (the Most Significant Bit).
    """
    num_bits = len(hex_str) * 4
    val = int(hex_str, 16)
    return [(val >> (num_bits - 1 - i)) & 1 for i in range(num_bits)]


def bits_to_hex(bits):
    """Convert a list of integer bits (0 or 1) into a zero-padded uppercase hex string."""
    val = 0
    for b in bits:
        val = (val << 1) | b
    hex_len = len(bits) // 4
    return f"{val:0{hex_len}X}"


def permute(bits, table):
    """Permute, expand, or compress a list of bits using a 1-indexed DES table.

    Because FIPS 46-3 tables use 1-based bit numbering (1..N) while Python lists
    use 0-based indexing (0..N-1), we subtract 1 from each table entry `pos`.
    """
    return [bits[pos - 1] for pos in table]


def xor_bits(bits_a, bits_b):
    """Element-wise XOR (addition modulo 2) of two equal-length bit lists."""
    return [a ^ b for a, b in zip(bits_a, bits_b)]


def left_shift(bits, n):
    """Perform a circular left shift (rotation) on a list of bits by `n` positions."""
    return bits[n:] + bits[:n]


# --- Core DES Cryptographic Functions ---

def generate_subkeys(key_bits):
    """Derive sixteen 48-bit round subkeys (K1..K16) from a 64-bit input key.

    The DES Key Schedule works as follows:
      1. Apply Permuted Choice 1 (PC-1) to strip the 8 parity bits and permute the
         remaining 56 bits into two 28-bit halves: C0 (left) and D0 (right).
      2. For each round i = 1..16:
         - Rotate C_{i-1} and D_{i-1} left independently by SHIFTS[i-1] bits (1 or 2 bits).
         - Apply Permuted Choice 2 (PC-2) to select 48 bits from the 56-bit state (C_i || D_i)
           to form the round subkey K_i.
    """
    print("=== Key Schedule (Subkey Generation) ===")
    # Step 1: Apply PC-1 to drop every 8th parity bit (64 bits -> 56 bits)
    key_56 = permute(key_bits, PC1)
    C, D = key_56[:28], key_56[28:]
    print(f"After PC-1: C0 = {bits_to_hex(C)}, D0 = {bits_to_hex(D)}")

    subkeys = []
    # Step 2: Generate 16 round subkeys via circular shifts and PC-2 compression
    for round_idx, shift in enumerate(SHIFTS, start=1):
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        subkey = permute(C + D, PC2)
        subkeys.append(subkey)
        print(
            f"Round {round_idx:2d}: C = {bits_to_hex(C)}, "
            f"D = {bits_to_hex(D)} -> K{round_idx:2d} = {bits_to_hex(subkey)}"
        )
    print()
    return subkeys


def feistel(right_half, subkey):
    """Evaluate the DES Feistel round function F(R_{i-1}, K_i) -> 32 bits.

    The Feistel function F consists of four stages:
      1. Expansion (E): Expand the 32-bit right half into 48 bits by duplicating
         outer bits of each 4-bit nibble so adjacent S-boxes share input bits.
      2. Key Mixing: XOR the 48-bit expanded block with the 48-bit round subkey K_i.
      3. Substitution (S-boxes): Split the 48-bit result into eight 6-bit chunks
         (B1..B8) and pass each through its corresponding non-linear S-box (S1..S8):
           - For a 6-bit chunk b1 b2 b3 b4 b5 b6:
             * Row index (0..3)     = 2-bit integer formed by outer bits (b1 b6).
             * Column index (0..15) = 4-bit integer formed by inner bits (b2 b3 b4 b5).
           - Each row of each S-box is a permutation of the integers 0..15 (4 bits).
      4. Permutation (P): Permute the 32-bit concatenated S-box output so that the
         4 output bits of each S-box fan out across 4 different S-boxes in the next round.
    """
    # 1. Expansion (32 bits -> 48 bits)
    expanded = permute(right_half, E)

    # 2. Key mixing (XOR with 48-bit round subkey)
    xored = xor_bits(expanded, subkey)

    # 3. Substitution through the 8 S-boxes (48 bits -> 32 bits)
    sbox_output = []
    for i in range(8):
        block = xored[i * 6: (i + 1) * 6]
        # Outer bits (1st and 6th, indices 0 and 5) determine the S-box row (0..3)
        row = (block[0] << 1) | block[5]
        # Inner 4 bits (2nd through 5th, indices 1..4) determine the S-box column (0..15)
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOXES[i][row][col]
        # Convert the 4-bit integer lookup result (0..15) back into 4 individual bits
        sbox_output.extend([(val >> (3 - bit_idx)) & 1 for bit_idx in range(4)])

    # 4. Permutation P (32 bits -> 32 bits)
    return permute(sbox_output, P)


def des_process_block(block_hex, subkeys, mode_name="Encryption"):
    """Process one 64-bit block (16 hex characters) through the 16-round DES Feistel network.

    A complete DES block operation follows three phases:
      1. Initial Permutation (IP): Rearrange the 64 input bits and split into two
         32-bit halves: L0 (left 32 bits) and R0 (right 32 bits).
      2. 16 Feistel Rounds (for i = 1..16):
           L_i = R_{i-1}
           R_i = L_{i-1} XOR F(R_{i-1}, K_i)
      3. Final Swap & Final Permutation (FP / IP^-1):
         Swap the final halves to form the 64-bit pre-output (R16 || L16), then apply FP.
         Why the final swap? In a Feistel round, only one half is modified and then the
         halves cross over. Reversing the crossover after Round 16 makes encryption and
         decryption structurally identical: feeding (R16 || L16) into the same network with
         reversed subkeys (K16..K1) directly cancels each round's XOR:
           L_{15} = R_{16} XOR F(L_{16}, K_{16}) = (L_{15} XOR F(R_{15}, K_{16})) XOR F(R_{15}, K_{16})
    """
    print(f"=== DES {mode_name} ===")
    print(f"Input Block : {block_hex}")

    bits = hex_to_bits(block_hex)

    # 1. Initial Permutation (IP) and split into 32-bit L0 and R0 halves
    ip_bits = permute(bits, IP)
    L, R = ip_bits[:32], ip_bits[32:]
    print(f"After IP    : L0 = {bits_to_hex(L)}, R0 = {bits_to_hex(R)}")

    # 2. 16 Rounds of the Feistel Network
    for i in range(16):
        f_out = feistel(R, subkeys[i])
        # Feistel crossover: new L is old R; new R is old L XOR F(old R, K_i)
        L, R = R, xor_bits(L, f_out)
        print(
            f"Round {i + 1:2d}    : f(R, K) = {bits_to_hex(f_out)}, L{i + 1:<2d} = {bits_to_hex(L)}, "
            f"R{i + 1:<2d} = {bits_to_hex(R)}"
        )

    # 3. 32-bit Irregular Swap (R16 || L16) followed by Final Permutation (FP = IP^-1)
    pre_output = R + L
    print(f"Pre-output  : R16||L16 = {bits_to_hex(pre_output)}")

    fp_bits = permute(pre_output, FP)
    result_hex = bits_to_hex(fp_bits)
    print(f"Output Block: {result_hex}\n")
    return result_hex


if __name__ == "__main__":
    # Standard classic test vector (from NBS/NIST & scholarly DES step-by-step walkthroughs).
    # Never use single DES or fixed demonstration keys to protect real data.
    PLAINTEXT_HEX = "0123456789ABCDEF"
    KEY_HEX = "133457799BBCDFF1"
    EXPECTED_HEX = "85E813540F0AB405"

    print(f"Plaintext   : {PLAINTEXT_HEX}")
    print(f"Key         : {KEY_HEX}\n")

    # Derive the sixteen 48-bit round subkeys (K1..K16)
    key_bits = hex_to_bits(KEY_HEX)
    subkeys = generate_subkeys(key_bits)

    # Encrypt the 64-bit plaintext block using subkeys in forward order (K1..K16)
    ciphertext_hex = des_process_block(PLAINTEXT_HEX, subkeys, mode_name="Encryption")
    assert ciphertext_hex == EXPECTED_HEX, f"Mismatch: got {ciphertext_hex}, expected {EXPECTED_HEX}"

    # Decrypt the 64-bit ciphertext block using the exact same function with reversed subkeys (K16..K1)
    decrypted_hex = des_process_block(ciphertext_hex, subkeys[::-1], mode_name="Decryption")
    assert decrypted_hex == PLAINTEXT_HEX, f"Mismatch: got {decrypted_hex}, expected {PLAINTEXT_HEX}"

    print("Verification successful: Ciphertext and Decrypted Plaintext match standard test vectors!")

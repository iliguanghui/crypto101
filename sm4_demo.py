"""GM/T 0002-2012 (GB/T 32907-2016 / ISO/IEC 18033-3) SM4 Block Cipher, in pure Python.

References:
  http://www.gmbz.org.cn/upload/2025-01-23/1737625646289030731.pdf (GM/T 0002-2012)
  https://datatracker.ietf.org/doc/html/rfc8998
  https://en.wikipedia.org/wiki/SM4_(cipher)

Parameters: block size = 128 bits (16 bytes, represented as four 32-bit big-endian words);
key size = 128 bits (16 bytes, four 32-bit words).
Structure: 32-round Unbalanced Feistel Network (specifically, a 4-branch Generalized
Feistel Network / shift-register structure) using thirty-two 32-bit round keys (rk_0..rk_31),
followed by a final 4-word Reverse Transformation R(X_32, X_33, X_34, X_35) = (X_35, X_34, X_33, X_32).

How SM4's Unbalanced Feistel Network Works & Why Decryption Reuses the Encryption Circuit:
  Unlike DES (a *balanced* Feistel network that splits the block into two equal 32-bit halves),
  SM4 splits its 128-bit state into FOUR 32-bit words (X_i, X_{i+1}, X_{i+2}, X_{i+3}).
  In each round i (0..31), THREE words (96 bits) are mixed together with the 32-bit round
  key rk_i inside the round function T, and the 32-bit output masks the remaining ONE word (X_i):
      X_{i+4} = X_i ^ T(X_{i+1} ^ X_{i+2} ^ X_{i+3} ^ rk_i)
  The state window then shifts by one 32-bit word: (X_i, X_{i+1}, X_{i+2}, X_{i+3}) -> (X_{i+1}, X_{i+2}, X_{i+3}, X_{i+4}).
  Notice that X_{i+1}, X_{i+2}, and X_{i+3} pass through to the next round UNCHANGED!
  Therefore, to invert the round and recover X_i from (X_{i+1}, X_{i+2}, X_{i+3}, X_{i+4}):
      X_i = X_{i+4} ^ T(X_{i+1} ^ X_{i+2} ^ X_{i+3} ^ rk_i)
  Because addition in GF(2) (XOR) is commutative (X_{i+1} ^ X_{i+2} ^ X_{i+3} == X_{i+3} ^ X_{i+2} ^ X_{i+1}),
  the final word reversal R(X_32, X_33, X_34, X_35) = (X_35, X_34, X_33, X_32) places the untouched
  words in the exact positions expected by the forward round function. Feeding (X_35, X_34, X_33, X_32)
  into the exact same 32-round encryption circuit with reversed round keys (rk_31..rk_0) computes:
      Round 0 (dec): X_35 ^ T(X_34 ^ X_33 ^ X_32 ^ rk_31) == X_31
      Round 1 (dec): X_34 ^ T(X_33 ^ X_32 ^ X_31 ^ rk_30) == X_30
      ...
      Round 31 (dec): X_4  ^ T(X_3  ^ X_2  ^ X_1  ^ rk_0)  == X_0
  And the final reversal R(X_3, X_2, X_1, X_0) = (X_0, X_1, X_2, X_3) restores the original plaintext!

Comparison with DES and AES:
  - Structure:
      * DES: 16-round Balanced Feistel (2 branches of 32 bits; 1/2 of block updated per round).
      * SM4: 32-round Unbalanced Feistel (4 branches of 32 bits; 1/4 of block updated per round,
             so 4 rounds are needed to modify every bit of the 128-bit state at least once).
      * AES: 10/12/14-round Substitution-Permutation Network (SPN; all 128 bits updated every round).
  - Decryption Symmetry:
      * DES & SM4: Encryption and decryption are 100% identical in hardware/software (only reverse
        the round key schedule). Neither T nor the S-box needs to be inverted for decryption.
      * AES: SPN requires separate inverse operations (InvSubBytes, InvShiftRows, InvMixColumns)
        and an equivalent inverse key schedule for decryption.
  - S-box & Algebraic Math:
      * DES: Eight different 6-to-4-bit S-boxes designed via combinatorial heuristics (lookup tables).
      * AES & SM4: Both use a single 8-to-8-bit S-box based on the multiplicative inverse in GF(2^8)
        wrapped in affine transformations (AES applies one affine transform after inversion modulo
        0x11B; SM4 applies the same affine transform both BEFORE and AFTER inversion modulo 0x1F5).
  - Diffusion Layer:
      * DES: Bit-level wire-crossing permutation P (fast in hardware gates, slow in software).
      * AES: MixColumns matrix multiplication over GF(2^8) + ShiftRows.
      * SM4: Pure 32-bit XOR and circular left shifts: L(B) = B ^ (B<<<2) ^ (B<<<10) ^ (B<<<18) ^ (B<<<24),
        making SM4 exceptionally compact and fast in both 32-bit software and hardware.

This teaching implementation accepts bytes/bytearray and returns bytes, using only primitive
types (ints, lists, bytes) with no constant-time or speed claims. Verbose output exposes
secret key state: use only with demo keys.

Run: python sm4_demo.py
"""

from typing import List, Union

ByteInput = Union[bytes, bytearray]

BLOCK_BYTES: int = 16
KEY_BYTES: int = 16
WORD_MASK: int = 0xFFFFFFFF  # 32-bit unsigned integer bitmask
FIELD_POLYNOMIAL: int = 0x1F5  # Irreducible polynomial x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1 in GF(2^8)

# --- SM4 Substitution Table (GM/T 0002-2012, Section 4.2.1) ---
# SBOX[byte] replaces one 8-bit byte. The high nibble selects the printed table's
# row, and the low nibble its column. Unlike AES (which applies an affine transform
# only AFTER GF(2^8) inversion), SM4 sandwiches the GF(2^8) multiplicative inverse
# between two identical affine bit transforms: SBOX(a) = Affine( (Affine(a))^(-1) ).
# Reference table; the active SBOX is constructed algebraically below.
# SBOX: List[int] = [
#     0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
#     0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
#     0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
#     0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
#     0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
#     0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
#     0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
#     0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
#     0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
#     0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
#     0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
#     0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
#     0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
#     0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
#     0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
#     0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
# ]

# System Parameter FK (Family Key): four 32-bit words used to initialize the key schedule
# by XORing with the 128-bit input cipher key (K_0..K_3) = (MK_0 ^ FK_0, ..., MK_3 ^ FK_3).
FK: List[int] = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

# Fixed Parameter CK (Constant Key): thirty-two 32-bit constants (one per round in the key schedule).
# Defined by standard formula (GM/T 0002-2012 Section 4.3.2): let CK_i = (ck_{i,0}, ck_{i,1}, ck_{i,2}, ck_{i,3})
# be 4 bytes for i = 0..31, where ck_{i,j} = ((4*i + j) * 7) mod 256 (for j = 0..3).
# This breaks self-similarity (slide attacks) across rounds.
# Reference table; the active CK is constructed below.
# CK: List[int] = [
#     0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
#     0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
#     0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
#     0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
#     0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
#     0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
#     0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
#     0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
# ]


def construct_ck_word(round_index: int) -> int:
    """Compute the 32-bit constant key word CK_i for round i (0..31)."""
    if type(round_index) is not int or not 0 <= round_index <= 31:
        raise ValueError("round_index must be an integer from 0 to 31")
    b0 = ((4 * round_index + 0) * 7) & 0xFF
    b1 = ((4 * round_index + 1) * 7) & 0xFF
    b2 = ((4 * round_index + 2) * 7) & 0xFF
    b3 = ((4 * round_index + 3) * 7) & 0xFF
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def construct_ck() -> List[int]:
    """Generate all 32 Constant Key words CK_0..CK_31 from the standard formula."""
    return [construct_ck_word(i) for i in range(32)]


CK: List[int] = construct_ck()


# --- GF(2^8) Byte Arithmetic & S-Box Construction ---

def field_multiply(first: int, second: int) -> int:
    """Multiply bytes in GF(2^8); polynomial addition is XOR, with no carries.

    Bit i represents the coefficient of x^i. A left shift multiplies by x;
    if x^8 (0x100) appears, XOR with 0x1F5 reduces modulo the SM4 irreducible
    polynomial x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1.
    """
    product = 0
    for _ in range(8):
        if second & 1:
            product ^= first
        first <<= 1
        if first & 0x100:
            first ^= FIELD_POLYNOMIAL
        second >>= 1
    return product


def affine_byte(byte_val: int) -> int:
    """Apply the SM4 8-bit affine transformation over GF(2): A * x + C.

    Equivalent to multiplying the 8-bit vector by a right-circulant matrix with first row
    (1, 1, 0, 0, 1, 0, 1, 1) and XORing the constant 0xD3:
      Affine(x) = x ^ (x <<< 1) ^ (x <<< 3) ^ (x <<< 6) ^ (x <<< 7) ^ 0xD3
    """
    result = byte_val
    for distance in (1, 3, 6, 7):
        rotated = ((byte_val << distance) | (byte_val >> (8 - distance))) & 0xFF
        result ^= rotated
    return result ^ 0xD3


def construct_s_box_byte(input_byte: int, verbose: bool = False) -> int:
    """Construct one SM4 S-box entry: pre-affine transform, GF(2^8) inverse, post-affine transform."""
    if type(input_byte) is not int or not 0 <= input_byte <= 255:
        raise ValueError("input_byte must be an integer from 0 to 255")

    # Step 1: Pre-inversion affine transform A(x) + 0xD3
    pre_affine = affine_byte(input_byte)

    # Step 2: Multiplicative inverse in GF(2^8) modulo 0x1F5 (0 maps to 0)
    inverse = 0
    if pre_affine != 0:
        for candidate in range(1, 256):
            if field_multiply(pre_affine, candidate) == 1:
                inverse = candidate
                break

    # Step 3: Post-inversion affine transform A(inverse) + 0xD3
    output_byte = affine_byte(inverse)
    if verbose:
        print(
            f"Input: {input_byte:02X} -> pre-affine: {pre_affine:02X} -> "
            f"GF(2^8) inverse: {inverse:02X} -> post-affine SBOX output: {output_byte:02X}"
        )
    return output_byte


def construct_s_box() -> List[int]:
    """Generate all 256 SM4 S-box entries algebraically; index is input byte, value is output."""
    return [construct_s_box_byte(input_byte) for input_byte in range(256)]


# Build the S-box once at import time from its algebraic definition.
SBOX: List[int] = construct_s_box()


# --- Primitive Helper Functions (Operating on bytes & 32-bit unsigned ints) ---

def byte_input(value: object, name: str) -> bytes:
    """Ensure the input is a byte-like object and convert it to immutable bytes."""
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray")
    return bytes(value)


def bytes_to_words(data: ByteInput) -> List[int]:
    """Convert 16 bytes (128 bits) into four 32-bit big-endian unsigned integers."""
    raw = byte_input(data, "data")
    if len(raw) != BLOCK_BYTES:
        raise ValueError(f"Expected {BLOCK_BYTES} bytes, got {len(raw)}")
    return [int.from_bytes(raw[offset : offset + 4], "big") for offset in range(0, BLOCK_BYTES, 4)]


def words_to_bytes(words: List[int]) -> bytes:
    """Serialize four 32-bit unsigned integers into 16 big-endian bytes."""
    return b"".join((w & WORD_MASK).to_bytes(4, "big") for w in words)


def rotl32(val: int, n: int) -> int:
    """Perform a 32-bit circular left shift (rotation): (val <<< n) mod 2^32."""
    return ((val << n) | (val >> (32 - n))) & WORD_MASK


# --- Core SM4 Building Blocks ---

def tau(word: int) -> int:
    """Non-linear transformation tau(A): apply the 8-bit S-box in parallel to all 4 bytes.

    Given a 32-bit word A = (a_0, a_1, a_2, a_3), tau(A) = (SBOX(a_0), SBOX(a_1), SBOX(a_2), SBOX(a_3)).
    This provides non-linear 'confusion'.
    """
    b0 = SBOX[(word >> 24) & 0xFF]
    b1 = SBOX[(word >> 16) & 0xFF]
    b2 = SBOX[(word >> 8) & 0xFF]
    b3 = SBOX[word & 0xFF]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def linear_l(b: int) -> int:
    """Linear diffusion transformation L(B) used in the cipher round function.

    L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24).
    Spreads changes from each 8-bit S-box output across the entire 32-bit word
    (achieving optimal branch number 5).
    """
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)


def linear_l_prime(b: int) -> int:
    """Linear transformation L'(B) used exclusively in the key schedule.

    L'(B) = B ^ (B <<< 13) ^ (B <<< 23).
    """
    return b ^ rotl32(b, 13) ^ rotl32(b, 23)


def mixer_t(word: int) -> int:
    """Composite permutation T(.) = L(tau(.)) for data encryption/decryption rounds."""
    return linear_l(tau(word))


def mixer_t_prime(word: int) -> int:
    """Composite permutation T'(.) = L'(tau(.)) for key expansion rounds."""
    return linear_l_prime(tau(word))


# --- Key Expansion & Unbalanced Feistel Cipher ---

def generate_round_keys(key: ByteInput, verbose: bool = True) -> List[int]:
    """Expand a 16-byte (128-bit) master key (MK_0..MK_3) into thirty-two 32-bit round keys (rk_0..rk_31).

    Notice that the SM4 key schedule is ALSO a 32-round Unbalanced Feistel Network!
      1. Initialize (K_0, K_1, K_2, K_3) = (MK_0 ^ FK_0, MK_1 ^ FK_1, MK_2 ^ FK_2, MK_3 ^ FK_3).
      2. For i = 0..31:
           rk_i = K_{i+4} = K_i ^ T'(K_{i+1} ^ K_{i+2} ^ K_{i+3} ^ CK_i)
    """
    key_bytes = byte_input(key, "key")
    if len(key_bytes) != KEY_BYTES:
        raise ValueError("SM4 key must be exactly 16 bytes (128 bits)")
    if verbose:
        print("=== SM4 Key Schedule (32 Round Keys) ===")
    mk: List[int] = bytes_to_words(key_bytes)
    K: List[int] = [mk[i] ^ FK[i] for i in range(4)]
    if verbose:
        print(f"Initial K0..K3 (MK ^ FK): {' '.join(f'{w:08X}' for w in K)}")

    round_keys: List[int] = []
    for i in range(32):
        # Mix K_{i+1}, K_{i+2}, K_{i+3} and constant CK_i through T', then XOR with K_i
        rk = K[0] ^ mixer_t_prime(K[1] ^ K[2] ^ K[3] ^ CK[i])
        round_keys.append(rk)
        # Shift the 4-word sliding window: (K_0, K_1, K_2, K_3) <- (K_1, K_2, K_3, rk)
        K = [K[1], K[2], K[3], rk]
        if verbose:
            print(f"Round {i:2d}: CK[{i:2d}] = {CK[i]:08X} -> rk[{i:2d}] = {rk:08X}")
    if verbose:
        print()
    return round_keys


def sm4_crypt_block(
    block: ByteInput,
    round_keys: List[int],
    mode_name: str = "Encryption",
    verbose: bool = True,
) -> bytes:
    """Process one 16-byte (128-bit) block through the 32-round SM4 Unbalanced Feistel Network.

    For encryption, pass `round_keys` in forward order (rk_0..rk_31).
    For decryption, pass `round_keys[::-1]` in reverse order (rk_31..rk_0).

    Steps:
      1. Split the 16-byte input block into four 32-bit big-endian words: (X_0, X_1, X_2, X_3).
      2. For round i = 0..31:
           X_{i+4} = X_i ^ T(X_{i+1} ^ X_{i+2} ^ X_{i+3} ^ rk_i)
         Advance the 4-word state register to (X_{i+1}, X_{i+2}, X_{i+3}, X_{i+4}).
      3. Apply the Reverse Transformation R to the final 4 words:
           Output = (X_35, X_34, X_33, X_32)
    """
    block_bytes = byte_input(block, "block")
    if len(block_bytes) != BLOCK_BYTES:
        raise ValueError("SM4 requires exactly one 16-byte (128-bit) block")

    if verbose:
        print(f"=== SM4 {mode_name} ===")
        print(f"Input Block : {block_bytes.hex().upper()}")

    X: List[int] = bytes_to_words(block_bytes)
    if verbose:
        print(f"Initial State (X0..X3): {' '.join(f'{w:08X}' for w in X)}")

    # 32 Rounds of the 4-Branch Unbalanced Feistel Network
    for i in range(32):
        # Mix the right 3 words (96 bits) with the round key, then pass through T = L(tau(.))
        t_out = mixer_t(X[1] ^ X[2] ^ X[3] ^ round_keys[i])
        # Mask the leftmost word (32 bits) with the output of T
        x_next = X[0] ^ t_out
        # Shift the 4-word register left by one word (X_1, X_2, X_3 pass through untouched)
        X = [X[1], X[2], X[3], x_next]
        if verbose:
            print(
                f"Round {i:2d} (rk={round_keys[i]:08X}): "
                f"T_out = {t_out:08X} -> X[{i + 4:2d}] = {x_next:08X} | "
                f"State = {' '.join(f'{w:08X}' for w in X)}"
            )

    # Final Reverse Transformation R(X_32, X_33, X_34, X_35) = (X_35, X_34, X_33, X_32)
    # Just like the final L/R swap in DES, reversing the 4 words aligns the untouched
    # words (X_34, X_33, X_32) into the exact positions needed by T() during decryption!
    reversed_words: List[int] = [X[3], X[2], X[1], X[0]]
    result: bytes = words_to_bytes(reversed_words)
    if verbose:
        print(f"After Reverse R(X32..X35): {result.hex().upper()}\n")
    return result


def sm4_process_block(
    block: ByteInput, key: ByteInput, decrypt: bool = False, verbose: bool = False
) -> bytes:
    """Encrypt/decrypt one 16-byte block given (block, key), matching aes_process_block.

    Expands the 16-byte master key into 32 round keys, reverses their order when
    `decrypt=True`, and runs the 32-round SM4 Unbalanced Feistel Network.
    """
    block_bytes = byte_input(block, "block")
    if len(block_bytes) != BLOCK_BYTES:
        raise ValueError("SM4 requires exactly one 16-byte (128-bit) block")
    round_keys = generate_round_keys(key, verbose=verbose)
    if decrypt:
        round_keys = round_keys[::-1]
    mode_name = "Decryption" if decrypt else "Encryption"
    return sm4_crypt_block(block_bytes, round_keys, mode_name=mode_name, verbose=verbose)


if __name__ == "__main__":
    # Official Standard Test Vector from GM/T 0002-2012 Appendix A (Example 1 & Example 2)
    plaintext: bytes = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    key: bytes       = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    expected: bytes  = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")
    expected_1m: bytes = bytes.fromhex("595298C7C6FD271F0402F804C33D3F66")

    print("Plaintext:", plaintext.hex().upper())
    print("Key      :", key.hex().upper())
    print()

    # 1. Encrypt the 16-byte plaintext block directly with (plaintext, key)
    ciphertext: bytes = sm4_process_block(plaintext, key, verbose=True)
    print("Ciphertext:", ciphertext.hex().upper())
    assert ciphertext == expected, f"Mismatch: got {ciphertext.hex().upper()}, expected {expected.hex().upper()}"

    # 2. Decrypt the 16-byte ciphertext block directly with (ciphertext, key, decrypt=True)
    recovered: bytes = sm4_process_block(ciphertext, key, decrypt=True, verbose=True)
    print("Recovered :", recovered.hex().upper())
    assert recovered == plaintext, f"Mismatch: got {recovered.hex().upper()}, expected {plaintext.hex().upper()}"

    print("Verification 1 successful: Single-block Encryption and Decryption match GM/T 0002-2012 Example 1!")
    if False:
        # Optional: GM/T 0002-2012 Example 2 (1,000,000 iterations)
        rks: List[int] = generate_round_keys(key, verbose=False)
        block: bytes = plaintext
        for _ in range(1_000_000):
            block = sm4_crypt_block(block, rks, verbose=False)
        assert block == expected_1m

"""FIPS 197 Advanced Encryption Standard (AES), in pure Python.

References:
  https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
  https://doi.org/10.6028/NIST.FIPS.197-upd1

Parameters: block size = 128 bits (16 bytes), for ALL key sizes.
Key sizes: 128/192/256 bits (16/24/32 bytes), giving 10/12/14 rounds.
FIPS notation: Nb = 4 state columns; Nk = 4/6/8 key words; Nr = Nk + 6.
Each word contains 4 bytes. There are Nr + 1 round keys, each 16 bytes.

AES is a substitution-permutation network. Unlike DES's Feistel network,
AES decryption uses inverse transformations, as well as reversed round keys.
This file implements the single-block primitive, without padding or a mode
such as CBC or GCM. It accepts bytes/bytearray and returns bytes.
Python table lookups and arithmetic are not constant-time. This is teaching
code; verbose output exposes intermediate secrets, so use demonstration keys.

Run: python3 aes_demo.py
The demo prints round keys and the state after each encryption/decryption step.
"""

from typing import List, Tuple, Union

# State matrices use state[row][column]; each entry is one byte.
State = List[List[int]]
ByteInput = Union[bytes, bytearray]

BLOCK_BYTES: int = 16
VALID_KEY_BYTES: Tuple[int, ...] = (16, 24, 32)
STATE_DIMENSION: int = 4
FIELD_POLYNOMIAL: int = 0x11B  # x^8 + x^4 + x^3 + x + 1.

# --- Substitution Tables (FIPS 197, Table 4) ---
# S_BOX[byte] replaces one byte. The high nibble selects the printed table's
# row, and the low nibble its column. This nonlinear substitution is formed
# from inversion in GF(2^8) (zero maps to zero), then an affine bit transform.
# Reference table; the active S_BOX is constructed below.
# S_BOX = [
#     0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
#     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
#     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
#     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
#     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
#     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
#     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
#     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
#     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
#     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
#     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
#     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
#     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
#     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
#     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
#     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
# ]


MIX_MATRIX: State = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
]

INV_MIX_MATRIX: State = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14]
]


# --- Byte Arithmetic and State Representation ---

def byte_input(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray")
    return bytes(value)


def field_multiply(first: int, second: int) -> int:
    """Multiply bytes in GF(2^8); polynomial addition is XOR, with no carries.

    Bit i represents the coefficient of x^i. A left shift multiplies by x;
    if x^8 appears, XOR with 0x11B reduces modulo the AES field polynomial.
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


def construct_s_box_byte(input_byte: int, verbose: bool = False) -> int:
    """Construct one AES S-box entry: field inverse, then affine transform."""
    if type(input_byte) is not int or not 0 <= input_byte <= 255:
        raise ValueError("input_byte must be an integer from 0 to 255")

    # Zero has no multiplicative inverse; AES defines this intermediate as 0.
    # For any other byte, try every nonzero field element until a*b == 1.
    inverse = 0
    if input_byte != 0:
        for candidate in range(1, 256):
            if field_multiply(input_byte, candidate) == 1:
                inverse = candidate
                break

    # Affine transform: XOR the inverse with four circular left rotations,
    # then XOR 0x63. Each rotation is of the ORIGINAL inverse, not the result.
    output_byte = inverse
    if verbose:
        print(f"Input: {input_byte:02X}; field inverse: {inverse:02X}")
    for distance in range(1, 5):
        rotated = ((inverse << distance) | (inverse >> (8 - distance))) & 0xFF
        output_byte ^= rotated
        if verbose:
            print(f"Rotate left {distance}: {rotated:02X}; running XOR: {output_byte:02X}")
    output_byte ^= 0x63
    if verbose:
        print(f"XOR constant 63 -> S-box output: {output_byte:02X}")
    return output_byte


def construct_s_box() -> List[int]:
    """Generate all 256 entries; index is the input byte, value is its output."""
    return [construct_s_box_byte(input_byte) for input_byte in range(256)]


# Build the tables once, after the construction helpers have been defined.
S_BOX: List[int] = construct_s_box()

# Reverse the mapping: INV_S_BOX[S_BOX[value]] == value.
INV_S_BOX: List[int] = [0] * 256
for original_byte, substituted_byte in enumerate(S_BOX):
    INV_S_BOX[substituted_byte] = original_byte


def block_to_state(block: ByteInput) -> State:
    """Fill a 4x4 byte matrix COLUMN by COLUMN, as required by FIPS 197.

    Input byte indices:      state[row][column]:
      0  4  8 12               row 0
      1  5  9 13               row 1
      2  6 10 14               row 2
      3  7 11 15               row 3
    """
    return [[block[row + 4 * column] for column in range(4)] for row in range(4)]


def state_to_block(state: State) -> bytes:
    return bytes(state[row][column] for column in range(4) for row in range(4))


def show_state(round_number: int, step: str, state: State, verbose: bool) -> None:
    if verbose:
        # Serialize column by column, allowing direct comparison with FIPS traces.
        print(f"Round {round_number:2d} {step:16s}: {state_to_block(state).hex().upper()}")


# --- Key Expansion ---

def generate_round_keys(key: ByteInput, verbose: bool = False) -> List[State]:
    """Expand the key into Nr+1 byte matrices (FIPS 197 KEYEXPANSION).

    Every Nk words: rotate the previous word left by one byte, substitute its
    bytes, then XOR Rcon into its first byte. AES-256 also substitutes the
    previous word at positions congruent to 4 modulo Nk. Each resulting word
    is XORed with the word Nk positions back. Rcon advances by multiplying by 2.
    """
    key = byte_input(key, "key")
    if len(key) not in VALID_KEY_BYTES:
        raise ValueError("AES key must contain 16, 24, or 32 bytes")
    key_word_count = len(key) // 4
    round_count = key_word_count + 6
    words = [list(key[offset:offset + 4]) for offset in range(0, len(key), 4)]
    round_constant = 1
    for word_index in range(key_word_count, 4 * (round_count + 1)):
        previous = words[-1].copy()
        if word_index % key_word_count == 0:
            previous = previous[1:] + previous[:1]  # RotWord.
            previous = [S_BOX[value] for value in previous]  # SubWord.
            previous[0] ^= round_constant  # Rcon = [round_constant, 0, 0, 0].
            round_constant = field_multiply(round_constant, 2)
        elif key_word_count == 8 and word_index % key_word_count == 4:
            previous = [S_BOX[value] for value in previous]
        words.append([words[word_index - key_word_count][index] ^ previous[index]
                      for index in range(4)])
    round_keys = []
    for round_number in range(round_count + 1):
        # Four consecutive words become the four columns of a round key.
        key_bytes = bytes(value for word in words[4 * round_number:4 * round_number + 4]
                          for value in word)
        round_keys.append(block_to_state(key_bytes))
        if verbose:
            print(f"Round key {round_number:2d}: {key_bytes.hex().upper()}")
    return round_keys


# --- Round Transformations (modify the state in place) ---

def sub_bytes(state: State, inverse: bool = False) -> None:
    """Replace each byte independently; the inverse table undoes substitution."""
    table = INV_S_BOX if inverse else S_BOX
    for row in range(4):
        for column in range(4):
            state[row][column] = table[state[row][column]]


def shift_rows(state: State, inverse: bool = False) -> None:
    """Rotate row r left by r bytes; inverse rotates right. Row 0 stays put."""
    for row in range(1, 4):
        distance = -row if inverse else row
        state[row] = state[row][distance:] + state[row][:distance]


def mix_columns(state: State, inverse: bool = False) -> None:
    """Multiply each column by a fixed matrix over GF(2^8), spreading bytes."""
    matrix = INV_MIX_MATRIX if inverse else MIX_MATRIX
    for column in range(4):
        original = [state[row][column] for row in range(4)]
        # Read from a copy: overwriting a row must not affect later products.
        for row in range(4):
            result = 0
            for index in range(4):
                result ^= field_multiply(matrix[row][index], original[index])
            state[row][column] = result


def add_round_key(state: State, round_key: State) -> None:
    """XOR the state with a round key. XOR is its own inverse."""
    for row in range(4):
        for column in range(4):
            state[row][column] ^= round_key[row][column]


def aes_process_block(
        block: ByteInput, key: ByteInput, decrypt: bool = False, verbose: bool = False
) -> bytes:
    """Encrypt/decrypt exactly 16 bytes; reject partial or multiple blocks.

    Encryption: initial AddRoundKey, then Nr rounds of SubBytes, ShiftRows,
    MixColumns, AddRoundKey. The final round omits MixColumns.
    Decryption follows INVCIPHER, undoing those steps in reverse order.
    """
    block = byte_input(block, "block")
    if len(block) != BLOCK_BYTES:
        raise ValueError("AES requires exactly one 16-byte block")
    if verbose:
        print("=== AES Key Expansion ===")
    round_keys = generate_round_keys(key, verbose)
    round_count = len(round_keys) - 1
    state = block_to_state(block)
    if verbose:
        print("=== AES Decryption ===" if decrypt else "=== AES Encryption ===")
    show_state(0, "Input", state, verbose)
    first_key = round_count if decrypt else 0
    add_round_key(state, round_keys[first_key])
    show_state(first_key, "AddRoundKey", state, verbose)
    if decrypt:
        for round_number in range(round_count - 1, -1, -1):
            shift_rows(state, inverse=True)
            show_state(round_number, "InvShiftRows", state, verbose)
            sub_bytes(state, inverse=True)
            show_state(round_number, "InvSubBytes", state, verbose)
            add_round_key(state, round_keys[round_number])
            show_state(round_number, "AddRoundKey", state, verbose)
            if round_number != 0:
                mix_columns(state, inverse=True)
                show_state(round_number, "InvMixColumns", state, verbose)
    else:
        for round_number in range(1, round_count + 1):
            sub_bytes(state)
            show_state(round_number, "SubBytes", state, verbose)
            shift_rows(state)
            show_state(round_number, "ShiftRows", state, verbose)
            if round_number != round_count:
                mix_columns(state)
                show_state(round_number, "MixColumns", state, verbose)
            add_round_key(state, round_keys[round_number])
            show_state(round_number, "AddRoundKey", state, verbose)
    return state_to_block(state)


if __name__ == "__main__":
    # Public demonstration inputs; change the key to 24/32 bytes for AES-192/256.
    plaintext = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    print("Plaintext:", plaintext.hex().upper())
    print("Key      :", key.hex().upper())
    ciphertext = aes_process_block(plaintext, key, verbose=True)
    print("Ciphertext:", ciphertext.hex().upper())
    recovered = aes_process_block(ciphertext, key, decrypt=True, verbose=True)
    print("Recovered :", recovered.hex().upper())

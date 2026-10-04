"""Argon2 Memory-Hard Function Implementation.

This module implements the Argon2 password hashing algorithm following
the pseudo-code and naming conventions from the Wikipedia Argon2 article:
  https://en.wikipedia.org/wiki/Argon2
combined with the definitive specification from RFC 9106:
  https://www.rfc-editor.org/info/rfc9106/

Variants implemented:
  - Argon2d  (hash_type = 0): Data-dependent memory access.
  - Argon2i  (hash_type = 1): Data-independent memory access.
  - Argon2id (hash_type = 2): Hybrid variant (Argon2i for first half of pass 0, Argon2d thereafter).

Usage:
  python argon2_demo.py
  python verify_argon2.py
"""

import math
import hashlib
from typing import List, Tuple

# ==============================================================================
# Constants (matching RFC 9106)
# ==============================================================================
ARGON2_D: int = 0  # hash_type 0 = Argon2d
ARGON2_I: int = 1  # hash_type 1 = Argon2i
ARGON2_ID: int = 2  # hash_type 2 = Argon2id

ARGON2_VERSION_13: int = 0x13  # Version 0x13 (19 decimal)

ARGON2_SYNC_POINTS: int = 4  # SL = 4 vertical slices per pass
ARGON2_BLOCK_SIZE: int = 1024  # 1024 bytes (1 KiB) per memory block
ARGON2_QWORDS_IN_BLOCK: int = 128  # 128 64-bit words per block (1024 / 8)

MASK_64: int = 0xFFFFFFFFFFFFFFFF
MASK_32: int = 0xFFFFFFFF


# ==============================================================================
# Primitive Endianness and Math Helpers
# ==============================================================================

def to_le32(value: int) -> bytes:
    """Convert 32-bit integer to 4 bytes in little-endian (LE32)."""
    return value.to_bytes(4, 'little')


def to_le64(value: int) -> bytes:
    """RFC 9106 Section 2: LE64(a) converts 64-bit integer to 8 bytes in little-endian."""
    return value.to_bytes(8, 'little')


# RFC 9106 Aliases
LE32 = to_le32
LE64 = to_le64


def rotr64(w: int, n: int) -> int:
    """64-bit circular right rotation: (w >>> n)."""
    return ((w >> n) | (w << (64 - n))) & MASK_64


def f_modular(a: int, b: int) -> int:
    """Argon2 core modular addition and multiplication function:
    (a + b + 2 * trunc(a) * trunc(b)) mod 2^64
    where trunc(x) is the 32 least significant bits.
    """
    trunc_a = a & MASK_32
    trunc_b = b & MASK_32
    return (a + b + 2 * trunc_a * trunc_b) & MASK_64


# ==============================================================================
# Round Function GB and Permutation P
# ==============================================================================

def GB(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    """Modified BLAKE2b round mixing function GB operating on four 64-bit words.

    RFC 9106 Section 3.6, Figure 19.
    """
    # First half
    a = f_modular(a, b)
    d = rotr64(d ^ a, 32)
    c = f_modular(c, d)
    b = rotr64(b ^ c, 24)

    # Second half
    a = f_modular(a, b)
    d = rotr64(d ^ a, 16)
    c = f_modular(c, d)
    b = rotr64(b ^ c, 63)

    return a, b, c, d


def permutation_P(v: List[int]) -> List[int]:
    """Permutation P operating on sixteen 64-bit words (eight 16-byte registers).

    Applies GB column-wise to the 4x4 matrix of 64-bit words, then diagonally.
    RFC 9106 Section 3.6, Figure 17 & 18.
    """
    state = list(v)

    # Column-wise rounds
    state[0], state[4], state[8], state[12] = GB(state[0], state[4], state[8], state[12])
    state[1], state[5], state[9], state[13] = GB(state[1], state[5], state[9], state[13])
    state[2], state[6], state[10], state[14] = GB(state[2], state[6], state[10], state[14])
    state[3], state[7], state[11], state[15] = GB(state[3], state[7], state[11], state[15])

    # Diagonal-wise rounds
    state[0], state[5], state[10], state[15] = GB(state[0], state[5], state[10], state[15])
    state[1], state[6], state[11], state[12] = GB(state[1], state[6], state[11], state[12])
    state[2], state[7], state[8], state[13] = GB(state[2], state[7], state[8], state[13])
    state[3], state[4], state[9], state[14] = GB(state[3], state[4], state[9], state[14])

    return state


# ==============================================================================
# Compression Function G
# ==============================================================================

def G(block_x: List[int], block_y: List[int]) -> List[int]:
    """Compression function G referenced in Wikipedia:
      B_i[j] = G(B_i[j-1], B_i'[j'])

    Operates on two 1024-byte blocks (each 128 uint64 words).
    RFC 9106 Section 3.5, Figure 15 & 16:
      1. R = X XOR Y
      2. Apply P row-wise to get Q
      3. Apply P column-wise to get Z
      4. Output Z XOR R
    """
    # Step 1: R = X XOR Y
    R = [x ^ y for x, y in zip(block_x, block_y)]
    Q = list(R)

    # Step 2: Apply P row-wise (8 rows of 16 uint64 words each)
    for row in range(8):
        row_offset = row * 16
        Q[row_offset:row_offset + 16] = permutation_P(Q[row_offset:row_offset + 16])

    # Step 3: Apply P column-wise (8 columns of 8 16-byte registers each)
    Z = list(Q)
    for col in range(8):
        col_words = []
        for row in range(8):
            w0 = Q[row * 16 + 2 * col]
            w1 = Q[row * 16 + 2 * col + 1]
            col_words.extend([w0, w1])

        col_out = permutation_P(col_words)

        for row in range(8):
            Z[row * 16 + 2 * col] = col_out[2 * row]
            Z[row * 16 + 2 * col + 1] = col_out[2 * row + 1]

    # Step 4: Final output is Z XOR R
    return [z ^ r for z, r in zip(Z, R)]


# ==============================================================================
# Variable-length Hash Function (Function H')
# ==============================================================================

def vl_hash(message: bytes, digest_size: int = 32) -> bytes:
    """Variable-length hash function built using Blake2b, capable of generating
    arbitrary digests up to 2^32 bytes.
    RFC 9106 Section 3.3, Figure 8 (Function H').
    """
    digest_size_bytes = to_le32(digest_size)

    # If the requested digest_size is 64-bytes or lower, use Blake2b directly
    if digest_size <= 64:
        return hashlib.blake2b(digest_size_bytes + message, digest_size=digest_size).digest()

    # Calculate the number of whole blocks (knowing we only use 32 bytes from each)
    r = math.ceil(digest_size / 32) - 2

    # Initial block V_1 is generated from message
    V = [hashlib.blake2b(digest_size_bytes + message, digest_size=64).digest()]

    # Subsequent blocks V_2 .. V_r are generated from previous blocks
    for _ in range(1, r):
        V.append(hashlib.blake2b(V[-1], digest_size=64).digest())

    # Generate the final (possibly partial) block V_{r+1}
    partial_bytes_needed = digest_size - 32 * r
    V.append(hashlib.blake2b(V[-1], digest_size=partial_bytes_needed).digest())

    # Concatenate first 32 bytes (A_i) of each block V_1 .. V_r, plus full V_{r+1}
    A = [v[:32] for v in V[:-1]]
    digest = b''.join(A) + V[-1]
    return digest


# ==============================================================================
# Block Conversion Utilities (Primitive Types: int and bytes)
# ==============================================================================

def block_from_bytes(b: bytes) -> List[int]:
    """Convert 1024-byte string to a list of 128 little-endian 64-bit unsigned integers."""
    return [int.from_bytes(b[i:i + 8], 'little') for i in range(0, len(b), 8)]


def block_to_bytes(b: List[int]) -> bytes:
    """Convert a list of 128 64-bit integers to a 1024-byte string."""
    return b''.join(x.to_bytes(8, 'little') for x in b)


def xor_blocks(b1: List[int], b2: List[int]) -> List[int]:
    """Bitwise XOR of two 128-word memory blocks."""
    return [x ^ y for x, y in zip(b1, b2)]


# ==============================================================================
# Indexing (Function get_block_indexes)
# ==============================================================================

ZERO_BLOCK: List[int] = [0] * ARGON2_QWORDS_IN_BLOCK


def generate_pseudo_random_block(
        pass_number: int,
        lane_index: int,
        slice_index: int,
        block_count: int,
        iterations: int,
        hash_type: int,
        counter: int,
) -> List[int]:
    """Computes a 1024-byte pseudo-random block for Argon2i addressing.

    RFC 9106 Section 3.4.1.2:
      G(ZERO(1024), G(ZERO(1024), Z || LE64(counter) || ZERO(968)))
    """
    input_block = [
                      pass_number,
                      lane_index,
                      slice_index,
                      block_count,
                      iterations,
                      hash_type,
                      counter,
                  ] + [0] * 121
    tmp = G(ZERO_BLOCK, input_block)
    return G(ZERO_BLOCK, tmp)


def get_block_indexes(
        pass_number: int,
        current_lane: int,
        slice_index: int,
        index_in_segment: int,
        segment_length: int,
        column_count: int,
        parallelism: int,
        J_1: int,
        J_2: int,
) -> Tuple[int, int]:
    """Maps pseudo-random values J_1 and J_2 to reference block indices (i_prime, j_prime)
    according to RFC 9106 Section 3.4.2.

    Returns:
      (i_prime, j_prime): Reference lane index and reference column index.
    """
    # 1. Determine reference lane (i_prime)
    if pass_number == 0 and slice_index == 0:
        # First pass and first slice: block must be taken from the current lane
        i_prime = current_lane
    else:
        i_prime = J_2 % parallelism

    same_lane = (i_prime == current_lane)

    # 2. Determine reference area size (|W|) and starting position
    if pass_number == 0:
        # First pass: only slices 0 .. slice_index have been generated so far
        if slice_index == 0:
            reference_area_size = index_in_segment - 1
        else:
            if same_lane:
                reference_area_size = slice_index * segment_length + index_in_segment - 1
            else:
                reference_area_size = slice_index * segment_length + (-1 if index_in_segment == 0 else 0)
        start_position = 0
    else:
        # Subsequent passes: memory was fully populated during previous pass
        if same_lane:
            reference_area_size = column_count - segment_length + index_in_segment - 1
        else:
            reference_area_size = column_count - segment_length + (-1 if index_in_segment == 0 else 0)
        start_position = ((slice_index + 1) % ARGON2_SYNC_POINTS) * segment_length

    # 3. Non-uniform mapping of J_1 over [0, |W|) (RFC 9106 Figure 13)
    x = (J_1 * J_1) >> 32
    y_val = (reference_area_size * x) >> 32
    z_offset = reference_area_size - 1 - y_val

    # 4. Map offset to column index (j_prime)
    j_prime = (start_position + z_offset) % column_count

    return i_prime, j_prime


# ==============================================================================
# Input Validation (RFC 9106 Section 3.1: Argon2 Inputs and Outputs)
# ==============================================================================

def validate_inputs(
    password: bytes,
    salt: bytes,
    parallelism: int,
    tag_length: int = 32,
    memory_size_kb: int = 64,
    iterations: int = 3,
    version: int = ARGON2_VERSION_13,
    key: bytes = b'',
    associated_data: bytes = b'',
    hash_type: int = ARGON2_ID,
) -> None:
    """Validates all input parameters per RFC 9106 Section 3.1 before processing.

    Parameters & Constraints (RFC 9106 Section 3.1):
      - Message string P (password): length in [0, 2^32 - 1] bytes.
      - Nonce S (salt): length in [0, 2^32 - 1] bytes (16 bytes recommended).
      - Parallelism p: integer in [1, 2^24 - 1].
      - Tag length T: integer in [4, 2^32 - 1] bytes.
      - Memory size m: integer in [8*p, 2^32 - 1] KiB.
      - Number of passes t (iterations): integer in [1, 2^32 - 1].
      - Version number v: one byte 0x13 (19 decimal).
      - Secret value K (key): optional, length in [0, 2^32 - 1] bytes.
      - Associated data X: optional, length in [0, 2^32 - 1] bytes.
      - Type y: 0 for Argon2d, 1 for Argon2i, or 2 for Argon2id.

    Raises:
      TypeError: If any parameter is of an unexpected type.
      ValueError: If any parameter violates its range/length constraint.
    """
    # 1. Message string P (password)
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError(f"password (P) must be bytes or bytearray, got {type(password).__name__}")
    if len(password) > 0xFFFFFFFF:
        raise ValueError(f"password (P) length must not be greater than 2^32 - 1 bytes, got {len(password)}")

    # 2. Nonce S (salt)
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt (S) must be bytes or bytearray, got {type(salt).__name__}")
    if len(salt) > 0xFFFFFFFF:
        raise ValueError(f"salt (S) length must not be greater than 2^32 - 1 bytes, got {len(salt)}")

    # 3. Degree of parallelism p (lanes)
    if not isinstance(parallelism, int) or isinstance(parallelism, bool):
        raise TypeError(f"parallelism (p) must be an integer, got {type(parallelism).__name__}")
    if not (1 <= parallelism <= 0xFFFFFF):
        raise ValueError(f"parallelism (p) must be an integer from 1 to 2^24 - 1, got {parallelism}")

    # 4. Tag length T
    if not isinstance(tag_length, int) or isinstance(tag_length, bool):
        raise TypeError(f"tag_length (T) must be an integer, got {type(tag_length).__name__}")
    if not (4 <= tag_length <= 0xFFFFFFFF):
        raise ValueError(f"tag_length (T) must be an integer from 4 to 2^32 - 1 bytes, got {tag_length}")

    # 5. Memory size m (KiB)
    if not isinstance(memory_size_kb, int) or isinstance(memory_size_kb, bool):
        raise TypeError(f"memory_size_kb (m) must be an integer, got {type(memory_size_kb).__name__}")
    min_memory = 8 * parallelism
    if not (min_memory <= memory_size_kb <= 0xFFFFFFFF):
        raise ValueError(
            f"memory_size_kb (m) must be an integer from 8*p ({min_memory}) to 2^32 - 1 KiB, got {memory_size_kb}"
        )

    # 6. Number of passes t (iterations)
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise TypeError(f"iterations (t) must be an integer, got {type(iterations).__name__}")
    if not (1 <= iterations <= 0xFFFFFFFF):
        raise ValueError(f"iterations (t) must be an integer from 1 to 2^32 - 1, got {iterations}")

    # 7. Version number v
    if not isinstance(version, int) or isinstance(version, bool):
        raise TypeError(f"version (v) must be an integer, got {type(version).__name__}")
    if version != ARGON2_VERSION_13:
        raise ValueError(f"version (v) must be one byte 0x13 ({ARGON2_VERSION_13} decimal), got 0x{version:02x}")

    # 8. Secret value K (key)
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"key (K) must be bytes or bytearray, got {type(key).__name__}")
    if len(key) > 0xFFFFFFFF:
        raise ValueError(f"key (K) length must not be greater than 2^32 - 1 bytes, got {len(key)}")

    # 9. Associated data X
    if not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError(f"associated_data (X) must be bytes or bytearray, got {type(associated_data).__name__}")
    if len(associated_data) > 0xFFFFFFFF:
        raise ValueError(
            f"associated_data (X) length must not be greater than 2^32 - 1 bytes, got {len(associated_data)}"
        )

    # 10. Type y (hash_type)
    if not isinstance(hash_type, int) or isinstance(hash_type, bool):
        raise TypeError(f"hash_type (y) must be an integer, got {type(hash_type).__name__}")
    if hash_type not in (ARGON2_D, ARGON2_I, ARGON2_ID):
        raise ValueError(
            f"hash_type (y) must be 0 for Argon2d, 1 for Argon2i, or 2 for Argon2id, got {hash_type}"
        )


# ==============================================================================
# Main Algorithm (Function argon2)
# ==============================================================================

def argon2(
    password: bytes,
    salt: bytes,
    parallelism: int = 4,
    tag_length: int = 32,
    memory_size_kb: int = 64,
    iterations: int = 3,
    version: int = ARGON2_VERSION_13,
    key: bytes = b'',
    associated_data: bytes = b'',
    hash_type: int = ARGON2_ID,
    verbose: bool = False,
) -> bytes:
    """Computes the Argon2 password hash.

    Parameters:
      - password: Bytes (password / message to be hashed)
      - salt: Bytes (salt, 16 bytes recommended)
      - parallelism: Degree of parallelism / number of lanes (default: 4)
      - tag_length: Desired number of returned bytes (default: 32)
      - memory_size_kb: Memory size in KiB (default: 64 KiB for educational demo;
                        RFC 9106 recommends 64 MiB (65536 KiB) or more for production)
      - iterations: Number of iterations / passes to perform (default: 3)
      - version: Current version (0x13 / decimal 19)
      - key: Optional secret key (bytes)
      - associated_data: Optional arbitrary extra data (bytes)
      - hash_type: 0=Argon2d, 1=Argon2i, 2=Argon2id (default: 2)
      - verbose: If True, prints intermediate calculation values.

    Returns:
      tag: Generated bytes, tag_length bytes long.
    """
    # Validate inputs before actually processing them (RFC 9106 Section 3.1)
    validate_inputs(
        password=password,
        salt=salt,
        parallelism=parallelism,
        tag_length=tag_length,
        memory_size_kb=memory_size_kb,
        iterations=iterations,
        version=version,
        key=key,
        associated_data=associated_data,
        hash_type=hash_type,
    )

    variant_names = {ARGON2_D: "Argon2d", ARGON2_I: "Argon2i", ARGON2_ID: "Argon2id"}
    variant_name = variant_names.get(hash_type, f"Unknown({hash_type})")

    # --------------------------------------------------------------------------
    # Generate initial 64-byte block H_0 (RFC 9106 Section 3.2)
    # --------------------------------------------------------------------------
    buffer = (
        to_le32(parallelism)
        + to_le32(tag_length)
        + to_le32(memory_size_kb)
        + to_le32(iterations)
        + to_le32(version)
        + to_le32(hash_type)
        + to_le32(len(password))
        + password
        + to_le32(len(salt))
        + salt
        + to_le32(len(key))
        + key
        + to_le32(len(associated_data))
        + associated_data
    )
    H_0 = hashlib.blake2b(buffer, digest_size=64).digest()

    if verbose:
        print(f"\n{'=' * 45}")
        print(f"{variant_name} (version=0x{version:02x}, hash_type={hash_type})")
        print(f"{'=' * 45}")
        print(
            f"Memory: {memory_size_kb} KiB, Iterations: {iterations}, Parallelism: {parallelism} lanes, Tag length: {tag_length} bytes"
        )
        print(f"Password ({len(password)} bytes): {password[:16].hex()}...")
        print(f"Salt ({len(salt)} bytes)    : {salt.hex()}")
        if key:
            print(f"Key ({len(key)} bytes)     : {key.hex()}")
        if associated_data:
            print(f"AssocData ({len(associated_data)} bytes): {associated_data.hex()}")
        print(f"Pre-hashing digest (H_0): {H_0.hex()}")

    # --------------------------------------------------------------------------
    # Memory allocation (RFC 9106 Section 3.4)
    # block_count = 4 * parallelism * (memory_size_kb // (4 * parallelism))
    # column_count = block_count // parallelism
    # --------------------------------------------------------------------------
    block_count = 4 * parallelism * (memory_size_kb // (4 * parallelism))
    column_count = block_count // parallelism
    segment_length = column_count // ARGON2_SYNC_POINTS

    # Two-dimensional array B of 1 KiB blocks (parallelism rows x column_count columns)
    B: List[List[List[int]]] = [[[] for _ in range(column_count)] for _ in range(parallelism)]

    # --------------------------------------------------------------------------
    # Initial two blocks (columns 0 and 1) for each lane
    # --------------------------------------------------------------------------
    for i in range(parallelism):
        B[i][0] = block_from_bytes(vl_hash(H_0 + to_le32(0) + to_le32(i), ARGON2_BLOCK_SIZE))
        B[i][1] = block_from_bytes(vl_hash(H_0 + to_le32(1) + to_le32(i), ARGON2_BLOCK_SIZE))

    # --------------------------------------------------------------------------
    # Pass 0 & Further passes (Wikipedia lines 83-100 & RFC 9106 Slicing)
    # --------------------------------------------------------------------------
    for pass_number in range(iterations):
        for slice_index in range(ARGON2_SYNC_POINTS):
            for i in range(parallelism):
                # Addressing mode check:
                # Argon2i: always data-independent
                # Argon2d: always data-dependent
                # Argon2id: data-independent for pass 0, slices 0 & 1; data-dependent thereafter
                is_data_independent = (hash_type == ARGON2_I) or (
                        hash_type == ARGON2_ID and pass_number == 0 and slice_index < 2
                )

                # Precompute pseudo-random values for data-independent addressing
                pseudo_words: List[int] = []
                if is_data_independent:
                    num_pseudo_blocks = math.ceil(segment_length / ARGON2_QWORDS_IN_BLOCK)
                    for counter in range(1, num_pseudo_blocks + 1):
                        pseudo_words.extend(
                            generate_pseudo_random_block(
                                pass_number, i, slice_index, block_count, iterations, hash_type, counter
                            )
                        )

                # First two blocks B[i][0] and B[i][1] already computed in pass 0, slice 0
                start_index = 2 if (pass_number == 0 and slice_index == 0) else 0

                for index_in_segment in range(start_index, segment_length):
                    j = slice_index * segment_length + index_in_segment
                    prev_block = B[i][(j - 1) % column_count]

                    # Derive J_1 and J_2
                    if is_data_independent:
                        pseudo_val = pseudo_words[index_in_segment]
                        J_1 = pseudo_val & MASK_32
                        J_2 = (pseudo_val >> 32) & MASK_32
                    else:
                        J_1 = prev_block[0] & MASK_32
                        J_2 = (prev_block[0] >> 32) & MASK_32

                    # Map pseudo-random values to reference block indices (i_prime, j_prime)
                    i_prime, j_prime = get_block_indexes(
                        pass_number,
                        i,
                        slice_index,
                        index_in_segment,
                        segment_length,
                        column_count,
                        parallelism,
                        J_1,
                        J_2,
                    )

                    ref_block = B[i_prime][j_prime]
                    new_block = G(prev_block, ref_block)

                    # In pass 0: B[i][j] = G(prev, ref)
                    # In passes > 0: B[i][j] = B[i][j] xor G(prev, ref)
                    if pass_number > 0:
                        new_block = xor_blocks(new_block, B[i][j])

                    B[i][j] = new_block

        if verbose:
            last_lane = parallelism - 1
            last_col = column_count - 1
            print(f"  After pass {pass_number}:")
            print(f"    Block 0000 [  0]: {B[0][0][0]:016x}")
            print(f"    Block 0000 [  1]: {B[0][0][1]:016x}")
            print(f"    Block 0000 [  2]: {B[0][0][2]:016x}")
            print(f"    Block 0000 [  3]: {B[0][0][3]:016x}")
            print("    ...")
            print(f"    Block {block_count - 1:04d} [124]: {B[last_lane][last_col][124]:016x}")
            print(f"    Block {block_count - 1:04d} [125]: {B[last_lane][last_col][125]:016x}")
            print(f"    Block {block_count - 1:04d} [126]: {B[last_lane][last_col][126]:016x}")
            print(f"    Block {block_count - 1:04d} [127]: {B[last_lane][last_col][127]:016x}")

    # --------------------------------------------------------------------------
    # Compute final block C as XOR of last column of each row (lines 101-104)
    # --------------------------------------------------------------------------
    C = list(B[0][column_count - 1])
    for i in range(1, parallelism):
        C = xor_blocks(C, B[i][column_count - 1])

    # --------------------------------------------------------------------------
    # Compute output tag (RFC 9106 Section 3.7: tag = vl_hash(C, tag_length))
    # --------------------------------------------------------------------------
    tag = vl_hash(block_to_bytes(C), tag_length)

    if verbose:
        print(f"  Final Block C (first 2 words): {C[0]:016x} {C[1]:016x}")
        print(f"  Tag ({tag_length} bytes): {tag.hex()}")

    return tag


# ==============================================================================
# Aliases and Convenience Wrappers
# ==============================================================================

# Generic alias matching snake_case naming
argon2_hash = argon2
Argon2 = argon2  # Backward compatibility alias


def argon2d(password: bytes, salt: bytes, **kwargs) -> bytes:
    """Argon2d convenience wrapper (hash_type = 0)."""
    kwargs.pop("hash_type", None)
    return argon2(password, salt, hash_type=ARGON2_D, **kwargs)


def argon2i(password: bytes, salt: bytes, **kwargs) -> bytes:
    """Argon2i convenience wrapper (hash_type = 1)."""
    kwargs.pop("hash_type", None)
    return argon2(password, salt, hash_type=ARGON2_I, **kwargs)


def argon2id(password: bytes, salt: bytes, **kwargs) -> bytes:
    """Argon2id convenience wrapper (hash_type = 2)."""
    kwargs.pop("hash_type", None)
    return argon2(password, salt, hash_type=ARGON2_ID, **kwargs)


# ==============================================================================
# Verification and Demonstration
# ==============================================================================

def verify_rfc_test_vectors():
    """Runs all three RFC 9106 Section 5 test vectors and verifies bit-for-bit equality."""
    print("=" * 60)
    print("VERIFYING RFC 9106 TEST VECTORS (Argon2d, Argon2i, Argon2id)")
    print("=" * 60)

    # Inputs from RFC 9106 Section 5
    password = b'\x01' * 32
    salt = b'\x02' * 16
    key = b'\x03' * 8
    associated_data = b'\x04' * 12
    parallelism = 4
    tag_length = 32
    memory_size_kb = 32  # 32 KiB
    iterations = 3  # 3 passes

    expected_vectors = {
        ARGON2_D: {
            "name": "Argon2d",
            "section": "5.1",
            "tag": "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        },
        ARGON2_I: {
            "name": "Argon2i",
            "section": "5.2",
            "tag": "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        },
        ARGON2_ID: {
            "name": "Argon2id",
            "section": "5.3",
            "tag": "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        },
    }

    for variant_type, expected in expected_vectors.items():
        actual_tag = argon2(
            password=password,
            salt=salt,
            parallelism=parallelism,
            tag_length=tag_length,
            memory_size_kb=memory_size_kb,
            iterations=iterations,
            version=ARGON2_VERSION_13,
            key=key,
            associated_data=associated_data,
            hash_type=variant_type,
            verbose=True,
        )

        actual_tag_hex = actual_tag.hex()
        expected_tag_hex = expected["tag"]
        assert actual_tag_hex == expected_tag_hex, (
            f"FAIL: {expected['name']} tag mismatch!\n"
            f"  Expected: {expected_tag_hex}\n"
            f"  Actual:   {actual_tag_hex}"
        )
        print(f"--> PASS: {expected['name']} matches RFC 9106 Section {expected['section']} exactly!\n")

    print("=" * 60)
    print("ALL RFC 9106 TEST VECTORS PASSED SUCCESSFULLY!")
    print("=" * 60)


def main():
    # 1. Run official test vector verification
    verify_rfc_test_vectors()

    # 2. Practical password hashing demonstration
    print("\n" + "=" * 60)
    print("PRACTICAL PASSWORD HASHING DEMO")
    print("=" * 60)
    user_password = b"correct horse battery staple"
    user_salt = b"unique_random_s1"
    print(f"Password : {user_password.decode('utf-8')}")
    print(f"Salt     : {user_salt.decode('utf-8')}")

    # Derive 32-byte key with Argon2id using Wikipedia names
    derived_key = argon2id(
        password=user_password,
        salt=user_salt,
    )
    print(f"Argon2id Derived Key (hex): {derived_key.hex()}")


if __name__ == "__main__":
    main()

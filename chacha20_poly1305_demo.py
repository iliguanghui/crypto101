"""RFC 8439 ChaCha20, Poly1305, and ChaCha20-Poly1305, in pure Python.

References:
  https://www.rfc-editor.org/info/rfc8439/
  https://en.wikipedia.org/wiki/ChaCha20-Poly1305

Parameters: key = 32 bytes (256 bits); nonce = 12 bytes (96 bits).
ChaCha20 counter = 0..2**32-1; each counter produces 64 bytes.
Poly1305 uses a 32-byte ONE-TIME key and produces a 16-byte tag.
AEAD reserves counter 0 for that key, and starts payload encryption at 1;
its maximum payload is (2**32-1)*64 bytes. AAD length fits in 64 bits.
Never reuse a nonce under a key, or a standalone Poly1305 key for messages.

Compared with AES-GCM: both XOR plaintext with a counter-based keystream,
then authenticate AAD and ciphertext. ChaCha20 uses addition, XOR and
rotation instead of AES. Poly1305 uses integer arithmetic modulo 2**130-5,
whereas GHASH uses GF(2**128) polynomial arithmetic. AEAD lengths here are
little-endian BYTE counts; GCM uses big-endian BIT counts. This AEAD always
has a 256-bit key and 128-bit tag; AES-GCM supports other key/tag lengths.
ChaCha20 is designed for efficient software; AES-GCM benefits from hardware
AES and carryless multiplication. This teaching code makes no speed claims.
Python big-integer operations are not constant-time. Verbose output exposes
secrets: use it only with demonstration keys.

Run: python3 chacha20_poly1305_demo.py
Test: python3 verify_chacha20_poly1305.py
"""

from hmac import compare_digest  # Constant-time comparison to prevent timing side-channel attacks

# --- Cryptographic Constants (RFC 8439) ---
KEY_BYTES = 32  # 256-bit key (used for both ChaCha20 and Poly1305)
NONCE_BYTES = 12  # 96-bit nonce (Number used ONCE)
TAG_BYTES = 16  # 128-bit authentication tag output by Poly1305
BLOCK_BYTES = 64  # ChaCha20 generates 64 bytes (512 bits) per block
WORD_MASK = (1 << 32) - 1  # 0xFFFFFFFF: bitmask for 32-bit unsigned arithmetic
MAX_PAYLOAD_BYTES = WORD_MASK * BLOCK_BYTES  # ~256 GB max payload (counters 1..2^32-1)
MAX_AAD_BYTES = (1 << 64) - 1  # AAD length is encoded as a 64-bit unsigned integer
POLY1305_MODULUS = (1 << 130) - 5  # Prime modulus 2^130 - 5 for Poly1305 field arithmetic
CLAMP_MASK = 0x0ffffffc0ffffffc0ffffffc0fffffff  # Clears 22 specific bits of Poly1305's 'r' parameter


def byte_input(value, name):
    """Ensure the input is a byte-like object and convert it to immutable bytes."""
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray")
    return bytes(value)


def validate_key_nonce(key, nonce):
    """Validate that the key is 32 bytes (256 bits) and nonce is 12 bytes (96 bits)."""
    key, nonce = byte_input(key, "key"), byte_input(nonce, "nonce")
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("Expected a 32-byte key and a 12-byte nonce")
    return key, nonce


def rotate_left(word, distance):
    """Perform a 32-bit circular left shift (rotation) by 'distance' bits."""
    return ((word << distance) | (word >> (32 - distance))) & WORD_MASK


def quarter_round(state, first, second, third, fourth):
    """Mix four selected words in place; addition wraps at 32 bits.

    This is the core ARX (Add-Rotate-XOR) primitive of ChaCha20 (RFC 8439 Section 2.1).
    Because it uses only 32-bit addition, XOR, and fixed-distance bit rotations
    (no S-box table lookups or secret-dependent branches), it naturally runs in
    constant time on modern CPUs.
    """
    # Step 1: a += b; d ^= a; d <<<= 16
    state[first] = (state[first] + state[second]) & WORD_MASK
    state[fourth] = rotate_left(state[fourth] ^ state[first], 16)
    # Step 2: c += d; b ^= c; b <<<= 12
    state[third] = (state[third] + state[fourth]) & WORD_MASK
    state[second] = rotate_left(state[second] ^ state[third], 12)
    # Step 3: a += b; d ^= a; d <<<= 8
    state[first] = (state[first] + state[second]) & WORD_MASK
    state[fourth] = rotate_left(state[fourth] ^ state[first], 8)
    # Step 4: c += d; b ^= c; b <<<= 7
    state[third] = (state[third] + state[fourth]) & WORD_MASK
    state[second] = rotate_left(state[second] ^ state[third], 7)


def check_counter(counter, length=0):
    """Ensure the 32-bit block counter is valid and will not overflow during encryption."""
    # Note: 'type(counter) is not int' rejects booleans (since bool is a subclass of int in Python).
    if type(counter) is not int:
        raise TypeError("counter must be an integer")
    if not 0 <= counter <= WORD_MASK:
        raise ValueError("counter must fit in 32 bits")
    # Calculate ceiling(length / 64) and ensure counter + num_blocks <= 2^32.
    if (length + BLOCK_BYTES - 1) // BLOCK_BYTES > (1 << 32) - counter:
        raise ValueError("Message would wrap the block counter")


def chacha20_block(key, counter, nonce, verbose=False):
    """Return one 64-byte keystream block (RFC 8439 section 2.3).

    ChaCha20 state is a 4x4 matrix of sixteen 32-bit little-endian words (64 bytes total):
      [ c0  c1  c2  c3 ]  <- Words  0..3 : ASCII constant "expand 32-byte k"
      [ k0  k1  k2  k3 ]  <- Words  4..7 : First 16 bytes of the 256-bit key
      [ k4  k5  k6  k7 ]  <- Words  8..11: Last 16 bytes of the 256-bit key
      [ ctr n0  n1  n2 ]  <- Word 12: 32-bit block counter; Words 13..15: 96-bit nonce
    """
    key, nonce = validate_key_nonce(key, nonce)
    check_counter(counter)
    # Helper to split a byte string into 4-byte (32-bit) little-endian unsigned integers
    words = lambda data: [int.from_bytes(data[offset:offset + 4], "little")
                          for offset in range(0, len(data), 4)]
    # Construct the 16-word initial state matrix
    initial = words(b"expand 32-byte k") + words(key) + [counter] + words(nonce)
    state = initial.copy()
    if verbose:
        print("Initial state:", " ".join(f"{word:08x}" for word in state))
    # ChaCha20 runs 20 rounds total, organized as 10 "double rounds".
    # Each double round consists of 1 column round (4 quarter-rounds down the columns)
    # followed by 1 diagonal round (4 quarter-rounds along the diagonals).
    for double_round in range(10):
        # View the 16 words as a 4x4 matrix: first columns, then diagonals.
        for indices in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14),
                        (3, 7, 11, 15), (0, 5, 10, 15), (1, 6, 11, 12),
                        (2, 7, 8, 13), (3, 4, 9, 14)):
            quarter_round(state, *indices)
        if verbose:
            print(f"After rounds {2 * double_round + 1}-{2 * double_round + 2}:",
                  " ".join(f"{word:08x}" for word in state))
    # Feed forward the original state, then serialize each word little-endian.
    # Adding the initial state prevents an attacker from simply inverting the 20 rounds
    # to recover the secret key directly from a known keystream block.
    block = b"".join(((word + original) & WORD_MASK).to_bytes(4, "little")
                     for word, original in zip(state, initial))
    if verbose:
        print("Keystream block:", block.hex())
    return block


def chacha20(key, nonce, data, counter=1, verbose=False):
    """Encrypt or decrypt using the same XOR operation; no authentication.

    As a stream cipher, ChaCha20 generates a pseudorandom keystream block for each
    64-byte chunk of data (incrementing the block counter each time) and XORs it
    with the input. Because (P ^ K) ^ K == P, encryption and decryption are identical.
    """
    key, nonce = validate_key_nonce(key, nonce)
    data = byte_input(data, "data")
    check_counter(counter, len(data))  # Reject wrap before producing any output.
    output = bytearray()
    for offset in range(0, len(data), BLOCK_BYTES):
        # Generate the 64-byte keystream block for the current block index
        stream = chacha20_block(key, counter + offset // BLOCK_BYTES, nonce, verbose)
        fragment = data[offset:offset + BLOCK_BYTES]
        # XOR the data chunk with the keystream (automatically truncates keystream on last partial block)
        output.extend(value ^ mask for value, mask in zip(fragment, stream))
    return bytes(output)  # Empty input returns empty bytes; no padding needed.


def poly1305(one_time_key, message, verbose=False):
    """Authenticate one message with a key that must never be reused.

    Poly1305 (RFC 8439 Section 2.5) evaluates a polynomial over the prime field
    GF(2^130 - 5) using Horner's method:
      1. Split the 32-byte one_time_key into two 16-byte little-endian numbers:
         - 'r' (multiplier): first 16 bytes, clamped with CLAMP_MASK
         - 's' (pad):        last 16 bytes, kept unmodified
      2. Break the message into 16-byte chunks. Append a 0x01 byte to the high end of
         each chunk so every chunk has a non-zero leading bit (preventing attacks that
         prepend/append zero blocks without changing the polynomial value).
      3. Update the running accumulator for each chunk:
         accumulator = ((accumulator + number) * r) mod (2^130 - 5)
      4. Add the secret pad 's' modulo 2^128 and serialize as 16 little-endian bytes.
    """
    one_time_key = byte_input(one_time_key, "one_time_key")
    message = byte_input(message, "message")
    if len(one_time_key) != KEY_BYTES:
        raise ValueError("Poly1305 requires a 32-byte one-time key")
    # Extract r (first 16 bytes) and apply clamping mask (clears top 4 bits of bytes 3, 7, 11, 15
    # and bottom 2 bits of bytes 4, 8, 12 to assist fast implementations and restrict r's range).
    multiplier = int.from_bytes(one_time_key[:16], "little") & CLAMP_MASK
    # Extract s (last 16 bytes) as the secret additive pad.
    pad = int.from_bytes(one_time_key[16:], "little")
    accumulator = 0
    if verbose:
        print(f"Clamped r = {multiplier:032x}; s = {pad:032x}")
    for offset in range(0, len(message), 16):
        fragment = message[offset:offset + 16]
        # Append a 1 BYTE before decoding: the extra set bit is just above
        # the fragment, even when the last fragment contains fewer than 16 bytes.
        # For a full 16-byte chunk, this adds 2^128; for an k-byte chunk, it adds 2^(8*k).
        number = int.from_bytes(fragment + b"\x01", "little")
        # Horner's rule step: add coefficient and multiply by r modulo (2^130 - 5)
        accumulator = ((accumulator + number) * multiplier) % POLY1305_MODULUS
        if verbose:
            print(f"Poly1305 block {offset // 16 + 1}: n={number:x}, accumulator={accumulator:x}")
    # This final reduction is modulo 2**128, not modulo 2**130-5.
    # Masking the polynomial result with the one-time pad 's' mod 2^128 hides the algebraic structure.
    tag = ((accumulator + pad) % (1 << 128)).to_bytes(TAG_BYTES, "little")
    if verbose:
        print("Poly1305 tag:", tag.hex())
    return tag


def mac_input(associated_data, ciphertext):
    """AEAD framing: pad AAD and ciphertext separately, then append lengths.

    RFC 8439 Section 2.8 specifies the exact byte layout fed into Poly1305:
      [ AAD ] [ 0-padding to 16B ] [ Ciphertext ] [ 0-padding to 16B ] [ len(AAD): 8B LE ] [ len(CT): 8B LE ]

    Encoding the explicit 64-bit lengths at the end prevents boundary-shifting
    ambiguities (where bytes from AAD could otherwise be mistaken for ciphertext bytes).
    Note: Even if both AAD and ciphertext are empty (b""), this still returns a 16-byte
    block of zeros (representing 0 and 0 for the two 8-byte lengths), which Poly1305
    evaluates as a single block with value 2^128.
    """
    if len(associated_data) > MAX_AAD_BYTES or len(ciphertext) > MAX_PAYLOAD_BYTES:
        raise ValueError("AEAD input is too long")
    # Aligned and empty inputs need no padding. These zeros are authenticated;
    # Poly1305 still appends its own extra set bit to every formatted block.
    # Note: In Python, (-n % 16) cleanly computes the number of padding bytes (0..15)
    # needed to reach the next multiple of 16.
    return (associated_data + bytes(-len(associated_data) % 16)
            + ciphertext + bytes(-len(ciphertext) % 16)
            + len(associated_data).to_bytes(8, "little")
            + len(ciphertext).to_bytes(8, "little"))


def chacha20_poly1305(key, nonce, data, associated_data=b"", *, decrypt=False, verbose=False):
    """Encrypt to ciphertext || tag, or authenticate/decrypt that packet.

    Decryption raises ValueError on failure and never returns unverified
    plaintext. The caller supplies the nonce and AAD separately.

    This implements the Encrypt-then-MAC AEAD construction (RFC 8439 Section 2.8):
      1. Generate the 32-byte one-time Poly1305 key using ChaCha20 with block counter = 0.
      2. Encrypt/decrypt the payload using ChaCha20 starting at block counter = 1.
      3. Format the AAD, ciphertext, and their lengths into the Poly1305 input layout.
      4. Compute the 16-byte authentication tag using Poly1305.
      5. On decrypt: verify the tag in constant time (via hmac.compare_digest) BEFORE
         decrypting and returning the plaintext.
    """
    key, nonce = validate_key_nonce(key, nonce)
    data = byte_input(data, "data")
    associated_data = byte_input(associated_data, "associated_data")
    # When decrypting, 'data' must be at least 16 bytes long to hold the trailing tag.
    if decrypt and len(data) < TAG_BYTES:
        raise ValueError("Authentication failed")
    payload_length = len(data) - TAG_BYTES if decrypt else len(data)
    if payload_length > MAX_PAYLOAD_BYTES or len(associated_data) > MAX_AAD_BYTES:
        raise ValueError("AEAD input is too long")
    # Counter zero is ONLY for key derivation. Discard its last 32 bytes.
    # This guarantees the Poly1305 key is completely independent of the encryption keystream
    # (which starts at counter = 1).
    one_time_key = chacha20_block(key, 0, nonce, verbose)[:KEY_BYTES]
    # On decrypt, slice off the 16-byte tag at the end; on encrypt, generate ciphertext at counter = 1.
    ciphertext = data[:-TAG_BYTES] if decrypt else chacha20(key, nonce, data, 1, verbose)
    # Build the padded AEAD structure and compute the expected 16-byte Poly1305 tag.
    formatted = mac_input(associated_data, ciphertext)
    if verbose:
        print("One-time Poly1305 key:", one_time_key.hex())
        print("AAD || padding || ciphertext || padding || byte lengths:", formatted.hex())
    tag = poly1305(one_time_key, formatted, verbose)
    if decrypt:
        # CRITICAL: Use constant-time digest comparison (hmac.compare_digest) instead of '=='
        # so an attacker cannot measure response time to guess the valid tag byte-by-byte.
        # Furthermore, never decrypt or return plaintext if tag verification fails!
        if not compare_digest(tag, data[-TAG_BYTES:]):
            raise ValueError("Authentication failed")
        return chacha20(key, nonce, ciphertext, 1, verbose)
    return ciphertext + tag


if __name__ == "__main__":
    # Public demo values only: never use this fixed pair for real messages.
    demo_key, demo_nonce = bytes(range(32)), bytes(range(12))
    demo_message, demo_aad = b"Hello, ChaCha20-Poly1305!", b"demo header"
    print("Plaintext:", demo_message)
    packet = chacha20_poly1305(demo_key, demo_nonce, demo_message, demo_aad, verbose=True)
    print("Ciphertext || tag:", packet.hex())
    print("Authenticated plaintext:", chacha20_poly1305(
        demo_key, demo_nonce, packet, demo_aad, decrypt=True))

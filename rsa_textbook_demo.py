"""Trace RSA-2048 with OAEP/SHA-256. Run: python3 rsa_textbook_demo.py

Teaching code: the trace reveals the OAEP seed and Python's private-key
operations are not constant-time. Use a vetted library for real secrets.
"""

from hashlib import sha256
from math import gcd
from secrets import randbelow, randbits, token_bytes
from typing import Tuple

PUBLIC_EXPONENT = 65537
PRIME_BITS = 1024
HASH_BYTES = sha256().digest_size


# Follow one message through the demo:
# message bytes -> OAEP encoding -> integer m -> ciphertext c = m**e mod n
# ciphertext c -> integer m = c**d mod n -> OAEP decoding -> message bytes


def is_probable_prime(candidate: int) -> bool:
    """Use trial division followed by 64 random Miller–Rabin rounds."""
    if candidate < 2:
        return False
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if candidate % prime == 0:
            # For divisor 7, for example, accept 7 itself but reject 49.
            return candidate == prime

    # Write candidate - 1 as an odd number times a power of two.
    odd_part = candidate - 1
    twos = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        twos += 1

    for _ in range(64):
        # Choose a fresh base from 2 through candidate - 2. For a prime,
        # base**(candidate - 1) is 1 modulo candidate (Fermat's theorem).
        base = 2 + randbelow(candidate - 3)
        residue = pow(base, odd_part, candidate)
        # Each squaring doubles the exponent. For a prime, only 1 and -1
        # square to 1, so the chain must start at 1 or encounter -1 before
        # the final square. Here candidate - 1 represents -1 modulo candidate.
        if residue in (1, candidate - 1):
            continue
        for _ in range(twos - 1):
            residue = residue * residue % candidate
            if residue == candidate - 1:
                break
        else:
            # Python's for/else runs this branch only if no break occurred.
            return False  # This base proves the candidate is composite.
    # A composite can pass for some bases. Passing all 64 is strong evidence
    # of primality, though it is not a proof.
    return True


def generate_prime() -> int:
    while True:
        # Set the top bit for the requested width and the low bit for oddness.
        candidate = randbits(PRIME_BITS) | (1 << (PRIME_BITS - 1)) | 1
        # The gcd check ensures the public exponent will have an inverse
        # when we build the key. If either check fails, draw a new candidate.
        if gcd(PUBLIC_EXPONENT, candidate - 1) == 1 and is_probable_prime(candidate):
            return candidate


def generate_key() -> Tuple[int, int]:
    """Return the modulus and private exponent; the public exponent is fixed."""
    first_prime = generate_prime()
    while True:
        second_prime = generate_prime()
        modulus = first_prime * second_prime
        # Equal primes would expose the factor as the square root of the modulus.
        # Two 1024-bit primes can give a 2047-bit product; retry the second
        # prime until the modulus has the full 2048 bits requested.
        if first_prime != second_prime and modulus.bit_length() == 2 * PRIME_BITS:
            break
    # For distinct primes p and q, Euler's totient of p*q is (p-1)*(q-1).
    totient = (first_prime - 1) * (second_prime - 1)
    # pow(e, -1, totient) finds d such that (e*d) % totient == 1, so raising
    # the ciphertext to d undoes encryption. The gcd check in generate_prime()
    # ensures e is coprime to both factors of the totient, so d exists.
    return modulus, pow(PUBLIC_EXPONENT, -1, totient)


def mgf1(source: bytes, mask_length: int) -> bytes:
    """Generate exactly mask_length bytes with MGF1 and SHA-256."""
    if not 0 <= mask_length <= (1 << 32) * HASH_BYTES:
        raise ValueError("Mask length outside the range supported by MGF1")
    mask = bytearray()
    # One SHA-256 digest gives 32 bytes. To mask, say, 40 bytes, hash the
    # source with counter 0 and then counter 1; use 32 + 8 bytes. Both sides
    # encode each counter in four bytes so they reproduce the same mask.
    for counter in range((mask_length + HASH_BYTES - 1) // HASH_BYTES):
        mask.extend(sha256(source + counter.to_bytes(4, "big")).digest())
    return bytes(mask[:mask_length])


def xor_mask(data: bytes, source: bytes) -> bytes:
    """Apply an MGF1 mask of the same length as the data."""
    mask = mgf1(source, len(data))
    return bytes(v ^ m for v, m in zip(data, mask))


def rsa_encrypt(message: bytes, modulus: int, public_exponent: int, verbose: bool = False) -> bytes:
    """Encode a byte string with OAEP, then apply the public RSA operation."""
    width = (modulus.bit_length() + 7) // 8
    # OAEP fills exactly one modulus-width block. Budget one hash for the
    # label, one hash-length seed, a leading zero byte and a delimiter byte.
    # With RSA-2048 and SHA-256 that leaves 256 - 32 - 32 - 2 = 190 bytes.
    padding_length = width - len(message) - 2 * HASH_BYTES - 2
    if padding_length < 0:
        raise ValueError("Message too long for this key and OAEP/SHA-256")

    # Both sides agree on an optional label (empty here) and use its hash.
    # Data block layout: [label hash | zero padding | 01 | original message].
    data_block = sha256(b"").digest() + bytes(padding_length) + b"\x01" + message
    seed = token_bytes(HASH_BYTES)  # Fresh randomness for every encryption.
    # Mask in two steps: the seed masks the block, then the masked block
    # masks the seed. The receiver can undo both without a separate seed.
    masked_block = xor_mask(data_block, seed)
    masked_seed = xor_mask(seed, masked_block)
    # RSA accepts integers smaller than the modulus. A leading zero byte
    # ensures the encoded integer fits, even if the masked bytes are all FF.
    encoded = b"\x00" + masked_seed + masked_block
    if verbose:
        print("OAEP seed (hex):", seed.hex())
        print("OAEP encoded message (hex):", encoded.hex())
    ciphertext = pow(int.from_bytes(encoded, "big"), public_exponent, modulus)
    return ciphertext.to_bytes(width, "big")


def rsa_decrypt(ciphertext: bytes, modulus: int, private_exponent: int) -> bytes:
    width = (modulus.bit_length() + 7) // 8
    value = int.from_bytes(ciphertext, "big")
    # Reject out-of-range integers rather than silently reducing them modulo n.
    if len(ciphertext) != width or value >= modulus or width < 2 * HASH_BYTES + 2:
        raise ValueError("Invalid ciphertext")
    # RSA recovers an integer. Converting back to exactly 'width' bytes
    # restores the leading zero that was lost when we converted to an integer.
    encoded = pow(value, private_exponent, modulus).to_bytes(width, "big")
    masked_seed = encoded[1:1 + HASH_BYTES]
    masked_block = encoded[1 + HASH_BYTES:]
    # Reverse the masking order. XOR with the same mask cancels it:
    # (seed XOR mask) XOR mask = seed. The recovered seed then unmasks the block.
    seed = xor_mask(masked_seed, masked_block)
    data_block = xor_mask(masked_block, seed)

    # Skip padding after the label hash. The 01 delimiter stops lstrip, so
    # even a message that begins with zero bytes is recovered intact.
    tail = data_block[HASH_BYTES:].lstrip(b"\x00")
    if encoded[0] != 0 or data_block[:HASH_BYTES] != sha256(b"").digest() or not tail.startswith(b"\x01"):
        raise ValueError("Invalid ciphertext")
    return tail[1:]


def main() -> None:
    modulus, private_exponent = generate_key()
    print("Fresh public modulus (hex):", hex(modulus))
    print("Public exponent:", PUBLIC_EXPONENT)
    message = b"Hello, RSA!"
    print("Plaintext:", message)
    # Keep the key and message fixed: the fresh OAEP seed is the only
    # difference between these encryptions. Both decrypt to the same bytes.
    for attempt in (1, 2):
        print(f"Encryption {attempt}, using the same public key:")
        ciphertext = rsa_encrypt(message, modulus, PUBLIC_EXPONENT, verbose=True)
        print("Ciphertext (hex):", ciphertext.hex())
        print("Recovered plaintext:", rsa_decrypt(ciphertext, modulus, private_exponent))


if __name__ == "__main__":
    main()

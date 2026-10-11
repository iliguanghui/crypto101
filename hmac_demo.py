"""Readable, one-shot HMAC construction using this project's hash functions.

RFC 2104 section 2 is authoritative; names follow Wikipedia's pseudocode.
All HMAC steps, demonstrations, and verification functions live in this file.
No third-party dependencies. Standard-library hmac is only a test oracle.

python hmac_demo.py --algo sha256 --key key --text "hello"
python hmac_demo.py --algo all --quiet
python hmac_demo.py --self-test

References:
https://www.rfc-editor.org/rfc/rfc2104.html
https://en.wikipedia.org/wiki/HMAC
"""

import argparse

from md5_demo import md5
from sha1_demo import sha1
from sha256_demo import sha224, sha256
from sha512_demo import sha384, sha512
from sha3_demo import sha3_224, sha3_256, sha3_384, sha3_512

# Each entry: H, B (block size in bytes), L (digest size in bytes).
# For SHA-3, B is the sponge rate, NOT the full 200-byte Keccak state.
HASH_FUNCTIONS = {
    "md5": (md5, 64, 16),
    "sha1": (sha1, 64, 20),
    "sha224": (sha224, 64, 28),
    "sha256": (sha256, 64, 32),
    "sha384": (sha384, 128, 48),
    "sha512": (sha512, 128, 64),
    "sha3_224": (sha3_224, 144, 28),
    "sha3_256": (sha3_256, 136, 32),
    "sha3_384": (sha3_384, 104, 48),
    "sha3_512": (sha3_512, 72, 64),
}


def to_bytes(value):
    """Encode text as UTF-8; copy bytearray so callers' inputs stay unchanged."""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError("key and message must be bytes, bytearray, or str")


def print_bytes(label, value):
    print(f"{label} ({len(value)} bytes): {value.hex()}")


def xor_bytes(left, right):
    """XOR equal-length byte strings; reject silent truncation by zip."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def compute_block_sized_key(key, hash_function, block_size, verbose=False):
    """RFC 2104: hash only if len(K) > B, then append zeros to reach B."""
    key = to_bytes(key)
    if verbose:
        print_bytes("Original key K", key)
    if len(key) > block_size:
        key = hash_function(key)
        if verbose:
            print_bytes("Long key: replace K with H(K)", key)
    # This is HMAC key normalization, NOT the hash function's message padding.
    block_sized_key = key + bytes(block_size - len(key))
    if verbose:
        print_bytes("block_sized_key (K padded with zeros)", block_sized_key)
    return block_sized_key


def hmac(key, message, algorithm="sha256", verbose=False):
    """Return a full-length tag: H((K XOR opad) || H((K XOR ipad) || message)).

    The default API is quiet; the command-line demo prints intermediate values.
    All actual hashing uses the local pure-Python implementations, not hashlib.
    """
    if algorithm not in HASH_FUNCTIONS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    hash_function, block_size, digest_size = HASH_FUNCTIONS[algorithm]
    key = to_bytes(key)
    message = to_bytes(message)
    if verbose:
        print(f"\nHMAC-{algorithm}: B={block_size}, L={digest_size} bytes")
        print_bytes("Message", message)
    block_sized_key = compute_block_sized_key(key, hash_function, block_size, verbose)
    ipad = bytes([0x36]) * block_size
    opad = bytes([0x5c]) * block_size
    i_key_pad = xor_bytes(block_sized_key, ipad)
    o_key_pad = xor_bytes(block_sized_key, opad)

    # Concatenation uses raw bytes throughout, never hexadecimal text.
    # Each call starts a fresh hash with that algorithm's normal initial state.
    inner_input = i_key_pad + message
    inner_hash = hash_function(inner_input)
    outer_input = o_key_pad + inner_hash
    tag = hash_function(outer_input)
    if verbose:
        for label, value in (
                ("ipad", ipad), ("opad", opad),
                ("i_key_pad = block_sized_key XOR ipad", i_key_pad),
                ("o_key_pad = block_sized_key XOR opad", o_key_pad),
                ("inner_input = i_key_pad || message", inner_input),
                ("inner_hash = H(inner_input)", inner_hash),
                ("outer_input = o_key_pad || inner_hash", outer_input),
                ("tag = H(outer_input)", tag),
        ):
            print_bytes(label, value)
    return tag


def hmac_hex(key, message, algorithm="sha256", verbose=False):
    """Hexadecimal is an output representation only."""
    return hmac(key, message, algorithm, verbose).hex()


def reference_hmac(key, message, algorithm):
    """Independent standard-library oracle; never called by the construction."""
    import hmac as standard_hmac
    return standard_hmac.new(to_bytes(key), to_bytes(message), algorithm).digest()


def check_equal(actual, expected, label):
    """Explicit failures remain active when Python is run with -O."""
    if actual != expected:
        raise AssertionError(f"{label}\nExpected: {expected!r}\nActual:   {actual!r}")


def self_test():
    # Literal examples from Wikipedia, not values generated by our code.
    wikipedia_vectors = {
        "md5": "80070713463e7749b90c2dc24911e275",
        "sha1": "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
        "sha256": "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        "sha512": (
            "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82"
            "f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"),
    }
    message = b"The quick brown fox jumps over the lazy dog"
    for algorithm, expected in wikipedia_vectors.items():
        check_equal(hmac_hex(b"key", message, algorithm), expected, f"Wikipedia {algorithm}")
    print("PASS: all 4 Wikipedia HMAC examples")

    # All three RFC 2104 appendix vectors (HMAC-MD5).
    rfc_vectors = (
        (b"\x0b" * 16, b"Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
        (b"Jefe", b"what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738"),
        (b"\xaa" * 16, b"\xdd" * 50, "56be34521d144c88dbb8c733f0e8b3f6"),
    )
    for key, message, expected in rfc_vectors:
        check_equal(hmac_hex(key, message, "md5"), expected, "RFC 2104")
    print("PASS: all 3 RFC 2104 appendix vectors")

    count = 0
    for algorithm, (hash_function, block_size, digest_size) in HASH_FUNCTIONS.items():
        # Exercise no hashing at exactly B, hashing at B+1, and multiple blocks.
        for key_length in (0, 1, block_size - 1, block_size, block_size + 1, 2 * block_size + 3):
            key = bytes(index % 256 for index in range(key_length))
            for message_length in (0, 1, block_size - 1, block_size, block_size + 1, 2 * block_size + 9):
                message = bytes((index * 17 + 128) % 256 for index in range(message_length))
                tag = hmac(key, message, algorithm)
                label = f"{algorithm}: key={key_length}, message={message_length}"
                check_equal(tag, reference_hmac(key, message, algorithm), label)
                check_equal(len(tag), digest_size, label + " digest size")
                count += 1
        key = b"K" * block_size
        check_equal(compute_block_sized_key(key, hash_function, block_size), key,
                    algorithm + " exactly B bytes")
        key += b"!"
        expected_key = hash_function(key) + bytes(block_size - digest_size)
        check_equal(compute_block_sized_key(key, hash_function, block_size), expected_key,
                    algorithm + " long key normalization")
        check_equal(hmac(key, b"message", algorithm),
                    hmac(hash_function(key), b"message", algorithm), algorithm + " long key equivalence")
        check_equal(hmac("密钥", "消息 🔐", algorithm), reference_hmac("密钥", "消息 🔐", algorithm),
                    algorithm + " UTF-8")
        key, message = bytearray(b"key"), bytearray(b"message")
        check_equal(hmac(key, message, algorithm), reference_hmac(key, message, algorithm),
                    algorithm + " bytearray")
        check_equal((key, message), (bytearray(b"key"), bytearray(b"message")), "input preservation")
    print(f"PASS: {count} boundary comparisons with standard-library hmac across all 10 hashes")
    print("PASS: key normalization, long-key equivalence, UTF-8, and bytearray inputs")

    import io
    from contextlib import redirect_stdout
    trace = io.StringIO()
    with redirect_stdout(trace):
        traced = hmac(b"k" * 65, b"test", verbose=True)
    check_equal(traced, reference_hmac(b"k" * 65, b"test", "sha256"), "verbose result")
    for label in ("Long key:", "inner_input", "inner_hash", "outer_input", "tag ="):
        check_equal(label in trace.getvalue(), True, "trace " + label)
    for key, message, algorithm, error_type in (
            (None, b"", "sha256", TypeError), (b"", 3, "sha256", TypeError),
            (b"", b"", "unknown", ValueError),
    ):
        try:
            hmac(key, message, algorithm)
        except error_type:
            pass
        else:
            raise AssertionError("Invalid input was accepted")
    print("PASS: intermediate trace and invalid-input checks")


def main():
    parser = argparse.ArgumentParser(description="HMAC from local pure-Python hash functions")
    parser.add_argument("--algo", choices=list(HASH_FUNCTIONS) + ["all"], default="sha256")
    parser.add_argument("--key", default="key", help="UTF-8 demonstration key")
    parser.add_argument("--text", default="The quick brown fox jumps over the lazy dog")
    parser.add_argument("--quiet", action="store_true", help="Hide intermediate bytes")
    parser.add_argument("--self-test", action="store_true", help="Run published vectors and library comparisons")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    print("HMAC = H((K XOR opad) || H((K XOR ipad) || message))")
    print("Teaching demo: the trace exposes key material; do not use real secrets.")
    algorithms = list(HASH_FUNCTIONS) if args.algo == "all" else [args.algo]
    for algorithm in algorithms:
        tag = hmac(args.key, args.text, algorithm, verbose=not args.quiet)
        expected = reference_hmac(args.key, args.text, algorithm)
        check_equal(tag, expected, algorithm + " library verification")
        print(f"HMAC-{algorithm}: {tag.hex()} (matches standard-library hmac)")


if __name__ == "__main__":
    main()

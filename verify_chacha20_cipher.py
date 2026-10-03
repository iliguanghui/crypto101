"""Standalone verification of RFC 7539 section 2.4.2 (standard library only).

Run: python verify_chacha20_cipher.py
Source: https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.2
"""

import struct

MASK = 0xFFFFFFFF


def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def quarter_round(s, ai, bi, ci, di):
    a, b, c, d = (s[i] for i in (ai, bi, ci, di))
    a = (a + b) & MASK
    d = rotl32(d ^ a, 16)
    c = (c + d) & MASK
    b = rotl32(b ^ c, 12)
    a = (a + b) & MASK
    d = rotl32(d ^ a, 8)
    c = (c + d) & MASK
    b = rotl32(b ^ c, 7)
    s[ai], s[bi], s[ci], s[di] = a, b, c, d


def chacha20_block(key, counter, nonce):
    # Decode the constants, key, and nonce as little-endian 32-bit words.
    state = list(struct.unpack('<4I', b'expand 32-byte k'))
    state += list(struct.unpack('<8I', key))
    state += [counter]
    state += list(struct.unpack('<3I', nonce))
    working = state.copy()

    for _ in range(10):  # Each iteration performs two rounds.
        # Column round
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        # Diagonal round
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    final = [(x + y) & MASK for x, y in zip(state, working)]
    return struct.pack('<16I', *final)


def chacha20_encrypt(key, counter, nonce, plaintext):
    ciphertext = bytearray()
    for offset in range(0, len(plaintext), 64):
        keystream = chacha20_block(key, counter + offset // 64, nonce)
        block = plaintext[offset:offset + 64]
        # zip uses only the needed keystream bytes for the last partial block.
        ciphertext.extend(p ^ k for p, k in zip(block, keystream))
    return bytes(ciphertext)


if __name__ == '__main__':
    key = bytes(range(32))
    nonce = bytes.fromhex('00000000 0000004a 00000000')
    counter = 1
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, sunscreen would be it."
    )
    expected = bytes.fromhex('''
        6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
        e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
        f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
        16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
        07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
        52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
        5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
        87 4d
    ''')

    ciphertext = chacha20_encrypt(key, counter, nonce, plaintext)
    assert ciphertext == expected, 'FAIL: ciphertext differs from the RFC.'
    print('PASS: all 114 ciphertext bytes match RFC 7539 section 2.4.2.')
    for offset in range(0, len(ciphertext), 16):
        print(f'{offset:03d}  {ciphertext[offset:offset + 16].hex(" ")}')

    # Decryption uses the same XOR operation, starting from the same counter.
    recovered = chacha20_encrypt(key, counter, nonce, ciphertext)
    assert recovered == plaintext, 'FAIL: decryption did not recover plaintext.'
    print('PASS: decryption recovers the original plaintext.')

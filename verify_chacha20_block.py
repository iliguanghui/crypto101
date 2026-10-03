"""Verify RFC 7539 sections 2.3.1-2.3.2 using only Python's standard library.

Run: python verify_chacha20_block.py
Source: https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.2
"""

import struct

MASK = 0xFFFFFFFF


def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def quarter_round(state, ai, bi, ci, di):
    a, b, c, d = (state[i] for i in (ai, bi, ci, di))

    a = (a + b) & MASK
    d = rotl32(d ^ a, 16)
    c = (c + d) & MASK
    b = rotl32(b ^ c, 12)
    a = (a + b) & MASK
    d = rotl32(d ^ a, 8)
    c = (c + d) & MASK
    b = rotl32(b ^ c, 7)

    state[ai], state[bi], state[ci], state[di] = a, b, c, d


def chacha20_block(key, counter, nonce):
    # '<' means little-endian; 'I' means a 32-bit unsigned integer.
    state = list(struct.unpack('<4I', b'expand 32-byte k'))
    state += list(struct.unpack('<8I', key))
    state += [counter]
    state += list(struct.unpack('<3I', nonce))
    working = state.copy()  # Preserve the original state for the final addition.

    for _ in range(10):  # 10 pairs of rounds = 20 rounds
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


if __name__ == '__main__':
    key = bytes(range(32))
    counter = 1
    nonce = bytes.fromhex('00000009 0000004a 00000000')

    expected = bytes.fromhex('''
        10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
        c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
        d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
        b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e
    ''')

    actual = chacha20_block(key, counter, nonce)
    for offset in range(0, len(actual), 16):
        print(f'{offset:03d}  {actual[offset:offset + 16].hex(" ")}')
    assert actual == expected, 'FAIL: block differs from the RFC test vector.'
    print('PASS: all 64 bytes match RFC 7539 section 2.3.2.')

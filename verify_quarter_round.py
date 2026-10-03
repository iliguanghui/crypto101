"""Verify the full ChaCha quarter round from RFC 7539, section 2.1.1."""

MASK = 0xFFFFFFFF


def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


# Initial values from section 2.1.1
a = 0x11111111
b = 0x01020304
c = 0x9B8D6F43
d = 0x01234567

# Sequence 1
a = (a + b) & MASK  # Addition modulo 2**32
d ^= a
d = rotl32(d, 16)

# Sequence 2
c = (c + d) & MASK
b ^= c
b = rotl32(b, 12)

# Sequence 3
a = (a + b) & MASK
d ^= a
d = rotl32(d, 8)

# Sequence 4
c = (c + d) & MASK
b ^= c
b = rotl32(b, 7)

expected = (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB)
assert (a, b, c, d) == expected, "Result does not match the RFC!"

for name, value in zip("abcd", (a, b, c, d)):
    print(f"{name} = 0x{value:08x}")
print("PASS: all four values match RFC 7539 section 2.1.1.")
"""Verification Suite for Pure Python AES (NIST FIPS 197, updated 2023).

Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
Covers Appendix A's three complete key schedules and Appendix B's full
cipher trace, plus field/S-box examples and encryption/decryption edge cases.
Appendix C in this edition links to external examples; it contains no vectors.
The classic three sequential-key vectors are included as supplemental checks.
Fixtures below are transcribed from the PDF, never calculated by aes_demo.
No third-party libraries or network access are required to run this suite.

Usage: python3 verify_aes.py
"""

import contextlib
import io
import random
import sys
from typing import Callable, Dict, List, Optional, Tuple, Type

import aes_demo as aes

# Appendix A: each row contains the word index followed by all hexadecimal
# columns printed in the PDF: temp, optional transformations, old word, new word.
KEY_SCHEDULE_VECTORS: List[Tuple[str, str]] = [
    ("2b7e151628aed2a6abf7158809cf4f3c", """
4    09cf4f3c   cf4f3c09      8a84eb01      01000000      8b84eb01       2b7e1516 a0fafe17
5    a0fafe17                                                            28aed2a6 88542cb1
6    88542cb1                                                            abf71588 23a33939
7    23a33939                                                            09cf4f3c 2a6c7605
8    2a6c7605   6c76052a      50386be5      02000000      52386be5       a0fafe17 f2c295f2
9    f2c295f2                                                            88542cb1 7a96b943
10     7a96b943                                                            23a33939 5935807a
11     5935807a                                                            2a6c7605 7359f67f
12     7359f67f   59f67f73      cb42d28f      04000000      cf42d28f       f2c295f2 3d80477d
13     3d80477d                                                            7a96b943 4716fe3e
14     4716fe3e                                                            5935807a 1e237e44
15     1e237e44                                                            7359f67f 6d7a883b
16     6d7a883b   7a883b6d      dac4e23c      08000000      d2c4e23c       3d80477d ef44a541
17     ef44a541                                                            4716fe3e a8525b7f
18     a8525b7f                                                            1e237e44 b671253b
19     b671253b                                                            6d7a883b db0bad00
20     db0bad00   0bad00db      2b9563b9      10000000      3b9563b9       ef44a541 d4d1c6f8
21     d4d1c6f8                                                            a8525b7f 7c839d87
22     7c839d87                                                            b671253b caf2b8bc
23     caf2b8bc                                                            db0bad00 11f915bc
24     11f915bc   f915bc11      99596582      20000000      b9596582       d4d1c6f8 6d88a37a
25     6d88a37a                                                            7c839d87 110b3efd
26     110b3efd                                                            caf2b8bc dbf98641
27     dbf98641                                                            11f915bc ca0093fd
28     ca0093fd   0093fdca      63dc5474      40000000      23dc5474       6d88a37a 4e54f70e
29     4e54f70e                                                            110b3efd 5f5fc9f3
30     5f5fc9f3                                                            dbf98641 84a64fb2
31     84a64fb2                                                            ca0093fd 4ea6dc4f
32     4ea6dc4f   a6dc4f4e      2486842f      80000000      a486842f       4e54f70e ead27321
33     ead27321                                                            5f5fc9f3 b58dbad2
34     b58dbad2                                                            84a64fb2 312bf560
35     312bf560                                                            4ea6dc4f 7f8d292f
36     7f8d292f   8d292f7f      5da515d2      1b000000      46a515d2       ead27321 ac7766f3
37     ac7766f3                                                            b58dbad2 19fadc21
38     19fadc21                                                            312bf560 28d12941
39     28d12941                                                            7f8d292f 575c006e
40     575c006e   5c006e57      4a639f5b      36000000      7c639f5b       ac7766f3 d014f9a8
41     d014f9a8                                                            19fadc21 c9ee2589
42     c9ee2589                                                            28d12941 e13f0cc8
43     e13f0cc8                                                            575c006e b6630ca6
"""),
    ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", """
6    522c6b7b   2c6b7b52      717f2100      01000000      707f2100       8e73b0f7 fe0c91f7
7    fe0c91f7                                                            da0e6452 2402f5a5
8    2402f5a5                                                            c810f32b ec12068e
9    ec12068e                                               809079e5 6c827f6b
10   6c827f6b                                               62f8ead2 0e7a95b9
11   0e7a95b9                                               522c6b7b 5c56fec2
12   5c56fec2   56fec25c   b1bb254a   02000000   b3bb254a   fe0c91f7 4db7b4bd
13   4db7b4bd                                               2402f5a5 69b54118
14   69b54118                                               ec12068e 85a74796
15   85a74796                                               6c827f6b e92538fd
16   e92538fd                                               0e7a95b9 e75fad44
17   e75fad44                                               5c56fec2 bb095386
18   bb095386   095386bb   01ed44ea   04000000   05ed44ea   4db7b4bd 485af057
19   485af057                                               69b54118 21efb14f
20   21efb14f                                               85a74796 a448f6d9
21   a448f6d9                                               e92538fd 4d6dce24
22   4d6dce24                                               e75fad44 aa326360
23   aa326360                                               bb095386 113b30e6
24   113b30e6   3b30e611   e2048e82   08000000   ea048e82   485af057 a25e7ed5
25   a25e7ed5                                               21efb14f 83b1cf9a
26   83b1cf9a                                               a448f6d9 27f93943
27   27f93943                                               4d6dce24 6a94f767
28   6a94f767                                               aa326360 c0a69407
29   c0a69407                                               113b30e6 d19da4e1
30   d19da4e1   9da4e1d1   5e49f83e   10000000   4e49f83e   a25e7ed5 ec1786eb
31   ec1786eb                                               83b1cf9a 6fa64971
32   6fa64971                                               27f93943 485f7032
33   485f7032                                               6a94f767 22cb8755
34   22cb8755                                               c0a69407 e26d1352
35   e26d1352                                               d19da4e1 33f0b7b3
36   33f0b7b3   f0b7b333   8ca96dc3   20000000   aca96dc3   ec1786eb 40beeb28
37   40beeb28                                               6fa64971 2f18a259
38   2f18a259                                               485f7032 6747d26b
39   6747d26b                                               22cb8755 458c553e
40   458c553e                                               e26d1352 a7e1466c
41   a7e1466c                                               33f0b7b3 9411f1df
42   9411f1df   11f1df94   82a19e22   40000000   c2a19e22   40beeb28 821f750a
43   821f750a                                               2f18a259 ad07d753
44     ad07d753                                                            6747d26b ca400538
45     ca400538                                                            458c553e 8fcc5006
46     8fcc5006                                                            a7e1466c 282d166a
47     282d166a                                                            9411f1df bc3ce7b5
48     bc3ce7b5    3ce7b5bc     eb94d565      80000000      6b94d565       821f750a e98ba06f
49     e98ba06f                                                            ad07d753 448c773c
50     448c773c                                                            ca400538 8ecc7204
51     8ecc7204                                                            8fcc5006 01002202
"""),
    ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", """
8    0914dff4    14dff409     fa9ebf01      01000000      fb9ebf01       603deb10 9ba35411
9    9ba35411                                                            15ca71be 8e6925af
10     8e6925af                                                            2b73aef0 a51a8b5f
11     a51a8b5f                                                            857d7781 2067fcde
12     2067fcde                 b785b01d                                   1f352c07 a8b09c1a
13     a8b09c1a                                                            3b6108d7 93d194cd
14     93d194cd                                                            2d9810a3 be49846e
15     be49846e                                                            0914dff4 b75d5b9a
16     b75d5b9a    5d5b9ab7     4c39b8a9      02000000      4e39b8a9       9ba35411 d59aecb8
17     d59aecb8                                                            8e6925af 5bf3c917
18     5bf3c917                                                            a51a8b5f fee94248
19     fee94248                                                            2067fcde de8ebe96
20     de8ebe96                 1d19ae90                                   a8b09c1a b5a9328a
21     b5a9328a                                                            93d194cd 2678a647
22     2678a647                                                            be49846e 98312229
23   98312229                                               b75d5b9a 2f6c79b3
24   2f6c79b3   6c79b32f   50b66d15   04000000   54b66d15   d59aecb8 812c81ad
25   812c81ad                                               5bf3c917 dadf48ba
26   dadf48ba                                               fee94248 24360af2
27   24360af2                                               de8ebe96 fab8b464
28   fab8b464              2d6c8d43                         b5a9328a 98c5bfc9
29   98c5bfc9                                               2678a647 bebd198e
30   bebd198e                                               98312229 268c3ba7
31   268c3ba7                                               2f6c79b3 09e04214
32   09e04214   e0421409   e12cfa01   08000000   e92cfa01   812c81ad 68007bac
33   68007bac                                               dadf48ba b2df3316
34   b2df3316                                               24360af2 96e939e4
35   96e939e4                                               fab8b464 6c518d80
36   6c518d80              50d15dcd                         98c5bfc9 c814e204
37   c814e204                                               bebd198e 76a9fb8a
38   76a9fb8a                                               268c3ba7 5025c02d
39   5025c02d                                               09e04214 59c58239
40   59c58239   c5823959   a61312cb   10000000   b61312cb   68007bac de136967
41   de136967                                               b2df3316 6ccc5a71
42   6ccc5a71                                               96e939e4 fa256395
43   fa256395                                               6c518d80 9674ee15
44   9674ee15              90922859                         c814e204 5886ca5d
45   5886ca5d                                               76a9fb8a 2e2f31d7
46   2e2f31d7                                               5025c02d 7e0af1fa
47   7e0af1fa                                               59c58239 27cf73c3
48   27cf73c3   cf73c327   8a8f2ecc   20000000   aa8f2ecc   de136967 749c47ab
49   749c47ab                                               6ccc5a71 18501dda
50   18501dda                                               fa256395 e2757e4f
51   e2757e4f                                               9674ee15 7401905a
52   7401905a              927c60be                         5886ca5d cafaaae3
53   cafaaae3                                               2e2f31d7 e4d59b34
54   e4d59b34                                               7e0af1fa 9adf6ace
55   9adf6ace                                               27cf73c3 bd10190d
56   bd10190d   10190dbd   cad4d77a   40000000   8ad4d77a   749c47ab fe4890d1
57   fe4890d1                                               18501dda e6188d0b
58   e6188d0b                                               e2757e4f 046df344
59   046df344                                               7401905a 706c631e
"""),
]

# Appendix B: Start, SubBytes, ShiftRows, MixColumns (absent in round 10), Key.
CIPHER_TRACE: List[Tuple[str, str, str, Optional[str], str]] = [
    ('193de3bea0f4e22b9ac68d2ae9f84808', 'd42711aee0bf98f1b8b45de51e415230', 'd4bf5d30e0b452aeb84111f11e2798e5',
     '046681e5e0cb199a48f8d37a2806264c', 'a0fafe1788542cb123a339392a6c7605'),
    ('a49c7ff2689f352b6b5bea43026a5049', '49ded28945db96f17f39871a7702533b', '49db873b453953897f02d2f177de961a',
     '584dcaf11b4b5aacdbe7caa81b6bb0e5', 'f2c295f27a96b9435935807a7359f67f'),
    ('aa8f5f0361dde3ef82d24ad26832469a', 'ac73cf7befc111df13b5d6b545235ab8', 'acc1d6b8efb55a7b1323cfdf457311b5',
     '75ec0993200b633353c0cf7cbb25d0dc', '3d80477d4716fe3e1e237e446d7a883b'),
    ('486c4eee671d9d0d4de3b138d65f58e7', '52502f2885a45ed7e311c807f6cf6a94', '52a4c89485116a28e3cf2fd7f6505e07',
     '0fd6daa9603138bf6fc0106b5eb31301', 'ef44a541a8525b7fb671253bdb0bad00'),
    ('e0927fe8c86363c0d9b1355085b8be01', 'e14fd29be8fbfbba35c89653976cae7c', 'e1fb967ce8c8ae9b356cd2ba974ffb53',
     '25d1a9adbd11d168b63a338e4c4cc0b0', 'd4d1c6f87c839d87caf2b8bc11f915bc'),
    ('f1006f55c1924cef7cc88b325db5d50c', 'a163a8fc784f29df10e83d234cd503fe', 'a14f3dfe78e803fc10d5a8df4c632923',
     '4b868d6d2c4a8980339df4e837d218d8', '6d88a37a110b3efddbf98641ca0093fd'),
    ('260e2e173d41b77de86472a9fdd28b25', 'f7ab31f02783a9ff9b4340d354b53d3f', 'f783403f27433df09bb531ff54aba9d3',
     '1415b5bf461615ec274656d7342ad843', '4e54f70e5f5fc9f384a64fb24ea6dc4f'),
    ('5a4142b11949dc1fa3e019657a8c040c', 'be832cc8d43b86c00ae1d44dda64f2fe', 'be3bd4fed4e1f2c80a642cc0da83864d',
     '00512fd1b1c889ff54766dcdfa1b99ea', 'ead27321b58dbad2312bf5607f8d292f'),
    ('ea835cf00445332d655d98ad8596b0c5', '87ec4a8cf26ec3d84d4c46959790e7a6', '876e46a6f24ce78c4d904ad897ecc395',
     '473794ed40d4e4a5a3703aa64c9f42bc', 'ac7766f319fadc2128d12941575c006e'),
    ('eb40f21e592e38848ba113e71bc342d2', 'e9098972cb31075f3d327d94af2e2cb5', 'e9317db5cb322c723d2e895faf090794', None,
     'd014f9a8c9ee2589e13f0cc8b6630ca6'),
]


def heading(title: str) -> None:
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)


def check_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise AssertionError(f'{label}\nExpected: {expected!r}\nActual:   {actual!r}')


def expect_error(
        error_type: Type[Exception], operation: Callable[[], object], label: str
) -> None:
    try:
        operation()
    except error_type:
        return
    raise AssertionError(f'{label}: expected {error_type.__name__}')


def verify_key_expansion_vectors() -> None:
    """Check every Appendix A word and every printed intermediate column."""
    heading('1. APPENDIX A: AES-128/192/256 KEY EXPANSION')
    for key_hex, table in KEY_SCHEDULE_VECTORS:
        key = bytes.fromhex(key_hex)
        key_words = len(key) // 4
        expanded = b''.join(aes.state_to_block(value) for value in aes.generate_round_keys(key))
        expected_words = [key_hex[offset:offset + 8] for offset in range(0, len(key_hex), 8)]
        round_constant = 1
        for line in table.strip().splitlines():
            fields = line.split()
            word_index = int(fields[0])
            values = fields[1:]
            check_equal(word_index, len(expected_words), 'Fixture word index')
            check_equal(values[0], expected_words[-1], 'Previous word')
            transformed = bytes.fromhex(values[0])
            if word_index % key_words == 0:
                transformed = transformed[1:] + transformed[:1]
                check_equal(transformed.hex(), values[1], 'RotWord')
                transformed = bytes(aes.S_BOX[value] for value in transformed)
                check_equal(transformed.hex(), values[2], 'SubWord')
                check_equal(bytes([round_constant, 0, 0, 0]).hex(), values[3], 'Rcon')
                transformed = bytes([transformed[0] ^ round_constant]) + transformed[1:]
                check_equal(transformed.hex(), values[4], 'SubWord XOR Rcon')
                round_constant = aes.field_multiply(round_constant, 2)
            elif key_words == 8 and word_index % key_words == 4:
                transformed = bytes(aes.S_BOX[value] for value in transformed)
                check_equal(transformed.hex(), values[1], 'AES-256 SubWord')
            check_equal(values[-2], expected_words[word_index - key_words], 'Earlier word')
            result = bytes(left ^ right for left, right in zip(transformed, bytes.fromhex(values[-2])))
            check_equal(result.hex(), values[-1], 'Expanded word intermediate')
            expected_words.append(values[-1])
        check_equal(expanded.hex(), ''.join(expected_words), f'AES-{len(key) * 8} entire schedule')
        print(f'  [PASS] AES-{len(key) * 8}: {len(expected_words)} words and all printed intermediate columns')


def verify_cipher_trace() -> None:
    """Observe the actual encryption method, checking every Appendix B state."""
    heading('2. APPENDIX B: ALL ENCRYPTION ROUND STATES AND DECRYPTION')
    key = bytes.fromhex(KEY_SCHEDULE_VECTORS[0][0])
    plaintext = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
    ciphertext = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')
    observed: Dict[Tuple[int, str], str] = {}

    def record(round_number: int, step: str, state: aes.State, verbose: bool) -> None:
        observed[round_number, step] = aes.state_to_block(state).hex()

    original_show_state = aes.show_state
    try:
        aes.show_state = record
        check_equal(aes.aes_process_block(plaintext, key), ciphertext, 'Appendix B ciphertext')
    finally:
        # Restore normal tracing even if encryption or an assertion fails.
        aes.show_state = original_show_state
    check_equal(observed[0, 'Input'], plaintext.hex(), 'Input state')
    round_keys = aes.generate_round_keys(key)
    for round_number, (start, substituted, shifted, mixed, round_key) in enumerate(CIPHER_TRACE, 1):
        check_equal(observed[round_number - 1, 'AddRoundKey'], start, 'Start of round')
        check_equal(observed[round_number, 'SubBytes'], substituted, 'SubBytes')
        check_equal(observed[round_number, 'ShiftRows'], shifted, 'ShiftRows')
        if mixed is not None:
            check_equal(observed[round_number, 'MixColumns'], mixed, 'MixColumns')
        else:
            check_equal((round_number, 'MixColumns') in observed, False, 'Final round omits MixColumns')
        check_equal(aes.state_to_block(round_keys[round_number]).hex(), round_key, 'Round key')
        print(f'  [PASS] Round {round_number}: every published state')
    check_equal(observed[10, 'AddRoundKey'], ciphertext.hex(), 'Final state')
    check_equal(aes.aes_process_block(ciphertext, key, decrypt=True), plaintext, 'Appendix B decryption')
    print('  [PASS] Published ciphertext decrypts to the original block')


def verify_known_answers() -> None:
    heading('3. SUPPLEMENTAL AES-128/192/256 KNOWN ANSWERS')
    plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
    # Classic FIPS 197 (2001), Appendix C vectors, supplemental to upd1.
    for size, expected_hex in ((16, '69c4e0d86a7b0430d8cdb78070b4c55a'),
                               (24, 'dda97ca4864cdfe06eaf70a0ec0d7191'),
                               (32, '8ea2b7ca516745bfeafc49904b496089')):
        key, ciphertext = bytes(range(size)), bytes.fromhex(expected_hex)
        check_equal(aes.aes_process_block(plaintext, key), ciphertext, 'Encryption')
        check_equal(aes.aes_process_block(ciphertext, key, decrypt=True), plaintext, 'Decryption')
        print(f'  [PASS] AES-{size * 8}: encryption and decryption')


def verify_components() -> None:
    heading('4. FIELD ARITHMETIC AND S-BOX EXAMPLES')
    # Section 4.1 addition, 4.2 multiplication, 4.4 inverse, 5.1.1 S-box.
    check_equal(0x57 ^ 0x83, 0xd4, 'Addition example')
    for multiplier, expected in ((2, 0xae), (4, 0x47), (8, 0x8e), (16, 0x07), (0x13, 0xfe), (0x83, 0xc1)):
        check_equal(aes.field_multiply(0x57, multiplier), expected, 'Field multiplication')
    check_equal(aes.field_multiply(0x53, 0xca), 1, 'Field inverse')
    check_equal(aes.construct_s_box_byte(0x53), 0xed, 'S-box example')
    check_equal(aes.construct_s_box_byte(0), 0x63, 'Zero inverse convention')
    for value in range(256):
        check_equal(aes.INV_S_BOX[aes.S_BOX[value]], value, 'Inverse S-box')
    print('  [PASS] Published arithmetic examples and all 256 inverse substitutions')


def verify_encryption_decryption_edges() -> None:
    heading('5. ENCRYPTION/DECRYPTION EDGE CASES')
    generator = random.Random(197)
    count = 0
    for size in (16, 24, 32):
        keys = [bytes(size), b'\xff' * size, bytes(range(size))]
        blocks = [bytes(16), b'\xff' * 16, b'\xaa\x55' * 8, bytes(range(16))]
        # Exercise each individual bit position, including the first and last.
        blocks += [(1 << bit).to_bytes(16, 'big') for bit in range(128)]
        blocks += [bytes(generator.getrandbits(8) for _ in range(16)) for _ in range(20)]
        for key in keys:
            for block in blocks:
                ciphertext = aes.aes_process_block(block, key)
                check_equal(type(ciphertext), bytes, 'Output type')
                check_equal(len(ciphertext), 16, 'Output length')
                check_equal(aes.aes_process_block(ciphertext, key, decrypt=True), block, 'Decrypt(encrypt(block))')
                recovered = aes.aes_process_block(block, key, decrypt=True)
                check_equal(aes.aes_process_block(recovered, key), block, 'Encrypt(decrypt(block))')
                count += 1
        for decrypt in (False, True):
            block, key = bytearray(range(16)), bytearray(range(size))
            original_block, original_key = bytes(block), bytes(key)
            expected = aes.aes_process_block(original_block, original_key, decrypt=decrypt)
            for block_input in (block, original_block):
                for key_input in (key, original_key):
                    check_equal(aes.aes_process_block(block_input, key_input, decrypt=decrypt), expected,
                                'Mutable inputs')
            check_equal(bytes(block), original_block, 'Block not mutated')
            check_equal(bytes(key), original_key, 'Key not mutated')
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                actual = aes.aes_process_block(block, key, decrypt=decrypt, verbose=True)
            check_equal(actual, expected, 'Verbose output preserves result')
            if not captured.getvalue():
                raise AssertionError('Verbose mode produced no trace')
    print(f'  [PASS] {count} block/key cases in both directions; bytearray and verbose behavior')


def verify_invalid_inputs() -> None:
    heading('6. INVALID BLOCK/KEY LENGTHS AND TYPES')
    count = 0
    for decrypt in (False, True):
        for size in (16, 24, 32):
            for length in (0, 1, 7, 15, 17, 24, 31, 32, 33, 64):
                expect_error(ValueError, lambda: aes.aes_process_block(bytes(length), bytes(size), decrypt=decrypt),
                             'Block length')
                count += 1
        for length in (0, 1, 15, 17, 23, 25, 31, 33, 64):
            expect_error(ValueError, lambda: aes.aes_process_block(bytes(16), bytes(length), decrypt=decrypt),
                         'Key length')
            count += 1
        for value in (None, True, 16, '0' * 16, [0] * 16, memoryview(bytes(16))):
            expect_error(TypeError, lambda: aes.aes_process_block(value, bytes(16), decrypt=decrypt), 'Block type')
            expect_error(TypeError, lambda: aes.aes_process_block(bytes(16), value, decrypt=decrypt), 'Key type')
            count += 2
    print(f'  [PASS] {count} invalid encryption/decryption calls rejected')


def main() -> None:
    print('#' * 72)
    print('# AES VERIFICATION SUITE (NIST FIPS 197 upd1)')
    print('#' * 72)
    try:
        verify_key_expansion_vectors()
        verify_cipher_trace()
        verify_known_answers()
        verify_components()
        verify_encryption_decryption_edges()
        verify_invalid_inputs()
    except Exception as error:
        print(f'\n[FATAL ERROR] Test suite aborted: {error}', file=sys.stderr)
        sys.exit(1)
    print('\nALL AES SUITE VERIFICATIONS COMPLETED! [100% PASS]')


if __name__ == '__main__':
    main()

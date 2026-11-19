""" Check certificate parameters. See https://www.rfc-editor.org/info/rfc8017/#section-5.1.2 """
import re
from math import gcd


def parse(text):
    fields, cur = {}, None
    for line in text.splitlines():
        if not line.startswith(" "):
            m = re.match(r"^(\w+):\s*(.*)$", line)
            if m:
                cur, rest = m.group(1), m.group(2)
                if cur == "publicExponent":
                    fields[cur] = int(rest.split()[0])  # e.g. "65537 (0x10001)"
                    cur = None
                else:
                    fields[cur] = ""
            else:
                cur = None
        elif cur:
            fields[cur] += line.strip().replace(":", "")
    # convert hex strings to integers
    return {k: (v if isinstance(v, int) else int(v, 16)) for k, v in fields.items()}


# openssl rsa -in xx.key -noout -text
key_content = """
Private-Key: (2048 bit, 2 primes)
modulus:
    bd:b9:86:b5:77:35:76:3a:5d:57:3e:85:f1:68:fa:7e:
    8e:a5:89:65:a4:c3:fe:c2:c0:f0:af:4a:54:f2:69:9b:
    01:92:a9:00:ae:c6:61:85:95:c2:22:90:c8:bb:0c:f0:
    a7:f2:52:cb:57:93:1e:3e:a2:fe:07:7a:c8:75:dc:28:
    b0:2e:47:dd:59:96:7d:7e:8d:bb:cc:89:16:e6:ec:49:
    f2:c7:c9:4f:bf:e7:cd:1e:ad:01:4a:5f:6c:e2:93:03:
    94:50:57:53:39:3f:73:11:42:48:3b:3c:41:aa:bd:08:
    7b:6f:24:6d:f6:ed:eb:d4:85:1e:02:5e:af:d9:4d:b3:
    81:27:3b:9d:4f:01:53:2a:6b:c0:5f:d4:78:48:06:b5:
    55:6f:4b:03:97:1b:62:74:ed:a9:4a:ea:c4:59:10:8b:
    34:cc:6c:b5:4c:d6:10:42:fc:8b:75:f3:b1:47:22:2f:
    ee:8b:43:d3:69:23:7f:8c:11:53:ac:b3:b4:70:18:d6:
    f5:03:30:6d:d0:aa:e0:48:2c:38:92:67:41:94:67:e6:
    c4:75:15:d7:13:57:b7:0d:d0:21:bb:9e:22:d1:cf:8f:
    da:67:cf:d0:5c:b2:3c:c8:e3:ca:f9:79:ab:ba:ce:82:
    5a:d6:df:6e:f9:af:67:0d:f7:ee:29:2b:87:dc:68:2d
publicExponent: 65537 (0x10001)
privateExponent:
    0b:4a:3b:46:83:59:1a:82:3c:c9:8d:e1:02:c8:39:b7:
    26:c3:6f:32:98:7f:08:f8:6b:6a:ac:85:0a:9a:e0:a7:
    16:a2:9f:82:78:ce:b9:81:18:1e:94:ed:28:8e:1d:a6:
    18:d9:be:22:0c:c1:d1:32:ae:83:2f:36:ed:5a:10:22:
    19:61:2e:54:71:24:98:04:06:d3:51:07:ab:bb:22:fe:
    aa:89:c7:84:6d:4f:27:61:11:85:55:0e:3f:d3:42:d1:
    86:20:50:20:ab:1f:32:b8:7e:9e:80:41:e4:c6:d0:2d:
    6d:4a:4e:f0:be:99:3d:67:a8:8d:41:87:03:70:0b:0e:
    ce:9a:b9:9c:00:ce:0a:a3:7f:8c:2e:6e:d6:ab:ee:cb:
    f1:0f:96:ae:83:bc:4c:9a:1a:58:a1:de:a9:16:e4:a4:
    aa:97:77:d0:d1:0d:03:c8:f2:d1:ad:2e:df:a6:95:de:
    75:9e:70:1a:89:57:11:3b:d7:60:c8:7e:e3:b0:61:4d:
    d1:48:2b:da:ca:89:a5:a7:25:af:e6:39:a7:b0:35:94:
    62:4a:b8:c5:c9:46:b1:d2:39:1f:de:81:d9:82:40:79:
    65:e0:4d:4e:97:f8:77:1e:66:31:80:3c:9d:0f:7f:3e:
    02:ca:32:51:15:c9:20:33:d8:45:4d:95:23:d9:70:39
prime1:
    fe:82:60:4d:89:29:28:87:a2:45:3f:d9:ff:dc:fc:36:
    f9:b4:83:f9:fe:a9:f0:f4:34:96:5e:1d:66:ae:5d:41:
    ef:fc:bc:92:00:a8:68:3d:7e:ab:42:de:8e:17:ac:8b:
    c6:34:cc:32:b3:38:7b:4c:4d:c3:a2:7b:08:18:47:43:
    99:b9:bf:2c:a7:39:3b:9e:15:78:25:5b:96:ed:33:b6:
    b5:64:25:8a:94:cc:5e:6d:d6:0e:33:0e:48:6f:fc:39:
    d7:c7:1b:1d:2d:00:ae:dd:33:a5:7f:ef:a3:27:3f:1b:
    3c:05:cd:91:a1:c9:93:7a:b7:a2:80:17:a8:e9:e1:55
prime2:
    be:d6:02:42:c9:67:0e:b2:6b:6a:1d:26:24:a1:2f:e8:
    35:ea:e6:3b:95:07:f0:76:32:3a:9b:ab:bb:77:5f:e3:
    99:c1:34:1c:15:ee:33:aa:cc:c3:a9:4e:87:e0:ca:90:
    2c:fb:b5:1e:b8:6d:71:79:1f:61:fd:36:7d:4a:e4:9d:
    87:ef:77:0b:62:cc:2d:d0:dd:df:fa:76:90:c5:86:25:
    a9:b7:df:c3:09:2e:b0:e4:5b:a3:03:80:55:42:12:76:
    95:8e:22:28:fa:d6:2b:e8:b3:e6:68:6d:25:d1:7d:86:
    92:6a:71:19:48:da:0f:93:05:ee:02:60:7f:19:4b:79
exponent1:
    50:6e:15:4f:0b:84:95:49:5f:cf:b0:a1:0d:09:e2:2e:
    e1:74:d9:ac:5c:7d:8a:27:32:a3:3e:74:de:29:46:51:
    7b:2d:0c:ce:bb:24:7d:64:c9:ae:07:c0:db:78:c1:cf:
    9e:40:bb:33:5e:8d:ff:f1:1a:36:34:17:db:74:08:b9:
    65:50:5d:09:18:83:ae:c2:83:98:67:7d:ed:51:62:e1:
    5f:ab:99:6d:95:1e:8c:cc:fb:33:9b:90:ec:f5:6e:e9:
    3c:b6:b0:6b:e4:f7:ed:4a:fc:72:55:de:fe:59:7d:c8:
    f6:8c:02:ed:fe:09:fc:f0:70:2e:0b:7a:ee:a7:92:cd
exponent2:
    34:7f:91:3d:a8:44:46:a1:c4:b4:fb:71:db:cf:cf:eb:
    14:b2:1b:46:36:d8:69:49:4a:c6:1e:bf:1e:a2:57:69:
    b8:89:92:f9:4a:fb:2d:91:86:25:29:75:66:21:eb:f7:
    bf:b8:3a:fa:49:88:2a:18:45:0e:e2:e6:d3:8e:ff:d7:
    6a:66:f1:1b:db:c1:09:b5:94:e4:21:f5:ee:1b:b8:ac:
    b1:c4:d8:b4:c1:d8:eb:66:d6:e2:c0:7a:d4:79:89:b4:
    bf:ad:cb:2d:f4:db:68:56:ea:ee:ae:b9:a0:16:c2:6e:
    7b:e6:f6:58:1b:57:89:c3:4b:75:4f:88:16:4e:f2:19
coefficient:
    ae:32:3b:40:9f:64:fe:c5:c9:cc:cc:c8:a3:89:88:15:
    ac:06:0d:95:de:0c:43:ad:3c:87:b8:31:bb:b2:94:3a:
    1c:3f:d8:3c:d9:52:18:7e:da:2b:f3:f2:e9:f8:59:3f:
    98:41:b6:e1:d0:6e:08:ae:ab:16:1c:9f:ad:b7:78:50:
    df:52:19:ad:6d:8d:c1:38:7b:29:52:cf:07:13:cd:9f:
    75:d7:22:a9:80:02:e8:ef:1c:69:15:c2:b5:b5:27:db:
    9b:ab:95:f8:12:3d:d4:ea:66:4b:94:22:cc:d3:73:43:
    63:b9:f2:38:44:c9:ed:c4:48:17:49:97:0a:f3:0d:61
"""
k = parse(key_content)
N, e, d = k["modulus"], k["publicExponent"], k["privateExponent"]
p, q = k["prime1"], k["prime2"]
dP, dQ, qInv = k["exponent1"], k["exponent2"], k["coefficient"]

phi = (p - 1) * (q - 1)
lam = phi // gcd(p - 1, q - 1)  # lcm(p-1, q-1)


def check(name, ok):
    print(f"{'PASS' if ok else 'FAIL'}  {name}")


print(f"N bit length: {N.bit_length()}, p: {p.bit_length()}, q: {q.bit_length()}")
check("p * q == N", p * q == N)
check("gcd(e, phi(N)) == 1", gcd(e, phi) == 1)
check("e*d == 1 (mod lambda(N))", (e * d) % lam == 1)
print(f"INFO  e*d == 1 (mod phi(N))? {(e * d) % phi == 1}  (may be False; that's fine)")
check("dP == d mod (p-1)", dP == d % (p - 1))
check("dQ == d mod (q-1)", dQ == d % (q - 1))
check("qInv * q == 1 (mod p)", (qInv * q) % p == 1)

# Round trip: encrypt with e, decrypt with d, and again via the CRT shortcut
m = 123456789
c = pow(m, e, N)
check("decrypt with d recovers m", pow(c, d, N) == m)

m1, m2 = pow(c, dP, p), pow(c, dQ, q)
h = (qInv * (m1 - m2)) % p
check("CRT decryption recovers m", m2 + h * q == m)

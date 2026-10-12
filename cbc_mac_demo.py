"""演示原始 CBC-MAC 的变长消息拼接伪造（整块输入，无填充）。"""

import secrets
from hmac import compare_digest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16  # AES 分组长度：16 字节


def xor(a, b):
    if len(a) != BLOCK or len(b) != BLOCK:
        raise ValueError("异或输入必须都是一个 AES 分组")
    return bytes(x ^ y for x, y in zip(a, b))


def cbc_mac(key, message):
    if not message or len(message) % BLOCK:
        raise ValueError("消息必须非空且长度为 16 字节的整数倍")
    aes = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    state = bytes(BLOCK)  # C_0 = 0
    for offset in range(0, len(message), BLOCK):
        state = aes.update(xor(state, message[offset:offset + BLOCK]))
    aes.finalize()
    return state


def forge(m, t, m_prime, t_prime):
    """攻击者只使用已知消息和标签，不需要密钥。"""
    forged = m + xor(m_prime[:BLOCK], t) + m_prime[BLOCK:]
    return forged, t_prime


def main():
    key = secrets.token_bytes(16)  # 只有认证方知道密钥
    m = b"A" * BLOCK + b"B" * BLOCK
    m_prime = b"C" * BLOCK + b"D" * BLOCK
    t = cbc_mac(key, m)
    t_prime = cbc_mac(key, m_prime)

    forged, claimed_tag = forge(m, t, m_prime, t_prime)
    actual_tag = cbc_mac(key, forged)  # 验证方使用密钥重新计算
    accepted = compare_digest(actual_tag, claimed_tag)
    fixed_length_accepted = (
            len(forged) == len(m)
            and compare_digest(cbc_mac(key, forged), claimed_tag)
    )

    print("m 和 m' 长度：", len(m), "字节（各 2 个分组）")
    print("伪造消息长度：", len(forged), "字节（4 个分组）")
    print("t                  =", t.hex())
    print("t'（攻击者提交）    =", claimed_tag.hex())
    print("MAC(伪造消息)      =", actual_tag.hex())
    print("变长验证通过：", accepted)
    print("固定 32 字节验证通过：", fixed_length_accepted)
    assert forged not in (m, m_prime)
    assert actual_tag == t_prime
    assert accepted and not fixed_length_accepted


if __name__ == "__main__":
    main()

# Note
"""
CBC-MAC 变长消息伪造与 Merkle-Damgård 长度扩展攻击本质上是同类问题：最终输出直接暴露了内部链状态，
而该状态又可作为后续计算的输入。解决方法都是引入 finalization 或 domain separation，
使“最终输出状态”和“继续迭代状态”不再等价，从而阻断扩展攻击。Blake2、HMAC、CMAC 等现代设计都体现了这一思想。
"""

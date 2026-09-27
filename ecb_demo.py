"""AES-256 ECB 教学：逐块加解密、PKCS#7 填充与重复块演示。"""

import argparse
import secrets

try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit("请先安装依赖：python -m pip install -r requirements.txt")


BLOCK_SIZE = 16


def pad(data):
    # PKCS7 的参数单位是位：AES 分组为 128 位，不是密钥的 256 位。
    context = padding.PKCS7(128).padder()
    return context.update(data) + context.finalize()


def unpad(data):
    context = padding.PKCS7(128).unpadder()
    return context.update(data) + context.finalize()


def transform_blocks(data, key, decrypt=False, verbose=False):
    """处理完整分组，不自动填充；ECB 的各块独立使用同一密钥。"""
    if len(key) != 32:
        raise ValueError("AES-256 密钥必须是 32 字节")
    if len(data) % BLOCK_SIZE:
        raise ValueError("ECB 输入必须是 16 字节的整数倍")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    context = cipher.decryptor() if decrypt else cipher.encryptor()
    output = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]
        result = context.update(block)
        output.extend(result)
        if verbose:
            print("\n第 {} 块：{}".format(
                offset // BLOCK_SIZE + 1,
                "P_i = AES_K^(-1)(C_i)" if decrypt else "C_i = AES_K(P_i)"))
            print("  输入：", block.hex(" "))
            print("  输出：", result.hex(" "))
    output.extend(context.finalize())
    return bytes(output)


def ecb_encrypt(plaintext, key, verbose=False):
    padded = pad(plaintext)
    if verbose:
        count = len(padded) - len(plaintext)
        print("明文 {} 字节 → 填充后 {} 字节".format(len(plaintext), len(padded)))
        print("PKCS#7：补 {} 个 0x{:02x} 字节".format(count, count))
        print("填充内容：", padded[-count:].hex(" "))
    return transform_blocks(padded, key, verbose=verbose)


def ecb_decrypt(ciphertext, key, verbose=False):
    if not ciphertext:
        raise ValueError("带 PKCS#7 填充的 ECB 密文不能为空")
    padded = transform_blocks(ciphertext, key, decrypt=True, verbose=verbose)
    plaintext = unpad(padded)
    if verbose:
        print("\n移除 {} 字节填充。".format(len(padded) - len(plaintext)))
    return plaintext


def repeated_block_demo(key):
    print("\n========== 相同明文块实验 ==========")
    block = b"0123456789ABCDEF"  # 正好 16 字节的 ASCII 文本。
    ciphertext = ecb_encrypt(block * 2, key)
    print("输入：两个相同的 16 字节块，另有一个完整填充块。")
    print("明文块 1 = 明文块 2 =", block.hex(" "))
    print("密文块 1：", ciphertext[:16].hex(" "))
    print("密文块 2：", ciphertext[16:32].hex(" "))
    print("密文块相同：", ciphertext[:16] == ciphertext[16:32])
    print("ECB 没有 IV 或计数器；同一密钥下，相同明文块总产生相同密文块。")


def self_test():
    # NIST SP 800-38A F.1.5：原始 ECB 向量不包含填充。
    key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex(
        "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
        "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7")
    assert transform_blocks(plaintext, key) == expected
    assert transform_blocks(expected, key, decrypt=True) == plaintext
    for size in (0, 1, 15, 16, 17, 31, 32, 64):
        data = plaintext[:size]
        encrypted = ecb_encrypt(data, key)
        assert len(encrypted) == (size // 16 + 1) * 16
        assert ecb_decrypt(encrypted, key) == data
        count = 16 - size % 16
        assert pad(data) == data + bytes([count]) * count
    text = "你好，ECB！".encode("utf-8")
    assert ecb_decrypt(ecb_encrypt(text, key), key) == text
    repeated = ecb_encrypt(b"A" * 32, key)
    assert repeated[:16] == repeated[16:32]
    # 构造解密后以 0x00 结尾的非法填充，避免随机篡改带来的偶然性。
    bad_padding = transform_blocks(b"\x00" * 16, key)
    for invalid in (b"", b"x", bad_padding):
        try:
            ecb_decrypt(invalid, key)
        except ValueError:
            pass
        else:
            raise AssertionError("应拒绝非法密文或填充")
    print("自检通过：NIST 四块向量、填充边界、中文、重复块及非法输入。")


def main():
    parser = argparse.ArgumentParser(description="AES-256 ECB 与 PKCS#7 填充教学")
    parser.add_argument("--text", default="你好，ECB！学习分组加密与填充。", help="待加密的 UTF-8 文本")
    parser.add_argument("--self-test", action="store_true", help="运行标准向量和边界自检")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    key = secrets.token_bytes(32)
    print("AES-256 ECB：32 字节密钥，16 字节分组。")
    print("ECB 直接加密明文块；本例使用 PKCS#7 补齐分组。")
    print("即使明文已对齐或为空，也补一个完整的 16 字节填充块。")
    print("教学密钥（真实系统不要打印）：", key.hex())
    print("原文：", args.text)
    plaintext = args.text.encode("utf-8")
    print("\n========== 填充与加密 ==========")
    ciphertext = ecb_encrypt(plaintext, key, verbose=True)
    print("\n完整密文（hex）：", ciphertext.hex())
    print("\n========== 解密与去填充 ==========")
    recovered = ecb_decrypt(ciphertext, key, verbose=True)
    print("还原明文：", recovered.decode("utf-8"))
    print("还原成功：", recovered == plaintext)
    repeated_block_demo(key)
    print("\nECB 会暴露重复模式，也不提供完整性保护，仅用于本次教学。")
    print("填充校验不等于完整性校验，不能可靠检测密文篡改。")


if __name__ == "__main__":
    main()

"""AES-256 CBC 教学：逐块查看链接、异或、AES 运算与 PKCS#7 填充。"""

import argparse
import secrets

try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit("请先安装依赖：python -m pip install -r requirements.txt")


def pad(data):
    # 参数是分组位数，与 AES-256 的密钥位数无关。
    context = padding.PKCS7(128).padder()
    return context.update(data) + context.finalize()


def unpad(data):
    context = padding.PKCS7(128).unpadder()
    return context.update(data) + context.finalize()


def xor_block(left, right):
    if len(left) != 16 or len(right) != 16:
        raise ValueError("异或双方必须都是 16 字节分组")
    return bytes(a ^ b for a, b in zip(left, right))


def transform_blocks(data, key, iv, decrypt=False, verbose=False):
    """教学实现 CBC 链接；输入必须对齐，不自动填充或去填充。"""
    if len(key) != 32:
        raise ValueError("AES-256 密钥必须是 32 字节")
    if len(iv) != 16:
        raise ValueError("CBC 的 IV 必须是 16 字节")
    if len(data) % 16:
        raise ValueError("CBC 输入必须是 16 字节的整数倍")
    # 这里只用 ECB 接口调用单块 AES 原语，CBC 链接在循环中完成。
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    aes = cipher.decryptor() if decrypt else cipher.encryptor()
    previous = iv  # 第一块使用 IV；后续块使用前一个密文块。
    output = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        if decrypt:
            intermediate = aes.update(block)
            result = xor_block(intermediate, previous)
        else:
            intermediate = xor_block(block, previous)
            result = aes.update(intermediate)
        if verbose:
            print("\n第 {} 块".format(offset // 16 + 1))
            print("  链接值（{}）：{}".format(
                "IV" if offset == 0 else "前一密文块", previous.hex(" ")))
            if decrypt:
                print("  密文 C_i            ：", block.hex(" "))
                print("  AES 解密 D_K(C_i)   ：", intermediate.hex(" "))
                print("  明文 = AES解密 XOR 链接值：", result.hex(" "))
            else:
                print("  明文 P_i            ：", block.hex(" "))
                print("  AES输入 = P_i XOR 链接值：", intermediate.hex(" "))
                print("  密文 = AES_K(AES输入)：", result.hex(" "))
        output.extend(result)
        # 解密时必须保存输入密文，而不是恢复出的明文。
        previous = block if decrypt else result
    output.extend(aes.finalize())
    return bytes(output)


def cbc_encrypt(plaintext, key, iv, verbose=False):
    padded = pad(plaintext)
    if verbose:
        count = len(padded) - len(plaintext)
        print("明文 {} 字节 → 填充后 {} 字节".format(len(plaintext), len(padded)))
        print("PKCS#7：补 {} 个 0x{:02x} 字节".format(count, count))
    return transform_blocks(padded, key, iv, verbose=verbose)


def cbc_decrypt(ciphertext, key, iv, verbose=False):
    if not ciphertext:
        raise ValueError("带 PKCS#7 填充的 CBC 密文不能为空")
    padded = transform_blocks(ciphertext, key, iv, decrypt=True, verbose=verbose)
    plaintext = unpad(padded)
    if verbose:
        print("\n移除 {} 字节填充。".format(len(padded) - len(plaintext)))
    return plaintext


def library_encrypt(padded, key, iv):
    context = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return context.update(padded) + context.finalize()


def self_test():
    # NIST SP 800-38A F.2.5：AES-256 CBC 四块已知答案，不包含填充。
    key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")
    assert transform_blocks(plain, key, iv) == expected
    assert transform_blocks(expected, key, iv, decrypt=True) == plain
    for data in [plain[:n] for n in (0, 1, 15, 16, 17, 31, 32, 64)] + ["你好，CBC！".encode()]:
        encrypted = cbc_encrypt(data, key, iv)
        assert encrypted == library_encrypt(pad(data), key, iv)
        assert len(encrypted) == (len(data) // 16 + 1) * 16
        assert cbc_decrypt(encrypted, key, iv) == data
    # 确定构造解密后全零的非法 PKCS#7 填充，避免随机篡改的偶然性。
    invalid_padding = transform_blocks(bytes(16), key, iv)
    for data, test_key, test_iv in (
        (b"", key, iv), (b"x", key, iv), (invalid_padding, key, iv),
        (expected, key[:16], iv), (expected, key, iv[:8]),
    ):
        try:
            cbc_decrypt(data, test_key, test_iv)
        except ValueError:
            pass
        else:
            raise AssertionError("应拒绝非法长度或填充")
    print("自检通过：NIST 向量、库结果对照、填充边界、中文及非法输入。")


def main():
    parser = argparse.ArgumentParser(description="AES-256 CBC 链接与填充教学")
    parser.add_argument("--text", default="你好，CBC！学习前一密文块如何参与下一块加密。", help="待加密的 UTF-8 文本")
    parser.add_argument("--self-test", action="store_true", help="运行标准向量与边界自检")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    plaintext = args.text.encode("utf-8")
    print("AES-256 CBC：32 字节密钥、16 字节分组、16 字节随机 IV。")
    print("令 C_0 = IV；加密：C_i = AES_K(P_i XOR C_(i-1))")
    print("解密：P_i = AES_K^(-1)(C_i) XOR C_(i-1)")
    print("教学密钥（真实系统不要打印）：", key.hex())
    print("IV（可公开，解密时需要）：", iv.hex())
    print("原文：", args.text)
    print("\n========== 填充与加密 ==========")
    ciphertext = cbc_encrypt(plaintext, key, iv, verbose=True)
    if ciphertext != library_encrypt(pad(plaintext), key, iv):
        raise RuntimeError("教学实现与库 CBC 结果不一致")
    print("\n与库自带 CBC 结果一致。密文（hex）：", ciphertext.hex())
    print("密文字节数（不含 IV）：", len(ciphertext))
    print("\n========== 解密与去填充 ==========")
    recovered = cbc_decrypt(ciphertext, key, iv, verbose=True)
    print("还原明文：", recovered.decode("utf-8"))
    print("还原成功：", recovered == plaintext)
    print("\n========== 更换 IV 实验 ==========")
    another_iv = secrets.token_bytes(16)
    while another_iv == iv:
        another_iv = secrets.token_bytes(16)
    another_ciphertext = cbc_encrypt(plaintext, key, another_iv)
    print("保持密钥和明文相同，新 IV：", another_iv.hex())
    print("原密文第一块：", ciphertext[:16].hex())
    print("新密文第一块：", another_ciphertext[:16].hex())
    print("第一块不同：", ciphertext[:16] != another_ciphertext[:16])
    print("\n学习要点：PKCS#7 即使遇到整块或空明文，也补一个完整填充块。")
    print("CBC 每次加密需要新的不可预测 IV；可随密文保存，密钥须保密。")
    print("CBC 本身不验证完整性，填充校验也不能替代认证。本脚本仅供教学。")


if __name__ == "__main__":
    main()

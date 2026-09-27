"""AES-256 OFB 教学：输出反馈、密钥流和异或，无需填充。"""

import argparse
import secrets

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit("请先安装依赖：python -m pip install -r requirements.txt")

try:
    from cryptography.hazmat.decrepit.ciphers.modes import OFB
except ImportError:
    # 兼容尚未迁移 OFB 接口的旧版 cryptography。
    from cryptography.hazmat.primitives.ciphers.modes import OFB


def ofb_transform(data, key, iv, verbose=False):
    """加解密共用的一次性函数；每次调用都从 IV 重新开始。

    不可通过重复调用本函数续传同一消息，否则会重复使用密钥流。
    """
    if len(key) != 32:
        raise ValueError("AES-256 密钥必须是 32 字节")
    if len(iv) != 16:
        raise ValueError("OFB 的 IV 必须是 16 字节")
    # ECB 接口仅用于调用单块 AES 加密原语，OFB 反馈在循环中完成。
    # 加密与解密都使用 AES 加密运算。
    aes = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    feedback = iv
    output = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        stream = aes.update(feedback)
        result = bytes(a ^ b for a, b in zip(block, stream))
        if verbose:
            print("\n第 {} 段（{} 字节）".format(offset // 16 + 1, len(block)))
            print("  反馈值（{}）：{}".format(
                "IV" if offset == 0 else "前一 AES 输出", feedback.hex(" ")))
            print("  密钥流 = AES_K(反馈值)：", stream.hex(" "))
            print("  输入：", block.hex(" "))
            print("  输出 = 输入 XOR 密钥流：", result.hex(" "))
            print("  首字节：{:08b} XOR {:08b} = {:08b}".format(
                block[0], stream[0], result[0]))
            if len(block) < 16:
                print("  最后一段仅使用密钥流前 {} 字节，不填充。".format(len(block)))
        output.extend(result)
        feedback = stream  # 反馈完整 AES 输出，不是明文或密文。
    output.extend(aes.finalize())
    return bytes(output)


def ofb_encrypt(plaintext, key, iv, verbose=False):
    return ofb_transform(plaintext, key, iv, verbose=verbose)


def ofb_decrypt(ciphertext, key, iv, verbose=False):
    return ofb_transform(ciphertext, key, iv, verbose=verbose)


def library_transform(data, key, iv, decrypt=False):
    cipher = Cipher(algorithms.AES(key), OFB(iv))
    context = cipher.decryptor() if decrypt else cipher.encryptor()
    return context.update(data) + context.finalize()


def self_test():
    # NIST SP 800-38A F.4.5：OFB-AES256.Encrypt 四块已知答案。
    key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex(
        "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d"
        "71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484")
    assert ofb_encrypt(plain, key, iv) == expected
    assert ofb_decrypt(expected, key, iv) == plain
    for data in [plain[:n] for n in (0, 1, 15, 16, 17, 31, 32, 33, 64)] + ["你好，OFB！".encode()]:
        encrypted = ofb_encrypt(data, key, iv)
        assert encrypted == library_transform(data, key, iv)
        assert len(encrypted) == len(data)
        assert ofb_decrypt(encrypted, key, iv) == data
        assert library_transform(encrypted, key, iv, decrypt=True) == data
    # OFB 密钥流与消息内容无关；翻转密文一位只翻转对应明文位。
    modified = bytearray(expected)
    modified[0] ^= 1
    recovered = ofb_decrypt(bytes(modified), key, iv)
    assert recovered == bytes([plain[0] ^ 1]) + plain[1:]
    for test_key, test_iv in ((key[:16], iv), (key, iv[:8])):
        try:
            ofb_encrypt(plain, test_key, test_iv)
        except ValueError:
            pass
        else:
            raise AssertionError("应拒绝非法密钥或 IV 长度")
    print("自检通过：NIST 向量、库加解密对照、长度边界、中文、位翻转及非法长度。")


def main():
    parser = argparse.ArgumentParser(description="AES-256 OFB 输出反馈教学")
    parser.add_argument("--text", default="你好，OFB！学习 AES 输出如何反馈生成密钥流。", help="待加密的 UTF-8 文本")
    parser.add_argument("--self-test", action="store_true", help="运行标准向量与边界自检")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    plaintext = args.text.encode("utf-8")
    print("AES-256 OFB：32 字节密钥、16 字节 AES 分组、16 字节 IV。")
    print("S_0 = IV；S_i = AES_K(S_(i-1))")
    print("加密：C_i = P_i XOR S_i；解密：P_i = C_i XOR S_i")
    print("反馈的是 AES 输出；密钥流不依赖明文或密文。")
    print("教学密钥（真实系统不要打印）：", key.hex())
    print("IV（可公开，解密时需要）：", iv.hex())
    print("原文：", args.text)
    print("\n========== 加密 ==========")
    ciphertext = ofb_encrypt(plaintext, key, iv, verbose=True)
    if ciphertext != library_transform(plaintext, key, iv):
        raise RuntimeError("教学实现与库 OFB 结果不一致")
    print("\n与库自带 OFB 结果一致。密文（hex）：", ciphertext.hex())
    print("明文字节数：{}；密文字节数（不含 IV）：{}".format(len(plaintext), len(ciphertext)))
    print("\n========== 解密（仍使用 AES 加密运算） ==========")
    recovered = ofb_decrypt(ciphertext, key, iv, verbose=True)
    print("\n还原明文：", recovered.decode("utf-8"))
    print("还原成功：", recovered == plaintext)
    print("\n学习要点：OFB 反馈 AES 输出；CFB 反馈密文；CTR 更新计数器。")
    print("OFB 无需填充；同一密钥下 IV 绝不能重复，否则会重复密钥流。")
    print("本例每次生成新密钥和随机 IV；解密时使用原密钥和 IV。")
    print("OFB 不验证完整性：翻转密文一位会翻转对应明文位。本脚本仅供教学。")


if __name__ == "__main__":
    main()

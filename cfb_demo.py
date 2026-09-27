"""AES-256 CFB-128 教学：密文反馈、密钥流与异或，无需填充。"""

import argparse
import secrets

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit("请先安装依赖：python -m pip install -r requirements.txt")

try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:
    # 兼容尚未迁移 CFB 接口的旧版本 cryptography。
    from cryptography.hazmat.primitives.ciphers.modes import CFB


def cfb_transform(data, key, iv, decrypt=False, verbose=False):
    """一次性处理完整消息；CFB-128 的最后一段可以不足 16 字节。

    每次调用都从 IV 开始，不可把多次调用当作同一消息的流式续传。
    """
    if len(key) != 32:
        raise ValueError("AES-256 密钥必须是 32 字节")
    if len(iv) != 16:
        raise ValueError("CFB 的 IV 必须是 16 字节")
    # ECB 接口仅用来调用单块 AES 加密原语，CFB 反馈由循环实现。
    # 注意：即使正在解密，也使用 AES encryptor，而非 decryptor。
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
                "IV" if offset == 0 else "前一密文段", feedback.hex(" ")))
            print("  密钥流 AES_K(反馈值)：", stream.hex(" "))
            print("  输入{}：{}".format("密文" if decrypt else "明文", block.hex(" ")))
            print("  输出{} = 输入 XOR 密钥流：{}".format(
                "明文" if decrypt else "密文", result.hex(" ")))
            print("  首字节：{:08b} XOR {:08b} = {:08b}".format(
                block[0], stream[0], result[0]))
            if len(block) < 16:
                print("  最后一段仅使用密钥流前 {} 字节，不填充。".format(len(block)))
        output.extend(result)
        # 两个方向都反馈密文：加密取输出，解密取输入。
        # 短段只能出现在消息末尾，无须生成下一轮反馈值。
        if len(block) == 16:
            feedback = block if decrypt else result
    output.extend(aes.finalize())
    return bytes(output)


def cfb_encrypt(plaintext, key, iv, verbose=False):
    return cfb_transform(plaintext, key, iv, verbose=verbose)


def cfb_decrypt(ciphertext, key, iv, verbose=False):
    return cfb_transform(ciphertext, key, iv, decrypt=True, verbose=verbose)


def library_transform(data, key, iv, decrypt=False):
    # cryptography 的 CFB 对应 CFB-128；CFB8 是另一种反馈段长。
    cipher = Cipher(algorithms.AES(key), CFB(iv))
    context = cipher.decryptor() if decrypt else cipher.encryptor()
    return context.update(data) + context.finalize()


def self_test():
    # NIST SP 800-38A F.3.17：CFB128-AES256.Encrypt 四段已知答案。
    key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex(
        "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407b"
        "df10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471")
    assert cfb_encrypt(plain, key, iv) == expected
    assert cfb_decrypt(expected, key, iv) == plain
    for data in [plain[:n] for n in (0, 1, 15, 16, 17, 31, 32, 33, 64)] + ["你好，CFB！".encode()]:
        encrypted = cfb_encrypt(data, key, iv)
        assert encrypted == library_transform(data, key, iv)
        assert len(encrypted) == len(data)
        assert cfb_decrypt(encrypted, key, iv) == data
        assert library_transform(encrypted, key, iv, decrypt=True) == data
    for test_key, test_iv in ((key[:16], iv), (key, iv[:8])):
        try:
            cfb_encrypt(plain, test_key, test_iv)
        except ValueError:
            pass
        else:
            raise AssertionError("应拒绝非法密钥或 IV 长度")
    print("自检通过：NIST 向量、库加解密对照、空输入、短段、整段、中文及非法长度。")


def main():
    parser = argparse.ArgumentParser(description="AES-256 CFB-128 密文反馈教学")
    parser.add_argument("--text", default="你好，CFB！学习密文反馈与无需填充的加密。", help="待加密的 UTF-8 文本")
    parser.add_argument("--self-test", action="store_true", help="运行标准向量与边界自检")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    plaintext = args.text.encode("utf-8")
    print("AES-256 CFB-128：32 字节密钥、16 字节 AES 分组、128 位反馈段。")
    print("令 C_0 = IV；S_i = AES_K(C_(i-1))")
    print("加密：C_i = P_i XOR S_i；解密：P_i = C_i XOR S_i")
    print("两个方向都用 AES 加密运算，都反馈密文；最后短段仅取所需密钥流。")
    print("教学密钥（真实系统不要打印）：", key.hex())
    print("IV（可公开，解密时需要）：", iv.hex())
    print("原文：", args.text)
    print("\n========== 加密 ==========")
    ciphertext = cfb_encrypt(plaintext, key, iv, verbose=True)
    if ciphertext != library_transform(plaintext, key, iv):
        raise RuntimeError("教学实现与库 CFB 结果不一致")
    print("\n与库自带 CFB 结果一致。密文（hex）：", ciphertext.hex())
    print("明文字节数：{}；密文字节数（不含 IV）：{}".format(len(plaintext), len(ciphertext)))
    print("\n========== 解密（仍使用 AES 加密运算） ==========")
    recovered = cfb_decrypt(ciphertext, key, iv, verbose=True)
    print("\n还原明文：", recovered.decode("utf-8"))
    print("还原成功：", recovered == plaintext)
    print("\n学习要点：CFB 反馈前一密文；CTR 则更新计数器。")
    print("CFB 每次加密应使用新的不可预测 IV，解密使用原 IV。")
    print("本例是 CFB-128，CFB-8 每次反馈 1 字节，结果与本例不同。")
    print("CFB 本身不验证完整性；本脚本打印密钥，仅供教学。")


if __name__ == "__main__":
    main()

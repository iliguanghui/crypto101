"""AES-256 CTR 教学：python ctr_demo.py 或 python ctr_demo.py --self-test。"""

import argparse
import secrets

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit("请先安装依赖：python -m pip install -r requirements.txt")


def ctr_transform(data, key, initial_counter, verbose=False):
    """CTR 加解密共用：输入 XOR AES_K(计数器)。计数器为大端 128 位。"""
    if len(key) != 32 or len(initial_counter) != 16:
        raise ValueError("AES-256 需要 32 字节密钥和 16 字节初始计数器")
    start = int.from_bytes(initial_counter, "big")
    if start + (len(data) + 15) // 16 > 2 ** 128:
        raise ValueError("计数器将溢出，请更换密钥和初始计数器")
    # ECB 仅用于调用单块 AES 原语，并非直接用 ECB 加密明文。
    aes = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    output = bytearray()
    for index, offset in enumerate(range(0, len(data), 16)):
        block = data[offset:offset + 16]
        counter = (start + index).to_bytes(16, "big")
        stream = aes.update(counter)
        # zip 使最后一个短块只使用所需长度的密钥流，不需要填充。
        result = bytes(a ^ b for a, b in zip(block, stream))
        output.extend(result)
        if verbose:
            print("\n第 {} 块（{} 字节）".format(index + 1, len(block)))
            print("  计数器 T_i       ：", counter.hex(" "))
            print("  密钥流 AES_K(T_i)：", stream.hex(" "))
            print("  输入             ：", block.hex(" "))
            print("  输出 = 输入 XOR S：", result.hex(" "))
            print("  首字节：{:08b} XOR {:08b} = {:08b}".format(
                block[0], stream[0], result[0]))
    aes.finalize()
    return bytes(output)


def library_ctr(data, key, counter):
    context = Cipher(algorithms.AES(key), modes.CTR(counter)).encryptor()
    return context.update(data) + context.finalize()


def self_test():
    """NIST SP 800-38A F.5.5 AES-256 CTR 已知答案及边界检查。"""
    key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    counter = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plain = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex(
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6")
    assert ctr_transform(plain, key, counter) == expected
    for size in (0, 1, 15, 16, 17, 31, 32, 64):
        data = plain[:size]
        encrypted = ctr_transform(data, key, counter)
        assert encrypted == library_ctr(data, key, counter)
        assert ctr_transform(encrypted, key, counter) == data
    assert len(ctr_transform(b"x" * 16, key, b"\xff" * 16)) == 16
    try:
        ctr_transform(b"x" * 17, key, b"\xff" * 16)
    except ValueError:
        pass
    else:
        raise AssertionError("应拒绝计数器溢出")
    print("自检通过：NIST 向量、库结果对照、空输入、短块、整块及溢出边界。")


def main():
    parser = argparse.ArgumentParser(description="逐块学习 AES-256 CTR 模式")
    parser.add_argument("--text", default="你好，CTR！AES-256 的分组仍是 16 字节。", help="待加密的文本")
    parser.add_argument("--self-test", action="store_true", help="运行已知答案和边界自检")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    key = secrets.token_bytes(32)
    counter = secrets.token_bytes(16)
    plain = args.text.encode("utf-8")
    print("AES-256：密钥 32 字节，分组 16 字节；CTR 不需要填充。")
    print("本例将完整的 16 字节作为大端计数器，每块加 1。")
    print("S_i = AES_K(T_i)；C_i = P_i XOR S_i；P_i = C_i XOR S_i")
    print("教学密钥（真实系统不要打印）：", key.hex())
    print("初始计数器：", counter.hex())
    print("原文：", args.text)
    print("UTF-8 字节数：", len(plain))
    print("\n========== 加密 ==========")
    encrypted = ctr_transform(plain, key, counter, verbose=True)
    if encrypted != library_ctr(plain, key, counter):
        raise RuntimeError("教学实现与库结果不一致")
    print("\n完整密文（hex）：", encrypted.hex())
    print("密文字节数：", len(encrypted), "；与库自带 CTR 结果一致。")
    print("\n========== 解密（仍调用 AES 加密运算） ==========")
    recovered = ctr_transform(encrypted, key, counter, verbose=True)
    print("\n还原明文：", recovered.decode("utf-8"))
    print("还原成功：", recovered == plain)
    print("\n注意：同一密钥下，任何消息使用的计数器块都不能重复或重叠。")
    print("CTR 不检测篡改：密文某位翻转会导致明文相应位翻转。")
    print("本例每次生成新密钥，仅供教学；实际应用通常使用 AES-GCM 等认证加密。")


if __name__ == "__main__":
    main()

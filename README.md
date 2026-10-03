# AES-256 CTR、ECB、CBC、CFB 与 OFB 教学

## RSA demo

```sh
python -m pip install -r requirements.txt
python rsa_demo.py
python rsa_demo.py --text "Hello, RSA!"
```

`rsa_demo.py` generates a fresh RSA-2048 key pair, encrypts a UTF-8 message with the public key using OAEP/SHA-256, and decrypts it with the private key. It prints the ciphertext as Base64 and checks the round trip. Keys exist only in memory and are not saved. The message limit is 190 UTF-8 bytes for these parameters; larger data needs hybrid encryption rather than direct RSA encryption.

## ChaCha20 demo

```sh
python -m pip install -r requirements.txt
python chacha20_demo.py
```

Edit the multiline `text` in `chacha20_demo.py`. The demo generates a fresh
32-byte key and 8-byte nonce, prints the keystream and ciphertext, and decrypts
the text. It demonstrates `ciphertext = plaintext XOR keystream`, without padding.
It uses the library's original ChaCha20 layout (64-bit counter and 64-bit nonce),
not the IETF layout (32-bit counter and 96-bit nonce).
Never reuse a key/nonce pair for different messages. Keys and keystreams are
printed only for teaching. Raw ChaCha20 does not authenticate messages;
applications should use ChaCha20-Poly1305 for tamper detection.

Reference: [cryptography ChaCha20 documentation](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20).

## OFB 演示

`ofb_demo.py` 使用 AES-256 OFB，共用现有依赖：

```powershell
python -m pip install -r requirements.txt
python ofb_demo.py
python ofb_demo.py --text "我正在学习 OFB 模式"
python ofb_demo.py --self-test
```

脚本逐段展示反馈值、AES 密钥流、输入输出和首字节异或。令 `S_0 = IV`，密钥流为 `S_i = AES_K(S_(i-1))`。加密为 `C_i = P_i XOR S_i`，解密为 `P_i = C_i XOR S_i`，两个方向都使用 AES 加密运算。OFB 反馈完整 AES 输出；CFB 反馈密文；CTR 更新计数器。

最后不足 16 字节时仅使用所需长度的密钥流，不填充；空输入得到空密文。密文长度等于明文字节数，不含 IV。教学函数一次处理完整消息，每次调用从 IV 重新开始，不支持通过重复调用续传同一消息。

同一密钥下 IV 绝不能重复，否则会重复密钥流。本例每次生成新密钥和随机的 16 字节 IV。IV 可公开，解密使用原密钥和 IV。OFB 不提供完整性保护，密文某位翻转会使对应明文位翻转；仅供教学。

自检包含 NIST SP 800-38A F.4.5 四块向量、库加解密对照、空输入、短段、整段、中文、位翻转和非法长度。

## CFB 演示

`cfb_demo.py` 使用 AES-256 CFB-128，共用现有依赖：

```powershell
python -m pip install -r requirements.txt
python cfb_demo.py
python cfb_demo.py --text "我正在学习 CFB 模式"
python cfb_demo.py --self-test
```

脚本逐段显示反馈值、AES 产生的密钥流、输入输出及首字节异或。CFB-128 的反馈段长为 128 位（16 字节），不同于每次反馈 1 字节的 CFB-8；这里 256 指密钥位数。

令 `C_0 = IV`，密钥流为 `S_i = AES_K(C_(i-1))`。加密为 `C_i = P_i XOR S_i`，解密为 `P_i = C_i XOR S_i`。两个方向都使用 AES 加密运算，都反馈密文：加密取输出密文，解密取输入密文。与 CBC 直接处理异或后的明文不同，CFB 用 AES 加密反馈值来生成密钥流。

最后不足 16 字节时，仅取相同长度的密钥流，无需 PKCS#7 填充；空输入得到空密文。密文长度等于明文字节数，不包含 IV。本教学函数一次处理完整消息，每次调用重新从 IV 开始，不支持通过重复调用续传同一消息。

每次加密应使用新的不可预测的 16 字节 IV，解密使用原 IV。IV 可公开，密钥必须保密。CFB 本身不提供完整性保护，脚本仅供教学。

自检覆盖 NIST SP 800-38A F.3.17 的 AES-256 CFB-128 四段向量、库加解密对照、空输入、短段、整段、中文和非法长度。

## CBC 演示

`cbc_demo.py` 是独立的 AES-256 CBC 教学脚本，共用现有依赖：

```powershell
python -m pip install -r requirements.txt
python cbc_demo.py
python cbc_demo.py --text "我正在学习 CBC 模式"
python cbc_demo.py --self-test
```

脚本展示 PKCS#7 填充、每块与 IV/前一密文块的异或、AES 加解密中间值及去填充，并用库自带 CBC 核对结果。最后保持密钥和明文相同，更换 IV，观察第一密文块的变化。

令 `C_0 = IV`，加密为 `C_i = AES_K(P_i XOR C_(i-1))`，解密为 `P_i = AES_K^(-1)(C_i) XOR C_(i-1)`。这里 P 表示填充后的明文块。CBC 的 IV 为 16 字节，每次加密应生成新的不可预测 IV；IV 可公开，解密时必须使用原 IV。密文长度统计不包含 IV。

CBC 本身不提供完整性保护，填充校验也不能替代认证。脚本仅供教学。自检覆盖 NIST SP 800-38A F.2.5 四块向量、库结果对照、空输入、短块、整块、中文和非法输入。

## ECB 演示

新增 `ecb_demo.py`，与 CTR 脚本共用依赖：

```powershell
python -m pip install -r requirements.txt
python ecb_demo.py
python ecb_demo.py --text "我正在学习 ECB 模式"
python ecb_demo.py --text "0123456789ABCDEF"
python ecb_demo.py --self-test
```

脚本逐块显示加解密输入和输出，并解释 PKCS#7 填充：缺 n 字节就补 n 个值为 n 的字节；已对齐或空明文补 16 个 `0x10`。最后演示相同明文块产生相同密文块。ECB 直接加密明文块，解密使用 AES 逆运算；CTR 加解密都使用 AES 加密运算生成密钥流。

ECB 不使用 IV 或计数器，会暴露重复模式，也不提供完整性保护。填充校验不能替代认证。此脚本仅用于教学。

自检包含 NIST SP 800-38A F.1.5 的 AES-256 ECB 四块向量（无填充），以及 PKCS#7 边界、中文、重复块和非法输入。

## CTR 演示

使用 Python 3.8 或更新版本，在项目目录运行：

```powershell
python -m pip install -r requirements.txt
python ctr_demo.py
python ctr_demo.py --text "我正在学习 CTR 模式"
python ctr_demo.py --self-test
```

PyCharm 用户应使用项目所选解释器安装依赖，然后运行 main.py。

脚本逐块显示计数器、密钥流、输入和输出，以及首字节的二进制异或。中文先编码为 UTF-8；按字节分组，可能跨越汉字边界。

AES-256 的密钥为 32 字节，但 AES 分组始终为 16 字节。CTR 加解密都计算 `AES_K(counter)`，再与输入异或。最后一个短块仅使用所需的密钥流，不需要填充，密文和明文字节数相等。

本例使用完整 128 位大端计数器；有些协议约定使用 nonce 与较短计数器拼接。cryptography 的 CTR 接口把完整初始计数器参数称作 nonce。代码中的 ECB 仅用来展示单块 AES 运算，结果会与库自带 CTR 对照。

同一密钥下，计数器块不能重复或重叠，否则会重复密钥流。CTR 本身不验证完整性。本脚本打印密钥以便学习，不应作为生产加密工具。

自检包含 NIST 四块已知答案，以及空输入、短块、整块、进位和溢出边界。

参考：[cryptography 官方文档](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)、[NIST SP 800-38A F.5.5](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)。

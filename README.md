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

```sh
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

```sh
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

```sh
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

```sh
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

```sh
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

## Argon2 演示与测试向量验证

`argon2_demo.py` 与 `verify_argon2.py` 实现了 RFC 9106 定义的 Argon2 内存硬哈希算法（版本 1.3，`0x13`），包含全部三种变体：
- **Argon2d**（Type 0）：数据依赖寻址，适合抗 GPU 挖矿与不需要防御侧信道计时的场景。
- **Argon2i**（Type 1）：数据无关寻址，适合密码哈希与基于密码的密钥派生（防御基于缓存/计时的侧信道攻击）。
- **Argon2id**（Type 2）：混合模式（第 0 轮前半段采用 Argon2i，其余采用 Argon2d），RFC 9106 首选推荐方案。

仅使用 Python 标准库（`hashlib.blake2b` 与 `math`），无第三方依赖。

```sh
python argon2_demo.py
python verify_argon2.py
```

支持输出预哈希摘要 $H_0$、每轮结束时首尾内存块、最终异或块 $C$ 与输出标签（Tag），严格通过 RFC 9106 第 5 节全部测试向量。代码及 API 统一遵循标准 Python 蛇形命名（`password`、`salt`、`parallelism`、`tag_length`、`memory_size_kb`、`iterations`、`version`、`key`、`associated_data`、`hash_type`）。

## MD5 演示与测试向量验证

`md5_demo.py` 与 `verify_md5.py` 实现了 RFC 1321 与 Wikipedia 算法伪代码定义的 MD5 消息摘要算法（128 位）：
- **设计目标**：代码直观清晰，仅使用 Python 原生数据类型（整数、字节串、字节数组），不依赖任何第三方库；
- **分步封装**：清晰封装了填充处理（`pad_message`）、非线性辅助函数（`f_func`、`g_func`、`h_func`、`i_func`）、512 位分组压缩处理（`process_block`）及摘要生成（`md5`、`md5_hex`）；
- **过程可视化**：支持在终端打印原始消息长度、填充细节、每组 16 个 32 位小端字 $M[0..15]$、每轮（Round 1..4）寄存器中间状态及最终累加器值；
- **规范与测试**：统一遵循 Python 蛇形命名规范，严格通过 RFC 1321 第 A.5 节官方全部 7 个测试向量、Wikipedia 测试向量及各种边界长度测试。

```sh
python md5_demo.py
python md5_demo.py --text "The quick brown fox jumps over the lazy dog"
python verify_md5.py
```

### 深度剖析：为什么 MD5 采用小端序（Little-Endian）而 SHA-1 采用大端序（Big-Endian）？

在对比 RFC 1321（MD5）第 3.2 节与 RFC 3174（SHA-1）第 4 节时，会发现两者在填充消息长度（Bit Length）时采用了相反的端序：**MD5 将长度作为 64 位小端序整数追加，而 SHA-1 则作为 64 位大端序整数追加**。这一差异源自设计者背景、目标架构优化及行业标准的历史分化：

| 维度 | MD5（1991 年，Ronald Rivest 设计） | SHA-1（1993/1995 年，NSA 设计 / NIST 发布） |
| :--- | :--- | :--- |
| **设计主体** | 麻省理工学院学者、RSA 创始人 Ronald Rivest | 美国国家安全局（NSA）设计，NIST 发布为联邦标准（FIPS） |
| **核心优化目标** | **32 位 x86 个人电脑（PC）软件吞吐速度最大化** | **标准规范的数学直观性、网络字节序统一性与 FIPS 标准一致性** |
| **当时硬件背景** | Intel 80386 / 80486 架构（原生 **Little-Endian**） | 政府与科研大型机/工作站（IBM, Sun SPARC 等 **Big-Endian**） |
| **全算法端序策略** | **全流程 Little-Endian**（字解析、长度填充、摘要序列化） | **全流程 Big-Endian**（字解析、长度填充、摘要序列化） |

#### 1. MD5 的选择：追求在 Intel x86 上的极致软件性能
1990 年代初，以 Intel 80386/80486 为代表的 32 位 PC 正席卷市场，该架构为原生小端序。在早期的 80386 处理器上，尚未提供专门的单周期字节反转指令（`BSWAP` 于 80486 才加入）。如果算法在内存中规定为小端序，C 语言中只需一条简单的指针转换：
```c
/* x86 平台直接读取 32 位字，零额外转换指令 */
uint32_t *M = (uint32_t *)block_buffer;
```
Rivest 在 RFC 1320（MD4）与 RFC 1321（MD5）第 1 节中明确写道：*"The algorithm is designed to be quite fast on 32-bit machines..."*。为了在 PC 软件层面上消除所有字节反转开销，Rivest 决定全流程统一使用小端序。

#### 2. SHA-1 的选择：网络字节序、数学自然顺序与政府标准体系
SHA-1 由 NSA 设计并由 NIST 作为联邦标准（FIPS PUB 180-1）发布。其选择大端序的原因包括：
* **网络字节序（Network Byte Order）标准**：IETF 基础通信协议（RFC 791 IPv4、RFC 793 TCP 等）均规定大端序为标准网络字节序，国家级密码标准自然优先向网络协议看齐；
* **数学书写的自然性（MSB First）**：人类习惯高位在左、低位在右。例如 40 比特的长度，在 SHA-1 的内存十六进制转储中表现为 `00 00 00 00 00 00 00 28`，直观易读；而在 MD5 中则为 `28 00 00 00 00 00 00 00`；
* **与 DSA（FIPS 186）等大数算法体系对齐**：NIST 推出 SHA 主要是为了搭配数字签名算法 DSA。大数算术（如 512~1024 位大素数运算）以及 ASN.1 / DER 等公钥编码标准历来均采用大端序。

#### 3. 端序差异贯穿全算法，而非仅限于填充长度
这两个算法在各个数据交互阶段上的端序均严格自洽且完全相反：
1. **消息块解析为 32 位字**：
   * 输入字符串 `"abcd"`（字节 `0x61, 0x62, 0x63, 0x64`）：
     * MD5（小端序）：$M[0] = \text{0x64636261}$（第 1 字节 `0x61` 在最低有效字节）；
     * SHA-1（大端序）：$W[0] = \text{0x61626364}$（第 1 字节 `0x61` 在最高有效字节）。
2. **填充时的长度字段**：
   * MD5：追加 `bit_length.to_bytes(8, 'little')`；
   * SHA-1：追加 `bit_length.to_bytes(8, 'big')`。
3. **输出摘要（Digest）串联序列化**：
   * MD5：$\text{Digest} = \text{LE32}(A) \parallel \text{LE32}(B) \parallel \text{LE32}(C) \parallel \text{LE32}(D)$；
   * SHA-1：$\text{Digest} = \text{BE32}(H_0) \parallel \text{BE32}(H_1) \parallel \text{BE32}(H_2) \parallel \text{BE32}(H_3) \parallel \text{BE32}(H_4)$。

#### 4. 后续密码学演进的历史反转
* **SHA-2 家族**（SHA-256、SHA-512）：沿袭 NIST 传统，依然保持大端序；
* **现代密码学算法**（ChaCha20、Poly1305、BLAKE2、BLAKE3）：随着 x86-64、ARM64（默认小端）与 RISC-V 全面统治计算硬件，现代密码学家为了榨干现代 CPU 向量指令集吞吐，**重新全面回归了小端序**；
* **SHA-3（Keccak）**：NIST 发布的下一代标准 SHA-3（FIPS 202）中，其内部状态阵列转换也正式采纳了**小端序（Little-Endian）**。

### 架构与算法对称性：为什么 SHA-1 的伪代码实现比 MD5 更简洁？

单从规范与伪代码实现的视角对比，**SHA-1 展现出了比 MD5 高得多的数学对称性、规整性与结构美感**。MD5 的核心循环中充斥着经验性的杂乱参数（64 个不同常数、64 项移位表、复杂的模运算置换），而 SHA-1 则极其正交平滑：

#### 1. 核心循环伪代码直观对照

```python
# -------------------------------------------------------------
# SHA-1 核心循环（80 步，极度规整，无查表，顺序读取）
# -------------------------------------------------------------
# 消息扩展：一次性线性生成 80 个字
for i in range(16, 80):
    W[i] = left_rotate(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1)

# 主循环：每步结构完全一致
for i in range(80):
    temp = (left_rotate(A, 5) + f(B, C, D) + E + W[i] + K) & 0xFFFFFFFF
    E = D
    D = C
    C = left_rotate(B, 30)
    B = A
    A = temp
```

```python
# -------------------------------------------------------------
# MD5 核心循环（64 步，参数异构，依赖两张 64 项大表与模运算）
# -------------------------------------------------------------
for i in range(64):
    if 0 <= i <= 15:
        f = (B & C) | (~B & D);         g = i
    elif 16 <= i <= 31:
        f = (D & B) | (~D & C);         g = (5 * i + 1) % 16
    elif 32 <= i <= 47:
        f = B ^ C ^ D;                  g = (3 * i + 5) % 16
    else:
        f = C ^ (B | ~D);               g = (7 * i) % 16

    temp = (A + f + K[i] + M[g]) & 0xFFFFFFFF           # K[i] 依赖 64 个不同常数
    new_b = (B + left_rotate(temp, s[i])) & 0xFFFFFFFF  # s[i] 依赖 64 项移位表
    A = D
    D = C
    C = B
    B = new_b
```

#### 2. 四大结构维度的降维打击

| 比较维度 | MD5（Ronald Rivest 设计） | SHA-1（NSA 设计） | 为什么 SHA-1 更简洁？ |
| :--- | :--- | :--- | :--- |
| **1. 加法常数** | **64 个各不相同的 32 位常数**<br>（由正弦函数 $2^{32} \cdot \|\sin(i+1)\|$ 生成） | **全程仅 4 个常数**<br>（每 20 步共享一个，分别来自 $\sqrt{2}, \sqrt{3}, \sqrt{5}, \sqrt{10}$） | SHA-1 不需要存储或计算庞大的 64 字常数表。 |
| **2. 循环移位位数** | **由 16 个不同数字组成的 64 项数组**<br>（7, 12, 17, 22, 5, 9, 14, 20...） | **全程固定仅 2 个常量**<br>（永远是固定的 `A <<< 5` 与 `B <<< 30`） | SHA-1 完全**不需要**移位查找表，每一步移位量完全恒定。 |
| **3. 消息字寻址** | **复杂的模同余跳跃置换**<br>第 1 轮：$i$<br>第 2 轮：$(5i+1) \bmod 16$<br>第 3 轮：$(3i+5) \bmod 16$<br>第 4 轮：$(7i) \bmod 16$ | **线性递增读取**<br>第 $i$ 步直接顺序读取 $W[i]$，无分支、无模运算 | SHA-1 将消息字映射完全平铺为顺序流水线访问。 |
| **4. 状态寄存器更新** | **非对称轮换**<br>对 `temp` 移位后累加到 $B$，再进行非对称置换 | **经典的五级移位寄存器管道（Feistel 风格）**<br>$E \leftarrow D \leftarrow C \leftarrow (B \lll 30) \leftarrow A \leftarrow \text{temp}$ | SHA-1 每一轮状态像规整的移位寄存器流水线单向流动。 |

#### 3. 为什么 NSA 能把 SHA-1 设计得如此规整？
从密码工程学角度看，这是 NSA（美国国家安全局）对 Rivest 的 MD4/MD5 架构做的一次**工程降维解耦**：
1. **“消息扩展（Message Schedule）”解耦了混乱度**：
   * MD5 没有消息扩展，全流程只能反复复用原本的 16 个输入字。为了防止相邻轮次和步骤使用相同的字而削弱抗差分能力，Rivest 不得不在主循环内使用复杂的模同余公式（如 $(5i+1) \bmod 16$）强行打乱访问次序；
   * NSA 引入了线性反馈移位寄存器（LFSR）式的扩展机制：先在输入级将 16 个字扩展到 80 个字（$W_i = (W_{i-3} \oplus W_{i-8} \oplus W_{i-14} \oplus W_{i-16}) \lll 1$）。**这一步在预处理阶段提前吸收了“雪崩效应”和“字间混淆”的开销**，使得后续的主压缩循环可以写得极其规整和平滑。
2. **硬件实现（ASIC / FPGA）极其友好**：
   * MD5 在硬件上充斥着随周期不断切换的多路选择器（Mux）和 64 项常数 ROM；
   * SHA-1 的核心算子在 80 个时钟周期内结构高度同构，流水线连线固定（Hardwired），硬件面积更小，时钟频率更容易提高。
这一“在消息扩展层做混淆、保持压缩内核极简规整”的架构，也直接奠定了后来的 **SHA-2（SHA-256 / SHA-512）** 标准范式。

## SHA-1 演示与测试向量验证

`sha1_demo.py` 与 `verify_sha1.py` 实现了 RFC 3174 与 FIPS PUB 180-1 定义的 SHA-1 安全哈希算法（160 位）：
- **设计目标**：纯 Python 标准库实现，不依赖任何第三方库；遵循蛇形命名（`snake_case`）；
- **模块化步骤**：封装大端序填充（`pad_message`）、消息扩展（`expand_message_schedule`：16 个 32 位大端字扩展至 80 个字）、非线性轮函数（`f_func`）、轮常数（`get_k`）、512 位分组压缩处理（`process_block`）及摘要序列化（`sha1`、`sha1_hex`）；
- **过程追踪与对比注释**：支持控制台详细打印填充、消息扩展、每 20 步中间寄存器 $(A, B, C, D, E)$ 状态演进；代码中包含大量针对其前身 MD5 的机制对比注释（端序、扩展、移位与常数差异）；
- **严格测试覆盖**：通过 RFC 3174 第 7.3 节官方全部测试向量（包含 100 万个 `'a'` 的性能测试）、Wikipedia 测试向量及多字节 UTF-8 边界测试。

```sh
python sha1_demo.py
python sha1_demo.py --text "The quick brown fox jumps over the lazy dog"
python verify_sha1.py
```

## SHA-2 家族（SHA-224, SHA-256, SHA-384, SHA-512）实现与对比

项目中提供了符合 FIPS PUB 180-4 与 RFC 6234 规范的 SHA-2 密码哈希算法纯 Python 教学参考实现，分为两个核心实现文件与一个综合验证套件：
- [`sha256_demo.py`](file://./sha256_demo.py)：实现 32 位字长核心引擎，承载 **SHA-256** 与 **SHA-224**；
- [`sha512_demo.py`](file://./sha512_demo.py)：实现 64 位字长核心引擎，承载 **SHA-512** 与 **SHA-384**；
- [`verify_sha2.py`](file://./verify_sha2.py)：独立的跨算法综合测试套件。

### 1. 算法架构与跨代/跨族横向对比

#### 对比一：SHA-256 vs SHA-1（算法演进与安全性跃升）
1. **内部状态位宽**：
   - SHA-1：160 位内部状态（5 个 32 位寄存器 $A, B, C, D, E$）；
   - SHA-256：256 位内部状态（8 个 32 位寄存器 $A, B, C, D, E, F, G, H$）。
2. **消息扩展（Message Schedule）抗差分强化**：
   - SHA-1：使用极度脆弱的线性递归方程（仅异或和 1 位循环左移）：
     $$W_t = (W_{t-3} \oplus W_{t-8} \oplus W_{t-14} \oplus W_{t-16}) \lll 1$$
   - SHA-256：引入两个非线性小 $\sigma$ 函数，混合了循环右移与逻辑右移，并通过模 $2^{32}$ 加法打破仿射性：
     $$W_t = (\sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16}) \bmod 2^{32}$$
     其中逻辑右移（`SHR`）的引入破坏了纯循环移位的旋转对称性，大幅增强对差分密码分析的抵御能力。
3. **轮函数状态扩散速度**：
   - SHA-1：每步仅计算 1 个中间变量 $temp$，仅更新 1 个工作寄存器（$A \leftarrow temp$，其余平移）；
   - SHA-256：每步同时计算 2 个中间变量 $T_1$ 和 $T_2$，同时更新 2 个工作寄存器：
     $$e \leftarrow (d + T_1) \bmod 2^{32}, \quad a \leftarrow (T_1 + T_2) \bmod 2^{32}$$
     扩散速度提升一倍，有效阻断局部差分特征的构造。
4. **轮常数分布**：
   - SHA-1：全程仅 4 个常数（每 20 步共享一个）；
   - SHA-256：每一步均拥有独立的 32 位常数（共 64 个，源自前 64 个素数的三次方根小数部分）。
5. **碰撞阻力**：
   - SHA-1：已于 2017 年被实证碰撞（SHAttered），理论复杂度仅约 $2^{63}$；
   - SHA-256：提供 128 位抗碰撞强度与 256 位抗原像强度，是全球密码基础设施基石。

#### 对比二：SHA-224 vs SHA-256（32 位族截断与长度扩展抵御）
1. **压缩引擎复用**：SHA-224 与 SHA-256 的 512 位分组压缩循环、64 步迭代逻辑、填充对齐逻辑（对齐至 56 模 64 字节并追加 64 位大端长度）和 64 个轮常数 $K$ **100% 完全相同**。
2. **初始状态差异**：SHA-224 使用了与 SHA-256 独立的初始向量 $H^{(0)}$（取自第 9 至第 16 个素数平方根的小数部分第 33 至 64 位），确保同一输入在两算法下哈希值完全无关。
3. **输出截断**：SHA-256 输出全部 8 个 32 位字（32 字节 / 256 位）；SHA-224 舍弃末尾的 $H_7$，只输出前 7 个 32 位字（28 字节 / 224 位）。
4. **天然免疫长度扩展攻击（Length Extension Attack）**：
   因为 SHA-224 丢弃了 32 位内部状态，攻击者仅凭输出摘要无法逆向还原完整的 256 位寄存器状态，因此在无需使用 HMAC 的场景下，直接作为 MAC 时亦对标准长度扩展攻击天然免疫。

#### 对比三：SHA-512 vs SHA-256（64 位架构飞跃与吞吐优势）
1. **字长与算术**：SHA-256 基于 32 位模 $2^{32}$ 运算；SHA-512 基于 64 位模 $2^{64}$ 运算。
2. **分组规模**：SHA-256 分组为 512 位（64 字节，16 个 32 位字）；SHA-512 分组为 1024 位（128 字节，16 个 64 位字）。
3. **轮数与常数表**：SHA-256 迭代 64 轮（64 个 32 位常数）；SHA-512 迭代 80 轮（80 个 64 位常数，取自前 80 个素数的三次方根）。
4. **填充长度字段**：SHA-256 追加 64 位（8 字节）大端长度；SHA-512 追加 128 位（16 字节）大端长度，理论支持最大输入可达 $2^{128}-1$ 位。
5. **计算效率反超**：
   在现代 64 位 CPU 硬件上，处理 128 字节消息时，SHA-512 仅需 80 轮（平均每字节只需 $80 / 128 = 0.625$ 轮运算），而 SHA-256 处理 128 字节需要 2 个分组共 128 轮（平均每字节 $64 / 64 = 1.0$ 轮运算）。因此在 64 位硬件上处理大文件时，**SHA-512 的实际运算速度通常比 SHA-256 更快**。

#### 对比四：SHA-384 vs SHA-512（64 位族截断与长度扩展抵御）
1. **压缩引擎复用**：SHA-384 与 SHA-512 的 1024 位分组压缩函数、80 步迭代结构、80 个 64 位轮常数 $K$ **100% 完全相同**。
2. **初始状态差异**：SHA-384 使用独立的初始状态向量 $H^{(0)}$（取自第 9 至第 16 个素数平方根的前 64 位小数部分）。
3. **输出截断**：SHA-512 输出全部 8 个 64 位字（64 字节 / 512 位）；SHA-384 舍弃末尾的 $H_6$ 和 $H_7$，只输出前 6 个 64 位字（48 字节 / 384 位）。
4. **抵御长度扩展攻击**：SHA-384 丢弃了多达 128 位内部状态，同样天然免疫标准长度扩展攻击。

### 2. 核心函数命名与密码学意图：BSIG0, BSIG1, SSIG0, SSIG1 的由来

在阅读 RFC 6234 或 C 源码时，经常会看到 `BSIG0`、`BSIG1`、`SSIG0`、`SSIG1` 这组函数名。它们的命名渊源与设计意图如下：

#### ① 命名溯源（ASCII 音译）
* **NIST 官方数学符号**：在 FIPS PUB 180-4 规范中，NIST 采用希腊字母表示两类非线性扩散函数：
  * 大写 Sigma：$\Sigma_0(x)$ 与 $\Sigma_1(x)$；
  * 小写 sigma：$\sigma_0(x)$ 与 $\sigma_1(x)$。
* **RFC / 源码助记缩写**：因 IETF RFC 文档和 C 语言早期受限于 7-bit ASCII 字符集，无法直接渲染希腊字母，作者（Eastlake & Hansen）采用了直观的音译缩写：
  * **`BSIG`** = **B**ig **Sig**ma（对应大写 $\Sigma$）；
  * **`SSIG`** = **S**mall **Sig**ma（对应小写 $\sigma$）；
  * `0` 和 `1` 分别表示该类别下的第 0 号与第 1 号函数。

| RFC / C 源码标识 | NIST FIPS 符号 | 英文全称 | 应用阶段 | 运算构成 |
| :--- | :--- | :--- | :--- | :--- |
| **`BSIG0`** | $\Sigma_0$ | **B**ig **Sig**ma **0** | **主压缩循环**（作用于工作寄存器 $a$） | 全循环移位（3 项 $\text{ROTR}$ 异或） |
| **`BSIG1`** | $\Sigma_1$ | **B**ig **Sig**ma **1** | **主压缩循环**（作用于工作寄存器 $e$） | 全循环移位（3 项 $\text{ROTR}$ 异或） |
| **`SSIG0`** | $\sigma_0$ | **S**mall **Sig**ma **0** | **消息扩展调度**（作用于历史字 $W_{t-15}$） | 混合移位（2 项 $\text{ROTR}$ + 1 项 $\text{SHR}$ 异或） |
| **`SSIG1`** | $\sigma_1$ | **S**mall **Sig**ma **1** | **消息扩展调度**（作用于历史字 $W_{t-2}$） | 混合移位（2 项 $\text{ROTR}$ + 1 项 $\text{SHR}$ 异或） |

#### ② 密码学设计意图对比
1. **BSIG（大 $\Sigma$）：状态高阶无损扩散**
   - 用于主压缩函数每一步计算：$T_1$ 结合 $\text{BSIG1}(e)$，而 $T_2$ 结合 $\text{BSIG0}(a)$；
   - 运算**全部由循环右移（$\text{ROTR}$）组成**，属于双射可逆变换，不会丢失任何比特熵，确保内部状态在轮与轮之间获得最大化的雪崩扩散。
2. **SSIG（小 $\sigma$）：打破旋转对称性以抵御差分分析**
   - 用于将 16 个输入字扩展为 64 字（SHA-256）或 80 字（SHA-512）：
     $$W_t = (\text{SSIG1}(W_{t-2}) + W_{t-7} + \text{SSIG0}(W_{t-15}) + W_{t-16}) \bmod 2^w$$
   - 注意最后一项是**逻辑右移（$\text{SHR}$）**，而不是循环移位；
   - 逻辑右移会在高位直接补 0，彻底破坏了纯循环移位的 **旋转对称性（Rotational Symmetry）** 与仿射不变性，使得攻击者无法构造沿消息扩展链无阻力传递的高概率差分特征。

#### ③ 数学公式对照表

| 族系 | $\text{BSIG0}(x)$ | $\text{BSIG1}(x)$ | $\text{SSIG0}(x)$ | $\text{SSIG1}(x)$ |
| :--- | :--- | :--- | :--- | :--- |
| **32 位族**<br>(SHA-224 / SHA-256) | $(x \ggg 2) \oplus (x \ggg 13) \oplus (x \ggg 22)$ | $(x \ggg 6) \oplus (x \ggg 11) \oplus (x \ggg 25)$ | $(x \ggg 7) \oplus (x \ggg 18) \oplus (x \gg 3)$ | $(x \ggg 17) \oplus (x \ggg 19) \oplus (x \gg 10)$ |
| **64 位族**<br>(SHA-384 / SHA-512) | $(x \ggg 28) \oplus (x \ggg 34) \oplus (x \ggg 39)$ | $(x \ggg 14) \oplus (x \ggg 18) \oplus (x \ggg 41)$ | $(x \ggg 1) \oplus (x \ggg 8) \oplus (x \gg 7)$ | $(x \ggg 19) \oplus (x \ggg 61) \oplus (x \gg 6)$ |

### 3. 运行与验证指令

```sh
# 运行 32 位族（SHA-256 & SHA-224）演示
python sha256_demo.py
python sha256_demo.py --text "The quick brown fox jumps over the lazy dog"

# 运行 64 位族（SHA-512 & SHA-384）演示
python sha512_demo.py
python sha512_demo.py --text "The quick brown fox jumps over the lazy dog"

# 运行综合测试套件（覆盖 RFC 6234 官方向量、Wikipedia 雪崩测试、边界对齐与 hashlib 全量对比）
python verify_sha2.py
```

## SHA-3 家族（Keccak-f[1600] 海绵结构）实现与解析

项目中提供了依据 **NIST FIPS PUB 202** 规范与 Keccak 官方白皮书实现的 SHA-3 及 SHAKE 系列算法纯 Python 参考实现：
- [`sha3_demo.py`](file://./sha3_demo.py)：实现底层 $\text{Keccak-f}[1600]$ 置换核、海绵吸收与挤压驱动器，涵盖固定长度哈希（**SHA3-224**, **SHA3-256**, **SHA3-384**, **SHA3-512**）与可扩展输出函数（**SHAKE128**, **SHAKE256**）；
- [`verify_sha3.py`](file://./verify_sha3.py)：全覆盖测试套件，严格校验 NIST 官方向量、Wikipedia 案例、多速率边界与 `hashlib` 全量对比。

### 1. 为什么 SHA-3 彻底颠覆了前代哈希算法架构？

从 MD4、MD5 到 SHA-1、SHA-2，长达二十余年的主流哈希算法均沿用 **Merkle-Damgård 结构** 与 **ARX 范式**（加法 Add、旋转 Rotate、异或 XOR）。SHA-3（Keccak）则带来了彻底的密码学范式革命：

| 对比维度 | 前代哈希（MD5 / SHA-1 / SHA-2） | 现代哈希（SHA-3 / Keccak） | 带来的优势 |
| :--- | :--- | :--- | :--- |
| **基础数学模型** | **Merkle-Damgård 结构**（压缩函数迭代） | **Sponge（海绵结构）**（置换函数迭代） | 彻底解耦哈希输出长度与内部状态大小；支持任意长度挤压输出（XOF）。 |
| **内部状态与隐匿性** | 状态大小几乎等同于输出长度（如 SHA-256 为 256 位状态） | 状态固定为 **1600 位**，划分 Rate $r$ 与 Capacity $c$ | **天然免疫长度扩展攻击**：未公开的 Capacity $c$ 彻底隔绝了从摘要逆推寄存器状态的可能。 |
| **基础运算集** | **模加法 ARX 体系**（依赖 32/64 位进位链加法） | **纯位逻辑运算**（仅异或、与、非、循环移位，无进位加法） | 在硬件（ASIC / FPGA）中几乎无门延迟瓶颈，抗侧信道功耗分析能力大幅提升。 |
| **非线性机制** | 复杂的轮展开、选择函数、多数函数混合 | 全算法**仅有一个极简的 5 比特非线性 S 盒**：$\chi$（Chi） | 数学结构高度清晰规整，易于进行严格的代数度与差分概率边界证明。 |
| **内存与数据端序** | 历史遗留的大端序（Big-Endian） | **原生小端序（Little-Endian）** | 完全契合现代主流 CPU（x86-64 / ARM / RISC-V）的硬件存取习惯，零字节翻转开销。 |

### 2. 海绵结构（Sponge Construction）工作流程

海绵结构由两个阶段组成（内部状态宽 $b = r + c = 1600$ 位 / 200 字节）：
1. **吸收阶段（Absorbing Phase）**：
   * 输入消息经填充对齐后分割为大小为 $r$（比特率，Rate）的数据块；
   * 每个输入块与当前状态的前 $r$ 比特执行按位异或（XOR）；
   * 随后调用 24 轮 $\text{Keccak-f}[1600]$ 置换函数混淆打乱状态。
2. **挤压阶段（Squeezing Phase）**：
   * 直接从状态的前 $r$ 比特按需读取输出；
   * 若请求的输出长度超出 $r$（如 SHAKE 函数长流输出），则重新调用 $\text{Keccak-f}[1600]$ 进行状态更新，继续读取下一段 $r$ 比特。

### 3. NIST FIPS PUB 202 官方算法编号与 $\text{Keccak-f}[1600]$ 核心映射

在阅读与实现 NIST FIPS PUB 202 规范时，标准文档对置换步映射、辅助函数、海绵结构与填充规则给出了清晰权威的算法编号（**Algorithm 1 至 Algorithm 9**）：

| 算法编号 | FIPS 202 章节 | 官方函数名称 | 对应实现函数 | 核心功能与密码学意图 |
| :--- | :--- | :--- | :--- | :--- |
| **Algorithm 1** | Section 3.2.1 | $\theta(A)$ | [`step_theta`](file://./sha3_demo.py#L277) | **列混合线性扩散**：计算每列校验位 $C[x]$ 并计算 $D[x]$ 扩散至全平面，提供跨 Sheet 的雪崩扩散 |
| **Algorithm 2** | Section 3.2.2 | $\rho(A)$ | [`step_rho`](file://./sha3_demo.py#L295) | **通道内循环移位**：按预计算三角形偏置矩阵 $r[x][y]$ 循环左移通道字，提供位切片间混淆 |
| **Algorithm 3** | Section 3.2.3 | $\pi(A)$ | [`step_pi`](file://./sha3_demo.py#L307) | **坐标空间置换**：按矩阵变换 $(x, y) \to (y, (2x+3y)\bmod 5)$ 置换通道，防止活动位局部化 |
| **Algorithm 4** | Section 3.2.4 | $\chi(A)$ | [`step_chi`](file://./sha3_demo.py#L321) | **行非线性映射**：$A'[x] = A[x] \oplus (\neg A[x+1] \land A[x+2])$，全算法**唯一的非线性 S-Box 层** |
| **Algorithm 5** | Section 3.2.5 | $rc(t)$ | [`rc_lfsr`](file://./sha3_demo.py#L121) / [`compute_round_constant`](file://./sha3_demo.py#L160) | **轮常数比特发生器**：基于本原多项式 $x^8+x^6+x^5+x^4+1$ 的 8 级 LFSR 动态生成单比特常数并组装 64 位常数 |
| **Algorithm 6** | Section 3.2.5 | $\iota(A, i_r)$ | [`step_iota`](file://./sha3_demo.py#L337) | **轮常数注入映射**：将由 $rc(t)$ 组装的 64 位常数异或注入原点通道 $A[0][0]$，打破轮对称性 |
| **Algorithm 7** | Section 3.3 | $\text{KECCAK-}p[b, n_r](S)$ | [`keccak_f1600`](file://./sha3_demo.py#L375) | **完整置换**：将 200 字节状态映射为 $5\times 5$ 阵列，迭代 24 轮 $\text{Rnd} = \iota \circ \chi \circ \pi \circ \rho \circ \theta$ |
| **Algorithm 8** | Section 4 | $\text{SPONGE}[f, pad, r](N, d)$ | [`keccak_sponge`](file://./sha3_demo.py#L427) | **海绵构造驱动器**：管理任意输入的分块吸收（Absorb）与多块长流挤压（Squeeze） |
| **Algorithm 9** | Section 5.1 | $pad10^*1(x, m)$ | [`pad10star1`](file://./sha3_demo.py#L389) | **多速率填充规则**：向填充区填充 $10^*1$ 模式比特串（在字节粒度配合域分离后缀生成） |

> **关键勘误与设计细节说明**：
> 初读 FIPS PUB 202 时极易误以为 5 个步映射依次对应 Algorithm 1 ~ 5，从而误把 $\iota$ 当作 Algorithm 5。但实际上，FIPS 202 规范在第 3.2.5 节先将 LFSR 轮常数比特生成过程独立定义为 **Algorithm 5: $rc(t)$**，随后才将利用该常数对通道 $A[0][0]$ 执行异或注入的步映射定义为 **Algorithm 6: $\iota(A, i_r)$**。因此代码与文档中均严格标注 $\iota$ 为 Algorithm 6。


### 4. 域分离（Domain Separation）与首字节填充陷阱

FIPS PUB 202 在多速率填充（$pad10^*1$）前引入了**域分离后缀位**，这导致了不同变体在字节边界上的填充首字节差异：
* **标准 SHA-3（SHA3-224..512）**：追加后缀位 `01`，与首个填充位 `1` 组合后，字节级填充首字节为 **`0x06`**；
* **可扩展输出 SHAKE（SHAKE128 / SHAKE256）**：追加后缀位 `1111`，字节级填充首字节为 **`0x1F`**；
* **原始 Keccak 提案（以太坊采用的 `keccak256`）**：无官方域分离后缀，首字节为 **`0x01`**。

### 5. 运行与验证指令

```sh
# 运行默认教学演示（输出 SHA3-256 详细海绵吸收与挤压日志）
python sha3_demo.py

# 指定算法对任意文本计算摘要
python sha3_demo.py --algo sha3-256 --text "The quick brown fox jumps over the lazy dog"
python sha3_demo.py --algo sha3-512 --text "The quick brown fox jumps over the lazy dog"

# 运行可扩展输出函数 SHAKE 并指定输出长度（例如 64 字节）
python sha3_demo.py --algo shake128 --text "abc" --length 64

# 运行全量验证套件（通过 NIST FIPS 202 官方测试、Wikipedia 案例、多块长流挤压与 hashlib 比对）
python verify_sha3.py
```





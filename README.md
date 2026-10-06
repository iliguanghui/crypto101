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

## Argon2 演示与测试向量验证

`argon2_demo.py` 与 `verify_argon2.py` 实现了 RFC 9106 定义的 Argon2 内存硬哈希算法（版本 1.3，`0x13`），包含全部三种变体：
- **Argon2d**（Type 0）：数据依赖寻址，适合抗 GPU 挖矿与不需要防御侧信道计时的场景。
- **Argon2i**（Type 1）：数据无关寻址，适合密码哈希与基于密码的密钥派生（防御基于缓存/计时的侧信道攻击）。
- **Argon2id**（Type 2）：混合模式（第 0 轮前半段采用 Argon2i，其余采用 Argon2d），RFC 9106 首选推荐方案。

仅使用 Python 标准库（`hashlib.blake2b` 与 `math`），无第三方依赖。

```powershell
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

```powershell
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

```powershell
python sha1_demo.py
python sha1_demo.py --text "The quick brown fox jumps over the lazy dog"
python verify_sha1.py
```




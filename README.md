# Blocknet RingCT NIF 原型

面向 Blocknet 当前椭圆曲线交易格式的 Elixir/Rustler 实验项目。基线为官方 core d4c7f78572e5dd637e7f322ea89573b65912e64c；实现 Ristretto255 环签名、Pedersen 承诺、单输出 Bulletproofs，以及 version 1 indexed stealth 支付构造与恢复。本项目不包含矿工或 Faraday 后量子证明。

本地完整 bin/check 已以退出码 0 完成：原生 Rust 7 测试、ExUnit 18 测试、官方 oracle Rust 20 测试、fmt/clippy、固定及 fresh 数据交叉验证均通过，包含 16×16 支付。平台实测和审计告警记录在 [HANDOFF.md](HANDOFF.md)。以下命令是复现入口；尚无 Linux CI 成功记录。源码依据与第三方许可见 [THIRD_PARTY.md](THIRD_PARTY.md)。

## 范围与限制

- 每笔 1..16 输入、1..16 输出；每输入恰好 16 个环成员，真实位置为 0..15。
- RingCT 签名 1120 字节，签名消息恰好 32 字节；单个范围证明最多 1024 字节，raw 最多 131072 字节。
- 支付金额为正 u64，累加检查溢出；fee 必须显式传入非负 u64，并满足输入总额 = 输出总额 + fee。fee=0 的本地接受不代表节点接纳，任何示例 fee 都不是共识最低费声明。
- 只实现 indexed 输出，不处理历史未加 index 的 stealth 派生，也不自动判断激活高度。调用者必须确认目标格式适用。
- 输入、诱饵及其承诺由调用者准备；无节点查询、UTXO 选择或预留、成熟度、链成员资格、已花费状态、重组、广播或 mempool 检查。
- 无地址字符串编解码、助记词或密码到种子的派生、普通 Ed25519/Schnorr 钱包认证、挖矿和 Faraday。

## 构建与检查

需要 OTP 27、Elixir 1.20.5、Rust 1.96.0（rustfmt/clippy）、Go 1.24.12 或更新版本、Python 3、常规 C/链接工具；下载锁定依赖和新鲜审计数据库时需联网。脚本从任意目录进入仓库根目录；Rust、Mix、Hex 缓存默认置于项目内。已有工具可以通过 CARGO_HOME、RUSTUP_HOME、MIX_HOME、HEX_HOME、GO 等环境变量选择，避免重复下载。

~~~sh
bin/run mix deps.get --check-locked
bin/check
bin/audit
~~~

全新环境可先运行项目缓存内的工具准备：

~~~sh
bin/run rustup toolchain install 1.96.0 --profile minimal --component rustfmt --component clippy
bin/run mix local.hex --force
bin/run mix local.rebar --force
~~~

[bin/check](bin/check) 依次核对上游快照/fixture 哈希，检查 Rust 格式与 clippy，运行 release Rust 测试、真实 mix precommit、官方 oracle 的新生成结果验证、一次 benchmark 导出（含一次 16×16 构造）及其独立 Go/Rust 交叉验证，最后再检查快照。不会改写固定 fixture。oracle 细节见 [interop/README.md](interop/README.md)。

[bin/audit](bin/audit) 审计两个 Rust lockfile 及 Hex 锁定依赖。它不安装工具；缺少 cargo-audit、Hex audit 或审计失败都会以非零退出并保存证据，不会静默忽略。可用 ADVISORY_DB 指向由调用者刚更新的 RustSec checkout，此时使用 --no-fetch 并记录 revision；该模式本身不证明数据库新鲜度。Linux CI 定义见 [ci.yml](.github/workflows/ci.yml)，本地存在配置不代表已有远程运行或发布。当前已知 clear_on_drop 0.2.5（经 bulletproofs 5）有 RUSTSEC-2026-0283 维护性告警；零已知漏洞不能写成无告警。

## API

公开入口为 [BlocknetNif](lib/blocknet_nif.ex)。结果为 {:ok, value} 或 {:error, reason}；验证结果可为 {:ok, false}。binary 参数使用原始字节，map 中以 _hex 结尾的字段和环列表元素使用十六进制字符串。

| 函数 | 输入与结果 |
|---|---|
| derive_keys(seed64) | 恰好 64 字节，前/后 32 字节分别是 spend/view seed；结果含 spend_secret_hex、view_secret_hex、spend_public_hex、view_public_hex |
| seeded_secret(seed32) | 单个 32 字节 seed，经官方 SHA-512 域和模约减得到 Ristretto secret binary；不是完整钱包 seed |
| public_key(secret)、key_image(secret) | 32 字节规范非零 secret scalar → 32 字节 binary |
| commitment(amount, blind)、range_prove(amount, blind) | u64 金额和 32 字节 blinding → commitment/proof binary |
| range_verify(commitment, proof) | 32 字节 commitment 与有界 proof → boolean |
| ring_sign(keys, commits, index, secret, blind, pseudo, pseudo_blind, message) | 两组各 16 个 point hex，真实 index，32 字节各秘密/承诺/message → 签名 binary |
| ring_verify(keys, commits, message, signature) | 相同环，32 字节 message、1120 字节 signature → boolean |
| build_payment(view_secret, network, inputs, outputs, fee) | 发送方 32 字节 view scalar、网络、准备好的输入/输出、显式 fee → payment map |
| verify_payment(raw) | raw binary → 密码学验证 boolean，不证明上链可花费性 |
| receive_payment(raw, spend_secret, view_secret, network) | raw 与收款方 32 字节 scalars → 已拥有输出列表 |

network 接受 :mainnet、:testnet 或同名字串。钱包 seed 的 64 字节要求来自官方钱包拆分；此 API 不接受以一个 32 字节 seed 冒充完整钱包种子。

输入 map 的 atom keys：secret_hex、amount、blinding_hex、ring_keys、ring_commitments、real_index。secret 是该真实输入的一次性私钥，blinding 是原始输入 opening；两组环列表必须按对应顺序提供真实链输出公钥/承诺。

输出 map 的 atom keys：spend_public_hex、view_public_hex、amount、memo_hex。memo 最多 124 字节（248 个 hex 字符），所有输出都显式给出；找零同样是调用者提供的输出。

payment 返回 raw_hex、txid、signing_hash_hex、tx_public_hex、fee、bytes。receive 返回 index、amount、memo_hex、memo_valid、secret_hex、blinding_hex；它包含敏感秘密，不应日志输出。无法解密 memo 时保留已确认拥有的资金记录，memo_valid=false、memo_hex 为空；空 memo 的正常解密仍为 memo_valid=true。

network 只参与 memo 加密域：raw 没有网络标识，交易签名不绑定网络。错误 network 仍可能恢复相同金额和一次性私钥，但 memo_valid=false。不得依赖此字段实现跨网络隔离。

## 精确编码规则

SigningHash = SHA3-256(version:u8 || txPublicKey:32 || inputCount:LE32 || outputCount:LE32 || fee:LE64 || serializedOutputs)。每个输出是 publicKey:32 || commitment:32 || encryptedAmount:8 || encryptedMemo:128 || proofLength:LE32 || proof；没有额外域标签，且不包含任何输入字段。RingCT 自身绑定 challenge；验证还核对内嵌与外层 key image/pseudo-output 一致。txid 是完整 canonical raw 的 SHA3-256。

交易 r 和 indexed shared scalar 使用官方 SHA-256 域及低 32 字节零扩展约减。金额加密使用原始 SHA3 blinding 字节；承诺计算才做 scalar 约减，不能互换。范围证明 transcript 为 Blocknet Range Proof。不保证随机证明、签名、memo padding 每次字节相同。

## 安全边界

本项目为原型，尚无生产安全认证。DirtyCpu 调度避免长密码学计算占用普通 scheduler，但不隔离 native abort、OOM 或内存错误；catch_unwind 只处理可展开的 Rust panic。调用者需限制并发和秘密生命周期。

部分 Rust 秘密缓冲/标量采用 Zeroizing；BEAM binary、hex/String 拷贝、哈希内部状态、底层证明库临时值、寄存器和编译器拷贝不保证全部擦除。没有硬件密钥保护或完整侧信道审计。使用合成公开数据的测试不证明真实链输入或节点接纳。

上游 BSD-3-Clause 与本原型 BSD-3-Clause 见 [LICENSE](LICENSE)、[NOTICE](NOTICE)；依赖保留各自许可，不将整个依赖树统一改许可。

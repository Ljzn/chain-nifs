# TensorCash NIF prototype

GitHub私有仓库：[Ljzn/tensorcash-nif](https://github.com/Ljzn/tensorcash-nif)，默认分支develop。

独立 Elixir/Rustler 项目，封装 TensorCash 普通 TSC 的 ML-DSA-65 后量子授权。所有秘密/prevout 都是公开合成测试数据；没有修改 Venezia 业务代码、接入生产节点或广播交易。

## 实现范围

- 固定 FIPS 204 seed32 -> ML-DSA-65 公钥及内部展开私钥；公钥1952bytes，展开私钥4032bytes，原始签名3309bytes。
- 官方钱包 BIP39 seed64 -> HKDF-SHA256 identity/spending seed；包含genesis、account、policyId、branch、index域。API不解析助记词或存储密码。
- Pure ML-DSA、空context、32bytes交易摘要；签名使用fresh系统随机数并自验。随机签名字节不固定。
- 官方 one-leaf **1-of-1** ML-DSA-65 witness-v2地址（mainnet/testnet/regtest：tc/tct/tcrt Bech32m）。
- 普通TSC交易：version2、locktime0、SIGHASH_ALL=01，所有输入属于同一把key的上述地址，所有输出为所选network的v2地址；最多64inputs、16outputs、raw512KiB。
- canonical交易序列化、TapSighash/ML-DSA、见证、txid/wtxid、fee、weight/vsize；本地限定格式解析与完整签名验证。

不支持传统secp输出、不同key混合输入、多签、资产/扩展输出、annex、其他sighash模式或通用脚本VM。verify_payment只验证给定prevout元数据下的格式/授权，不查询UTXO是否存在/已花费、成熟度、链状态或交易是否满足节点relay政策。fee返回值是输入金额减输出金额，不是网络报价或最小手续费判定。serialized raw没有network字段：相同witness program在不同network具有相同脚本/交易字节。build校验输出地址HRP是否匹配所选network；verify_payment只校验合法network参数、脚本格式和授权，不能从raw恢复或证明输出HRP/network。

## 固定上游与构建

- 官方钱包/主仓库：443ebf7ef6a717116ef80f9d6e1f38711905c77a。
- 节点bcore对照版本：38fabe7ed2d5ccec5d303c7a131c87ca3f4a7a52。
- 本项目子模块liboqs：97f6b86b1b6d109cfd43cf276ae39c2e776aed80（0.15.0）。
- Rust1.96.0，Rustler Hex0.37.3 / crate0.37.2；CMake及C编译器；Elixir1.15+，本机OTP27/Elixir1.20.5。

使用项目本地缓存，默认编译static PIC/reference ML-DSA-65并禁用OpenSSL。首次构建：

```sh
git submodule update --init vendor/liboqs
bin/run rustup toolchain install 1.96.0 --profile minimal --component rustfmt --component clippy
bin/run mix local.hex --force
bin/run mix deps.get
bin/run mix compile --warnings-as-errors
ERL_FLAGS="+S 2:2" bin/run mix precommit
bin/run cargo test --manifest-path native/tensorcash_nif/Cargo.toml --locked --lib
bin/run cargo clippy --manifest-path native/tensorcash_nif/Cargo.toml --locked --all-targets --no-deps -- -D warnings
```

bin/run为每次命令设置项目本地RUSTUP_HOME/CARGO_HOME/MIX_HOME/HEX_HOME，并检查liboqs精确版本及tracked/untracked干净。允许显式环境变量覆盖缓存位置；项目构建不依赖相邻research或parano1d目录。上面命令需要置于项目根目录执行。

## Elixir API

返回 {:ok, result} 或 {:error, reason}。Network可以是 :mainnet/:testnet/:regtest 或对应字符串。

verify/3和verify_payment/4的{:ok, true}表示在本地验证范围内有效；{:ok, false}表示验证未通过，例如长度正确的无效签名。verify_payment对可继续解析的prevout/sequence/见证内容不匹配或缺失签名可返回false，但false不承诺完成所有解析检查。格式、长度、限额、解析或结构性元数据问题返回{:error, reason}；金额不合法、合计超限、输出超过给定输入金额，以及某些结构性见证/元数据不匹配均可能是error。有效范围内的输入金额改变通常导致摘要验签false，不能假定所有金额或prevout不匹配都返回false。调用方必须分别处理true、false、error。

- TensorCashNif.public_key(seed32)
- TensorCashNif.sign(seed32, digest32)
- TensorCashNif.verify(public_key1952, digest32, signature3309)
- TensorCashNif.identity_seed(bip39_seed64, genesis32, account_u32)
- TensorCashNif.spending_seed(bip39_seed64, genesis32, account_u32, policy_id32, branch_0_or_1, index_u32)
- TensorCashNif.derive_address(public_key1952, network)
- TensorCashNif.unsigned_payment(public_key1952, network, inputs, outputs)
- TensorCashNif.build_payment(seed32, network, inputs, outputs)
- TensorCashNif.verify_payment(raw_binary, public_key1952, network, inputs)

输入maps：%{txid: display_order_hex64, vout: u32, amount: integer_sats, sequence: u32}。输出maps：%{address: canonical_address, amount: integer_sats}。字段必须为atom keys。genesis32的字节序使用官方钱包genesis hex直接解码，不自行reverse；txid字段是浏览器显示序，wire编码会反转。地址生成结果含address/script_pubkey_hex/leaf_script_hex/control_block_hex/output_key_hex/leaf_hash_hex。

所有输入/输出amount必须严格为正整数sats，单项和输入/输出各自合计不得超过MAX_MONEY=2_100_000_000_000_000。拒绝零值amount是本原型限制；固定Core版本38fabe7ed2d5ccec5d303c7a131c87ca3f4a7a52的src/consensus/amount.h中MoneyRange允许0。MAX_MONEY与该版本amount.h的21000000 * COIN一致，是金额范围sanity bound，不是对TensorCash发行总量的声明。输入总额等于输出总额时fee=0允许；这不代表节点dust/最低费率/relay政策会接纳。

sequence接受任意u32整数（0..0xFFFFFFFF）；示例0xFFFFFFFD不是强制值。sequence被序列化并承诺进签名摘要，verify会对照给定值；本地验证不检查BIP68相对锁定成熟度或RBF政策。

Payment含unsigned_hex/raw_hex/txid/wtxid/fee/weight/vsize/digests；hex均小写。传给verify_payment前用 Base.decode16!(payment.raw_hex, case: :lower) 转成binary。重复签名同一笔交易的txid固定、wtxid通常不同。unsigned_payment的weight/vsize是实际未签名数据的大小，不可用作最终手续费预算；signed build返回实际见证weight。

交易草案输入示例（仅格式示意，不是链上可花费数据）：

    seed = :binary.copy(<<7>>, 32)
    {:ok, pk} = TensorCashNif.public_key(seed)
    {:ok, own} = TensorCashNif.derive_address(pk, :regtest)
    inputs = [%{txid: String.duplicate("11", 32), vout: 0, amount: 100_000, sequence: 0xFFFFFFFD}]
    outputs = [%{address: own.address, amount: 90_000}]
    {:ok, signed} = TensorCashNif.build_payment(seed, :regtest, inputs, outputs)
    {:ok, true} = TensorCashNif.verify_payment(Base.decode16!(signed.raw_hex, case: :lower), pk, :regtest, inputs)

## 独立互操作验证

interop/oracle里14个官方TypeScript模块逐字节保留，source-manifest记录hash及原始路径；使用官方noble/post-quantum0.7.1及锁定npm依赖。详见interop/README.md及THIRD_PARTY.md。

    cd interop
    npm ci --cache .npm-cache --ignore-scripts --no-audit --no-fund
    npm run check

fixture含2组seeded公私钥、4组显式随机数签名、官方HKDF、6组地址、3个network的2in2out完整交易；另保留官方Core捕获签名和NIST ACVP子集。Rust逐字节比较公钥、展开私钥和显式rnd签名；ExUnit通过真实NIF核验官方交易，也对Native直接入口进行畸形输入测试。

    ERL_FLAGS="+S 2:2" bin/run mix run bench/run.exs
    npm --prefix interop run --silent crossverify < results/generated/native-sample.json
    ERL_FLAGS="+S 2:2" bin/run mix run bench/reload.exs

bench/run.exs先创建目录，默认只写ignored的results/generated/benchmark.json和results/generated/native-sample.json，不覆盖tracked历史快照。需要旧路径兼容副本时，为benchmark命令设置TENSORCASH_NATIVE_LOCAL_COMPAT=1，另写ignored的interop/native.local.json。从项目根重放历史签名/交易快照（不重新生成签名）：

    npm --prefix interop run --silent crossverify < results/native-sample.json

crossverify使用官方钱包解析器/两套摘要路径/MLDSA验签，验收NIF产生的随机签名及完整交易，而非同一NIF自验。正常reload测试不是native崩溃恢复承诺。性能结果保留在results，实际本机结果见下文；[CI说明](CI.md)记录本机验证与已通过的远程Linux运行。

## 本机实测

Apple M2 / 8GiB，release NIF，BEAM普通/dirty CPU scheduler各2。原语31样本，交易每形状5样本，下表为中位数，单次任务顺序执行：

| 操作 | 耗时 | 完整交易bytes |
|---|---:|---:|
| seed32派生公钥 | 0.139 ms | — |
| 签名（含keygen和自验） | 0.820 ms | — |
| 独立验签 | 0.145 ms | — |
| 1input / 2outputs 构造+签名+自验 | 1.060 ms | 5,465 |
| 2inputs / 2outputs 构造+签名+自验 | 1.753 ms | 10,832 |
| 64inputs / 2outputs 构造+签名+自验 | 46.177 ms | 343,586 |

64inputs完整独立验证中位9.123ms。整个基准BEAM峰值RSS107,167,744bytes（102.20MiB）；macOS另报footprint94,519,920bytes（90.14MiB），包含BEAM/fixtures/JSON/64input交易分配，不是每次签名增量。签名拒绝采样导致耗时变化，31次实测0.488–1.622ms。本次没有持续内存增长/生产并发压测。

8份fresh NIF签名及1笔fresh2in2out完整交易已由独立官方钱包代码验证通过。Bob review修复后Rust11项、ExUnit33项（含并发、identity派生与1×16/64×16最大形状）、mix precommit及warnings-as-errors编译均已通过；完整交接记录于[HANDOFF](HANDOFF.md)。没有节点接纳验证；benchmark的固定10,000sat fee是合成差额，尤其64input时不代表满足网络最低费率。

历史快照（保持tracked，不由新benchmark重写）：[benchmark](results/benchmark.json)、[RSS/时间](results/time.txt)、[官方交叉验签](results/crossverify.json)、[reload](results/reload.txt)。

修复commit14b77dd的[Linux x86-64 CI](https://github.com/Ljzn/tensorcash-nif/actions/runs/42822439599)已全部通过，包含Rust/真实NIF测试、官方oracle及最大形状交叉验证、reload和Cargo/Hex/npm审计。运行保留linux-validation artifact30天，含审计报告、fresh样本及交叉验证结果。历史M2性能快照不是Linux性能数据。

## Native边界与秘密

所有计算NIF均DirtyCpu，不在普通scheduler执行密码学。没有额外Rayon/OpenMP工作线程或全局证明门闩；并发由BEAM dirty scheduler和调用方有界队列控制。Direct Native也在分配前限制列表、binary字段及raw长度，拒绝improper lists/超限。

liboqs公开接口没有seed参数，且普通randombytes失败路径可能exit。项目的adapter.c沿用固定版本reference KeyGen_internal，显式seed参数；signing_workspace.c复制固定reference签名函数，仅重命名及清理主工作区，使用Pure前缀{0,0}及Rustgetrandom显式rnd。没有修改vendor、没有切换全局RNG；随机源失败从Rust返回普通error。本项目不提供任意展开私钥签名NIF，避免非规范SK进入拒绝采样循环。

Rust秘密工作缓冲使用Zeroizing；固定32bytes HKDF使用显式清理pads/root/inner/output及启用zeroize的SHA256状态，RFC5869和官方派生向量守护语义。C KeyGen/sign主工作区显式cleanse。这是尽力清理，不保证所有嵌套上游临时副本、CPU寄存器、BEAM binary和调用方副本均擦除。

Rust unwind返回稳定native panic错误并建议重启BEAM；无法捕获C abort/exit、内存破坏或OOM。若生产必须隔离这些故障，应把相同接口放进独立port/worker。本原型未宣称生产安全审计、恒定时间证明或全平台支持。

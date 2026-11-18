# Parano1d Rustler NIF 验证项目

现位于公开独立 monorepo [Ljzn/chain-nifs](https://github.com/Ljzn/chain-nifs) 的 nifs/parano1d；统一入口及当前 CI 见 [根目录说明](../../README.md)。项目验证在 BEAM 内调用官方 Rust 库生成普通 NOID 支付的 V4 所有权证明。原型使用合成测试数据，未接入生产钱包或广播接口。

## 固定来源与构建

- 官方源码：[Parano1d f47f386c842ab60d65b70351b0a5b2729f1d9179](https://git.parano1d.org/ignotusnemo/parano1d/commit/f47f386c842ab60d65b70351b0a5b2729f1d9179)，workspace 2.1.1，Apache-2.0。
- 官方依赖以 Git 子模块保存在 `vendor/parano1d`，固定到上述提交，不修改官方代码。
- Rust 1.96.0、Rustler 的 Hex 包 0.37.3 / Rust crate 0.37.2；Rust / Hex 依赖版本由各自 lock 文件固定。两端包的发布版本并非完全一致，Hex 未发布 0.37.2。
- 原生库使用 release、Thin LTO、unwind；不设置 `target-cpu=native`，由官方库运行时选择 CPU 后端。
- ARM64 要求 NEON + PMULL；x86-64 要求 SSE4.1 + PCLMULQDQ。每个计算入口调用官方硬件检查。

先克隆完整项目，再从项目目录执行：

```sh
git clone --branch develop --recurse-submodules https://github.com/Ljzn/chain-nifs.git
cd chain-nifs/nifs/parano1d
# 已有普通 clone 可以补取依赖：
git submodule update --init --recursive
```

```sh
# 初次准备，工具链及依赖缓存放在项目内
RUSTUP_HOME="$PWD/.rustup" CARGO_HOME="$PWD/.cargo-cache" \
  rustup toolchain install 1.96.0 --profile minimal --component rustfmt,clippy
bin/run mix deps.get

# 两个普通 scheduler 足以测试证明期间的 BEAM 响应
ERL_FLAGS="+S 2:2" bin/run mix precommit
bin/run cargo fmt --manifest-path native/parano1d_nif/Cargo.toml --check
bin/run cargo clippy --manifest-path native/parano1d_nif/Cargo.toml --locked --all-targets --no-deps -- -D warnings
bin/run cargo test --manifest-path native/parano1d_nif/Cargo.toml --locked --lib
```

`bin/run` 会进入项目目录，设置本地工具链 / Cargo / Hex 缓存，并拒绝不是指定提交或存在 tracked 修改的上游源码。首次 Rust release 编译需要时间；后续运行复用构建产物。

官方依赖通过 `git submodule update --init --recursive` 恢复，构建所需上游源码由固定子模块提供。不要将相同 32 字节同时当作钱包 master secret 与本接口 SpendSecret：官方 master 还会经过索引派生，两者生成的地址不同。

## 接口

```elixir
secret = :crypto.strong_rand_bytes(32)
{:ok, owner} = Parano1dNif.derive_address(secret)

# 仅展示字段；这些输入和槽位不是实际链上资金。
request = %{
  owner: owner,
  epoch_anchor: :binary.copy(<<3>>, 32),
  fee: 6_000,
  inputs: [%{slot_index: 10, amount: 100_000, creation_id: 42}],
  outputs: [%{slot_index: 20, amount: 94_000, owner: owner}]
}

{:ok, unsigned} = Parano1dNif.build_transaction(request)
{:ok, authorized} =
  Parano1dNif.authorize_transaction(unsigned.raw_transaction, secret, 4)
{:ok, verified} = Parano1dNif.verify_transaction(authorized.raw_transaction, 4)
true = verified.txid == unsigned.txid
```

返回值为 `{:ok, artifact}` 或 `{:error, reason_string}`。artifact 包含完整二进制 `raw_transaction`、小写十六进制 `txid`、owner、epoch anchor、输入、输出、手续费、页数、授权字节数和授权版本。未授权交易的版本字段为 `0`，已验证授权为 `4`。RPC 提交所需 hex 应由调用方编码，接口本身不联网。

## 原型边界

- 只支持 V4、普通支付、1..64 个输入、1..2 个输出、最多 8 页。明确拒绝 coinbase / 合约标记；这不是链的完整容量上限。
- 输入必须属于同一 owner。调用方负责获取实际输入、creation_id、空输出槽位、当前 anchor 与费用，并核对审批过的收款人、金额及找零。
- 使用官方 `TxPage` / `PagedSpendIntent` codec、canonical validation、Poseidon2b txid 和完整授权证明验证器。证明生成后先完整自验才返回。
- 输入输出金额、重复/重叠槽位、空 dummy、页边界等由官方 canonical validator 验证。地址要求规范小写 Bech32m。即使绕过 Elixir wrapper 直接调用 Native，Rust 也先检查借用的二进制长度和最多 65 个列表单元，再进行有界分配。
- `verify_transaction` 只验证交易格式、公有算术与所有权授权。它不证明输入尚未花费、输出槽位仍空、anchor 新鲜、节点费用足够、链身份正确或会被节点接纳。
- 当前 V4 校验没有接受 V3 降级选项；后续接节点应根据可信候选高度规则选择支持版本，而不是相信远端参数。

## 验证和测量

真实 NIF 回归覆盖 1 / 2 / 9 / 64 个输入（最多八页、两输出）生成和完整验证、收款人/输入/金额/费用/anchor/owner 被修改时拒绝旧证明、证明破损/截断/尾部数据、随机化证明保持 txid、精确 little-endian wire 布局、直接 Native 大输入限制、并发拒绝及普通 scheduler 的消息响应。

在本目录复现资源测量和卸载测试：

```sh
bin/run mix compile --warnings-as-errors
mkdir -p results
ERL_FLAGS="+S 2:2" bin/run mix run --no-compile bench/reload.exs
ERL_FLAGS="+S 2:2" bin/run /usr/bin/time -l \
  mix run --no-compile bench/run.exs results/benchmark.json \
  > results/benchmark.stdout.json 2> results/time.txt
```

`reload` 只能在独立测试 BEAM 内运行，它主动删除 Native 模块、soft purge、确认旧代码已清除，再重新加载，连续三轮验证先前证明。这些结果仅验证独立 BEAM 中的正常卸载与重载行为。

基准每种形状只测首次和一次热调用，不提供 p95 或吞吐量结论。`authorize` 包含完整自验。每次 scoped pool 的创建和 join 也包含在耗时内。BEAM memory 不包含所有 Rust 分配，因此整体内存以 macOS `time -l` 的 maximum resident set size 为准；本环境 `ps` 无法取得自身 RSS，JSON 中相应字段为 null。其他操作系统的 peak RSS 命令与计量单位需对应调整。

## 本机实测结果（2026-11-10）

Apple M2 / 8 GiB RAM / macOS Darwin 25.6.0 / Elixir 1.20.5 / OTP 27，release NIF，2 个普通 scheduler、2 个 dirty CPU scheduler，每次计算 2 个 scoped Rayon 线程、并发上限 1。

| 输入 / 输出 / 页 | 首次授权（含自验） | 第二次授权（含自验） | 首次 / 第二次验证 | 首次完整交易字节 | 首次授权组件字节 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 / 1 / 1 | 1326 ms | 1943 ms | 61.0 / 41.5 ms | 89,934 | 89,604 |
| 2 / 1 / 1 | 1206 ms | 1133 ms | 38.3 / 38.8 ms | 90,478 | 90,148 |
| 9 / 2 / 2 | 1630 ms | 1420 ms | 38.8 / 38.5 ms | 90,865 | 90,212 |

每种形状两次样本；第二次不保证比首次快。随机证明长度也可能变化，表中是首次调用结果。整体进程 peak RSS 为 86,818,816 bytes（82.80 MiB），macOS 另报 peak memory footprint 为 106,218,072 bytes（101.30 MiB），包含 BEAM / NIF / 运行时，不是单独 prover 的增量内存。

初版基准提交（3b281c2）验证：13 项 ExUnit 测试全部通过；`mix precommit`、`mix compile --warnings-as-errors`、Cargo fmt 和 Clippy `-D warnings` 通过；独立 BEAM 内三轮 prove → unload → reload → verify 全部通过。证明运行期间完成 100 次普通进程消息握手；重叠证明请求返回 busy，测得该请求 224 μs 返回，后续两次验证均通过，门闩正常释放。

原始数据保留在 `results/benchmark.json`、`results/time.txt`、`results/host.txt` 和 `results/reload.txt`。只使用合成秘密与槽位，不代表链上交易可被接纳；尚未做真实节点联调、长期并发压测、Linux/x86 构建验证（新增 CI 后以远程 run 为准）。64 输入现已纳入自动完整证明回归，但尚无对应性能基准。

## Review 修复验证

本次本机回归：18 项 ExUnit 和 4 项 Rust 单元测试通过，包含 64 输入/两输出完整证明、248 个畸形容器用例、busy 优先于解码、普通 Err 释放锁、持锁/真实 scoped worker panic 后明确 faulted 且不重试。Clippy all-targets、编译/测试 warnings-as-errors 通过；正常路径的独立 BEAM 三轮 unload/reload 验证通过。panic 注入只在 Rust 单元测试的独立 gate 实例中执行，不提供生产 NIF 注入入口。

GitHub Actions 已配置 Linux x86-64 的真实 NIF 验证及锁文件审计。详细步骤和证据边界见 [CI.md](CI.md)，远程结果以对应 commit 的 run 为准。

## 调度、资源与秘密

地址、构造、证明、验证均标记 `DirtyCpu`。证明和验证共用一个 native `try_lock` 门闩，繁忙返回 `{:error, "busy"}`，不在 native 中无限排队；官方并行计算在独立、固定两个线程的 scoped Rayon pool 内执行。每次证明或验证结束前都会关闭线程池并 join 所有工作线程，避免模块卸载时遗留 native 线程。授权/验证在交易容器解码前获取准入锁，页数在官方解码前限为 1..8。版本、二进制类型/长度等廉价检查仍可先于准入；因此繁忙时 wrapper 合法但内容畸形的请求返回 busy，空闲时返回解析错误。

`proof_status/0` 返回字符串 `"idle"`、`"busy"` 或 `"faulted"`，只反映当前准入锁快照，不是预留或完整健康检查。`proof_busy?/0` 仅在 busy 时为 true，faulted 为 false，调用方不能用 false 判断可服务。`limits/0` 提供 wrapper 限制，与 Native 限制的回归比较防止两侧漂移；地址长度统一为 3..100 字节，仍须满足 canonical Bech32m。

调用方需有界队列和持久化任务策略。busy 是暂时冲突，可按有界退避策略重试；输入/证明校验错误不能盲目重试；faulted 为终止故障，应告警并重启宿主 BEAM，不能继续排队尝试。BEAM 调用方超时或死亡不会可靠中断正在运行的 dirty NIF，超时后不得立即并行重试同一任务，应等待原任务结果并核对 txid/持久化状态；本原型没有强制取消或异步证明任务接口，具体队列容量和业务重试策略由集成层决定。

Rust 的秘密工作缓冲使用 `Zeroizing`，官方 `SpendSecret` / witness 在释放时零化。Elixir 原始 binary 及其他副本不会因此被清除。不会把秘密写入日志或文件；测试中所有秘密都是公开的合成数据。

NIF 边界捕获 Rust unwind 并返回稳定错误；无法隔离 native 内存错误、abort 或 OOM。持有准入锁期间 panic 会毒化门闩：首次返回 `native panic; restart the BEAM before retrying`，后续授权/验证返回 `faulted; restart the BEAM before retrying`。不会自动清 poison、不会自动重试，也没有暴露生产 panic 注入接口。必须重启宿主 BEAM，不能只重启 Elixir Task，也不将模块 reload 作为故障恢复契约；锁未持有时的 panic 不保证反映在准入状态，任何 native panic 都要求重启。官方 panic hook 仍可能向 stderr 输出诊断，因此生产还需要日志审查与额外稳定性验证。

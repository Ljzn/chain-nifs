# Blocknet NIF 原型交接

## 当前状态

当前仅本地实验仓库，尚未发布 GitHub，未执行节点广播。CI 配置是未来 Linux 检查入口，不代表已有 GitHub Actions 成功记录。

官方基线：blocknetprivacy/core d4c7f78572e5dd637e7f322ea89573b65912e64c。许可：BSD-3-Clause，见 [LICENSE](LICENSE)、[NOTICE](NOTICE)、[THIRD_PARTY.md](THIRD_PARTY.md)。

## 已提供的接口与范围

[Elixir API](lib/blocknet_nif.ex) 提供钱包 64 字节种子拆分、Ristretto 公钥/key image、Pedersen 承诺、Bulletproofs、16 成员 RingCT，以及 indexed version 1 支付构造/验证/恢复。支付最多 16 输入和 16 输出，128 KiB raw。接口字段、精确 hash 和限制见 [README.md](README.md)。

无历史 unindexed 钱包派生、地址/助记词层、节点/UTXO 状态、诱饵链成员核查、矿工或 Faraday。fee 显式指定，不能将原型约束解释为共识最低费。network 只参与 memo；raw 不绑定网络，错误 network 仍可能恢复资金，memo_valid 标记解密状态。

## 复现入口

~~~sh
bin/run mix deps.get --check-locked
bin/check
bin/audit
~~~

[bin/check](bin/check) 包含 Rust fmt、release clippy -D warnings、release cargo test、test 环境 mix precommit（强制重编译与测试均 warnings-as-errors）、固定和新生成官方 oracle 校验、原生 benchmark 导出及 Go/Rust crossverify、前后快照 hash。benchmark 包含一次 16×16 构造，其余迭代按脚本默认设置。所有 seed/UTXO 是合成公开数据。

[bin/audit](bin/audit) 不安装工具；已有 cargo-audit 可通过 PATH 指定。本地可复用 ../parano1d_nif/.cargo-cache/bin/cargo-audit，将该目录加入 PATH 后执行 bin/audit，无需新安装。缺少工具、数据库访问失败或审计失败会非零退出，证据默认在 results/generated/audit。工具准备和 CI 的安装步骤需由实际执行者明确执行，不会自动写入用户 home。

## 本轮 review 修复与验收结果

- 收款策略：整笔交易先验证；单个 owned output 的金额 opening 与承诺不匹配时跳过并继续，保留其他正常输出。opening 匹配的零金额输出仍恢复；坏 memo 保留资金并标记 memo_valid=false。
- 构造策略：build_payment 在每个输入内拒绝重复 ring 公钥；不单独要求 commitment 唯一，也不改变 parse/verify 的协议接受规则。
- warning gate：bin/check 固定 MIX_ENV=test，mix precommit 依次执行格式检查、mix compile --force --warnings-as-errors 和 mix test --warnings-as-errors。强制重编译覆盖应用与 test/support，避免缓存掩盖编译 warning。benchmark 先 Code.ensure_loaded?，仅在 helper 尚未加载时 require，避免 test 环境重复定义模块。
- range_verify、verify_payment 和 receive_payment 依赖 OS entropy：Bulletproofs 对单 proof 的多个验证等式也采用随机系数合并；熵失败返回错误。保留当前随机 verifier RNG，不改用固定 seed。
- Red/green：新增 5 项真实 NIF 对抗回归，修复前 3 项按预期失败（坏 opening、有效零金额、重复诱饵），修复后全部通过；不是仅篡改后验签失败。坏输出位于首/中/尾以及全部无效、坏 memo、重复 decoy、重复 commitment 均有明确断言。
- 完整 bin/check 退出 0：原生 Rust 10 项、官方 Rust 20 项、ExUnit 23 项；fmt、release clippy -D warnings、强制编译和测试 warnings-as-errors 均通过。日志 results/generated/review-check.log 与 benchmark.txt 无 warning。固定及 fresh oracle（1 case/1 payment）、fresh native（1 case/4 payments，含 16×16）交叉验证通过，来源前后 16 项均通过。
- 新增 bin/fuzz：默认 256 样本/768 次直接 Native 调用，seed=20261111。独立静态复核提出返回断言过宽的问题后，已加强为按 API 检查类型，并强制截断/尾随/超长/非法计数等结构被拒绝；加强后单独重跑 bin/fuzz 与 mix precommit 均退出 0。此入口仅有界变异检查，未声称覆盖率导向 fuzz、Miri、ASan 或长期压力。
- 依赖审计刷新数据库后重跑 bin/audit 退出 0：native/oracle 各 61 依赖、0 已知漏洞、ignore=[]，仅保留 clear_on_drop 0.2.5 未维护告警；Hex 无 retired/security advisory。来源与固定 fixture 均未变更。
- 独立静态复核未发现核心修复的其他功能/安全问题；未构成完整密码学审计。以下 7/20/18 与性能数据保留为初始版本历史证据。

## 初始版本验证证据

- 初始已验收实现提交：98d50b9a594e0dc1122047a1d9d2d19a0895cf9c（develop），初始交接 HEAD 为 cf802bd521def3b4fd7f7bf3d8c27aaa6ad1ab94。本轮 review 修复的最终提交与 dirty 状态待主维护者验收后记录。
- 主维护者完整执行 [bin/check](bin/check)，退出码 0；Rust fmt、release clippy -D warnings、原生 release Rust 7 测试、官方 oracle Rust 20 测试和 mix precommit / ExUnit 18 测试均通过。oracle 固定 rand 0.8.8。
- 前后来源/fixture snapshot 均为 16 项并通过；固定 fixture 的独立 Go/Rust 校验通过。
- fresh 官方生成数据通过：1 个环签名 case、1 笔 payment；结果在 results/generated/fresh-oracle-crossverify.json。
- fresh 原生导出经独立官方 Rust 验签/恢复及 Go wire 比较通过：1 个环签名 case、4 笔 payment，覆盖 1×2、2×2、16×2、16×16；结果在 results/generated/native-crossverify.json。
- 16×16 最大 shape 构造、密码学验证及接收恢复完成；memo_valid 与错误网络/输入边界的本地回归属于已通过的 ExUnit 套件。
- 主维护者另行执行 3 次全新普通 BEAM 进程启动及 NIF 加载，均通过。
- Linux CI 未执行，尚无 GitHub Actions 成功记录。上述结果仅是本地 macOS ARM64 证据。


## 初始版本资源实测

测量命令为 BLOCKNET_BENCH_MAX=1 bin/run mix run --no-compile bench/run.exs。主维护者在空闲、无并发 oracle 编译状态测量：Apple M2，macOS 26.6.2，OTP 27 / ERTS 15.2.7.8，Elixir 1.20.5，Rust 1.96.0。常规项 3 次中位数，16×16 只测 1 次。单位 ms。

| 操作 | 时间 |
|---|---:|
| ring sign（含自验） | 8.033 |
| ring verify | 3.978 |
| range prove / verify | 13.997 / 3.183 |

| 支付 shape | build | verify | raw 字节 |
|---|---:|---:|---:|
| 1×2 | 47.907 | 10.570 | 4017 |
| 2×2 | 60.393 | 14.481 | 6233 |
| 16×2 | 233.991 | 71.657 | 37257 |
| 16×16（1 次） | 470.706 | 114.950 | 49521 |

测量只反映当前机器、合成数据和构造，不推导节点吞吐、网络接纳或生产容量。固定历史数据见 [macOS ARM64 reference](results/macos-arm64-reference.json) 与 [reference time](results/macos-arm64-reference-time.txt)。整条 BEAM benchmark 命令峰值 RSS 为 117506048 字节（112.06 MiB），峰值 memory footprint 为 105464456 字节；这些不是单次 NIF 的内存增量。bin/check 会产生新的独立测量，不覆盖历史 reference，也不保证复现相同数值。

## 已有依赖审计

主维护者已执行 bin/audit，退出码 0。cargo-audit 0.22.2 对原生和 oracle 两个 lockfile 各审计 61 依赖：均为 0 已知漏洞，唯一告警为 clear_on_drop 0.2.5 经 bulletproofs 5 引入的 unmaintained RUSTSEC-2026-0283，ignore=[]。不能将此结论写成无告警或生产安全认证。Hex 检查无 retired/security advisory。

RustSec 数据库为本轮新鲜 checkout，commit 28d73fc95e5972af3403225a217def57dcaba3c4，1446 条，更新时间 2026-11-10T14:45:03+01:00；通过 ADVISORY_DB 显式使用并保存 git revision。证据由脚本保存在 results/generated/audit。oracle 旧 rand 0.8.5 已升级至 0.8.8，不再有 RUSTSEC-2026-0097 unsound 告警；升级后 20 项官方 Rust 测试及固定 helper/provenance 复验通过。

显式传 ADVISORY_DB 时记录其 revision 并 --no-fetch；必须由执行者确认该 checkout 已及时更新，不能将旧缓存或工具缺失当作当前零漏洞。

## 风险与下一步

DirtyCpu 不是进程隔离；native abort/OOM 不由 catch_unwind 保证恢复。部分缓冲采用 Zeroizing，但 BEAM binary、String、底层库临时值和寄存器等不能保证全清理。无完整侧信道、安全认证、sanitizer/长期压力或真实节点接纳结论。

上线前仍需独立代码审查、边界 fuzz、资源/并发压力、完整秘密生命周期检查，以及正确网络和真实链 UTXO 上的节点验收。任何新增链查询、钱包状态持久化、发布或广播都应由主任务另行定义范围。

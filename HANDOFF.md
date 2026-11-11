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

[bin/check](bin/check) 包含 Rust fmt、release clippy -D warnings、release cargo test、mix precommit、固定和新生成官方 oracle 校验、原生 benchmark 导出及 Go/Rust crossverify、前后快照 hash。benchmark 包含一次 16×16 构造，其余迭代按脚本默认设置。所有 seed/UTXO 是合成公开数据。

[bin/audit](bin/audit) 不安装工具；已有 cargo-audit 可通过 PATH 指定。缺少工具、数据库访问失败或审计失败会非零退出，证据默认在 results/generated/audit。工具准备和 CI 的安装步骤需由实际执行者明确执行，不会自动写入用户 home。

## 验证证据

- 已验收实现提交：98d50b9a594e0dc1122047a1d9d2d19a0895cf9c（develop）。其后仅追加本交接中的提交标记；最终 HEAD 见 git log，交付时工作区 clean。
- 主维护者完整执行 [bin/check](bin/check)，退出码 0；Rust fmt、release clippy -D warnings、原生 release Rust 7 测试、官方 oracle Rust 20 测试和 mix precommit / ExUnit 18 测试均通过。oracle 固定 rand 0.8.8。
- 前后来源/fixture snapshot 均为 16 项并通过；固定 fixture 的独立 Go/Rust 校验通过。
- fresh 官方生成数据通过：1 个环签名 case、1 笔 payment；结果在 results/generated/fresh-oracle-crossverify.json。
- fresh 原生导出经独立官方 Rust 验签/恢复及 Go wire 比较通过：1 个环签名 case、4 笔 payment，覆盖 1×2、2×2、16×2、16×16；结果在 results/generated/native-crossverify.json。
- 16×16 最大 shape 构造、密码学验证及接收恢复完成；memo_valid 与错误网络/输入边界的本地回归属于已通过的 ExUnit 套件。
- 主维护者另行执行 3 次全新普通 BEAM 进程启动及 NIF 加载，均通过。
- Linux CI 未执行，尚无 GitHub Actions 成功记录。上述结果仅是本地 macOS ARM64 证据。


## 已有资源实测

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

# 第三方来源与许可

## 官方 Blocknet 基线

来源：[blocknetprivacy/core](https://github.com/blocknetprivacy/core/tree/d4c7f78572e5dd637e7f322ea89573b65912e64c)，固定 commit d4c7f78572e5dd637e7f322ea89573b65912e64c。上游是 BSD-3-Clause，Copyright (c) 2026, Blocknet。原型新代码同样采用 BSD-3-Clause；此选择不改变依赖自己的许可。

[LICENSE](LICENSE) 保留上游条款和版权并加入原型贡献者版权，[NOTICE](NOTICE) 记录改编来源；[原始上游许可](interop/official-rust/LICENSE.upstream) 按原样保存。源码改编与 oracle 复制不能被描述为全部原创或统一 MIT。

原生实现依据官方 crypto-rs/src/{ring,stealth,commitment,rangeproof}.rs，以及 wallet/{builder,scanner,memo,mnemonic}.go 和 protocol/params 的格式/派生规则，重写为有界 Rust API。没有包含 core 的 PoW kernel、Go runtime、节点、矿工或 Faraday 实现。

[oracle 说明](interop/README.md) 记录独立验证路径：[来源清单](interop/SHA256SUMS.json) 标注 exact-file、保留函数体的 extract 和本地 wrapper/artifact 的区别。Rust oracle 保存官方五个 Rust 模块；Go oracle 保存官方 memo/network 等文件及 seed/blinding/amount 函数提取。两个交易 wire parser 为本地独立实现，不能称为直接调用官方完整钱包或节点。

~~~sh
bin/run python3 interop/verify_provenance.py
# 有完整基线 checkout 时还可逐项对照原始来源：
bin/run python3 interop/verify_provenance.py ../blocknet-core-research
~~~

无参数检查本地清单及 fixture SHA-256；带参数同时核对上游 commit、整文件及函数原始行范围。上游 core 没有提供 Cargo.lock；oracle 自己锁定兼容依赖解析，不能称为复现了上游不存在的锁文件。

## 构建依赖

原生 Rust lockfile 位于 [Cargo.lock](native/blocknet_nif/Cargo.lock)，oracle 独立 lockfile 位于 [oracle Cargo.lock](interop/official-rust/Cargo.lock)。Rustler、curve25519-dalek、Bulletproofs、Merlin、rand、SHA-2/SHA-3、zeroize 及传递包保留各自许可证。具体使用版本以锁文件为准；manifest 范围不是完整依赖审计结果。发布二进制前需汇总最终解析依赖的许可文本，不将本页视为完整二进制分发许可包。

Elixir 使用 Rustler 与 Jason；Jason 同时是 Rustler 构建链依赖，不能仅因业务逻辑未调用就宣称运行依赖已去除。Hex 的实际版本以 [mix.lock](mix.lock) 为准。

主维护者已报告原生依赖审计存在维护性告警 RUSTSEC-2026-0283：clear_on_drop 0.2.5 经 bulletproofs 5 引入。它与已知漏洞计数为零可以同时成立，不能称为无告警或完整安全认证；没有设置忽略项，具体最终证据见 [HANDOFF.md](HANDOFF.md)。

Go oracle 使用标准库独立 module；本项目不需要 Node/npm。Go/Rust/OTP 等工具链保留自己的分发许可。来源哈希验证、漏洞审计与许可证合规检查是不同任务。[bin/audit](bin/audit) 不会把审计工具缺失或数据库下载失败解释为零漏洞。

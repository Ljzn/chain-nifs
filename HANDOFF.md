# Chain NIF monorepo 交接

## 状态与边界

私有仓库 [Ljzn/chain-nifs](https://github.com/Ljzn/chain-nifs)，开发分支 develop。本地位于 Alice/_local/chain_nifs。三个原仓库继续保留；精确来源和无 squash subtree 导入记录见 [MIGRATION.md](MIGRATION.md)。

三个独立 Mix/Rustler 项目位于 nifs/parano1d、nifs/tensorcash、nifs/blocknet。保留原 API、Rust/Hex/npm lockfile 和许可，不建立 umbrella 或统一 Cargo workspace。协议源码、固定 fixture 与官方来源未改变。唯一子项目脚本调整是 Parano1d bin/run 允许外部缓存环境覆盖，默认仍为项目本地。

## 统一入口

~~~sh
git submodule update --init --recursive
bin/setup all
mix precommit
# 可单独执行 bin/check parano1d / tensorcash / blocknet
bin/run blocknet cargo install cargo-audit --version 0.22.2 --locked
export PATH="$PWD/.cache/cargo/bin:$PATH"
bin/audit all
~~~

根 bin/run <项目> <命令...> 切换项目目录；其他入口接受 all 或单项目。共享 .cache/{cargo,rustup,mix,hex,npm}；构建 target、Mix _build/deps、generated 结果各自独立。直接子项目入口依旧可用。

## 本轮迁移验收

- 三个来源提交均通过 git merge-base --is-ancestor，历史完整可达；源 SHA 和导入提交见 MIGRATION。
- 根 .gitmodules 登记两份公开官方源码：Parano1d f47f386c842ab60d65b70351b0a5b2729f1d9179、liboqs 97f6b86b1b6d109cfd43cf276ae39c2e776aed80，均 clean。嵌套注册已移除；本地 reference 加速后已 repack 并清空 alternates，两个模块 fsck --connectivity-only 通过，不依赖原仓库对象库。
- 真实 bin/setup all exit0；根格式检查、四个 shell 的 sh -n、非法项目/路径选择拒绝均通过。
- 真实根 mix precommit exit0，等价于完整 bin/check all；新路径重新编译全部 native/BEAM，未复用旧项目编译产物。仅工具链和下载缓存通过显式环境变量复用。
- Parano1d：Rust4、ExUnit18，通过 debug Clippy、原生测试、release NIF、force compile/test warnings-as-errors。
- TensorCash：Rust11、ExUnit33，通过 fmt/Clippy、ML-DSA/JS oracle、native/review payments 交叉验证、reload 压力检查。
- Blocknet：native Rust10、官方 Rust20、ExUnit23；固定/fresh Rust+Go 交叉验证、16×16、256个变异样本/768调用、前后来源验证全部通过。
- 根完整日志 .cache/local-check.log 无编译 warning/error。首次审计在 Cargo 尚未填充所有包索引时出现 yank 查询缺项提示；完整构建后通过 bin/audit all 重新收齐最终报告，不掩盖该诊断。
- 审计保留 Parano1d bincode 与 Blocknet clear_on_drop 的 unmaintained 信息性告警；零已知漏洞不等于无告警。数据库具体 revision、数量及各项目依赖数见实际报告。

## Linux 与发布追溯

[根 matrix CI](.github/workflows/ci.yml) 为三个项目各执行 setup/check/audit，Ubuntu24.04、fail-fast=false、每行45分钟；递归 checkout 两个官方 submodule并保留全历史。固定OTP27.3.4.19、Elixir1.20.5、Rust1.96.0，TensorCash Node22，Go1.24.12。cargo-audit0.22.2 显式安装，audit 不隐式安装或忽略失败。每行有独立 artifact，保留30天。

远程 SHA、matrix实际结论及artifact以 [GitHub Actions](https://github.com/Ljzn/chain-nifs/actions/workflows/ci.yml) 对应提交为准；本节不以本地验收代替远程执行。最终集成提交可由 git log 查询，发布时核对 origin/develop 与本地 HEAD 一致、工作区 clean。

## 许可与限制

这是多许可聚合，沿用各子项目 LICENSE/NOTICE/THIRD_PARTY，不在根目录重新授权所有组件。原项目 README/HANDOFF 中性能、旧链接与CI数据是对应旧提交历史记录。公开合成种子、不含生产钱包或广播、协议范围与链状态宿主责任、partial secret zeroization、native abort/OOM 隔离限制继续适用。聚合和CI通过不构成完整生产密码学安全审计。

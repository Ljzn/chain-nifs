# Chain NIFs

Parano1d、TensorCash、Blocknet 的独立 Elixir/Rustler 原型合集。三个项目保留完整 Git 历史、各自工具链、lockfile、原生构建和官方互操作验证。它们不是 Mix umbrella，也没有合并 Cargo workspace 或依赖锁。

私有仓库：[Ljzn/chain-nifs](https://github.com/Ljzn/chain-nifs)，默认分支 develop。三个原仓库保留历史发布记录。迁移验收见 [HANDOFF.md](HANDOFF.md)，远程验证以对应提交的 [Linux CI](https://github.com/Ljzn/chain-nifs/actions/workflows/ci.yml) 为准。

## 项目导航

| 项目 | 目录与 API | 范围 |
|---|---|---|
| Parano1d | [README / API](nifs/parano1d/README.md) | 官方 NOID 普通支付 V4 所有权证明 |
| TensorCash | [README / API](nifs/tensorcash/README.md) · [交接](nifs/tensorcash/HANDOFF.md) | ML-DSA-65、普通 TSC 限定格式支付、官方 JS 互操作 |
| Blocknet | [README / API](nifs/blocknet/README.md) · [交接](nifs/blocknet/HANDOFF.md) | 当前 RingCT、indexed stealth 支付及收款恢复、官方 Rust/Go 互操作 |

每个子项目的原有 review、性能和 CI 记录属于对应原仓库提交的历史证据，不能当作本 monorepo 的验收结果。根目录入口优先使用下方命令；子目录直接运行的缓存行为以其自身说明为准。

## Venezia Alpine 预编译模式

使用仓库中的 musl 产物时，在 Alpine 3.21 / OTP 27 构建环境设置 CHAIN_NIFS_MODE=precompiled，即可编译 Elixir 包装层并打包 release，无需 Rust/Cargo/CMake/Go。支持 amd64 和 arm64，自动检查平台、OTP、manifest 与 SHA-256；缺失或不匹配时明确失败。默认仍从源码编译。使用方式、模式切换、构建来源和容器验证见 [PRECOMPILED.md](PRECOMPILED.md)。

## 克隆与准备

~~~sh
git clone --recurse-submodules git@github.com:Ljzn/chain-nifs.git
cd chain-nifs
# 普通 clone 或更新后的 checkout 可补取固定依赖：
git submodule update --init --recursive
bin/setup all
~~~

需要 Git、Rustup、OTP/Elixir、Python 3、Go、Node.js/npm、C/C++ 编译器及 CMake。当前 CI 固定 Ubuntu 24.04、OTP 27.3.4.19、Elixir 1.20.5、Rust 1.96.0；TensorCash 使用 Node 22，Blocknet Go oracle 使用 GOTOOLCHAIN=go1.24.12+auto。首次准备或更新依赖/审计数据库需要网络。

两个公开官方源码 submodule 固定在 [MIGRATION.md](MIGRATION.md) 记录的版本；顶层 Git 必须递归初始化它们。不要用旧子项目目录各自的 .gitmodules 替代顶层 submodule 映射。

## 统一入口，独立执行

~~~sh
bin/setup all                 # 或 parano1d / tensorcash / blocknet
bin/check all
bin/audit all
mix precommit                 # 根 alias 等价于 bin/check all

bin/run blocknet mix test --warnings-as-errors
bin/run tensorcash cargo test --locked --manifest-path native/tensorcash_nif/Cargo.toml
bin/run parano1d mix precommit
~~~

[bin/run](bin/run) 的第一个参数始终是项目名，后面是要执行的命令；执行目录切换到对应子项目。[bin/setup](bin/setup)、[bin/check](bin/check)、[bin/audit](bin/audit) 接受 all 或一个项目名。独立的 Mix/Cargo/npm lockfile 继续由各项目维护，不在根目录重新解析成统一依赖图。

[bin/check](bin/check) 默认使用 `ERL_FLAGS="+S 2:2"`，以满足 Parano1d scheduler 回归测试；根 `mix precommit` 同样经过此入口。调用者显式设置的非空 `ERL_FLAGS` 会保留，运行完整测试时仍需满足两个在线 scheduler 的前提。

根入口默认缓存位于 .cache/cargo、.cache/rustup、.cache/mix、.cache/hex、.cache/npm、.cache/go（GOPATH，包括 Go 工具链校验缓存）。共享下载缓存不会合并项目依赖或构建产物；原生 target、Mix _build/deps 和 generated 结果仍属于各项目。CARGO_HOME 是 Cargo 包缓存，RUSTUP_HOME 是工具链目录；Rustup 及其代理命令需预先在 PATH 中可用。setup 使用 --no-self-update，只安装固定工具链，不尝试在项目 CARGO_HOME 更新系统 Rustup。允许显式覆盖这些缓存变量。

[bin/check-bootstrap](bin/check-bootstrap) 接受 all 或单项目：将当前已提交版本克隆到新临时目录，清除缓存环境覆盖，使用新 checkout 的默认空缓存执行 setup 和完整检查。它保留日志和目录、不会删除现有缓存；需要网络、磁盘空间及正常构建时间。未提交的修改不参与此检查。

审计工具必须显式准备；例如：

~~~sh
bin/run blocknet cargo install cargo-audit --version 0.22.2 --locked
export PATH="$PWD/.cache/cargo/bin:$PATH"
bin/audit all
~~~

如使用已有工具，可显式设置 CARGO_AUDIT_BIN=/绝对路径/cargo-audit；如复用刚更新的 RustSec checkout，可设置 ADVISORY_DB=/绝对路径/advisory-db（此时不自动刷新数据库，应自行记录 git revision 与更新时间）。此前本地验收使用过这些显式覆盖；默认缓存没有审计程序不代表此前报告未执行。

审计入口不把缺工具、数据库访问失败或命令失败当作零漏洞。clear_on_drop 未维护等已知信息性告警必须保留；各项目历史记录中的零已知漏洞不等于无告警，也不等于当前数据库已经复验。

## CI 与迁移证据

[Linux matrix workflow](.github/workflows/ci.yml) 分别为三个项目执行 setup、check、audit，fail-fast=false，每行最多 45 分钟，递归 checkout 官方 submodule。每个项目有独立的验证 artifact，并保留子项目及根目录生成证据。配置存在不代表远程运行成功；实际结果应关联精确 monorepo SHA。

[MIGRATION.md](MIGRATION.md) 记录原仓库 SHA、完整历史导入方法、submodule 迁移和后续历史查阅方式。[HANDOFF.md](HANDOFF.md) 记录迁移验收和发布状态。

## 许可和使用范围

这是多许可项目的集合，不用一个根 LICENSE 重新授权三个项目或其依赖。各子项目的 LICENSE、NOTICE、THIRD_PARTY 和官方依赖许可继续适用：见 [Parano1d README](nifs/parano1d/README.md)、[TensorCash 第三方说明](nifs/tensorcash/THIRD_PARTY.md)、[Blocknet 第三方说明](nifs/blocknet/THIRD_PARTY.md)。

三个原型使用公开合成测试数据，不包含生产钱包秘密或节点广播。它们仍保留各自协议范围、链状态检查、秘密生命周期和 native 故障隔离限制；聚合与统一命令入口不构成生产安全认证。

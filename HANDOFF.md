# Chain NIF monorepo 交接

## 状态与边界

私有仓库 [Ljzn/chain-nifs](https://github.com/Ljzn/chain-nifs)，开发分支 develop。本地位于 Alice/_local/chain_nifs。三个原仓库继续保留；精确来源和无 squash subtree 导入记录见 [MIGRATION.md](MIGRATION.md)。

三个独立 Mix/Rustler 项目位于 nifs/parano1d、nifs/tensorcash、nifs/blocknet。保留原 API、Rust/Hex/npm lockfile 和许可，不建立 umbrella 或统一 Cargo workspace。协议源码、固定 fixture 与官方来源未改变。唯一子项目脚本调整是 Parano1d bin/run 允许外部缓存环境覆盖，默认仍为项目本地。

## Scheduler 环境 review 修复

根 bin/check 现在默认导出 ERL_FLAGS="${ERL_FLAGS:-+S 2:2}"，显式非空配置保持不变；不修改或放宽 Parano1d scheduler 测试。未设置 ERL_FLAGS 的实际完整命令 `env -u ERL_FLAGS bin/check all` 已 exit 0，ExUnit 26/41/31、Rust 4/11/10 和官方20项及互操作检查通过。实际赋值语句的显式覆盖 `+S 2:2 +A 4` 保留检查、sh -n 与 git diff --check 也通过。日志 .cache/check-scheduler-default.log。仅修改根入口和说明，六个预编译库及 manifest 未改，Venezia 固定依赖提交不需要改变。

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
- 初次迁移验收的 bin/setup all exit0 使用显式工具链/下载缓存覆盖；它证明迁移路径可构建，不证明默认空缓存首次安装。根格式检查、四个 shell 的 sh -n、非法项目/路径选择拒绝均通过。
- 真实根 mix precommit exit0，等价于完整 bin/check all；新路径重新编译全部 native/BEAM，未复用旧项目编译产物。仅工具链和下载缓存通过显式环境变量复用。
- Parano1d：Rust4、ExUnit18，通过 debug Clippy、原生测试、release NIF、force compile/test warnings-as-errors。
- TensorCash：Rust11、ExUnit33，通过 fmt/Clippy、ML-DSA/JS oracle、native/review payments 交叉验证、reload 压力检查。
- Blocknet：native Rust10、官方 Rust20、ExUnit23；固定/fresh Rust+Go 交叉验证、16×16、256个变异样本/768调用、前后来源验证全部通过。
- 根完整日志 .cache/local-check.log 无编译 warning/error。首次审计在 Cargo 尚未填充所有包索引时出现 yank 查询缺项提示；完整构建后通过 bin/audit all 重新收齐最终报告，不掩盖该诊断。
- 审计保留 Parano1d bincode 与 Blocknet clear_on_drop 的 unmaintained 信息性告警；零已知漏洞不等于无告警。数据库具体 revision、数量及各项目依赖数见实际报告。

## Bootstrap review 响应

Reviewer 记录了默认空缓存初始化失败。本轮独立复现使用全新临时 CARGO_HOME/RUSTUP_HOME 和 Rustup1.27.1，原命令首次安装退出0，因此尚未确认旧失败的完整触发条件，不能声称 red/green。setup 新增 --no-self-update，明确只管理项目工具链、不更新系统Rustup；保留独立缓存，不把工具安装写入用户全局Cargo目录。

新增 bin/check-bootstrap：克隆当前已提交版本到临时目录，清除 Cargo/Rustup/Mix/Hex/npm 缓存覆盖，再按新 checkout 默认空缓存执行 setup 与根 mix precommit。记录 source SHA/setup.log/check.log，不删除现有缓存；依赖主机 PATH 和网络，范围不含 audit。根 CI 每行显式断言四个默认缓存不存在，清除继承的缓存变量，后续步骤也使用空值恢复根默认值。

README 已补 Rustup/proxy/cache 边界和本地审计工具/数据库覆盖方式；MIGRATION 明确子目录 workflow 是历史文件、仅根 workflow 生效。实际冷 checkout 首轮（053be49）通过 Rustup/Hex/npm，但 Go 下载固定工具链时写入全局 GOPATH 校验缓存，被工作区沙箱拒绝；这与 reviewer 的 Rustup 错误不同，作为真实失败证据保留。随后根 bin/run 新增项目 .cache/go 默认 GOPATH，冷启动清除 GOPATH/GOMODCACHE/GOCACHE/RUSTUP_TOOLCHAIN，以新 checkout 重跑。最终源码 e6e50ee324aaa5f09b03326e05ccc7b769b7b082 的新 checkout 默认空缓存 setup 全部成功。本地首次完整检查在 TensorCash release 库生成后 Mix 长期无输出，已停止保留日志；随后同一个冷 checkout/default-cache、未切换旧环境，重新执行根 mix precommit 退出0（Parano18/Tensor33/Block23 ExUnit，Rust4/11/10+官方20，全部互操作与变异检查）。同一默认环境重复 bin/setup all 也退出0，幂等性检查通过，checkout clean。不把被停止的 helper 记作端到端一次性通过。系统Rustup文件SHA256验证前后均760b18611021deee1a859c345d17200e0087d47f68dfe58278c57abe3a0d3dd0。

最终空缓存三行Linuxmatrix全部success：[run43000502219](https://github.com/Ljzn/chain-nifs/actions/runs/43000502219)，精确headSHA为e6e50ee。每行setup/check/audit/artifact通过，三份artifact已下载复核。RustSec1453条，revision31cf5a8673e10d3a4d7d829ad5095f47ed419049；native依赖44/59/61及Blockoracle61，0已知漏洞、ignore=[]，保留bincode/clear_on_drop未维护告警。

## Venezia Alpine 预编译产物

产物提交79aa874包含三项目的amd64/arm64 musl共享库与各自manifest（共六库约7.82MiB）。准确源码来源fabebe947a2d4d3226f100b797fd0ace91d985a8，Rust1.96.0，固定Venezia Alpine3.21.7/OTP27 builder及digest，动态musl参数-C target-feature=-crt-static；manifest记录SHA256/目标/OTP/官方来源，下载后逐个核对哈希与ELF架构。

[原生双平台生成与运行CI43010298955](https://github.com/Ljzn/chain-nifs/actions/runs/43010298955)全部success：各自无原生编译工具的干净Elixir容器中包装层编译、完整ExUnit26/41/31；最终Alpine release --networknone中实际Parano证明、Tensor签名与正负验签、Block范围证明与正负验证均成功。本地默认源码根mixprecommit也退出0，保持Rust测试/interop/mutation/reload全部通过。

消费设置CHAIN_NIFS_MODE=precompiled，自动选当前musl架构；Rustler skip_compilation?:true且无Cargo调用。加载前编译/运行两次检查主机、OTP27、manifest和SHA，无下载/回退。runtime无需MODE/TARGET环境。切换mode需fresh输出或强制依赖编译。详见[PRECOMPILED.md](PRECOMPILED.md)。尚未修改或实际构建完整Venezia项目镜像；这是针对其目标环境的独立release验收。

预编译workflow手动触发生成+验证；push相关产物/loader/runtime变更时直接验证仓库二进制，跳过Rust编译。[已提交产物直接消费CI43011582747](https://github.com/Ljzn/chain-nifs/actions/runs/43011582747)在79aa874的两行全部success，实际Compile pinned Alpine binaries为skipped，无工具编译与真实release验证通过。ELF DT_NEEDED核对六库只需libgcc_s.so.1及对应musl libc；BEAM/其他应用仍保留自己的运行依赖。默认源码matrix保留。[79aa874源码完整matrix43011582762](https://github.com/Ljzn/chain-nifs/actions/runs/43011582762)三个项目全部success，包含完整原生/互操作检查、审计和证据上传。监控曾因GitHub API EOF退出1，重查权威状态及恢复监控后确认实际全部通过，不将监控网络中断记为测试失败。

## Linux 与发布追溯

[根 matrix CI](.github/workflows/ci.yml) 为三个项目各执行 setup/check/audit，Ubuntu24.04、fail-fast=false、每行45分钟；递归 checkout 两个官方 submodule并保留全历史。固定OTP27.3.4.19、Elixir1.20.5、Rust1.96.0，TensorCash Node22，Go1.24.12。cargo-audit0.22.2 显式安装，audit 不隐式安装或忽略失败。每行有独立 artifact，保留30天。

远程 SHA、matrix实际结论及artifact以 [GitHub Actions](https://github.com/Ljzn/chain-nifs/actions/workflows/ci.yml) 对应提交为准；本节不以本地验收代替远程执行。最终集成提交可由 git log 查询，发布时核对 origin/develop 与本地 HEAD 一致、工作区 clean。

## 许可与限制

这是多许可聚合，沿用各子项目 LICENSE/NOTICE/THIRD_PARTY，不在根目录重新授权所有组件。原项目 README/HANDOFF 中性能、旧链接与CI数据是对应旧提交历史记录。公开合成种子、不含生产钱包或广播、协议范围与链状态宿主责任、partial secret zeroization、native abort/OOM 隔离限制继续适用。聚合和CI通过不构成完整生产密码学安全审计。

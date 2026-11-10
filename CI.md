# 自动验证与证据边界

GitHub Actions 的 CI 在 Ubuntu 24.04 x86-64、OTP 27.3.4.19、Elixir 1.20.5、Rust 1.96.0 上运行。checkout 和 setup-beam 固定完整 commit；权限仅 contents:read，递归初始化官方源码子模块，不持久化 Git 凭据。工具链/Hex/Mix 缓存使用 job 工作目录。

流程执行 Elixir/Rust 格式、Clippy all-targets warnings-as-errors、Rust gate 单元测试、release NIF 编译、真实 ExUnit（+S 2:2，包括 64 输入/两输出）、Hex retired 包检查，以及固定版本 cargo-audit 0.21.2 的 RustSec 锁文件审计。没有 advisory ignore。审计结果依赖当时的数据库，不等于完整供应链审计或上游人工审查。

248 个有界畸形 wire 用例使用固定 seed，覆盖空/超限页头、header/page/authorization 截断、proof 长度/尾部不匹配、unsigned/raw 边界，分别调用 wrapper 与 Native。它们是确定性随机回归，不是长期覆盖引导 fuzz，也不代表完整 proof decoder 的所有内部状态已经覆盖。现有真实 proof mutation 测试继续保留。

Rust 单元测试使用独立 Admission 实例注入 unwind，不毒化进程全局生产 gate；验证 busy 与 faulted 不调用工作闭包、普通 Err 释放锁。生产不提供 fault 重置/注入入口。ExUnit 在证明任务占用期间发送畸形但 wrapper 长度合法的容器，验证准入优先于解码；空闲时同一输入返回页数错误。

bench/reload.exs 必须在独立 BEAM 执行，验证正常证明/卸载/重载/验证；不能作为 panic 后允许热重载恢复的承诺。

CI 通过与否以对应提交的远程 run 为准。本机 Apple ARM 检查与配置静态检查不能替代 Linux 运行结果。审计数据库、官方源码域名、工具链下载源均为外部依赖；没有保证离线构建。

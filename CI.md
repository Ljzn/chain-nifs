# Validation and CI scope

本机环境：Apple M2 arm64 / 8GiB，OTP27、Elixir1.20.5、Rust1.96.0，release NIF。远程工作流目标为Ubuntu24.04 x86-64、OTP27.3.4.19、Elixir1.20.5、Node22；本轮用户已授权创建GitHub私有仓库。远程运行结果将在完成后追加，当前不宣称Linux已通过。

## Review后验证

- 实际NIF33项ExUnit、11项Rust：包含官方identity/spending派生、1×16和64×16完整交易、精确weight/vsize/fee、金额/coinbase/raw边界、Direct Native、并发。
- Wrapper百万项列表回归以BEAMreductions验证有界拒绝；旧实现实测62,900，断言<5,000先失败，改为最多65cells后通过。无计时阈值。
- Direct Native补测发现branch256被u8解码截断为0：改为u32解码后checked转换，拒绝256/257/65536/u32max；高层wrapper原本已有0/1约束。
- Rust解析器有限变异集：对官方真实raw做512个单bitmutation和512个截断，原样交易必须有效，所有变异均拒绝。属于确定性corpus回归，不是coverage-guided fuzz、sanitizer或长期soak。
- 官方14个TS模块未改；新增identitySeedHex由官方identityKeySeed生成。fixture SHA256为8172bf06db4a1b70b8559ed963b7094fe99f28a25c004bef2bab1799073dbb6d。
- 独立TS解析、两套摘要路径及逐witness验签覆盖随机签名和交易，另有1×16/64×16及0/fffffffd/ffffffff序列组合。

## 审计证据

bin/run bin/audit生成results/generated/audit/{cargo-audit.json,npm-audit.json,hex-audit.txt,revision.txt}。即使某项失败也继续保留其他报告，最终返回非零；不忽略advisory。CI安装cargo-audit0.22.2后使用fresh RustSec DB，完整npm audit包括oracle全部依赖。

本机使用已安装的相邻原型cargo-audit0.22.2和既有RustSecDBd9cb059f3217db87aeccd190b81eaffe8cc29cb9（1430advisories，--no-fetch）生成JSON，Cargo/Hex/npm均exit0。这是可复查的特定数据库结果，不是全面安全证明。可用CARGO_AUDIT_BIN和ADVISORY_DB显式选择审计工具/离线DB；项目构建和CI不依赖相邻项目。

CI的always artifact步骤保留results/generated下的audit报告、fresh随机支付样本、独立交叉验签结果、benchmark和reload证据30天。历史results快照仍保留，复现默认只写ignored的generated目录，不应弄脏工作区。

## 已确认的依赖约束

Jason虽未被核心lib直接调用，但Rustler0.37.3声明它为非可选依赖；把直接依赖改为only:dev/test会触发Mix依赖冲突。因此保留现状，未用override绕过Rustler构建要求。

## 生产边界

正常3次unload/reload不保证C abort/exit/OOM/UB恢复；不声称全部嵌套秘密/寄存器/BEAMbinary清理。并发测试32keys/8callers，不是服务吞吐或长期内存soak。当前没有ASan/UBSan/Miri或coverage-guided fuzz，生产前仍需相应审计。没有节点UTXO/maturity/fee-policy/testmempoolaccept验证。其他API范围见README。

# TensorCash NIF prototype handoff — 2026-11-10

本项目现位于公开独立仓库 [Ljzn/chain-nifs](https://github.com/Ljzn/chain-nifs) 的 `nifs/tensorcash`，默认分支 `develop`。以下保留原独立仓库 [Ljzn/tensorcash-nif](https://github.com/Ljzn/tensorcash-nif) 的实现与 review 历史，修复提交为 `14b77dd8b4b24f521dd6512af05528b40398a8ae`。所有验证使用公开合成数据，未访问真实钱包秘密或广播交易。

## Bob review处理

Wrapper整表length已改为有界遍历，百万列表reductions回归先red后green。新增DirectNative回归发现branch256截断，已改为u32+checked窄化；对256/257/65536/u32max拒绝。新增官方identity向量、1×16/64×16、MAX_MONEY/零金额/零fee/coinbase/rawcap/sequence及DirectNative边界；本机33ExUnit、11Rust通过。

有限解析器corpus覆盖512单bitmutation+512truncations；官方TS交叉验证现在接受全部u32sequence，并新增最大形状支付独立验收脚本。CI新增完整npm audit、Cargo/Hex报告与always artifact；[Linux CI42822439599](https://github.com/Ljzn/tensorcash-nif/actions/runs/42822439599)对修复commit14b77dd全部通过（8m9s），审计与linux-validation artifact上传也通过；细节见CI.md。

LICENSE恢复标准Apache附录模板，NOTICE保留上游与本项目贡献者归属；benchmark默认写ignored results/generated，历史样本不覆盖。金额严格正数是原型限制，zero fee允许但不代表relay；MAX_MONEY来自固定Core且不是发行量声明，network/sequence/false:error语义已补文档。Jason为Rustler非可选依赖，不能简单限制为test/dev，已保留并说明。

以下原型首版记录与性能为历史快照。当前fresh验证使用results/generated/native-sample.json和review-payments.json；相应命令在CI.md与workflow中。

## Ready

ML-DSA65seededkeygen/Purehedgedsign/verify，官方BIP39seed64 HKDFidentity/spendingseed，3network1of1thresholdv2地址，version2/lock0/SIGHASH_ALL普通TSC完整交易与限定格式本地验签。64inputs16outputs512KiB上限，金额/双花outpoint/格式/字段长度等校验。API见README.md。

liboqs97f6b86b1b6d109cfd43cf276ae39c2e776aed80，仅静态PIC referenceMLDSA65，OpenSSLoff。Seedkeygen/sign显式seed/rnd，不切全局RNG。Cadapter耦合内部接口的理由/差异/许可在THIRD_PARTY.md。NativeAPI不接受任意展开SK；签名仅从validseedkeygen产生SK，freshgetrandom失败返回error。

## Review fixes

独立只读review未发现限定交易格式/摘要/边界的highcritical或正确性blocker，发现并修复两项memory-hygiene问题：

1. 上游sign_internal主栈工作区不清理：本地复制solefunction，数学不变，只重命名+soleexit前cleanse11arrays；源码归一化比较与固定rnd向量核实。
2. hkdf0.12/HMAC状态和pad保留root：移除hkdf/hmac，启用SHA2.11zeroize，用显式Zeroizingpad/root/inner/output实现固定HKDFsingleblock；RFC5869case1和官方完整派生回归相同，独立review确认。

仍不声称完整调用链/寄存器/BEAMbinary都擦除。Cabort/exit/OOM/UB不能由Rustcatch_unwind隔离。生产如要求nativefault隔离，应使用port/worker；当前是实际可运行原型，不是生产securitycertification。

## Evidence

- Rust9tests passed；包含固定公私钥、显式rnd签名与RFC/官方HKDF逐字节比较。
- ExUnit20tests为最终suite；真实NIF/官方Core签名/ACVPkeygen/三网络地址和支付/64input/畸形DirectNative/并发。
- 独立官方TS模块14files原样保留，sourcehashmanifest，npmexactlock；npmruncheck通过2seededkeypairs、4signatures、6addresses、3payments、2Corecapturecases、6ACVPcases。
- freshNative8signatures+1full2in2outtransaction独立TS解析+两套sighash+每个witness验签通过，结果results/crossverify.json，可重验results/native-sample.json。
- 3次sign/unload/reload/verify通过，results/reload.txt；不等于崩溃恢复。
- Clippyalltargets-Dwarnings、mixcompilewarnings-as-errors、mixprecommit、格式检查作为最终gate；最终本地commit说明在共享handoff。
- cargoaudit0.22.2对actual59-crateCargo.lock exit0，现有RustSecDBd9cb059f3217db87aeccd190b81eaffe8cc29cb9/1430advisories，nofetch；Hex及npm audit0已知漏洞。CI.md包含数据库时间性限制。
- LinuxCI配置已加入但未远程运行；本项目尚未发布。

## Performance

AppleM2/8GiB，OTP27/Elixir1.20.5，releaseNIF，+S2:2/dirtyCPU2。原语31samples，交易5samples，warmmedian：keygen0.139ms，sign含keygen+selfverify0.820ms，verify0.145ms；1/2/64inputs2outputsbuild+sign+selfverify1.060/1.753/46.177ms；64inputverify9.123ms。

全基准peakRSS107,167,744bytes=102.20MiB，footprint94,519,920bytes=90.14MiB，包含BEAM/fixture/JSON/最大交易，不是签名每次增加的内存。完整1/2/64inputraw5,465/10,832/343,586bytes；64inputvsize87,937。合成固定fee10,000sat不代表最低relay费率。没有持续soak/生产吞吐或链上接纳测试。

## Remaining scope

未实现多key输入/thresholdmultisig/其他sighash/legacyrecipient/资产extensions/annex/通用VM，也未连接节点查询UTXO、成熟度或testmempoolaccept。verify依赖调用方提供真实金额及prevouts，所有输入script由本keydescriptor推导。raw没有network标记，network校验发生在地址和构造。

## Reproduce

项目根：bin/run mix precommit；bin/run cargo test --manifest-path native/tensorcash_nif/Cargo.toml --locked --lib；bin/run cargo clippy --manifest-path native/tensorcash_nif/Cargo.toml --locked --all-targets --no-deps -- -D warnings。

npm --prefix interop run check；ERL_FLAGS="+S 2:2" MIX_ENV=test bin/run mix run --no-compile bench/run.exs；npm --prefix interop run --silent crossverify < results/native-sample.json；ERL_FLAGS="+S 2:2" MIX_ENV=test bin/run mix run --no-compile bench/reload.exs。

bin/run检查vendor精确版本和dirty状态，缓存均项目本地。全新clone按README初始化git submodule、rustup、mixdeps/npmci。构建不依赖相邻research/parano1d项目。结果均来自公开合成fixture，不要给示例地址充值。

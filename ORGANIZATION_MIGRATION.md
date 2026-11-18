# 组织仓库迁移记录

记录起始日期：2026-11-13；ParkingLot 切换完成：2026-11-14。当前目标：[peatio/ParkingLot 的 chain-nifs 分支](https://github.com/peatio/ParkingLot/tree/chain-nifs)，仓库仍为 private。
本仓库用于组织维护三条链的 NIF 原型、预编译产物与互操作验证材料。

## 历史导入与保留边界

- 完整签名历史存放在长期分支 `chain-nifs`，不继承 ParkingLot 的旧文件或历史。下列 signed head 是新增迁移文档之前的导入基准，原始 24 个提交及其父图均保留。
- ParkingLot 的默认 `main` 和其他现有分支保持原样。维护 NIF 时必须显式 checkout `chain-nifs`；私库权限和仓库级设置由各分支共享。
- 此前 Gondola 仅为迁移尝试，不再作为依赖来源。消费者切换验证及推送后，其迁移 PR 已关闭且未合并，本次新增的五个临时分支已删除。远端仅保留原 `main`（`b3966ee0bb20762133159d78fe6b8473d5250420`）和 `feat/tron`（`1b4d69a68713db3896057faece508239bd0bff36`），原始内容未变。
- 原私有个人源 [Ljzn/chain-nifs](https://github.com/Ljzn/chain-nifs) 保留原 refs 与历史，本次未改写、删除或归档它。
- 三个原项目仓库、各自许可和官方 submodule 固定版本继续按历史记录保留。
- [MIGRATION.md](MIGRATION.md) 与 [HANDOFF.md](HANDOFF.md) 是此前迁移及验收的历史证据，不能据此宣称组织提交已完成新一轮构建或 CI。

## 旧新提交与重签原因

用户已授权迁入组织仓库并明确允许改变 SHA。原历史的三份 subtree merge 缺少签名；
为导入带签名的历史，为它们添加签名，并对受父 SHA 变化影响的后代重新签名。
commit 对象包含父 SHA 与签名，因此即便 tree 和 message 相同，SHA 也会改变。
共保留 24 个提交与原父图结构，其中 12 个原签名提交保留原 SHA，12 个提交重写。

| 用途 | 个人源 SHA | 组织签名历史 SHA |
|---|---|---|
| 导入 head | `8d0c7753321774b3a8ce6c0b2643e911bca771d8` | `f0d24edc8766699035deb6965a027869e80bbac9` |
| Venezia 消费 pin | `198cb6f7a1908650a4cca3315d4559498591bd39` | `78005ac4a1afc46cee1d9cd7c51df297e6674705` |
| Parano1d subtree merge | `ba30e42303e13c491e5b0fc1ed3ac4c7de4792d3` | `f075c9961481a611b56fc458b31c986bb70024e2` |
| TensorCash subtree merge | `961a1c778166cc9ebf85768b49e0b1d5619e581e` | `cf094fcf1e62fc45ead334cae8c47dc49736e02c` |
| Blocknet subtree merge | `452e341d45a28f48482aa1a05290b48c56723afd` | `cc08b60529d958c901bca3153f3c67deaa7d1284` |

完整 24 对映射保存在 [signed-history-map.json](signed-history-map.json)，包括未改变的 SHA。
在组织克隆中查阅旧引用时，先用映射取新 SHA；不保证改写前的对象在该克隆可达或存在。
个人源仓库仍可用于查询原始历史。映射只含提交标识与审计摘要，不含凭据或本机路径。

## 独立 Git 对象审计

使用 `git cat-file commit <sha>` 读取原始对象字节，不通过格式化日志重建元数据。
逐对检查结果如下，全部通过：

| 检查项 | 通过数 |
|---|---|
| tree 对象 SHA 完全相同 | 24/24 |
| author 原始 header 字节（含时间与时区）相同 | 24/24 |
| committer 原始 header 字节（含时间与时区）相同 | 24/24 |
| 原始 commit message 字节相同 | 24/24 |
| 原 parents 按映射转换后与新 parents 顺序相同 | 24/24 |
| 新对象具有非空 `gpgsig` header | 24/24 |

旧 head 的 `git rev-list` 集合等于映射键，新 head 的集合等于映射值，均为 24 个。
只有上表三份旧 subtree merge 缺少 `gpgsig`。这里审计签名 header 的存在，
不把它等同于签名密码学验证、密钥信任或 GitHub Verified 状态。审计未签名、改 refs 或推送。

## 源码、ABI 与预编译产物

旧新 pin 的完整 tree 均为 `9576ea08449db77142b3b72764dfaa7f4191b278`；
旧新导入 head 的完整 tree 均为 `7d543b07037f46e6c734dc7d776119aed42a6697`。
相同 tree 递归引用相同 blob、文件模式和 gitlink，因此所有已跟踪源码、ABI 定义、
manifest、预编译 artifact 字节和 submodule pin 均未因重签改变。
该证据针对已提交的 Git 内容，不声称重新构建或重新进行运行时 ABI 测试。

manifest 的 `source_revision` 记录产物当时的构建来源，属于历史 provenance，
不能为迎合组织 SHA 而机械替换。需要关联组织历史时使用映射；保持原产物与 manifest 字节。
本次文档变更不修改 NIF 源码、manifest、workflow 或编译依赖。
独立文档审计只执行 `git diff --check`，未运行会构建三条链的根 `mix precommit`。

## 验证记录与读取权限

- GitHub 已接受签名历史导入，组织仓库中的消费 pin `78005ac4a1afc46cee1d9cd7c51df297e6674705` 返回 `verified: true`、`reason: valid`。
- 此前从 Gondola 临时迁移分支全新克隆并初始化递归 submodule 已成功，两份官方依赖保持原 gitlink；这是前一托管位置的验证记录。
- Gondola 的首次 Linux CI run `43450849590` 在 checkout 读取该仓库时收到 HTTPS 403，编译和测试未开始；不能据此断言 ParkingLot CI 已通过或必然失败，新位置需要独立验证。
- 已从 ParkingLot 的 `chain-nifs` 分支全新克隆并成功初始化两份递归 submodule，固定消费 pin 与原完整历史均可达。
- 三个 Venezia 消费分支均实际从 ParkingLot 获取固定 pin，拉取前后 lock 一致；`mix precommit` 重新编译 NIF 并通过。真实 TensorCash 签名/验签/篡改拒绝，以及 Parano1d 原生调用、Blocknet 加载验证通过。未启动应用、Repo 或 Endpoint，未重复运行数据库回归。
- ParkingLot 独立 CI run `43458073310` 在 checkout 读取本仓库时也收到 HTTPS 403，编译和 Linux 测试未开始；该读取权限问题仍需处理，本地成功不代表远端 Linux 验证通过。
- 当前方案只在 ParkingLot 新建独立历史分支，无需改动任一仓库的默认分支、清空旧项目或绕过保护规则。
- 迁移后继续执行组织签名、PR review 等规则；无需为新签名历史关闭签名要求。
- Venezia 的 CI 读取凭据仍需具备私有 `peatio/ParkingLot` 的读取权限；个人仓库上的 deploy key 授权不会自动迁移。

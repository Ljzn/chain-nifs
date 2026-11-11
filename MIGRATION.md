# 完整历史迁移记录

本合集采用 git subtree 的完整历史导入，不使用 --squash，不重写来源提交。三个子项目在当前树中位于 nifs/ 下；来源仓库中的旧提交保留其原始根目录路径。这不是把三个原仓库变成 Git submodule：只有下述两份官方依赖继续使用 submodule。

## 导入来源

| 项目 | 保留的原仓库 | 导入时 develop HEAD | 当前目录 |
|---|---|---|---|
| Parano1d | [Ljzn/parano1d-nif](https://github.com/Ljzn/parano1d-nif) | 4b432a93e989180fc4351c6bb1fa2f94d76e7b46 | [nifs/parano1d](nifs/parano1d/README.md) |
| TensorCash | [Ljzn/tensorcash-nif](https://github.com/Ljzn/tensorcash-nif) | 45fe20797475578540177699c54bb1680344a3f9 | [nifs/tensorcash](nifs/tensorcash/README.md) |
| Blocknet | [Ljzn/blocknet-nif](https://github.com/Ljzn/blocknet-nif) | 4a9140025408694aa8393377049043a6f4eec70b | [nifs/blocknet](nifs/blocknet/README.md) |

原仓库及其 remote 保留，不归档、不删除、不改写历史。本 monorepo 计划使用独立私有 remote Ljzn/chain-nifs、默认分支 develop；是否已发布和 CI 是否通过见 [HANDOFF.md](HANDOFF.md)。

## 实际导入过程

执行位置为 Alice/_local/chain_nifs；三个 sibling 来源目录均已存在。父代理实际执行的关键命令为：

~~~sh
git init -b develop
# 创建初始 README 与 ignore，并提交初始化版本。
git subtree add --prefix=nifs/parano1d ../parano1d_nif develop
git subtree add --prefix=nifs/tensorcash ../tensorcash_nif develop
git subtree add --prefix=nifs/blocknet ../blocknet_nif develop
~~~

没有 --squash 参数。可在任意完整克隆中找到的导入提交为：

| 步骤 | 导入提交 |
|---|---|
| 初始化根仓库 | 884a419f40cbdf1c8d01d4f5f46b3e817561074b |
| Parano1d subtree | ba30e42303e13c491e5b0fc1ed3ac4c7de4792d3 |
| TensorCash subtree | 961a1c778166cc9ebf85768b49e0b1d5619e581e |
| Blocknet subtree | 452e341d45a28f48482aa1a05290b48c56723afd |

这些导入提交把来源 HEAD 作为可达历史接入，因此原 SHA 可直接用于 git show 或 merge-base --is-ancestor。旧提交中的文件仍使用旧根路径，例如：

~~~sh
git merge-base --is-ancestor 4a9140025408694aa8393377049043a6f4eec70b HEAD
git show 4a9140025408694aa8393377049043a6f4eec70b:README.md
git log --all --graph --oneline
# 当前树及迁移后的修改使用新路径：
git log -- nifs/blocknet
~~~

仅对新路径执行 git log 不能完整显示旧根路径时期的文件演变；不要据此认定历史被 squash 或丢失。完整迁移不意味着来源目录中未提交文件、未跟踪文件或忽略缓存也被导入；导入基准是表中的 Git 提交。

## 官方 submodule 路径迁移

顶层 .gitmodules 将原 gitlink 注册为新路径：

| 官方依赖 | 当前路径 | 固定提交 |
|---|---|---|
| Parano1d | nifs/parano1d/vendor/parano1d | f47f386c842ab60d65b70351b0a5b2729f1d9179 |
| liboqs | nifs/tensorcash/vendor/liboqs | 97f6b86b1b6d109cfd43cf276ae39c2e776aed80 |

公开上游 URL 分别为 https://git.parano1d.org/ignotusnemo/parano1d.git 和 https://github.com/open-quantum-safe/liboqs.git。旧子目录级 submodule 注册由迁移维护者处理，当前树以顶层 .gitmodules 为准；历史提交中的原 .gitmodules 仍保留在历史里。执行 git submodule update --init --recursive 应在仓库根完成。

## 统一入口和依赖边界

根 bin/run 负责选择项目、进入子目录和设置 .cache 下的默认工具缓存；bin/setup、bin/check、bin/audit 支持 all 或单项目。根 mix precommit 只调度 bin/check all，不代表统一的 Mix application 或 umbrella。

三个 Mix/Cargo/npm 依赖图、lockfile、原生库名称、API 和测试目录各自保留。迁移不合并 Cargo workspace、不共享一个 Mix deps lock、不替换官方密码学算法。公共下载缓存可复用，但不能把缓存命中当作依赖版本或检查成功证据。

子项目目录保留的 .github/workflows/ci.yml 仅为原仓库历史文件；GitHub 不执行嵌套 workflow。当前唯一生效入口是 [根 matrix CI](.github/workflows/ci.yml)，变更检查流程时应维护根入口。

## 验收边界

原仓库中已经成功的本地或 Linux CI、review、benchmark、audit 属于原提交的历史证据。迁移后需要在 monorepo 的精确 SHA 上重新执行根入口并验证递归 submodule、三个项目、matrix CI 与 artifact 路径。

本文记录迁移来源与方法，不声称迁移后的构建、审计、Linux matrix 或私有发布已经完成；最终结果由父维护者在 [HANDOFF.md](HANDOFF.md) 补充。各项目 LICENSE/NOTICE/THIRD_PARTY 继续有效，本合集为多许可聚合，不提供统一替代许可。

---
id: kno-ci-supply-chain-imported
title: CI/CD 供应链安全加固清单
category: CI_SUPPLY_CHAIN
type: playbook
tags: CI, 供应链, 加固, Artifact, 签名, 依赖审查
source: 御盾智核导入样例
version: 1.0
---
导入型知识文档示例。此文件位于 data/knowledge/ 目录，系统启动与 reload 时会自动并入知识库，用于演示"内置 + 可导入文档"的扩展方式。

CI/CD 供应链加固要点：
1. 固定第三方 Action 的版本与哈希摘要，禁止未固定引用的动作在受信流水线中执行。
2. 对构建产物与发布物实施签名校验，防止中间人替换。
3. 对 Secret 的注入与读取保持最小可见范围，并记录访问审计日志。
4. 启用依赖与动作的自动审查，发现未知或可疑变更立即阻断构建。
5. 定期演练凭据泄露与供应链投毒场景，验证检测与处置链路可回查、可恢复。

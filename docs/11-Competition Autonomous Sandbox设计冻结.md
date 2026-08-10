# Competition Autonomous Sandbox 设计冻结

> 状态：CR-003 编码前冻结；适用范围仅为 `scenario_api_key_compromise_v1` 的本地 Synthetic/Mock Sandbox。

## 1. 目标与边界

Competition Autonomous Sandbox 用于证明系统具备零人工完成安全事件调查、受控处置、验证和反馈闭环的技术能力。它不改变生产安全原则：`PRODUCTION_GUARDED` 继续要求真实人工审批，真实生产 Adapter、任意 Shell、任意 HTTP 写操作和 Official 离线数据均不得成为自治执行目标。

两个模式共用同一 ActionRequest、SYSTEM_EXECUTOR、MockState、Verification、Audit 和状态机，不建立第二套执行器。

## 2. 冻结枚举

```text
RunMode
- PRODUCTION_GUARDED
- COMPETITION_AUTONOMOUS

ResourceEnvironment
- SANDBOX

PreAuthorizationDecision
- AUTO_PREAUTHORIZED
- DENY
```

禁止使用散落的 `autonomous=true` 代替 RunMode。未来生产环境枚举必须另行设计，当前不预设。

## 3. PolicyPreAuthorization

它是确定性系统授权对象，不是 ApprovalRecord，也不代表人类决定。正式字段冻结为：

```text
preauthorization_id       paz_<ULID>
incident_id               当前 Incident
action_request_id          当前 ActionRequest
run_mode                   COMPETITION_AUTONOMOUS
scenario_id                allowlist 场景
environment                SANDBOX
policy_version             autonomous-sandbox-1.0
allowed_operations         三个冻结操作
request_digest             ActionRequest canonical SHA-256
guard_checks               每项确定性检查与理由
decision                   AUTO_PREAUTHORIZED / DENY
created_by                 SYSTEM_POLICY
created_at                 UTC RFC3339
```

PreAuthorization 只追加，不原地修改。它与 ApprovalRecord 使用不同表、不同 ID 和不同审计事件；自治运行的 ApprovalRecord 数量必须为 0。

## 4. 确定性安全守卫

只有以下检查全部通过才生成 `AUTO_PREAUTHORIZED`：

1. RunMode 精确为 `COMPETITION_AUTONOMOUS`；
2. 显式配置 `COMPETITION_AUTONOMOUS_ENABLED=1`；
3. Mock state 的 resource_environment 为 `SANDBOX`；
4. scenario_id 在冻结 allowlist；
5. ActionType 为 `CREDENTIAL_CONTAINMENT_PLAN`；
6. Operations 精确为 `FREEZE_OLD_KEY → CREATE_NEW_KEY_VERSION → UPDATE_CI_BINDING`；
7. Target 属于当前 Incident 的六个 ConfirmedFact；
8. Fact 关联 Evidence 仅为 `SYNTHETIC` 或 `MOCK`；
9. ActionRequest 不含明文 Secret，digest 未变化；
10. 不存在生产 Action Adapter；
11. 不存在 Shell/Subprocess/任意命令；
12. 前置 PolicyDecision 已通过原八项确定性检查。

任一失败生成并审计 `DENY`，不执行，不自动降级为伪造人工审批。

## 5. LangGraph 路由

```text
policy_check
├─ PRODUCTION_GUARDED → wait_for_approval → interrupt/resume
└─ COMPETITION_AUTONOMOUS → autonomous_preauthorization
                                  ↓
                         Controlled Executor
                                  ↓
                         Verification 6/6
                         ├─ PASS → Audit → CLOSED
                         └─ FAIL → Observe/Replan
```

GraphState 新增 `run_mode` 与 `preauthorization_id` 引用，不保存完整授权对象、Mock state 或秘密。

## 6. Executor 授权契约

`ControlledExecutor.execute()` 必须显式接收 RunMode：

- Guarded：校验 Policy + APPROVED ApprovalRecord + digest；
- Autonomous：校验 Policy + AUTO_PREAUTHORIZED PolicyPreAuthorization + digest + SANDBOX；
- 其他模式或缺失授权：DENY。

两条路径之后执行完全相同的三步 Mock 操作、幂等、快照、Evidence、状态推进和 Verification。

## 7. UI 与真实性

仅当运行时报告 Autonomous 配置可用时，UI 才允许选择 `COMPETITION_AUTONOMOUS`，并固定展示：

```text
SANDBOX ONLY
NO PRODUCTION SIDE EFFECT
Human Approval Count = 0
```

Guarded 仍展示 Approval 控件；Autonomous 展示 PolicyPreAuthorization，不出现伪造审批人。

## 8. 验收

- Autonomous 连续三轮：PreAuthorization 有效、ApprovalRecord 0、三步 Execution、6/6 Verification、Audit VALID、CLOSED、无跨轮污染；
- Guarded 三轮继续在 `WAITING_APPROVAL` 中断，审批前 Mock 不变；
- Official、生产环境、未授权场景、非法动作、明文 Secret、目标越界、禁用配置全部 DENY；
- Verification failure 保持 ROTATED 并进入 Replan。

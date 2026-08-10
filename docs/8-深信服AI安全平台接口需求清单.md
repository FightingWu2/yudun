# 御盾智核 × 深信服 AI 安全平台接口需求清单

## 1. 文档目的与当前状态

本文可直接发送给企业指导老师，用于确认比赛环境中可提供的模型、告警、证据与沙箱处置能力。

当前真实状态：`PENDING EXTERNAL INTERFACE`。项目没有深信服接口文档、测试账号、Endpoint 或授权范围，因此未伪造任何平台调用；现有系统已经冻结外部数据转换和沙箱工单的最小 Adapter Contract。

## 2. 项目架构简介

御盾智核是面向云服务商安全运营团队的 API 凭据安全事件多智能体协作响应系统。系统以 Evidence 为事实依据，以受限 Agent 完成调查和溯源，以确定性 Policy、审批/预授权、受控执行和 Verification 完成安全闭环。

外部平台接入必须经过以下路径：

```text
深信服 Alert / Evidence
→ Adapter 转换
→ RawEvent / EvidenceReference / SecuritySignal
→ AgentTask + Tool ACL
→ Fact Validator
→ Policy
→ Approval 或 Sandbox PreAuthorization
→ Controlled Executor
→ Verification + Audit
```

外部接口不能绕过 Evidence、Fact Validator、Tool ACL、Event State Manager 或 Policy。

## 3. 为什么需要平台接口

- Model API：验证真实垂域模型能否稳定生成符合 Pydantic Schema 的调查计划与 Finding。
- Alert / Evidence API：把企业平台告警和 NTA 证据转换为系统现有数据对象，证明可接入真实安全运营数据。
- Action / Workorder API：仅在企业明确提供比赛沙箱、动作白名单和授权后，验证受控处置工单；当前禁止生产写操作。

## 4. 最低可行接入等级

| 等级 | 企业方提供 | 比赛可证明内容 | 当前代码准备度 |
| --- | --- | --- | --- |
| Level A | Model API only | 真实模型结构化分析与失败降级 | `ModelAdapter` 已就绪，待凭据与 Endpoint |
| Level B | Model + Alert/Evidence | 企业告警/证据进入多智能体调查并可回查 | `EnterpriseAlertEvidenceAdapter` Contract 已冻结 |
| Level C | Model + Evidence + Action Sandbox | 在企业比赛沙箱中完成受控工单与状态回读 | Sandbox Action Contract 已冻结；需单独安全评审 |

建议企业方优先提供 Level A；若时间允许再推进 Level B。Level C 不能以生产写权限替代比赛沙箱。

## 5. Alert API 需求

请确认：

- Endpoint、HTTP 方法、分页/游标机制、时间范围过滤方式；
- 告警唯一 ID、发生时间、租户/资产引用、严重级别、告警类型、规则 ID/版本；
- 来源 IP、目标 IP、协议、端口、会话/Flow ID 等可用字段；
- 告警与原始证据的关联 ID；
- 告警状态、误报标识、更新时间及幂等语义；
- 是否提供 Webhook；如提供，请说明签名与重放防护。

告警名称或模型文字不会直接成为 `ConfirmedFact`，必须形成可回查的 `EvidenceReference` 并经过确定性验证。

## 6. Evidence / NTA API 需求

请确认：

- 是否可按 Alert ID、Flow ID、Packet ID、时间窗查询；
- 是否返回 PCAP/PCAP-NG、Flow、HTTP、DNS、TLS metadata 或脱敏 Payload；
- 原始证据下载是否有临时 URL、过期时间和完整性 Hash；
- Packet/Flow 定位方式是否稳定；
- 敏感字段是否已脱敏、字段级访问权限和审计记录；
- 单次响应上限、最大时间窗、数据保留周期。

系统需要把平台定位信息保存为安全 locator，而不是只保存平台摘要文本。

## 7. Model API 需求

请提供或确认：

- OpenAI-compatible 与否；Base URL、模型 ID、鉴权 Header；
- 是否支持 JSON Schema / structured output；
- 最大输入、最大输出、超时、并发、速率限制；
- 是否存在垂域安全 GPT/模型及可用版本；
- 数据是否出域、是否留存、日志保留策略；
- 比赛现场的 IP 白名单、网络依赖和离线替代方案；
- 错误码、重试建议、服务可用时间。

模型输入不包含明文 API Key、SECRET Evidence 或隐藏推理；输出必须通过 Pydantic 校验后才能进入业务服务。

## 8. Action / Workorder API 需求

当前只申请了解或接入比赛沙箱能力。请确认：

- 是否提供独立 Sandbox Tenant/Resource；
- 允许动作白名单与目标资源范围；
- 是否支持创建工单而非直接执行；
- 幂等键、请求 Digest、异步状态查询、UNKNOWN 状态处理；
- 执行前授权机制与审计字段；
- Before/After 状态回读接口；
- 回滚、超时和失败语义。

本项目当前动作白名单只有：`FREEZE_OLD_KEY`、`CREATE_NEW_KEY_VERSION`、`UPDATE_CI_BINDING`。在没有比赛环境、明确授权和接口文档前，不会发送真实写请求。

## 9. 认证与秘密管理

请说明 OAuth2、API Token、AK/SK、mTLS 或其他方式，以及 Token 生命周期、轮换方法、最小权限 Scope 和测试凭据申请流程。凭据必须通过环境变量或秘密配置提供，不写入源码、日志、Audit 或 Fixture。

## 10. 测试环境与数据

请提供：

- 测试环境访问时间、区域、租户与可重置性；
- 脱敏样例请求/响应；
- Schema/字段字典；
- 可用于联调的 Alert ID、Evidence ID 和预期结果；
- 是否允许保存脱敏响应作为比赛回归 Fixture。

## 11. 字段映射最低要求

| 平台字段类别 | 映射目标 | 最低要求 |
| --- | --- | --- |
| 告警身份与时间 | `RawEvent` / `SecuritySignal` | 唯一 ID、UTC 时间、类型、严重级别 |
| 证据定位 | `EvidenceReference` | 平台记录 ID、可回查 locator、完整性 Hash |
| 网络上下文 | `NetworkFlow` / HTTP / DNS | 五元组或平台 Flow ID、协议与时间 |
| 模型结果 | Agent 结构化输出 | JSON Schema 可校验，不直接写 Fact |
| 沙箱工单 | `ActionRequest` / Receipt | 请求 ID、Digest、幂等键、状态与回读引用 |

平台原字段可保存在 `metadata` 的非核心扩展部分，但核心字段不能只塞入未类型化字典。

## 12. 调用限制与可靠性

请明确 QPS/TPM、并发、超时、重试、分页大小、日配额、维护时间、错误码与服务降级建议。对于写操作，网络超时后系统会标记 `UNKNOWN` 并先回读状态，不盲目重试。

## 13. Sandbox 写操作确认

需要企业方书面确认以下问题：

1. 是否提供明确标识的比赛 Sandbox；
2. 允许的动作、目标和时间窗；
3. 是否禁止访问任何生产租户；
4. 是否提供一键 Reset；
5. 是否允许零人工预授权实验；
6. 谁负责批准比赛前联调。

## 14. 比赛现场网络条件

请确认比赛现场是否允许公网、是否需要代理/VPN/IP 白名单、DNS/证书限制、可开放端口和现场断网预案。御盾智核本地确定性路径可离线运行；真实模型/企业平台能力必须根据现场网络单独标识。

## 15. MCP / OpenAPI 支持

请确认是否提供 OpenAPI 3.x 文档、SDK 或 MCP Server。优先采用稳定 OpenAPI/HTTP 接口；只有当平台已提供受治理 MCP Server 且工具 Schema、权限和审计语义明确时才接入 MCP，不为了技术展示强行转换。

## 16. 企业方需回复的最小信息

- 可提供的接入等级：A / B / C；
- 接口文档与样例；
- 测试环境、鉴权方式和可用期限；
- 数据与模型的安全/留存要求；
- 比赛现场网络要求；
- Sandbox 写操作是否允许及授权人；
- 技术联系人与联调时间窗。

## 17. 当前结论

`SANGFOR PLATFORM INTEGRATION = PENDING EXTERNAL INTERFACE`。

项目已具备最小 Adapter 边界，但真实接入只有在收到企业接口、测试环境和授权后才能标记为完成。任何内部 Mock、Deterministic Test Model 或本地 Tool 均不会包装成“已接入深信服平台”。

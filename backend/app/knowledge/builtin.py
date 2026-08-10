"""Built-in security knowledge base for the Security Knowledge RAG.

Every entry is a plain dict so it can be loaded without the ORM/Pydantic
stack. Entries deliberately follow the project's Golden Path scenario:
CI/CD supply-chain mutation, API-credential exposure, and cloud API abuse.

Content constraint: entries must never contain plaintext-secret patterns
such as ``access key: <value>`` because the project's ``StrictSchema``
rejects them. Keep technical terms in prose form.
"""

from __future__ import annotations

BUILTIN_DOCUMENTS: list[dict[str, object]] = [
    # ------------------------------------------------------------------ ATT&CK
    {
        "doc_id": "kno-attack-t1078",
        "category": "ATTACK_TECHNIQUE",
        "doc_type": "playbook",
        "title": "ATT&CK T1078 有效账号（Valid Accounts）",
        "tags": ["T1078", "有效账号", "凭据", "认证", "ATTACK"],
        "content": (
            "有效账号指攻击者使用合法账号与凭据进入系统，规避大多数访问控制。"
            "在云环境中，泄露的访问密钥（Access Key / Secret Access Key）与临时令牌都可被归类为有效账号滥用。"
            "检测重点是发现凭据来源与预期身份不符：例如 CI Runner 使用应用内环境变量中的密钥发起云 API 调用。"
            "应对措施包括最短凭据有效期、来源 IP 白名单、异常地理位置告警与即时轮换。"
        ),
        "source": "MITRE ATT&CK v15",
        "version": "1.0",
    },
    {
        "doc_id": "kno-attack-t1110",
        "category": "ATTACK_TECHNIQUE",
        "doc_type": "playbook",
        "title": "ATT&CK T1110 暴力破解（Brute Force）",
        "tags": ["T1110", "暴力破解", "口令", "认证爆破"],
        "content": (
            "暴力破解通过重复尝试口令或密钥来获取访问权限，常见形式为口令猜测、口令喷洒与密钥枚举。"
            "云 API 场景中表现为高频失败认证请求后紧跟成功登录。"
            "检测信号包括相同来源的大量 AUTH_FAILED 事件、失败/成功比例突变。"
            "处置上应启用账户锁定、多因素认证、异常登录分析与临时来源封禁。"
        ),
        "source": "MITRE ATT&CK v15",
        "version": "1.0",
    },
    {
        "doc_id": "kno-attack-t1195",
        "category": "ATTACK_TECHNIQUE",
        "doc_type": "playbook",
        "title": "ATT&CK T1195 供应链投毒（Supply Chain Compromise）",
        "tags": ["T1195", "供应链", "CI", "Action", "投毒"],
        "content": (
            "供应链投毒指攻击者篡改开发或交付链中的组件、构建脚本或第三方动作。"
            "典型场景是 CI Action 引用被替换为含恶意逻辑的版本，导致构建过程窃取环境变量中的凭据。"
            "检测方法包括动作哈希固定与比对（expected digest 对 observed digest）、"
            "依赖清单审计、以及发布物签名校验。发现篡改后应立即回滚版本并轮换受影响凭据。"
        ),
        "source": "MITRE ATT&CK v15",
        "version": "1.0",
    },
    {
        "doc_id": "kno-attack-t1190",
        "category": "ATTACK_TECHNIQUE",
        "doc_type": "playbook",
        "title": "ATT&CK T1190 利用公开应用（Exploit Public-Facing Application）",
        "tags": ["T1190", "漏洞利用", "公开应用", "RCE", "webshell"],
        "content": (
            "利用公开应用指攻击者通过 Web 应用或组件的已知漏洞获得初始访问，"
            "常见形式包括 SQL 注入、命令注入、反序列化漏洞与后门 Webshell。"
            "检测规则覆盖 SQL 注入特征、命令执行原语、Webshell 控制特征与回连域名（如 DNSLog）。"
            "处置重点为修复漏洞、隔离受影响主机、清除后门并审计受害期间的凭据与敏感数据访问。"
        ),
        "source": "MITRE ATT&CK v15",
        "version": "1.0",
    },
    {
        "doc_id": "kno-attack-t1496",
        "category": "ATTACK_TECHNIQUE",
        "doc_type": "playbook",
        "title": "ATT&CK T1496 资源劫持（Resource Hijacking）",
        "tags": ["T1496", "资源劫持", "挖矿", "高成本资源", "GPU"],
        "content": (
            "资源劫持指攻击者利用已控制凭据创建高成本计算资源（如 GPU 集群、云主机）用于牟利。"
            "云 API 滥用检测重点关注异常的 CREATE 操作、成本等级为 HIGH 的新资源、以及来源与 CI 出口不符的调用。"
            "应对措施为停止未授权资源、吊销凭据、核查账单异常并补充资源配额上限。"
        ),
        "source": "MITRE ATT&CK v15",
        "version": "1.0",
    },
    {
        "doc_id": "kno-attack-t1530",
        "category": "ATTACK_TECHNIQUE",
        "doc_type": "playbook",
        "title": "ATT&CK T1530 未保护敏感数据（Data from Cloud Storage Object）",
        "tags": ["T1530", "敏感数据", "对象存储", "数据窃取", "bucket"],
        "content": (
            "未保护敏感数据指攻击者利用泄露的凭据直接读取云对象存储中的敏感对象，"
            "例如客户导出桶（customer export bucket）中的敏感信息。"
            "检测信号包括非预期来源对敏感对象的 READ 操作、批量列举与高吞吐下载。"
            "防护重点是对象级访问控制、敏感数据加密、来源校验与对读取行为的持续审计。"
        ),
        "source": "MITRE ATT&CK v15",
        "version": "1.0",
    },
    # ------------------------------------------------------------ CI 供应链安全
    {
        "doc_id": "kno-ci-action-mutation",
        "category": "CI_SUPPLY_CHAIN",
        "doc_type": "playbook",
        "title": "第三方 CI Action 被篡改的识别与应对",
        "tags": ["CI", "Action", "篡改", "digest", "供应链"],
        "content": (
            "当 CI Action 声明引用的哈希摘要与解析到的实际摘要不一致，说明第三方动作已被篡改。"
            "应视为供应链攻击前兆：攻击者可能借此窃取构建环境中的 API 凭据。"
            "处置流程为停止当前构建、冻结受影响凭据、回滚 Action 版本并通知维护者。"
            "长期修复建议为对动作使用带版本哈希的引用，并启用依赖审查。"
        ),
        "source": "御盾智核处置手册",
        "version": "1.0",
    },
    {
        "doc_id": "kno-ci-secret-env",
        "category": "CI_SUPPLY_CHAIN",
        "doc_type": "playbook",
        "title": "CI 环境变量中的凭据风险",
        "tags": ["CI", "环境变量", "密钥", "凭据", "runner"],
        "content": (
            "CI Runner 将 API 凭据注入环境变量是常见做法，但也扩大了泄露面。"
            "一旦构建脚本或第三方 Action 被篡改，凭据即可被恶意逻辑读取并外传。"
            "降低风险的方式包括使用临时凭据、限制 Secret 可见的作业范围、"
            "对 Secret 访问打审计日志，并避免将长期密钥写入环境变量。"
        ),
        "source": "御盾智核处置手册",
        "version": "1.0",
    },
    {
        "doc_id": "kno-ci-binding",
        "category": "CI_SUPPLY_CHAIN",
        "doc_type": "playbook",
        "title": "CI 与凭据绑定关系及更新",
        "tags": ["CI", "绑定", "凭据", "轮换", "runner"],
        "content": (
            "CI Runner 通过绑定关系引用某个凭据版本。当凭据轮换后，需要同步更新绑定到新版本，"
            "否则合法构建会因旧密钥被禁用而失败。"
            "在处置中，更新 CI 绑定是恢复合法业务的关键步骤之一，需在禁用旧密钥后尽快完成。"
        ),
        "source": "御盾智核处置手册",
        "version": "1.0",
    },
    # ------------------------------------------------------------ 云凭据安全
    {
        "doc_id": "kno-cloud-access-key",
        "category": "CLOUD_CREDENTIAL",
        "doc_type": "reference",
        "title": "云访问密钥（Access Key）与安全使用",
        "tags": ["Access Key", "AK", "SK", "云凭据", "IAM"],
        "content": (
            "云服务商通过访问密钥（Access Key）与秘密访问密钥（Secret Access Key）对调用者鉴权。"
            "长期密钥一旦泄露即等于账户接管，攻击者可读取敏感数据或创建高成本资源。"
            "安全基线为：使用短期临时凭据替代长期密钥、将密钥绑定最小权限策略、"
            "启用密钥轮换与使用审计，并严禁密钥出现在日志、代码仓库或明文配置中。"
        ),
        "source": "御盾智核云安全基线",
        "version": "1.0",
    },
    {
        "doc_id": "kno-credential-leak-path",
        "category": "CLOUD_CREDENTIAL",
        "doc_type": "reference",
        "title": "API 凭据泄露的常见路径",
        "tags": ["凭据泄露", "泄露路径", "CI", "外传"],
        "content": (
            "凭据泄露常见路径包括：被篡改的 CI Action 读取环境变量并外传、"
            "日志与错误信息中包含密钥、依赖组件将配置写入共享存储、以及通过 DNS 或外部回调域名外带。"
            "识别泄露的关键是对照凭据预期来源与实际使用来源，并持续监控外传通道。"
        ),
        "source": "御盾智核云安全基线",
        "version": "1.0",
    },
    {
        "doc_id": "kno-credential-rotation",
        "category": "CLOUD_CREDENTIAL",
        "doc_type": "reference",
        "title": "凭据轮换最佳实践",
        "tags": ["轮换", "rotation", "新密钥", "旧密钥"],
        "content": (
            "凭据轮换应遵循先建后弃的次序：先创建新密钥版本并更新依赖方绑定，"
            "确认合法业务恢复后再禁用旧密钥。禁用旧密钥前需确认其已无合法调用方。"
            "轮换完成后必须验证旧密钥调用被拒绝、新密钥正常生效，防止业务中断。"
        ),
        "source": "御盾智核云安全基线",
        "version": "1.0",
    },
    {
        "doc_id": "kno-iam-least-privilege",
        "category": "CLOUD_CREDENTIAL",
        "doc_type": "reference",
        "title": "IAM 最小权限原则",
        "tags": ["IAM", "最小权限", "least privilege", "策略"],
        "content": (
            "最小权限原则要求每个身份只拥有完成其任务所需的最小权限。"
            "CI 身份通常只需特定资源的读写权限，不应具备创建高成本资源或读取全量敏感数据的权限。"
            "在策略判定中，若请求的动作超出该身份职责，应判定为可疑并需要人工审批。"
        ),
        "source": "御盾智核云安全基线",
        "version": "1.0",
    },
    # ------------------------------------------------------------ 检测规则
    {
        "doc_id": "kno-detect-sensitive-read",
        "category": "DETECTION_RULE",
        "doc_type": "reference",
        "title": "敏感数据读取检测规则",
        "tags": ["检测", "敏感读取", "READ", "对象存储", "数据"],
        "content": (
            "敏感数据读取规则关注来源与资源不匹配的读取操作："
            "当调用来源并非该资源的合法访问方，却对敏感对象执行列举或读取时触发告警。"
            "证据来源包括云审计日志（Cloud Audit）与资源事件，规则按确定性条件评估，不依赖模型判断。"
        ),
        "source": "御盾智核检测规则库",
        "version": "1.0",
    },
    {
        "doc_id": "kno-detect-cost-anomaly",
        "category": "DETECTION_RULE",
        "doc_type": "reference",
        "title": "高成本资源创建检测规则",
        "tags": ["检测", "成本", "资源创建", "CREATE", "GPU"],
        "content": (
            "高成本资源创建规则监测异常的资源 CREATE 操作，重点标记成本等级为 HIGH 的资源类型。"
            "若创建来源与 CI 出口预期不符且资源不在审批清单内，应判定为高风险并进入策略评估。"
            "检测结果必须关联可回查的证据引用，避免仅凭模型文字形成结论。"
        ),
        "source": "御盾智核检测规则库",
        "version": "1.0",
    },
    {
        "doc_id": "kno-detect-cloud-api-anomaly",
        "category": "DETECTION_RULE",
        "doc_type": "reference",
        "title": "云 API 调用异常检测",
        "tags": ["检测", "云API", "异常调用", "来源", "audit"],
        "content": (
            "云 API 异常调用检测比对调用的预期来源与实际来源。"
            "当使用 CI 凭据的调用来自外部来源，或动作类型与身份职责不符，即构成异常信号。"
            "检测需要结合 Cloud Audit 事件与资源事件，形成可回查的证据链。"
        ),
        "source": "御盾智核检测规则库",
        "version": "1.0",
    },
    # ------------------------------------------------------------ 处置手册
    {
        "doc_id": "kno-playbook-leak-response",
        "category": "RESPONSE_PLAYBOOK",
        "doc_type": "playbook",
        "title": "API 凭据泄露应急响应手册",
        "tags": ["应急响应", "处置", "playbook", "凭据泄露"],
        "content": (
            "API 凭据泄露应急响应的标准次序为：停止恶意活动、冻结旧密钥、创建新密钥版本、"
            "更新 CI 绑定、验证恢复（旧密钥拒绝调用、新密钥生效、恶意资源已停止）。"
            "整个过程应留存审计链，并确保任何写操作都经过人工审批或沙箱预授权。"
            "未经验证的处置不能宣称恢复完成。"
        ),
        "source": "御盾智核处置手册",
        "version": "1.0",
    },
    {
        "doc_id": "kno-playbook-freeze-old-key",
        "category": "RESPONSE_PLAYBOOK",
        "doc_type": "playbook",
        "title": "冻结旧密钥操作说明",
        "tags": ["冻结", "freeze", "旧密钥", "禁用"],
        "content": (
            "冻结旧密钥指将泄露的凭据版本标记为禁用，使恶意调用不再被接受。"
            "该操作属于受控写操作，应经人工审批或沙箱预授权后由受控执行器完成。"
            "冻结前应确认合法 CI 已切换绑定到新版本，避免业务中断。"
        ),
        "source": "御盾智核处置手册",
        "version": "1.0",
    },
    {
        "doc_id": "kno-playbook-verify-recovery",
        "category": "RESPONSE_PLAYBOOK",
        "doc_type": "playbook",
        "title": "恢复验证断言",
        "tags": ["验证", "恢复", "断言", "verification"],
        "content": (
            "恢复验证通过确定性断言确认处置有效，典型断言包括旧密钥已禁用、"
            "旧密钥调用被拒绝、恶意活动已停止、新密钥生效、合法 CI 恢复、高成本资源已停止。"
            "六项断言全部通过方可认为恢复完成并进入审计关闭。"
        ),
        "source": "御盾智核处置手册",
        "version": "1.0",
    },
    # ------------------------------------------------------------ 云滥用
    {
        "doc_id": "kno-cloud-abuse-pattern",
        "category": "CLOUD_ABUSE",
        "doc_type": "reference",
        "title": "云 API 滥用典型模式",
        "tags": ["云滥用", "credential stuffing", "资源创建", "数据窃取"],
        "content": (
            "云 API 滥用典型模式包括：使用泄露凭据进行批量数据读取、创建高成本资源、"
            "以及在云环境内部横向探测。识别滥用需要把认证来源、资源操作与成本信号关联起来。"
            "任何疑似滥用都必须落到可回查的证据，而不是模型的主观判断。"
        ),
        "source": "御盾智核威胁情报",
        "version": "1.0",
    },
    {
        "doc_id": "kno-evidence-audit",
        "category": "CLOUD_ABUSE",
        "doc_type": "reference",
        "title": "证据链与审计完整性要求",
        "tags": ["证据", "审计", "完整性", "chain", "回查"],
        "content": (
            "证据链要求每个事实都能回溯到可回查的证据引用，审计记录采用追加式账本并校验完整性。"
            "知识检索结果只作为参考材料，不能直接成为攻击事实或授权依据；"
            "模型输出必须通过结构化校验后才能进入业务服务。"
            "关闭事件前必须确认审计链完整有效。"
        ),
        "source": "御盾智核审计基线",
        "version": "1.0",
    },
]

BUILTIN_DOCUMENT_IDS = frozenset(
    item["doc_id"] for item in BUILTIN_DOCUMENTS if isinstance(item.get("doc_id"), str)
)

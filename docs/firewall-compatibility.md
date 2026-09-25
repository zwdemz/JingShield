# 防火墙厂商兼容性与接入证据

核验日期：2026-09-25。本文只记录本仓库实际能力、官方接口证据及接入条件，不表示已连接任何生产防火墙，也不提供未经对应固件确认的 CLI 命令。

## 1. 支持状态不能混用

“同协议桥接已实现”“厂商文档存在”“实机流量已阻断”是三个不同结论。界面中的厂商名称只是设备标记，不会自动安装原生驱动。当前联动状态返回 `integration_mode=same_protocol_adapter_only`。

| 对象 | 本仓库已实现与验证边界 | 实机验证 | 仍需完成 |
| --- | --- | --- | --- |
| 捷云鲸盾对端、实现 `jingshield-v1` 的 WAF/防火墙桥接端 | HTTPS 能力握手、认证、最多 500 项批量请求、结果校验、审计；已有 mock 与 handler 回归 | 未验证真实网络阻断 | 部署可信证书、配置专用凭据，核验对端规则与业务流量路径 |
| Cisco 本地 FMC 7.4.1 / 7.6.0 管理的设备 | 已核验官方认证说明；没有 Cisco 原生适配器 | 未验证 | 域/组/策略/设备映射、增量更新、部署任务跟踪及回滚 |
| 华为云 CFW | 已核验 `ImportIpBlacklist` 与认证说明；没有 CFW 原生适配器 | 未验证 | 区域与实例权限、增量导入、效果范围、读回、期限管理 |
| 华为本地 USG / HiSecEngine | 产品系列存在独立 API 文档；没有本地设备适配器 | 未验证 | 对应固件 NETCONF/RESTCONF/API 模型、提交语义和策略关联 |
| 奇安信/网神及用户称为“360”的设备 | 未取得与具体设备版本匹配的完整鉴权及写入契约；没有原生适配器 | 未验证 | 确认实际厂商、型号、固件和官方 API 开发指南 |
| 中兴设备 | 官方部分产品说明有北向接口能力；没有通用中兴防火墙驱动 | 未验证 | 指定产品/控制器/固件的接口或命令参考与配置提交语义 |

Linux `nftables` / `ipset` 专用桥接是单独交付项，其源码、mock 测试和部署状态以 [Linux 防火墙桥接部署说明](../deploy/firewall/README.md) 为准；不得据此宣称已完成上述商业厂商原生对接，或已验证 NAS/Linux 内核上的流量阻断。

## 2. 当前可用的同协议边界

实现位置：`internal/operations/linkage.go`、`internal/operations/types.go`、`internal/api/ip_batch.go`。相关回归位于 `internal/operations/operations_test.go` 与 `tests/internal/api/block_batch_handlers_test.go`。

### 2.1 传输、认证与能力握手

- 管理端只接受显式配置的 HTTPS 根地址；禁止 URL 内嵌凭据、路径、查询和重定向。TLS 最低 1.2，必须校验证书及名称；不提供跳过验签选项。
- 凭据只通过 `JINGSHIELD_LINKAGE_` 前缀的专用环境变量引用注入，调用头为 `X-API-Key`。这是捷云鲸盾桥接协议，不是任何厂商原生认证方式。
- `GET /openapi/v1/capabilities` 只核验认证与声明的能力，不改变策略、不证明拦截生效。每次下发前重新握手。
- `protocol` 必须为 `jingshield-v1`；`device_type` 必须与配置的 `waf` 或 `firewall` 一致；必须声明 `block-batch`。本地硬上限为 500，若对端声明更低上限，还需遵守该上限。

以下是协议响应格式，不是任何厂商已经返回过的实机证据：

```json
{
  "code": 0,
  "data": {
    "protocol": "jingshield-v1",
    "device_type": "firewall",
    "capabilities": ["block-batch"],
    "max_batch_size": 500
  }
}
```

### 2.2 批量请求及结果约束

`POST /openapi/v1/ip/block-batch` 接受 `ips`、`reason`、`expire_seconds`。每次原始提交为 1–500 项，重复项也占用提交上限；只允许独立 IPv4/IPv6 地址，不接受 CIDR、通配符或命令文本。归一化后去重；原因必填且不得含 CR、LF 或 NUL；`expire_seconds=0` 表示永久，非零为临时期限。

同协议返回须同时满足 HTTP 200、`code=0`、非空数据，以及以下计数一致性：

```text
requested = 原始提交项数
unique = 规范化后的唯一 IP 数
blocked + skipped_whitelist = unique
len(skipped_ips) = skipped_whitelist
```

`skipped_ips` 只能包含本批次内、无重复的地址。适配器不得把“请求发出”“对象保存”“任务受理”记作 `blocked`。本地白名单、厂商白名单、管理来源地址与保留业务网段应在实际执行层保护，不能只依赖浏览器提示。

现有客户端请求时限为 1–10 秒，网络超时、非 200、结果不一致或结果审计失败均不自动重发。厂商若异步部署超过该预算，需要另行设计任务查询/确认契约；当前同协议接口未实现厂商异步部署跟踪，不能将厂商 HTTP 202 包装成成功批量计数。

## 3. Cisco：区分 FMC、FDM 与云托管接口

### 3.1 已核验的认证版本

本地 FMC **7.4.1** 和 **7.6.0** 指南均说明：以 Basic 认证调用 `POST /api/fmc_platform/v1/auth/generatetoken`，请求体留空；随后通过 `X-auth-access-token` 访问资源，并使用返回的 `Domain_UUID`。刷新路径是 `/api/fmc_platform/v1/auth/refreshtoken`，需要 access/refresh 两个 token 头。这不是把所有 Cisco 产品统一配置为 OAuth2 的依据。[FMC 7.4.1 认证说明](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_741/Connecting_With_A_Client.html)、[FMC 7.6.0 认证说明](https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760/Connecting_With_A_Client.html)。

本项目的接入要求是独立最小权限 API 账户、可靠的证书信任和密钥托管；不得将文档中浏览器接受证书警告的步骤转换成适配器永久关闭 TLS 验证。

### 3.2 NetworkGroup 必须使用已确认的增量语义

Cisco DevNet 的 FMC `updateNetworkGroup` 文档给出 `PUT /api/fmc_config/v1/domain/{domainUUID}/object/networkgroups/{objectId}`，并明确 `action=add` 为追加、`action=remove` 为移除。集成实现应在确认目标版本支持后使用 `?action=add`；不能拿仅包含新增 IP 的普通 PUT 覆盖已有组。[官方 updateNetworkGroup 契约](https://developer.cisco.com/docs/fmc-ansible/updatenetworkgroup/)。

该 DevNet 操作页面没有标注与用户设备相同的完整固件构建号。因此，认证版本已核验不等于所有对象操作已在该固件实测。接入前需从目标 FMC 的 API Explorer 导出该操作的参数、返回值和版本，并确认该组确实被目标设备的阻断策略引用。只增加一个未被策略引用的网络对象组，不构成业务流量阻断证据。

### 3.3 部署受理不等于部署成功

FMC 官方操作说明将 `createDeploymentRequest` 定义为向设备发起配置部署请求，路径为 `/api/fmc_config/v1/domain/{domainUUID}/deployment/deploymentrequests`。[官方 FMC 部署操作](https://developer.cisco.com/docs/fmc-ansible/createdeploymentrequest/)。

公开可读取的 **云托管 cdFMC API 1.17.0** 完整 schema 明确返回 HTTP 202，并提供 `metadata.task.id`/任务状态链接；它的云端路径与鉴权不能直接移植为本地 FMC 7.4.1/7.6.0 契约。无论目标版本是否使用 202，都必须分别记录“受理”“任务完成”“逐设备结果”；本地版本的状态字段与终态以其 API Explorer 为准。[Cisco cdFMC Create Deployment Request](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/create-deployment-request/)。

未来适配器验收还须确认策略部署对象、任务失败详情、管理连接未受影响及受控验证流量命中目标规则。不能默认启用强制部署或忽略所有警告，也不能把组写入成功直接返回为封禁成功。

## 4. 华为：云 CFW 与本地 USG 分开适配

### 4.1 华为云 CFW 已核验字段

官方 `ImportIpBlacklist` 路径为 `POST /v1/{project_id}/ptf/ip-blacklist/import`，查询参数包含 `fw_instance_id`。必须显式指定 `add_type=0` 才是增量导入；`1` 会覆盖旧黑名单。`ip_blacklist` 是字符串，`effect_scope` 是整数数组：`[1]` 为 EIP，`[2]` 为 NAT，`[1,2]` 为两者。不得把数组写成单个数字或照抄官方“全量导入”示例。[华为云 ImportIpBlacklist](https://support.huaweicloud.com/api-cfw/ImportIpBlacklist.html)。

CFW 官方认证文档同时支持 Token 和 AK/SK，并推荐 AK/SK。未来适配器应使用官方签名 SDK，确认项目、区域、IAM 权限和时钟；临时 AK/SK 还需要安全令牌。不能只发送一个名为 AK 的普通头，也不能把捷云鲸盾的 `X-API-Key` 当成华为云签名。[CFW 认证鉴权](https://support.huaweicloud.com/api-cfw/cfw_02_0009.html)。

导入后应使用官方 `ListIpBlacklist` 读回目标实例条目，并结合实际防护范围核验。上述导入接口文档没有提供捷云鲸盾 `expire_seconds` 的等价逐 IP TTL 字段；适配器必须额外实现可审计期限管理，或明确拒绝不支持的临时封禁，不能静默变成永久封禁。[华为云 ListIpBlacklist](https://support.huaweicloud.com/api-cfw/ListIpBlacklist.html)。

### 4.2 本地 USG 不能套用云接口

华为企业支持页面分别列出 USG 对应固件的 NETCONF/RESTCONF API 开发指南，例如 USG6000E V600R007C20；这是另一条产品接口线。本文不据目录标题猜测其 RPC、YANG 路径、认证方式或提交命令，也不把 CFW 的区域 Endpoint、AK/SK 和 `fw_instance_id` 用于本地设备。[华为 USG 产品及版本文档入口](https://info.support.huawei.com/enterprise/en/security/usg6625e-pid-250510912)。

## 5. 奇安信 / 用户称“360”的设备：目前不能宣称原生兼容

官方可核验的[网神新一代智慧防火墙产品页](https://www.qianxin.com/product/detail/pid/341)描述协同管理能力；[奇安信产品文档入口](https://www.qianxin.com/support/product)与[资料下载中心](https://download.qianxin.com/)提供产品资料渠道。但是本次公开核验未取得与指定设备固件相匹配、包含完整鉴权 schema 与黑名单增量写入/回读操作的正式 API 指南正文。

这不是“厂商没有 API”的结论，而是本次证据不足。白皮书、下载目录或一个《API 开发指南》标题不能证明具体 token 头、签名算法、URL 路径及部署生效语义。“360”亦不足以唯一确定当前产品归属、网神/网康系列或软件版本。

因此，当前只能经另行开发并验证的 `jingshield-v1` 适配器接入，不能把厂商原生管理地址直接填入联动地址。还需设备铭牌/型号、固件构建、对应官方指南文件或可访问下载链接、认证章节、追加/撤销/查询黑名单的请求响应及策略关联证据。凭据应通过安全配置通道提供，不放入文档、聊天、测试夹具或 Git。

## 6. 中兴：有北向接口说明不代表存在通用封禁命令

[中兴 USC 控制器官方产品说明](https://www.zte.com.cn/china/enterprisesolution/enterprise_network/Relate_Products/Router/zte_usc.html)提到 REST API 北向能力；[中兴 ZXSG SVFW-S 产品说明](https://sdnfv.zte.com.cn/zh-CN/products/VNF/vcube/zxsg-svfw-s)说明的是特定虚拟防火墙产品。它们不能证明其他型号共享同一黑名单接口，更不能用控制器 API 或云平台认证推导硬件防火墙 CLI。

本次未核验到与用户具体型号/固件对应的完整封禁写入契约。原生中兴适配器状态为“待资料与实现”，不提供猜测的 `configure`、ACL、保存或提交命令。需要用户/厂商提供准确型号、固件、管理控制器、虚拟系统/安全域、接口或命令参考，以及变更提交和 HA 同步方式。

## 7. 从文档证据到实机验收

所有新厂商适配器都应分三阶段验收，不能把阶段一结果标记为阶段三：

1. **源码与模拟验证**：认证头/签名、500 项边界、IPv4/IPv6 归一化、白名单、增量更新、超时、部分失败、异步部署、重复请求、结果校验与日志脱敏。
2. **隔离设备验证**：指定型号/固件/租户或安全域、专用地址组、专用策略引用、证书与最小权限、追加前后读回、提交任务、到期撤销及回滚；保留版本与响应证据。
3. **业务路径验证**：在明确授权的测试窗口，用受控地址验证规则计数/日志与实际流量，确认访问确实穿过设备；检查 NAS 管理、音乐、下载、内网 DNS 与既有远程连接均未误伤。

正式接入前的最小输入清单：

| 类别 | 必须提供的非秘密信息 |
| --- | --- |
| 设备身份 | 厂商、完整型号、管理产品名称、固件/控制器版本及补丁号 |
| 作用域 | FMC Domain UUID；CFW 区域/project/instance；或设备租户、虚拟系统、安全域 |
| 策略映射 | 专用地址组 ID、引用它的阻断策略 ID/规则序号、部署目标与实际流量入口 |
| API 证据 | 对应版本官方指南、认证 schema、增量/查询/撤销/任务状态示例、限额和失败语义 |
| 安全保障 | 受信任 CA、管理地址及来源白名单、预留控制台、维护窗口、备份与回滚责任人 |
| 封禁期限 | 永久/临时、到期责任、已有更长期限的保留规则、适配器重启后的恢复行为 |

日志路径与封禁路径始终分离：syslog 发送成功只证明传输层完成；API HTTP 成功只证明接口响应；只有设备配置、部署结果和实际业务路径的联合证据，才能支持“已有效阻断”的结论。

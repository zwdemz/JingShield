# WAF 运营、行为防护与同步

## 本次能力与边界

控制台沿用现有主题，页面标题统一为紧凑的 20px 层级；大尺寸交互区域用于真正的引擎开关，而不是标题留白。原独立 WAF 状态页按职责并入相关功能，旧 `/admin/waf-status` 地址重定向到系统状态。

- 攻击事件：完整 IPv4/IPv6、按段前缀、CIDR 检索，服务端分页与 IP 画像，过期请求取消。
- 防护配置：兼容优先/标准/严格三级预设，逐引擎启停，行为观察/拦截及有界阈值。
- 系统状态：本机运行环境、资源告警阈值、WAF 总状态、进程运行时间、状态后端与防护站点。
- 防护配置：引擎实际运行状态；访问审计：评估/挑战/拦截计数与审计追加队列；攻击事件：行为检测计数。
- 安全设备联动：Syslog 配置、同步状态、同协议封禁与白名单快照下发。
- 本地与同协议对端批量封禁：原始提交最多 500 项，前后端双重校验，白名单跳过、操作审计。
- Syslog：RFC5424，UDP/TCP/TLS，持久有界队列、重试、失败保留和手动重试。
- Linux 防火墙：独立 HTTPS 桥接器，nftables/ipset 专用集合；默认预览、不修改内核规则，真实应用须显式启用。安装与回滚见[Linux 联动部署](../deploy/firewall/README.md)。

同产品联动是**单个已配置对端的显式批量 IP 处置同步**，不是全配置、管理员账号、证书、站点或策略数据库复制，也不会因为打开 syslog 就自动下发封禁。

厂商原生 API 与 `jingshield-v1` 不是同一个协议；360 网神、华为、中兴、思科的品牌选项只标识专用适配器，不能据此判定可直接对接原生设备。详见[兼容性与核验清单](firewall-compatibility.md)。

## 模块

| 模块 | 职责 |
| --- | --- |
| `internal/config/protection.go` | 真实引擎目录、预设、边界校验、有效配置快照 |
| `internal/protection/detector/scanner.go` | 按站点及来源隔离的高置信行为关联 |
| `internal/store/{memory,redis}/behavior.go` | 原子窗口及固定过期封禁 |
| `internal/repository/ip_batch.go` | 原子名单变更及处置审计 |
| `internal/repository/attack_ip.go` | IP 画像查询 |
| `internal/operations/` | 日志投递和同协议联动；传输结果与处置结果分离 |
| `internal/api/` | Session/CSRF 或 API Key 边界、参数接收和响应 |
| `web/src/views/WAFStatusView.vue` | 独立运行状态、syslog 与联动设置 |
| `web/src/components/BatchBlockDialog.vue` | 本地与对端共用的 500 项确认窗口 |

## 行为与等级

行为状态按规范化的 **Host（含端口）+ IP** 隔离，不再通过浏览器指纹将不同 IP 连坐。普通下载的 `.zip`、`.bak`、`.sql` 后缀、音乐路径或普通备份目录不单独作为扫描证据。

敏感探测达到阈值，且存在两类敏感路径或明确扫描客户端特征时触发；只有一类探测时须达到两倍阈值。阈值是次数，不是机器学习概率。临时阻断不因继续请求而延长，到期后重新累计。

| 设置 | 兼容优先 | 标准 | 严格 | 可单独配置范围 |
| --- | --- | --- | --- | --- |
| CC 次数/60 秒 | 300 | 100 | 60 | 1–1,000,000 次 |
| 行为窗口 | 300 秒 | 300 秒 | 300 秒 | 10–3,600 秒 |
| 行为阈值 | 16 | 8 | 4 | 2–1,000 |
| 行为阻断期限 | 300 秒 | 600 秒 | 1,800 秒 | 10–86,400 秒 |
| 行为处置 | 观察 | 拦截 | 拦截 | `observe` / `block` |

三个等级均启用 CC/XSS/SQL/路径穿越/SSRF/XXE/行为/自定义策略八个已实现引擎。等级不会改变 WAF 总开关、海外 IP 策略、syslog 或设备联动。没有运行实现的文件校验不作为引擎卡片提供。

预设与明确覆盖项在一个事务中保存，提交成功才替换进程配置快照。独立开关或阈值偏离预设时显示“自定义”。关闭总开关时应区分“配置已启用”与“当前未生效”。

`observe` 命中保存为观察事件（`status=2`），本身不阻断，也不阻止后续其它引擎拦截真正攻击。状态后端故障时行为模块限时 200ms 失败放行，并增加 `state_errors_total`；其它引擎仍继续。`state_available` 表示后端实现了行为接口，不是实时 Redis 连通性健康探测。

Redis 由 `JINGSHIELD_REDIS_URL` 选择。内存模式仅当前节点共享，重启不保留行为窗口；Redis 模式可多节点共享。所有页面运行计数均为当前进程计数，不是永久累计。

## 攻击 IP 检索

`ip_mode` 支持：

- `exact`：完整地址，如 `203.0.113.8`、`2001:db8::1`，映射 IPv4 规范化为原生 IPv4。
- `prefix`：按地址段边界，如 `203.0.113.`、`2001:db8:`；内部转换为数值区间，不能注入 SQL 通配符。复杂压缩 IPv6 前缀请改用 CIDR。
- `cidr`：如 `203.0.113.0/24`、`2001:db8::/48`，按网络边界规范化。

精确 IP 使用现有 `(ip, created_at)` 索引。CIDR/前缀需要 `INET6_ATON` 数值比较，可能扫描更多数据，建议同时指定起止时间。列表和画像查询有 5 秒超时，取消旧查询不应被当成错误提示。

当前历史库按**每日 IP + 攻击类型**聚合，不是逐请求明细：次数是匹配聚合行的累计次数，Host 是聚合行最后记录的 Host；时间筛选以聚合行创建时间为准。画像 `last_seen` 优先读取事件编号索引的最近时间，旧数据回退到创建时间。不要把聚合统计解释为任意秒级窗口的精确流量。

## 批量封禁

每次提交 1–500 个独立 IP；**先检查原始数量，再规范化去重**，501 个重复 IP 也会被拒绝。IPv6 与 IPv4 映射地址去重，禁止 CIDR/范围/通配符、回环、组播、未指定地址及链路本地地址。

必须填写原因（1–255 UTF-8 字节，不接受换行/NUL）。`expire_seconds=0` 为永久，1–31,536,000 为临时。已有永久或更长的封禁不会被重试缩短。若对端声明更小的 `max_expire_seconds`，下发前按对端上限校验；ipset 桥接器上限为 2,147,483 秒。

本地事务先锁定白名单并检查 IP/CIDR/通配符命中，再更新名单及 `jyj_ip_action_log`。数据库或审计失败时整批回滚，不返回部分成功。封禁结果分别提供原始数、去重数、已封禁数和白名单跳过项。返回成功代表名单已写入，不代表经过了实际流量验证。

## Syslog 配置与同步

默认关闭，在“安全设备联动”页设置：传输协议、`host:port`、TLS 服务名、facility、超时、重试次数与队列容量。

- TLS 默认校验系统信任链和主机名，最低 TLS 1.2，不提供跳过证书验证选项。私有 CA 应在运行节点/容器中由管理员安装。
- TCP/TLS 使用 octet-count framing；UDP 只表示一次尽力发送，不能保证接收。
- 外发字段只有事件编号、投递编号、来源 IP、攻击类型、严重度、观察/拦截动作与时间。请求体、URI、Host、凭据和请求原文不会外发。
- 本地攻击审计写成功后尝试入 outbox，最多等待 200ms。队列已满/数据库错误会丢弃该次**导出**并计数，本地已持久化的攻击日志仍保留。两者不是同一事务，进程在两步之间崩溃也可能丢导出，不承诺零丢失。
- 仅已成功入队的事件按至少一次传输方式重试。发送成功而数据库确认失败可能重复投递，接收端应按 `delivery_id` 去重（旧事件无该字段时回退 `event_id`）。同一请求的观察与拦截分别投递，原始 `event_id` 保留用于关联本地审计。
- 待发送与失败记录共同占用 1–10,000 的容量。失败次数达到上限后保留记录，勾选“重试失败记录”才重新处理。
- 每条任务有 30 秒租约；进程退出不会清空队列，重启待租约过期后可续传。
- 已损坏、无法解码的队列记录会标记失败并释放租约，保留原记录供排查，不阻塞其余健康消息。
- 页面显示队列/失败记录（数据库状态）和已发送/重试/丢弃（当前进程计数）。“唤醒同步”只唤醒工作器，不代表日志已被接收，更不代表远端封禁。
- 配置约每 10 秒跨节点刷新；共享同一数据库的节点共用一个接收端和 outbox，不是每节点独立 syslog 目标。

## 同协议 WAF / 防火墙

1. 对端须提供 HTTPS `GET /openapi/v1/capabilities` 和 `POST /openapi/v1/ip/block-batch`。
2. 管理员为当前节点注入专用 `JINGSHIELD_LINKAGE_*` 环境变量，值为对端 API Key；界面只保存环境变量名。
3. 选择对端类型 `waf` 或 `firewall`，填写 HTTPS 根地址，不允许 URL 用户信息、查询参数、片段和重定向。
4. 保存后执行能力验证，校验 `jingshield-v1`、设备类型、`block-batch` 能力及对端批量上限。保存配置会清除旧验证状态。
5. 确认本次 IP/原因/期限后才下发；每批下发前再次检查能力。对端响应的去重数、处置数和白名单跳过 IP 必须自洽。
6. 网络失败或结果不确定时不自动重发封禁。先在对端检查结果，避免盲目重复变更。

对端管理 API Key 与本节点管理员 Session 是不同凭据。环境变量密钥变更需要遵循所在容器/systemd 的重启流程；不在浏览器、仓库或数据库中保存密钥正文。

设备日志自动封禁另有独立开关：仅接受经 OpenAPI 鉴权、明确声明同协议和 WAF/防火墙类型的受支持事件。CEF/LEEF/Suricata/Wazuh 和厂商原生日志可归一化保存，但不是可信封禁指令，不能仅凭其中的品牌标签触发封禁。

## API 合同

所有 `/api/v1` 接口需要管理员 Session；写入接口还需要 `X-CSRF-Token`。以下路径均为完整路径：

| 方法/路径 | 输入 | 成功数据/用途 |
| --- | --- | --- |
| `GET /api/v1/protection/settings` | 无 | `profile, profiles, values, engines` |
| `PUT /api/v1/protection/settings` | `profile` 和/或 `values` | 原子应用后的同结构快照 |
| `GET /api/v1/system/waf-status` | 无 | `waf_enabled, started_at, uptime_seconds, state_backend, shared_state, metrics, protection, sites, server_time` |
| `GET /api/v1/attacks` | `ip, ip_mode, attack_type, severity, event_id, start_at, end_at, page, size` | 分页日志；起止时间 RFC3339 |
| `GET /api/v1/attacks/ip-summary` | 完整 `ip`，可选时间范围 | 计数/严重度/时段/类型/站点聚合及名单状态 |
| `POST /api/v1/ip-list/block-batch` | `ips[], reason, expire_seconds` | 原子本地批封结果 |
| `GET/PUT /api/v1/system/syslog` | PUT 为完整配置 | GET 返回 `config,status`；PUT 保存配置 |
| `POST /api/v1/system/syslog/sync` | `retry_failed: boolean` | 唤醒后的配置/队列快照 |
| `GET/PUT /api/v1/system/linkage` | PUT 为完整配置 | GET 返回 `config,status`；PUT 保存并清除旧握手 |
| `POST /api/v1/system/linkage/probe` | 无 | 验证能力，不发送封禁 |
| `POST /api/v1/system/linkage/block-batch` | `ips[], reason, expire_seconds` | 对端确认的批量处置结果 |
| `GET /openapi/v1/capabilities` | `X-API-Key` | 同协议能力声明 |
| `POST /openapi/v1/ip/block-batch` | `X-API-Key` + 批封输入 | 对本节点名单执行原子批封 |
| `GET /api/v1/system/linkage/whitelist/preview` | 管理员会话 | 预览本机手工白名单的规范化快照及 SHA-256 摘要 |
| `POST /api/v1/system/linkage/whitelist/sync` | CSRF + `expected_digest` | 二次核对快照并显式下发；对端必须声明 `whitelist-sync` |
| `POST /openapi/v1/ip/whitelist/sync` | `X-API-Key` + `source/revision/rules` | 按来源原子接收完整白名单快照 |
| `GET /api/v1/ip-list/received-whitelist` | 管理员会话 | 查看各来源已接收版本和规则 |

成功响应统一为 `{ "code": 0, "message": "...", "data": ... }`。格式/边界错误为 400；无 Session/API Key 为 401；CSRF/管理网段失败为 403；运营服务不可用为 503；远端能力/传输/确认失败为 502。系统异常不向客户端返回原生堆栈。

批封输入示例（文档地址，无真实处置）：

```json
{"ips":["203.0.113.8","2001:db8::8"],"reason":"已确认的敏感路径扫描","expire_seconds":600}
```

批封结果示例：

```json
{"requested":2,"unique":2,"blocked":1,"skipped_whitelist":1,"skipped_ips":["2001:db8::8"]}
```

## 数据库与迁移

### 白名单快照协议

在联动页为每个发送节点设置唯一的 `source_id`（1–64 位英数、下划线或短横线，首字符须为英数），保存并探测后预览、确认下发。只导出本机手工白名单，不回传其他节点接收的快照，以免循环放大。单次最多 500 条原始规则；精确 IPv4/IPv6、CIDR 与连续 IPv4 后缀通配符受支持，后者规范化为 CIDR；全网 `/0` 和不连续通配符被拒绝。接收端只替换该 `source_id` 的完整规则集；空数组清空该来源，其他来源和本机手工规则保留。同版本同内容幂等，旧版本或同版本不同内容返回 409。`source_id` 必须保持稳定，改名会产生新来源；受控退役先从旧来源发送空快照。

请求示例：`{"source":"nas_waf_01","revision":1790000000000000,"rules":["192.0.2.1","198.51.100.0/24"]}`。确认结果包含相同的 `source/revision/count/digest`；发送侧核对后才显示成功。发送前后的意图和结果写审计，网络超时或审计失败不能当作“未生效”，需先查接收状态。WAF 当前按**白名单优先**判定：已接收白名单立即覆盖已有黑名单命中，但不删除黑名单记录；从白名单移除后，未过期的旧封禁会再次生效。Linux 桥接器会清理其专属托管集合中与新白名单匹配的封禁，具体见部署文档。

原有业务数据不删除，新迁移幂等执行：

| 表/配置 | 关键字段与索引 | 关系 |
| --- | --- | --- |
| `jyj_ip_action_log` | actor/reason/ips_json/requested/blocked/skipped_whitelist/expire_seconds/created_at；时间索引 | 与本地名单同事务写入的批次审计 |
| `jyj_syslog_outbox` | event_id 列保存唯一投递编号；event_json 含原始事件编号；attempts/next_attempt；lease_token/lease_until；failed；待投递复合索引 | 独立保存已脱敏事件，不依赖聚合日志行继续存在 |
| `jyj_config` | 原有唯一 config_key | 保存两个 operations JSON 配置及容量锁行，不存密钥正文 |
| `jyj_device_events` | 原有事件表 | 记录配置变更、远端处置意图及确认/不确定结果 |
| `jyj_synced_whitelist_state` | source_id 主键、revision、digest | 每个发送来源的已接收版本；最多 16 个来源 |
| `jyj_synced_whitelist` | `(source_id, rule)` 主键 | 接收规则与来源的 1:N 关系；不混入手工名单表 |

逻辑关系：`本地攻击审计 -> 脱敏 outbox -> syslog 接收端`；`管理员批封 -> 名单事务 + IP 处置审计`；`远端批封 -> 意图审计 -> 对端确认 -> 结果审计`。网络请求不占用数据库任务认领事务。

## 构建、部署与回滚

使用仓库既有 Go/Vue/MySQL 技术栈，不增加生产 npm 依赖或外部前端 CDN。Windows/macOS/Linux 均可构建主 WAF；Linux 防火墙适配器另见 `deploy/firewall/` 文档。

```text
cd web
npm ci --ignore-scripts
npm run build
cd ..
go test -p 1 ./...
go vet ./...
go build ./cmd/jingshield
```

已有 Dockerfile 会构建前端并嵌入 Go 产物：`docker build -t jingshield:operations .`。NAS 已使用离线编译的二进制构建测试镜像并替换 WAF 容器；此验证不代表完成真实防火墙设备联调。

部署前备份数据库与现有配置，先在测试环境执行 `jingshield migrate -c <配置文件>`，再启动应用。不要复用生产数据库做测试。syslog/远端联动默认停用；明确设置接收端、密钥环境变量和信任链后再启用。

回滚先停用 syslog/远端联动并记录队列状态，恢复上一个应用镜像/二进制及已备份的防护设置。新增表可以保留，旧版本会忽略；不要为回滚删除已有攻击日志、名单或队列。回滚代码不会自动撤销已经确认的本地/远端封禁，需按处置审计逐项确认解封。

## 验证方法

Go 回归包括真实路由与 Session/CSRF、SQL 事务契约模拟、500/501 边界、白名单、Redis/miniredis、窗口/TTL、观察模式、发送失败与租约恢复。浏览器冒烟脚本在 `web/tests/operations-ui.smoke.mjs`，使用本地模拟 API，不向真实 WAF/防火墙发包。

真实上线还需对目标 MySQL 版本跑迁移、配置 syslog 接收器并确认日志、部署 Linux 适配器后检查 nftables/ipset 的实际流量效果。厂商设备必须验证具体固件的策略提交、部署完成和回滚行为，不能用模拟测试替代。

### 本地验证记录（2026-09-25）

- 前端生产构建、TypeScript 检查通过；Chromium 模拟 API 冒烟 44/44（含白名单预览/下发及行为阈值 20 的字符串提交），通过 1280×720 和 375px 布局检查，无控制台异常。
- Go 全量回归和 `go vet` 通过；白名单新增专项测试涵盖认证、来源隔离、版本幂等/冲突、白名单优先、桥接器持久化与读回。先前的 Windows、Linux amd64、macOS arm64 编译结果未在本轮重新执行；跨平台编译不等于实机运行验证。
- `internal/operations` 语句覆盖率 85.6%，`internal/firewallbridge` 87.9%，新增两个批量 IP 校验函数 100%；这些不是全库覆盖率声明。
- 生产 npm 依赖审计 0 项漏洞，nanoid 已更新至 3.3.19。Go 扫描未发现代码可达漏洞，但仍报告 4 条未调用的模块级提示，不能解释为所有依赖无漏洞。
- 本次源码差异的 Gitleaks 脱敏扫描通过。前端原有仪表盘分块仍约 508 kB，构建存在体积提示，不影响构建成功。
- 已在 NAS Docker 更新测试 WAF 容器，验证管理页面和已接入的 NAS/下载代理路径；未以真实管理员会话写入阈值 20，也未执行真实内核或厂商设备封禁。测试镜像不等于正式发布或生产验收。

<p align="center">
  <img src="web/public/favicon.png" alt="JingShield" width="80">
</p>

<h1 align="center">JingShield 捷云鲸盾</h1>

<p align="center">
  <strong>轻量反向代理型 Web 应用防火墙</strong><br>
  <em>Go 单二进制 · Vue 3 管理控制台 · MySQL 持久化 · 一键部署</em>
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong>
</p>

---

## 安全控制台预览

<p align="center"><img src="docs/assets/jingshield-dashboard.png" alt="JingShield Security Dashboard" width="800"></p>

> 深色安全运营控制台：今日安全态势、攻击趋势图、Top 攻击 IP、本机资源监控（CPU / 内存 / 磁盘 / 日志 / 业务速率）和五级攻击分类。

---

## 项目简介

JingShield（捷云鲸盾）是使用 **Go** 开发的轻量反向代理型 Web 应用防火墙。请求转发、应用层攻击检测、CC 防护、人机验证、多站点路由、安全运营 API 和 Vue 3 管理界面被整合在同一个可部署二进制中。

命名取「鲸盾」意象，寓意守护网站安全。

Linux 标准发行物是完整应用包。目标服务器不需要 Go、Node.js 或源码构建环境：解压后首次安装和日常启动使用 `run.sh`，升级使用 `upgrade.sh`。

---

## 主要能力

新增运营控制台功能及部署边界见 [WAF 运营、行为防护与同步](docs/operations-console.md)：紧凑页面、系统状态与按功能归位的 WAF 运行信息、分级引擎开关、IP 画像、500 项批量封禁、持久 Syslog 同步和同协议设备联动。

运营要点：

- 来源 IP 以 TCP 对端为起点；仅当直接对端是配置中的受控代理时，才从 X-Forwarded-For 右向左逐跳回溯。不可盲取最左侧 IP，也不可把整个内网段加入 `trusted_proxies`。
- 本机白名单优先于黑名单；同协议节点支持白名单快照接收与显式下发。商业防火墙品牌名称仅是适配器标签，未验证的原生接口不宣称可直接封禁。
- 行为检测支持观察与拦截模式，触发阈值可设为 2–1000；管理界面会把数字输入转换为接口所需的字符串后提交。Syslog 的发送成功仅表示传输成功，不等于对端已执行封禁。

| 能力 | 说明 |
|------|------|
| **反向代理** | 基于 Go `httputil.ReverseProxy` 的请求转发、请求体限制和源站超时控制 |
| **可信 IP 解析** | 可信代理来源 IP 解析，避免伪造转发请求头绕过策略 |
| **攻击检测** | SQL 注入（26 条正则）、XSS（10 条正则）、自定义 RE2 策略以及可导入的 Ed25519 签名规则包 |
| **CC 防护** | 7 个子检测器：主频率、TCP 连接、变异请求、穿盾检测、URL 频率、请求间隔、端口扫描 |
| **人机验证** | 工作量证明 (PoW) 浏览器挑战、HMAC-SHA256 签名验证 Cookie 和一次性消费 |
| **多站点路由** | 精确域名和 `*.example.com` 通配域名动态源站路由 |
| **双入口监听** | HTTP / HTTPS 双入口、站点级源站 TLS 校验和 30 年测试证书生成 |
| **IP 管理** | IP / CIDR / 通配符白名单、黑名单和自动临时封禁 |
| **安全鉴权** | Session + CSRF、管理网段限制、bcrypt 密码哈希、首次登录强制改密 |
| **设备联动** | API Key 鉴权，支持 CEF、LEEF、Suricata EVE、Wazuh、通用 JSON 事件归一化接入 |
| **安全监控** | 攻击趋势图、本机 CPU / 内存 / 磁盘 / 日志 / 业务速率监控和可配告警阈值 |
| **事件运营** | 严重 / 高危 / 中危 / 低危 / 信息五级攻击分类，服务端筛选分页与流式 CSV 导出 |
| **持久化与部署** | MySQL 持久化、幂等迁移、systemd 加固和升级失败自动回滚 |
| **高并发审计** | 有界访问/攻击日志队列、访问日志批量写入和受保护的运行指标 |

---

## 架构概览

```text
客户端
  │
  ├─ HTTP  :18080
  └─ HTTPS :18443
       │
       ▼
JingShield Go 进程
  ├─ /admin/       Vue 3 管理控制台（embed.FS 内嵌）
  ├─ /api/v1/      Session + CSRF 管理 API
  ├─ /openapi/v1/  X-API-Key 设备联动 API
  └─ 其他路径       WAF 防护链
                      │
                      ├─ 1. 系统总开关
                      ├─ 2. 黑名单 → 403 拦截
                      ├─ 3. 白名单 → 放行短路
                      ├─ 4. 海外 IP → 403 拦截
                      ├─ 5. 自定义策略 → 拦截 / 记录
                      ├─ 6. CC 攻击 → 验证页 / 403 拦截
                      ├─ 7. XSS 检测 → 403 拦截
                      ├─ 8. SQL 注入 → 403 拦截
                      └─ 9. 全部通过 → 按 Host 转发到站点 upstream
```

防护引擎返回 `Decision`（Allow / Block / Verify），与 HTTP 层完全解耦，由代理层翻译为 HTTP 响应。

---

## 技术栈

| 层面 | 技术 |
|------|------|
| 后端 | Go 1.25 · 标准库 `net/http` + `httputil.ReverseProxy` |
| 前端 | Vue 3.5 · TypeScript 5.9 · Vite 8 · Pinia 4 · ECharts 6 |
| 数据库 | MySQL 5.7+ / 8.x（`go-sql-driver/mysql`） |
| 配置 | YAML + 环境变量覆盖 + 数据库动态配置（30s 热加载） |
| 监控 | `gopsutil/v3`（CPU / 内存 / 磁盘采集） |
| 安全 | `golang.org/x/crypto`（bcrypt） · `crypto/ed25519`（策略签名） |
| 部署 | Linux systemd · PowerShell 构建脚本 · Python 远程部署器 |

Go 依赖仅 **5 个直接包**，极度精简，无 ORM、无 Web 框架。

---

## 工程目录

```text
jingshield/
├── cmd/jingshield/main.go          # 程序入口：serve / migrate / init / cert
├── internal/
│   ├── config/                     # 静态配置 + 动态配置热加载
│   ├── proxy/proxy.go              # 反向代理 + 拦截页 + 验证页
│   ├── protection/
│   │   ├── engine.go               # 9 级保护链编排
│   │   ├── reqctx/                 # 请求上下文 + 上传文件检查
│   │   ├── cc/                     # CC 7 子检测 + 动态阈值
│   │   ├── detector/               # XSS / SQL 注入检测器
│   │   ├── iplist/                 # IP 黑白名单 + 海外 IP
│   │   └── verify/                 # 8 种验证模式 + PoW 挑战
│   ├── policy/                     # RE2 策略 CRUD + 签名规则包导入 + 远程自动更新
│   ├── api/                        # 50+ REST 端点（管理 + 设备联动）
│   ├── repository/                 # MySQL 持久层 + 幂等迁移（13 张表）
│   ├── model/                      # 实体模型 + 攻击类型 / 严重度常量
│   ├── iplib/                      # QQWry IP 归属地（可选）
│   ├── store/memory/               # 进程内内存状态（预留 Redis 接口）
│   └── pkg/                        # 工具：iputil / logx / errx
├── web/                            # Vue 3 前端（构建后 embed 嵌入二进制）
├── configs/config.yaml             # 静态配置
├── rules/packs/                    # 规则包 JSON
├── scripts/                        # 构建、部署、测试脚本
├── run.sh                          # Linux 一键安装
├── upgrade.sh                      # Linux 原子升级 + 回滚
└── go.mod
```

---

## 快速开始

完整的在线、离线、数据库向导和配置文件部署说明见：[`docs/部署指南.md`](docs/部署指南.md)。

在仓库的 `bin/jingshield-linux-amd64` 存在时，也可以直接执行 `sudo bash run.sh`；脚本会自动识别源码仓库，在当前目录内完成数据库初始化并以前台方式启动，不写入 `/opt` 或 `/etc`。

### Linux 完整包安装

目标环境需要 64 位 systemd Linux、MySQL 5.7+/8.x、`mysql` 命令行客户端和 sudo 权限。

```bash
tar -xzf jingshield-0.1.0-linux-amd64.tar.gz
cd jingshield-0.1.0-linux-amd64
sudo ./run.sh
```

`run.sh` 会校验包内文件、询问管理员用户名、创建最小权限系统账号、随机生成数据库密码和 Session 密钥、迁移数据库、初始化管理员、按需生成测试证书并启动 systemd 服务。

### 本地开发

```powershell
cd web && npm install && npm run build && cd ..
go test ./...
go vet ./...
go run ./cmd/jingshield -c configs/config.yaml
```

前端开发模式：

```powershell
cd web
$env:JINGSHIELD_DEV_API='http://127.0.0.1:18080'
npm run dev
```

### 构建发行包

```powershell
pwsh -File scripts/build-linux-package.ps1 -Arch amd64
```

---

## 安装路径

| 用途 | 路径 |
|------|------|
| 主程序 | `/opt/jingshield/jingshield` |
| 运行与升级脚本 | `/opt/jingshield/run.sh`、`/opt/jingshield/upgrade.sh` |
| 主配置 | `/opt/jingshield/config.yaml` |
| 敏感环境变量 | `/opt/jingshield/jingshield.env` |
| 测试证书 | `/opt/jingshield/tls/` |
| 规则 | `/opt/jingshield/rules/` |
| 可选 QQWry 数据 | `/opt/jingshield/data/QQWry.Dat` |
| 日志 | `/opt/jingshield/logs/` |

---

## 默认端口与入口

| 入口 | 地址 | 说明 |
|------|------|------|
| 管理控制台 | `https://<节点>:18443/admin/` | Vue 3 深色安全运营界面 |
| 管理 API | `https://<节点>:18443/api/v1/` | Session + CSRF + 管理网段限制 |
| 设备联动 API | `https://<节点>:18443/openapi/v1/` | X-API-Key 鉴权 |
| HTTP 防护流量 | `http://<节点>:18080/` | WAF 反向代理入口 |

---

## 管理控制台功能

- **安全态势** — 今日请求总量、独立 IP 数、拦截攻击数、黑白名单统计
- **攻击趋势** — 24 小时攻击数量折线图（ECharts）
- **Top 攻击 IP** — 今日攻击次数排名
- **系统资源** — CPU / 内存 / 磁盘 / 日志大小 / 业务速率实时告警
- **攻击事件** — 五级严重度筛选、IP/类型/时间范围/事件编号过滤、流式 CSV 导出
- **防护站点** — 精确域名 / 通配域名、源站地址、Host 透传、TLS 校验策略
- **策略中心** — RE2 自定义规则 CRUD、JSON 规则包导入、Ed25519 签名远程自动更新
- **IP 管理** — 白名单 / 黑名单 / 临时黑名单（IP / CIDR / 通配符）
- **用户管理** — 多管理员、启停、密码重置、首次登录强制改密
- **设备联动** — API Key 轮换、CEF / LEEF / Suricata / Wazuh / JSON 事件接入
- **防护配置** — 系统开关、CC / XSS / SQL 防护开关、告警阈值、拦截页联系信息

---

## 安全设计

| # | 风险点 | 加固方案 |
|---|--------|----------|
| 1 | 配置明文密码 | 环境变量覆盖，不进 YAML 不进 Git |
| 2 | 默认弱口令 | 初始化随机密码 + 首次登录强制改密 |
| 3 | API Key 时序攻击 | `crypto/subtle.ConstantTimeCompare` |
| 4 | 拦截页泄露规则 | 不展示规则名、正则、命中载荷 |
| 5 | SQL 注入面 | `database/sql` 全参数化查询 |
| 6 | XSS 输出面 | `html/template` 自动转义 |
| 7 | 验证 Cookie 伪造 | HMAC-SHA256 签名 + HttpOnly/Secure/SameSite |
| 8 | 策略更新 SSRF | HTTPS-only + 拒绝内网/回环/链路本地 IP |
| 9 | CSV 公式注入 | `=+-@` 前缀自动加单引号 |
| 10 | JSON 未知字段 | `DisallowUnknownFields` + 单值校验 |
| 11 | 拦截页安全头 | CSP `default-src 'none'` + `X-Frame-Options: DENY` + `no-store` |

---

## 日常运维

```bash
sudo systemctl status jingshield --no-pager
sudo journalctl -u jingshield -f
sudo /opt/jingshield/run.sh
```

---

## 远程安装与升级

远程客户端通过 SFTP 上传完整包，在目标机复核 SHA-256，然后通过 sudo 调用 `run.sh`。

```powershell
pwsh -File scripts/setup-python-env.ps1 -NetworkProfile Auto
$env:JINGSHIELD_SSH_PASSWORD = 'SSH密码'
$env:JINGSHIELD_SUDO_PASSWORD = 'sudo密码'
.\.venv\Scripts\python.exe scripts/deploy-linux.py `
  --host waf-node.example.net `
  --user deployer `
  --admin-user YOUR_ADMIN_NAME `
  --package release/jingshield-0.1.0-linux-amd64.tar.gz
```

升级使用 `--action upgrade`，升级脚本会校验完整包、获取独占锁、验证候选程序、提前执行数据库迁移、保留带时间戳的旧二进制，并在新服务启动失败时自动回滚。

SSH 主机密钥必须已记录于 `~/.ssh/known_hosts`（或 `--known-hosts` 指定的文件）。首次连接新主机时，先通过独立可信渠道核对 OpenSSH SHA-256 主机密钥指纹，再传入 `--host-key-sha256 SHA256:...`；程序校验后才允许本次连接，不会暗中持久化新密钥。不要直接信任未经独立核验的 `ssh-keyscan` 输出。`scripts/deploy-test-linux.py` 使用同样的参数与拒绝策略。

---

## 安全建议

- 通过主机防火墙或监听地址限制真实源站，避免客户端绕过 WAF 直连。
- 只有受控代理才能加入 `trusted_proxies`，并应确保代理清理客户端伪造的转发头。
- 生产环境应替换自签测试证书、启用安全 Cookie，并把 `admin_ips` 收紧为实际管理网段。
- `/opt/jingshield/jingshield.env` 只能由 root 和服务组读取，重要升级前应备份 MySQL 与配置。
- QQWry 数据为可选外部文件，不随项目发布；缺失时 IP 归属地功能自动降级。

## 防护性能与多实例配置

- 生产配置使用 `environment: prod`、至少 32 字节的 `JINGSHIELD_SESSION_KEY` 和 `session.secure: true`；启动时校验。开发与测试可使用 `dev`、`test`。
- 请求体限制为 `server.max_body_bytes`（最高 32 MiB）。超过限制且声明了 `Content-Length` 的请求会在读取前拒绝；最多 8 个请求同时进入请求体检测，其余请求短暂等待或返回 503。JSON 检测最多解析 8192 个 token、单个字符串最多 64 KiB，超出时返回 413。
- `server.method_policies` 可按站点和路径设置方法白名单，例如 `[{host: "api.example.com", path_prefix: "/v1", allowed_methods: [GET, POST, OPTIONS]}]`。未配置时不因 HTTP 方法阻断请求。
- `GET /api/v1/system/waf-metrics` 需管理员会话，返回防护决策总数、累计耗时、审计队列深度及丢弃/失败总数。审计队列满时记录会丢弃并计数，应配置监控告警。
- 单实例默认使用进程内状态。多实例部署可通过 `JINGSHIELD_REDIS_URL=redis://user:password@host:6379/0` 启用共享 CC 计数与一次性挑战状态；所有实例必须使用相同的 Session 密钥。Redis 需支持 `GETDEL`（6.2+），连接失败时服务拒绝启动。管理会话仍保存在本机，管理入口需固定路由到一个实例。

容器构建可执行 `docker build -t jingshield:local .`。镜像自带 `deploy/docker/config.yaml`，启动时通过环境变量设置 `JINGSHIELD_DB_PASS`、`JINGSHIELD_SESSION_KEY`，并根据实际网络设置 `JINGSHIELD_DB_HOST` 与 `JINGSHIELD_UPSTREAM`；Linux 宿主机目标可在启动时添加 `--add-host=host.docker.internal:host-gateway`。管理入口应放在 HTTPS 终止代理之后，并按部署网络收紧 `admin_ips`。

2026-09-25 的 NAS Docker 测试已验证管理页面、飞牛系统/音乐代理和下载服务入口可响应；当前测试配置保持 `trusted_proxies: []`，不会采信客户端自行添加的 XFF。行为阈值 `20` 的保存链路已通过浏览器模拟与 API 测试，但没有代管理员修改 NAS 上的现行阈值。缺少可选 `QQWry.Dat` 时 IP 归属地与海外 IP 检测会降级。此测试不代表已经完成公网入口、厂商防火墙或 Linux 内核封禁的实机验收。

---

## 当前范围

- TLS 终止使用单张静态证书；多站点 SNI 和 ACME 自动化尚未实现。
- SQL / XSS 内置检测以 RE2 特征为主，语义检测持续建设中。
- 管理员为统一系统级角色；细粒度 RBAC、MFA、OIDC 尚未包含。
- 审计日志异步写入；在数据库持续故障、队列满或关闭期限到达时，记录可能丢失，应监控 `audit_dropped_total` 与 `audit_failed_total`。

---

<p align="center"><em>JingShield 捷云鲸盾 — 让您的网站安全无忧</em></p>

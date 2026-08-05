# 捷云鲸盾 JingShield

捷云鲸盾是一个使用 Go 开发的轻量反向代理型 Web 应用防火墙。项目已经形成请求代理、基础攻击检测、CC 防护、人机验证、管理 API、Vue 3 管理界面、MySQL 持久化和 Linux systemd 部署闭环。

> 当前定位是单机、单二进制的轻量 WAF，不应视为雷池 SafeLine 等成熟产品的等价替代。

## 已实现能力

- Go `ReverseProxy` 请求转发与请求体大小限制
- 可信代理来源 IP 解析，防止伪造 `X-Forwarded-For`
- SQL 注入、XSS 基础特征检测
- CC、URL 频率、请求间隔、变异 CC 和穿盾检测
- IP/CIDR/通配符白名单、黑名单和临时黑名单
- HMAC 挑战 token、工作量证明、一次性消费和签名验证 Cookie
- Session、CSRF、管理网段白名单和首次登录强制改密
- 仪表盘、攻击/访问日志、IP 名单、用户管理和系统设置管理界面
- 防护站点增删改、启停、精确/通配域名与按 Host 动态源站路由
- HTTP/HTTPS 双入口、自签名测试证书和 HTTPS 源站校验策略
- 独立 API Key 的状态查询、IP 联动封禁/解封及密钥轮换
- CEF、LEEF、Suricata EVE、Wazuh 与通用 JSON 安全事件接入及高危 IP 自动临时封禁
- 自定义 RE2 防护策略、离线规则包原子导入、Ed25519 签名自动更新与实时优化建议
- 今日自然日安全态势与本机 CPU、内存、磁盘、日志、业务速率告警
- MySQL 幂等迁移、管理员初始化和 systemd 部署

## 环境要求

- Go 1.25+
- Node.js 20.19+ 或 22.12+
- npm 10+
- MySQL 5.7+

Redis 目前不是运行依赖。状态层使用进程内存，并为后续 Redis 多节点实现保留了接口。

## 快速开始

### 1. 修改配置

复制或修改 `configs/config.yaml`：

- `database`：MySQL 地址、账号和库名
- `upstream.target`：尚未创建防护站点时使用的兼容源站
- `server.listen`：WAF 监听地址，默认 `127.0.0.1:18080`
- `server.tls_listen/tls_cert_file/tls_key_file`：可选 HTTPS 监听与证书文件
- `admin_ips`：允许访问管理界面和管理 API 的来源 IP

敏感值建议使用环境变量：

```powershell
$env:JINGSHIELD_DB_PASS='数据库密码'
$env:JINGSHIELD_SESSION_KEY='至少32字节随机密钥'
```

### 2. 构建前端和后端

```powershell
cd web
npm install
npm run build
cd ..
go build -o bin/jingshield.exe ./cmd/jingshield
```

`web/dist` 会通过 `embed.FS` 编译进 Go 二进制，因此全新检出后必须先构建前端。

### 3. 初始化数据库和管理员

```powershell
bin/jingshield.exe migrate -c configs/config.yaml
bin/jingshield.exe init -c configs/config.yaml --username admin
```

`init` 只在尚无管理员时执行，随机密码和设备 API Key 只显示一次，不会写入 README。首次登录必须修改密码。

### 4. 启动

```powershell
bin/jingshield.exe -c configs/config.yaml
```

- 管理界面：`http://127.0.0.1:18080/admin/`
- 管理 API：`http://127.0.0.1:18080/api/v1/`
- 设备联动 API：`http://127.0.0.1:18080/openapi/v1/`
- 其他请求：经过 WAF 检测后转发至 `upstream.target`

进入管理界面的“防护站点”添加域名与真实源站。未创建任何站点时使用静态 `upstream.target` 兼容旧部署；创建第一个站点后，代理按 HTTP Host 精确匹配或匹配 `*.example.com` 通配规则，未知/停用站点返回 421。

HTTPS 源站默认执行完整证书校验。可信内网中的自签名源站可对单个站点开启“允许自签名源站证书”，该选项不会影响其他站点。正式环境更推荐把内部 CA 加入系统信任并保持校验开启。

管理界面的“用户管理”可添加、启停管理员并重置临时密码；“安全设备联动”可启停开放接口、轮换 API Key、接收 CEF/LEEF/Suricata/Wazuh/通用 JSON 事件并配置高危 IP 自动临时封禁。完整 Key 只在生成时显示一次。

“策略中心”支持自定义规则、JSON 规则包导入和在线自动更新。自定义规则与导入/在线来源相互隔离；导入和更新采用事务替换，失败不破坏当前规则。在线更新只允许公网 HTTPS，规则包必须通过已固定 Ed25519 公钥的签名验证。

“今日安全态势”按数据库当前时区统计当日请求、独立 IP、攻击趋势和高风险来源。本机资源每 15 秒刷新，默认告警阈值为 CPU 80%、内存 85%、磁盘 85%、日志 512 MB、业务速率 600 请求/分钟（10 RPS）；资源阈值只影响运维告警，不会隐式修改 CC 防护策略。

## 前端开发

先启动 Go 服务，再运行：

```powershell
cd web
$env:JINGSHIELD_DEV_API='http://127.0.0.1:18080'
npm run dev
```

访问 `http://127.0.0.1:5173/admin/`。更多信息见[前端说明](web/README.md)。

## Linux 部署

```bash
cd web
npm ci
npm run build
cd ..
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o bin/jingshield-linux-amd64 ./cmd/jingshield
```

systemd 目录、安装约定和测试部署说明见 [deploy/linux](deploy/linux/README.md)。生产环境应使用专用数据库用户、随机 Session 密钥、HTTPS、安全 Cookie，并将 upstream 限制为只能由 WAF 访问。

已安装节点可使用 `deploy/linux/run.sh` 启动/迁移，使用 `deploy/linux/upgrade.sh <新二进制>` 原子升级并自动回滚。Windows Server 使用计划任务托管，安装与升级脚本见 [deploy/windows](deploy/windows/README.md)。

跨平台生成 30 年 PEM 测试证书：

```bash
jingshield cert --cert jingshield.crt --key jingshield.key --hosts "waf.example.com,192.0.2.10" --days 10950
```

命令拒绝覆盖已有证书；自签名证书只适用于测试环境。

## 验证

```powershell
cd web
npm run build
cd ..
go test ./...
go vet ./...
```

对本机环境执行低影响 WAF 冒烟测试：

```powershell
pwsh -File scripts/test-waf.ps1
```

脚本只发送少量请求，必要时自动完成一次 5 秒安全挑战，然后依次验证正常访问、XSS、SQL 注入和未知 Host，不执行并发 CC 压测。自定义地址时可传入 `-BaseUrl` 与 `-HostHeader`。

## 更多说明

- [内置规则包](rules/README.md)
- [Linux systemd 部署](deploy/linux/README.md)

## 当前边界

- 已支持单张静态证书的 TLS 终止；尚无按站点 SNI 证书、ACME 自动签发和证书自动轮换
- SQL/XSS 主要采用正则特征，尚未达到成熟 WAF 的语义检测水平
- 用户均为系统管理员，尚无细粒度 RBAC、OIDC、MFA 和集群控制面
- 开放 API 已支持状态、封禁、解封和安全事件接入；尚无 UDP/TCP Syslog 监听、事件订阅、webhook 与细粒度 API scope
- 状态存储为单进程内存，多实例部署会造成计数分散
- QQWry 数据文件需自行提供；缺失时归属地功能会降级

请先在测试环境完成误报率、漏报率、吞吐量和故障恢复验证，再用于生产流量。

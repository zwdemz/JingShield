# 捷云鲸盾 JieYun JingShield - Web 安全防护系统设计方案

> 版本：v1.2  日期：2026-08-06  状态：运行、防护、管理、策略、部署闭环已实现；语义检测引擎进入规划阶段
>
> 产品名：捷云鲸盾（英文 JieYun JingShield） | Go 模块名：`jingshield` | 命名取「鲸盾」意象，寓意守护网站安全

---

## 一、方案总览

### 1.1 设计目标
构建一款 **Go 反向代理型 WAF + Vue3 管理后台 + 开放 REST API（设备联动）** 的原创 Web 安全防护系统，具备 CC 防护 8 模式、XSS、SQL 注入、IP 黑白名单、海外 IP、QQWry 归属地、日志统计、验证流程等完整业务能力，并覆盖 9 项常见 WAF 安全风险加固。

### 1.2 架构设计
| 维度 | 设计 |
|---|---|
| 部署形态 | 独立反向代理进程，站前拦截 |
| 进程模型 | Go 长驻进程，内存共享状态 |
| 状态存储 | 内存 `sync.Map` + `Store` 接口（Redis 预留） |
| 后台 | Vue3/Vite SPA + Go REST API |
| 集成 | 完整 REST API，含**设备联动开放 API** |

> 反向代理模型：Go 默认监听 `127.0.0.1:18080`，由 Nginx 的 80/443 端口接入，将"干净请求"转发至 upstream（真实站点，如 `127.0.0.1:9000`），攻击请求在代理层拦截/验证。验证页由代理自身提供。

### 1.3 实施状态总表（2026-08-06）

状态说明：✅ 已实现并完成构建验证；🟡 已有基础能力但尚未达到目标；⬜ 尚未实现。

| 能力域 | 状态 | 当前实现与边界 |
|---|---:|---|
| 可运行入口与请求转发 | ✅ | CLI 启动、HTTP/HTTPS 监听、请求体恢复转发、大小限制和源站超时已实现 |
| 可信代理客户端 IP | ✅ | 仅信任配置网段的转发头，非可信来源不能伪造客户端 IP |
| 多防护站点 | ✅ | 精确/通配 Host、动态源站、启停、Host 未配置返回 421 |
| CC 与验证闭环 | ✅ | 频率、URL 频率、请求间隔、变异/穿盾、PoW、一次性状态和签名 Cookie |
| SQL/XSS 基础检测 | ✅ | 26 条 SQL 和 10 条 XSS RE2 特征已运行；属于特征检测，不标记为语义检测完成 |
| IP 策略与归属地 | ✅ | IP/CIDR/通配符白黑名单、临时封禁、QQWry 可选降级 |
| 管理鉴权与用户管理 | ✅ | Session、CSRF、管理网段、bcrypt、首登改密、多管理员、停用和密码重置 |
| 管理 UI | ✅ | 仪表盘、站点、攻击/访问日志、IP、策略、设置、用户和设备联动页面 |
| 攻击事件运营 | ✅ | 五级严重度、服务端筛选分页、时间范围、流式 CSV 导出和公式注入防护 |
| 策略中心 | ✅ | 自定义规则、事务导入、Ed25519 在线更新、版本状态和热加载 |
| JSON 规则包上传 | ✅ | 浏览器受限读取、2MB 限制、固定结构、未知字段/多 JSON 值拒绝，不落盘原始文件 |
| 安全设备 API | ✅ | API Key、CEF/LEEF/Suricata/Wazuh/通用 JSON 接入和高危 IP 联动封禁 |
| 节点资源与告警 | ✅ | CPU、内存、磁盘、日志大小、业务速率及可调告警阈值 |
| Linux 完整包与远程部署 | ✅ | `run.sh`、`upgrade.sh`、完整包、校验、systemd、回滚和远程 SFTP 部署 |
| Windows 运行脚本 | ✅ | PowerShell 启停、升级和计划任务方案；尚不是原生 Windows Service |
| 证书生命周期 | 🟡 | HTTP/HTTPS 和 30 年测试证书已实现；多证书、ACME、到期告警未实现 |
| 多节点共享状态 | ⬜ | 当前为单机内存状态；Redis 接口只完成抽象预留 |
| RBAC/MFA/OIDC | ⬜ | 当前管理员为统一系统角色 |

### 1.4 语义检测能力计划

语义检测统一经过“受限读取 → 规范化 → 结构解析 → 上下文画像 → 风险评分 → 记录/验证/拦截”，在线主链使用确定性解析器，不使用大模型直接决定是否封禁。

| 模块 | 当前状态 | 已有基础 | 计划验收条件 | 优先级 |
|---|---:|---|---|---:|
| 公共规范化管线 | 🟡 | Query/Form/Cookie/JSON/文本/XML 取值，请求体可恢复转发 | 有界多层 URL/HTML/Unicode 解码；保留原值、规范值和参数来源；限制深度、节点数、解压比 | P0 |
| SQL 注入语义 | 🟡 | 26 条固定 RE2 特征 | SQL tokenizer、注释/编码归一化、布尔/联合/堆叠/时间型评分、正负样本回归 | P1 |
| NoSQL 注入 | ⬜ | JSON 键值可提取 | MongoDB 操作符、Elasticsearch DSL 和类型混淆检测，按参数位置评分 | P1 |
| 命令注入 | ⬜ | 自定义 RE2 可临时补充 | Shell 元字符、命令替换、管道/重定向和编码变体 tokenizer，支持站点级豁免 | P1 |
| XSS 上下文语义 | 🟡 | 10 条固定 RE2 特征 | HTML/属性/JS/URL 上下文 tokenizer、实体解码和事件处理器评分 | P1 |
| 路径穿越 | ⬜ | 请求 URI 和参数可见，Java 包含少量 Tomcat 路径规则 | 多层解码、分隔符统一、点段折叠、绝对路径/协议包装器识别 | P0 |
| SSRF URL | ⬜ | URL 字符串可由自定义规则匹配 | URL 解析、DNS/IP 分类、内网/回环/链路本地/元数据地址、重定向和混淆地址检测 | P0 |
| XXE/XML | ⬜ | XML 原文已进入可检测文本 | 流式 XML token 检查 DTD、ENTITY、SYSTEM/PUBLIC、XInclude；禁止外部实体解析 | P0 |
| SSTI/表达式注入 | ⬜ | 自定义 RE2 可临时补充 | Jinja/FreeMarker/Thymeleaf/SpEL/OGNL 等语法族评分和框架画像 | P2 |
| Fastjson/JNDI 反序列化 | 🟡 | Java 应急规则包覆盖已知 `@type`、JNDI 和 Tomcat 特征 | JSON 类型元数据结构检查、JNDI 规范化、嵌套/转义变体回归，不宣称通用反序列化拦截 | P1 |
| 文件上传类型与内容 | ⬜ | 管理端 JSON 规则上传已安全实现；尚未检查被保护业务的文件内容 | multipart 文件计数/大小、扩展名、声明 MIME、魔数一致性、活动内容和压缩炸弹限制；不落盘 | P1 |
| GraphQL | ⬜ | JSON 请求体可读取 | GraphQL parser、深度/别名/字段数/批量复杂度限制；可选 Schema 和危险字段配置 | P2 |

阶段目标：完成 P0 后形成通用解析底座；完成 P1 后使主要请求层攻击进入风险评分闭环；P2 负责框架和业务上下文增强。任何覆盖率结论必须由版本化正负样本集、误报率、召回率、P95 延迟和吞吐测试支撑。

### 1.5 技术选型（已定）
- **后端**：Go 1.25，标准库 `net/http` + `httputil.ReverseProxy` + `database/sql` + `encoding/json` + `html/template`
- **前端**：Vue 3 + Vite + Vue Router + Pinia + ECharts + Lucide，使用原生 Fetch API
- **数据库**：MySQL 5.7+（建表 DDL 见《开发文档.md》6.4 节）
- **状态层**：单机内存先行，`Store` 接口预留 Redis 实现
- **依赖最小化**：`go-sql-driver/mysql`、`golang.org/x/crypto`、`golang.org/x/text`、`gopsutil`、`yaml.v3`；路由使用标准库 `net/http`

---

## 二、工程目录结构

项目落盘 `E:\codeaudit\jingshield\`：

```
jingshield/
├── cmd/
│   └── jingshield/              # main 入口：加载配置、启动反代+API+后台静态资源
│       └── main.go
├── internal/
│   ├── config/                # 配置加载（文件+DB 动态配置，热加载）
│   │   └── config.go
│   ├── proxy/                 # 反向代理 + 中间件链
│   │   ├── proxy.go           # ReverseProxy 封装
│   │   └── chain.go           # 保护中间件链编排
│   ├── protection/            # 防护核心
│   │   ├── engine.go          # Engine：编排各检测器
│   │   ├── context.go        # RequestContext：ip/ua/uri/method/get/post/cookie
│   │   ├── cc/               # CC 攻击子检测
│   │   │   ├── frequency.go      # 主频率 + URL频率 + 请求间隔 + 端口扫描
│   │   │   ├── tcp.go            # TCP 连接检测
│   │   │   ├── variant.go        # 变异 CC 检测
│   │   │   ├── shield_bypass.go  # 穿盾检测（方差分析）
│   │   │   └── dynamic_threshold.go # 动态阈值（gopsutil 真实 CPU）
│   │   ├── detector/         # XSS / SQL 检测器
│   │   │   ├── detector.go       # Detector 接口
│   │   │   ├── xss.go            # XSS 特征检测
│   │   │   └── sql.go            # SQL 注入特征检测
│   │   ├── iplist/           # 黑白名单/临时黑名单/海外IP
│   │   │   └── iplist.go
│   │   └── verify/           # 8 种验证模式
│   │       ├── verify.go         # 调度 + cookie 签名
│   │       └── handlers.go       # verify_5second/slide/click/302/jsredirect/rotate/securitycheck/human
│   ├── iplib/                # QQWry 二进制解析
│   │   ├── locator.go            # IPLocator 接口
│   │   └── qqwry.go             # 纯真库二进制搜索 + GBK 解码
│   ├── store/                # 状态层（内存共享，预留 Redis）
│   │   ├── store.go              # StateStore 接口
│   │   └── memory/              # 内存实现（sync.Map + per-key mutex）
│   │       └── memory.go
│   ├── model/                # 实体（9 张表）
│   │   └── model.go
│   ├── repository/           # 数据持久层（database/sql 参数化）
│   │   ├── access_log.go
│   │   ├── attack_log.go
│   │   ├── ip_list.go
│   │   ├── config.go
│   │   ├── user.go
│   │   └── verify_fail.go
│   ├── api/                  # REST API（管理 + 设备联动）
│   │   ├── router.go
│   │   ├── middleware/        # auth（session）/ apikey（设备联动）/ recover / cors
│   │   ├── handler/          # 各资源 handler
│   │   └── dto/              # 请求/响应传输对象
│   ├── admin/                # 后台静态资源 + 验证页模板（embed.FS）
│   │   ├── static/            # cc1-cc7 验证页 html/js
│   │   └── embed.go
│   └── pkg/                  # 工具（IP 解析/CIDR/日志/错误封装）
│       ├── iputil/
│       ├── logx/
│       └── errx/
├── web/                      # Vue3 前端工程（独立 npm 工程）
│   ├── src/
│   │   ├── views/            # 后台页面
│   │   ├── api/              # axios 封装
│   │   ├── router/
│   │   ├── store/            # Pinia
│   │   └── components/
│   ├── vite.config.ts
│   └── package.json
├── configs/
│   └── config.yaml           # 运行配置（DB/upstream/listen/admin_ips 等）
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── jingshield.service      # systemd
├── docs/                     # 配套文档
└── go.mod
```

---

## 三、数据库设计

### 3.1 表结构
9 张表：`jyj_config` / `jyj_ip_list` / `jyj_attack_log` / `jyj_access_log` / `jyj_file_check` / `jyj_users` / `jyj_url_rules` / `jyj_verify_fail` / `jyj_login_log`，完整建表 DDL 见《开发文档.md》6.4 节。

### 3.2 设计要点
1. `jyj_users.password`：存 bcrypt 哈希（`golang.org/x/crypto/bcrypt`）。
2. `jyj_config`：含 `api_key`（设备联动密钥）、`upstream_url`（反代目标）、`webhook_url`（设备联动事件推送，可选）等配置项。
3. `jyj_access_log`：索引 `idx_ip_created_at(ip, created_at)` 支撑 CC 子检测高频查询；内存化后查询大幅减少。

### 3.3 初始化
提供 `migrate` 子命令执行建表 + 默认配置 + 默认管理员（**随机初始密码**，首登强制改密）。

---

## 四、核心模块设计

### 4.1 反向代理与中间件链

保护链采用顺序检测，Go 用中间件链实现：

```
HTTP 请求
  -> RecoveryMiddleware（全局异常捕获，禁原生 panic 外泄）
  -> RequestInfoMiddleware（提取 IP/UA/URI/Method，构建 RequestContext）
  -> AccessLogMiddleware（异步写 jyj_access_log）
  -> ProtectionChain（保护链，任一拦截即短路响应）：
       1. SystemStatusCheck   （!system_status -> 放行）
       2. BlacklistCheck      （黑名单/临时黑名单 -> 403 + logAttack）
       3. WhitelistCheck      （白名单 -> 放行短路）
       4. OverseaIPCheck      （海外 IP -> 403 + logAttack）
       5. CCAttackCheck       （频率/TCP/变异/穿盾/URL频率/端口扫描/区间 -> 验证页或403）
       6. XSSCheck            （-> logAttack + 错误页）
       7. SQLInjectionCheck   （-> logAttack + 错误页）
       8. ShieldBypassCheck   （-> 验证页）
  -> ReverseProxy（干净请求转发至 upstream）
```

每个检测器实现统一接口：
```go
// Detector 保护检测器接口
type Detector interface {
    Name() string
    // Check 执行检测；detected=true 表示命中攻击
    Check(ctx context.Context, rc *RequestContext) *Result
}
type Result struct {
    Detected    bool   // 是否命中攻击
    AttackType  string // CC攻击/XSS攻击/SQL注入/IP黑名单/海外IP拦截/穿盾攻击
    Detail      string
    Code        int    // -100/-110/-112 等
}
```

### 4.2 CC 检测引擎

| 子检测 | Go 模块 | 状态来源 |
|---|---|---|
| 主频率检测 | `cc/frequency.go` | 内存滑窗 `Store.HitAndCount(ip, window)` |
| TCP 连接检测 | `cc/tcp.go` | 内存计数（窗口内连接数） |
| 变异 CC 检测 | `cc/variant.go` | 内存（UA 模式 + 参数计数 + 唯一 URL 数） |
| 穿盾检测 | `cc/shield_bypass.go` | 内存（header/cookie/proxy 计数 + 区间标准差<0.3） |
| URL 频率检测 | `cc/frequency.go` | 内存 `Store.HitAndCount(ip+uri, 60s)` |
| 请求间隔检测 | `cc/frequency.go` | 内存 `Store.LastRequestAt(ip)` |
| 端口扫描检测 | `cc/frequency.go` | 内存 `Store.RecordPort(ip, port, 60s)` |
| 动态阈值 | `cc/dynamic_threshold.go` | `gopsutil` 真实 CPU 采样，动态阈值生效 |

### 4.3 状态层 `Store` 接口
```go
// StateStore 防护状态存储（单机内存实现，预留 Redis）
type StateStore interface {
    HitAndCount(ctx, key string, windowSec int) (count int, err error) // 滑动窗口
    LastRequestAt(ctx, ip string) (last time.Time, err error)            // 记录并返回上次请求时间
    RecordPort(ctx, ip string, port, windowSec int) (distinct int, err error)
    RecentIntervals(ctx, ip string, n int) ([]time.Duration, error)      // 方差分析用
    ResetIP(ctx, ip string) error                                        // 验证成功后清理
    ClearAll(ctx) error                                                  // 后台清理缓存
}
```
内存实现：`sync.Map[string]*entry`，每 entry 自带 `sync.Mutex` + 滑动窗口切片。过期清理由后台 goroutine 定时扫描。

### 4.4 XSS / SQL 检测器
- XSS/SQL 特征检测（10 条 XSS、26 条 SQL 正则），`regexp.MustCompile` 包级预编译。
- 正则仅用 `i/s` 标志 + 字符类 + 非贪婪，**无前瞻/反向引用**，Go RE2 100% 兼容。
- 预编译为包级 `[]*regexp.Regexp`，`init()` 时编译，避免每请求重编译。

### 4.5 QQWry 二进制归属地（`iplib/qqwry.go`）
纯真 IP 库二进制搜索实现：
- 索引偏移与记录地址用 `binary.LittleEndian.Uint32(b[:4])` 解析
- 随机读取用 `*os.File` 的 `Seek` / `io.SectionReader`
- GBK 转 UTF8 解码用 `golang.org/x/text/encoding/simplifiedchinese.GBK.NewDecoder()`
- 首次加载索引偏移；查询结果 LRU 缓存

### 4.6 验证流程（8 模式）
- 8 种验证模式，静态页 `cc1-cc7.html/js` 经 `embed.FS` 内嵌。
- 验证页由代理自身提供（`/cc/verify/*` 路由），前端 JS 调用 `/cc/verify?action=verify_xxx` 完成验证。
- `cc_verified` cookie 加 **HttpOnly + Secure + SameSite=Lax + HMAC 签名**，防伪造。
- 验证成功 -> `Store.ResetIP(ip)` + 清 `jyj_verify_fail` + 设签名 cookie。

### 4.7 配置管理
- 静态配置 `configs/config.yaml`：DB、upstream、listen、admin_ips、日志路径。
- 动态配置 `jyj_config` 表：防护开关、阈值、验证模式、API key、webhook 等，`DynamicConfig` 带 `sync.RWMutex` 热加载（后台改完即时生效，无需重启）。

---

## 五、REST API 设计（管理 + 设备联动）

统一前缀 `/api/v1`，JSON 响应，统一错误码与封装。两套鉴权：
- **后台**：session cookie（登录后）
- **设备联动开放 API**：`X-API-Key` 头，`crypto/subtle.ConstantTimeCompare` 常量时间比较

### 5.1 管理接口（session 鉴权）
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/auth/login` | 登录，返回 session |
| POST | `/api/v1/auth/logout` | 登出 |
| GET | `/api/v1/dashboard/stats` | 仪表盘统计 |
| GET | `/api/v1/dashboard/trend` | 24h 攻击趋势 |
| GET | `/api/v1/attacks` | 攻击日志列表（筛选/分页） |
| GET | `/api/v1/access-logs` | 访问日志列表 |
| GET/POST/DELETE | `/api/v1/ip-list` | IP 黑白名单 CRUD（含 CIDR/通配符） |
| GET/PUT | `/api/v1/config` | 动态配置读写 |
| GET/PUT | `/api/v1/users` | 用户管理/改密 |
| GET/PUT | `/api/v1/system/status` | 系统开关、各防护开关 |
| DELETE | `/api/v1/cache` | 清理缓存 |
| GET | `/api/v1/login-logs` | 登录日志 |

### 5.2 设备联动开放 API（`X-API-Key` 鉴权，`/api/v1/open/*`）
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/open/status` | 实时防护状态 + 关键统计（设备轮询） |
| GET | `/api/v1/open/blacklist` | 查询当前黑名单 |
| POST | `/api/v1/open/blacklist` | 设备联动封禁 IP（如蜜罐/IDS 触发） |
| DELETE | `/api/v1/open/blacklist` | 设备联动解封 |
| GET/POST/DELETE | `/api/v1/open/whitelist` | 白名单联动 |
| GET | `/api/v1/open/attacks` | 最近攻击事件（设备拉取） |
| GET/PUT | `/api/v1/open/config` | 远程切换防护开关/阈值 |
| GET | `/api/v1/open/events` | **SSE 事件流**：攻击事件实时推送至设备 |
| POST | `/api/v1/open/webhook/test` | 测试 webhook 推送 |

> 设备联动场景：蜜罐/IDS 检测到恶意 IP -> 调 `POST /open/blacklist` 联动封禁；攻击发生 -> Go 主动 webhook 推送 + SSE 流供设备订阅。

---

## 六、后台前端（Vue3/Vite）

- **技术栈**：Vue3 + Vite + Vue Router + Pinia + Element Plus + ECharts + axios
- **页面**：登录、仪表盘、攻击仪表盘（图表）、攻击日志、访问日志、IP 黑白名单、系统配置、用户设置、代码生成器、登录日志、API 密钥管理、缓存清理
- **构建产物** `web/dist` 由 Go 经 `embed.FS` 内嵌，单二进制交付（`/admin/*` 路由）
- **UI 规范**（遵循 CLAUDE.md 2.5）：紫蓝渐变配色（`#667eea->#764ba2`），统一适中圆角 + 柔和阴影，弱化硬边框

---

## 七、鉴权与安全

### 7.1 鉴权
- 管理员：用户名 + bcrypt 校验 -> session cookie（HttpOnly/Secure/SameSite）
- 后台 IP 白名单：`admin_ips`（CIDR/通配符），Go `iputil` 实现
- 设备联动：API key（DB 存哈希，常量时间比较）

### 7.2 安全加固清单
1. 配置文件明文 DB 口令 -> `config.yaml` + 环境变量覆盖，不入库不进 git
2. 默认弱口令 -> 初始化随机密码 + 首登强制改密
3. API key 非常量时间比较 -> `crypto/subtle.ConstantTimeCompare`
4. 海外 IP 硬编码 `/8` 段误杀 -> 改用 QQWry 精准归属地判断
5. CPU 采样恒返回 0 -> `gopsutil` 真实采样，动态阈值生效
6. SQL 注入面 -> Go `database/sql` 全参数化，天然免疫
7. XSS 输出面 -> `html/template` 自动转义 + 验证页静态资源不拼接用户输入
8. `cc_verified` cookie 裸值 -> HMAC 签名 + 安全属性
9. 全局异常 -> `RecoveryMiddleware` 捕获封装，禁原生 panic/错误外泄

---

## 八、交付分阶段

| 阶段 | 交付项 | 状态 | 备注 |
|---|---|---:|---|
| 第一阶段 | Go 入口、配置、DB、`migrate`/`init` | ✅ | 可运行并完成本地数据库迁移 |
| 第一阶段 | 反向代理、请求体转发、可信代理 IP、多站点 | ✅ | HTTP/HTTPS 双入口已实现 |
| 第一阶段 | CC、IP、QQWry、验证闭环、SQL/XSS 基础检测 | ✅ | SQL/XSS 为特征检测 |
| 第一阶段 | REST API、Session/CSRF、设备 API | ✅ | 已有主流事件格式接入 |
| 第一阶段 | Vue 管理后台和单二进制嵌入 | ✅ | 核心管理页面已完成 |
| 第二阶段 | 用户、站点、策略、攻击运营和资源告警 | ✅ | 含分页、导出、规则上传和签名更新 |
| 第二阶段 | Linux 完整包、本地/远程安装、升级回滚 | ✅ | `run.sh`/`upgrade.sh` 为正式部署入口 |
| 第二阶段 | Windows 脚本和跨平台编译 | ✅ | 原生 Windows Service 仍为后续项 |
| 第二阶段 | SSE 与主动 webhook 推送 | ⬜ | 当前以安全设备拉取/推送到 JingShield 为主 |
| 第三阶段 | P0/P1 请求语义引擎 | ⬜ | 详细验收见 1.5 |
| 第三阶段 | Redis、多节点、集中控制面 | ⬜ | Store 接口已预留 |
| 第三阶段 | RBAC/MFA/OIDC、完整审计 | ⬜ | 企业身份能力 |
| 第三阶段 | 多证书、ACME、证书告警 | ⬜ | 当前仅静态证书和测试证书 |

---

## 九、部署与运维

- **单二进制** `jingshield`（含前端 `embed.FS`），Windows10/Linux 跨平台编译
- **启动**：`jingshield -c config.yaml`，默认监听 `127.0.0.1:18080`，反代至 `upstream`
- **配置**：`config.yaml`（静态）+ `jyj_config` 表（动态热加载）
- **日志**：结构化 JSON 日志（access/attack/error 分通道）
- **部署**：Docker / docker-compose / systemd / Windows 服务
- **运维**：`jingshield migrate`（建表）、`jingshield init`（初始化向导）、`jingshield reload`（热重载配置）

---

## 十、配套文档（CLAUDE.md 3.x 规范）
Markdown 标准排版，含：项目简介、技术栈说明、完整工程目录结构、环境配置、启停命令、全局配置说明、各模块功能适配说明、部署运维说明、**REST API 接口文档**（含设备联动开放 API，固定字段：接口名/方法/URL/入参/出参示例/约束/状态码/场景）。

---

## 十一、风险与边界
1. **部署模型**：独立反向代理，站前拦截。被保护站点需改为只监听内网，由 Go 反代对外。此为必要改动。
2. **多节点横向扩展**：单机内存状态在多副本下计数分散。本期单机先行；`Store` 接口已预留 Redis，多副本时换实现即可，无需改业务代码。
3. **正则兼容**：现有 XSS/SQL 正则已验证 RE2 兼容；未来新增正则需避开前瞻/反向引用。
4. **QQWry 数据文件**：`QQWry.Dat` 需随二进制分发或外挂路径配置。

---

**捷云鲸盾 JieYun JingShield**  让您的网站安全无忧！

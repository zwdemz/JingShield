# Linux 软防火墙桥接器

独立进程 `jingshield-firewall` 为 nftables/ipset 提供 `jingshield-v1` HTTPS 协议。主 WAF 不需要 `CAP_NET_ADMIN`。默认 `apply:false`，只进行内存演练，不执行任何系统命令。

当前交付是可编译源码、离线命令模拟和 HTTP 单元测试；**未对真实 Linux 内核、NAS 或生产防火墙执行初始化/封禁，也不代表任何厂商设备已经兼容**。

## 构建与前提

从仓库根目录构建：

```sh
go build -o jingshield-firewall ./cmd/jingshield-firewall
go test ./internal/firewallbridge ./cmd/jingshield-firewall
```

可跨平台编译；真实 apply 仅 Linux 支持。管理员需事先提供 `/usr/sbin/nft` 或 `/usr/sbin/ipset`，本程序不安装软件、不搜索 PATH、不执行 shell、不创建规则/集合。运行环境须允许相应内核 Netfilter 功能。

程序仅管理固定名称 `jingshield_blocked_v4`、`jingshield_blocked_v6`；nftables 额外限定 `inet jingshield` 表及 `jingshield-managed-v1` 集合注释。禁止其他进程/动态规则写这些集合；进程通过 `/run/jingshield-firewall/adapter.lock` 排它锁避免自身多实例并发写。

## 部署步骤

1. 备份并检查现有防火墙配置，确认设备实际需要过滤的 input/forward 路径。两种后端只选择一种，不能对同一流量重复初始化。
2. nftables：人工审阅 `jingshield.nft`，先运行 `nft -c -f` 检查，再手动加载。脚本以 `create table` 开始：已有同名表会使整批失败，不覆盖已有数据。
3. ipset：人工审阅并执行 `initialize-ipset.sh`。它只建立空的专属集合及 INPUT/FORWARD 引用，不清空其他规则；同名集合已存在则拒绝。若中途失败，保留已创建的空集合/引用，由管理员核验后恢复，不自动删除。规则持久化交由原系统防火墙管理器配置。
4. 将二进制安装至 `/usr/local/bin/jingshield-firewall`，使用独立非 root 账户 `jingshield-firewall`。复制 JSON 示例到 `/etc/jingshield-firewall/config.json`，配置受信任 TLS 证书/私钥，保证服务账户可读且无其他用户读取权限。
5. 在权限 `0600` 的 `/etc/jingshield-firewall/secret.env` 写入专用环境变量 `JINGSHIELD_LINKAGE_FIREWALL_KEY`，使用安全生成的至少 32 字节密钥，不复用 NAS 登录密码。同一值通过专用环境变量注入 WAF，不放入 JSON、Git 或日志。
6. 按实际 WAF 地址设置 `allowed_cidrs`（优先 `/32`、`/128`）和 `listen`。允许来源 CIDR、配置白名单和本机接口 IP 自动受到封禁保护；不会信任 `X-Forwarded-For`。`127.0.0.0/8`、链路本地、组播等不可作为批封对象。
7. 先保持 `apply:false`。安装并审阅 systemd 示例；dry-run 可去掉两个能力配置项，apply 仅授予 `CAP_NET_ADMIN`，不授予 root/全能力。手动运行时先创建服务账户拥有、权限 `0700` 的 `/run/jingshield-firewall`。
8. 演练通过、管理员确认专属集合及规则路径后，手工设置 `apply:true` 并重启桥接器。在 WAF 联动页选择设备类型 `firewall`、协议 `jingshield-v1`，配置 HTTPS 根地址及密钥环境变量，重新验证能力。

不要为方便而关闭 TLS 校验；WAF 必须信任桥接器证书链，证书 SAN 应匹配配置地址。systemd 的网络命名空间不能隔离到独立空网络，否则操作不到目标主机的防火墙。

## API

两个接口均要求 HTTPS、允许的实际连接来源及 `X-API-Key`。请求体最多 64 KiB，默认每分钟 60 次请求、8 秒批次超时；同一时刻只接受一个批量变更。

- `GET /openapi/v1/capabilities`：返回 `protocol`、`device_type:firewall`、`max_batch_size:500`、`driver`、`dry_run`、`max_expire_seconds`。演练仅宣告 `preview-block-batch`；apply 才宣告 `block-batch`，避免 WAF 把演练识别为真正封禁。
- `POST /openapi/v1/ip/block-batch`：输入 `ips:[]string`、必填 `reason`、`expire_seconds`。最多 500 个原始条目，重复项也计入上限；仅精确 IPv4/IPv6，不接收 CIDR、主机名、脚本或任意命令。
- `POST /openapi/v1/ip/whitelist/sync`：输入 `source`、正整数 `revision`、完整的 `rules[]`。需配置 `whitelist_state_file`，演练模式只声明 `preview-whitelist-sync` 且不落盘；apply 模式才声明 `whitelist-sync`。规则最多 500 条，支持精确 IP、CIDR、连续 IPv4 后缀通配符（转为 CIDR），禁止全网白名单。

接收快照按来源隔离（最多 16 个来源），只替换该来源规则；空数组清除该来源旧规则。本机静态 `whitelist_cidrs` 与管理来源保护保持不变。apply 模式先将快照以 0600 文件原子写入 `whitelist_state_file`，再仅从桥接器托管集合中清理匹配的封禁 IP，并读回确认；不操作其他防火墙规则或集合。若清理或审计失败，返回非成功并要求核查状态，不能盲目重发。重启时重新读取持久快照并对托管集合对账；文件损坏会阻止启动。服务账户必须能写入状态文件所在目录（systemd 示例使用 `/var/lib/jingshield-firewall` 的 0700 目录）。删除状态文件会丢失接收快照，须纳入备份与回滚计划。

正常 apply 返回标准 envelope：

```json
{"code":0,"message":"success","data":{"requested":2,"unique":2,"blocked":1,"skipped_whitelist":1,"skipped_ips":["192.0.2.10"],"dry_run":false,"partial":false}}
```

演练返回 `blocked:0`、`dry_run:true` 和 `would_block`。失败返回非 2xx，`partial:true` 表示部分生效或结果无法完整确认；必须检查设备集合/审计记录，不得因 HTTP 超时直接当作失败无副作用或无限重发。

`blocked` 表示目标 IP 的专属集合成员及期限经内核读回确认，并非网络流量实测结论。集合是否正确接入实际 input/forward、既有连接、流量卸载、容器桥接等路径，需要管理员在隔离测试流量中验证。

## TTL、幂等与失败恢复

- `expire_seconds:0` 为永久；nftables 本适配器支持到 31536000 秒，ipset 到 2147483 秒。超过后端上限直接拒绝，不截断为较短封禁。
- 每批读取内核集合，不依赖进程缓存。已有永久或更晚到期的封禁不会被缩短；重试可以延长临时到期时间，成员不会重复创建。秒级读回会保守保留约 1 秒余量。
- nftables：检查生成的事务，然后通过单次 `nft -f -` 原子执行，只增改本批专属元素，不删除/清空任何表或链；执行后重新读回集合。
- ipset：`restore` 不当作事务。失败或读回不符时，在独立 3 秒窗口内尝试恢复本批触及元素的原状态；恢复失败明确返回 partial。不会覆盖整套防火墙。
- 桥接器重启不删除现有内核元素。主机重启后的持久规则/永久名单恢复属于系统防火墙管理器，不由本程序暗中写入系统启动配置。
- 操作 intent/outcome 输出 JSON 至 stdout/systemd journal，记录来源、规范化 IP、期限、确认/partial/演练状态；不记录 API Key、TLS 私钥、请求原文。审计写入失败会阻止新下发，或将已操作结果标记为需要人工核查。

## 停用与回滚

先将 WAF 联动关闭，再停止桥接器；不会自动移除任何现有封禁。临时条目由内核按 TTL 到期；永久条目与专属规则需管理员对照变更审计和原备份逐项恢复。不要通过全局 flush 清理桥接器，不要直接覆盖整套生产 ruleset。若仅需继续演练，可改 `apply:false` 重启，无需更改任何内核规则。

## 核验依据

CLI 参数、集合与时间语义依据 Netfilter 官方 [nft 手册](https://netfilter.org/projects/nftables/manpage.html)、[原子事务说明](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)、[ipset 手册](https://ipset.netfilter.org/ipset.man.html)。JSON 解析结构依据 Debian 随上游库发布的 [libnftables-json 手册](https://manpages.debian.org/bookworm/libnftables1/libnftables-json.5.en.html)。实际发行版/内核版本仍须在部署前验证，不猜测额外厂商命令。

时间单位额外以 [nftables 1.1.3 官方源代码](https://www.netfilter.org/projects/nftables/files/nftables-1.1.3.tar.xz) 的 `src/json.c:set_elem_expr_json` 核对：内部 `timeout`、`expiration` 除以 1000 后才写入 JSON，故 JSON 使用秒，不是毫秒。ipset 的 [Linux 内核实现](https://github.com/torvalds/linux/blob/master/net/netfilter/ipset/ip_set_core.c) 中 `ip_set_timeout_get` 对永久元素输出 0，将仍存活但不足一秒的元素上取为 1，不能把 `timeout 0` 当作即将过期。两项均有离线固定样本测试；不意味着任何目标发行版已实机验收。

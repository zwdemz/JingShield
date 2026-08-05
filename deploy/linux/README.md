# Linux systemd 部署

推荐目录：

- 二进制：`/opt/jingshield/bin/jingshield`
- 配置：`/etc/jingshield/config.yaml`
- 密钥环境文件：`/etc/jingshield/jingshield.env`（权限 `0600`）
- 日志：`/var/log/jingshield`

构建 Linux amd64 二进制：

```bash
cd web
npm ci
npm run build
cd ..
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/jingshield-linux-amd64 ./cmd/jingshield
```

前端必须先构建；`web/dist` 会被嵌入二进制。部署后管理控制台与管理 API 共用服务端口，入口为 `/admin/`，并受 `admin_ips` 限制。

测试配置同时监听 HTTP `18080` 和 HTTPS `18443`。安装脚本在证书不存在时生成 RSA 3072、SHA-256、有效期 10950 天（约 30 年）的自签名证书，文件位于 `/etc/jingshield/tls/`。它仅用于隔离测试，浏览器仍会提示不受信任；生产环境请替换为受信任证书，并将 `session.secure` 设为 `true`。

环境文件至少包含：

```ini
JINGSHIELD_DB_PASS=<专用数据库密码>
JINGSHIELD_SESSION_KEY=<至少 32 字节随机值>
```

安装配置和 systemd 单元后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now jingshield
sudo systemctl status jingshield --no-pager
```

`install-remote-test.sh` 用于全新测试机：创建最小权限系统/数据库账号、生成随机密钥、
执行幂等迁移和初始化、生成缺失的测试证书，并启动隔离测试上游与 WAF。脚本不会修改现有 80/443/8080 服务；
若发现数据库账号已存在但密钥文件缺失，会拒绝重置账号密码。

本目录的测试配置监听 `0.0.0.0:18080`，管理接口仅允许本机和
`192.168.118.0/24`，上游为隔离的 `127.0.0.1:19000` 测试页。正式部署时应将
监听地址、`admin_ips` 和 `upstream.target` 改成实际网络，并在 HTTPS 入口下将
`session.secure` 设为 `true`。

测试入口：

- `http://<节点IP>:18080/admin/`
- `https://<节点IP>:18443/admin/`
- `https://<节点IP>:18443/openapi/v1/status`（请求头携带 `X-API-Key`）

源站必须通过主机防火墙、安全组或监听地址限制为仅允许 WAF 节点访问。若业务服务仍公开监听（例如 `*:8080`），访问者可以绕过 WAF 直连源站。

## 运行与升级脚本

节点已按推荐目录安装后：

```bash
sudo bash deploy/linux/run.sh
sudo bash deploy/linux/run.sh --init --username admin  # 仅首次空库
sudo bash deploy/linux/upgrade.sh /absolute/path/to/jingshield-linux-amd64
```

`run.sh` 会生成缺失的 30 年 PEM 测试证书、执行幂等迁移并重启 systemd 服务。`upgrade.sh` 使用独占锁，先用候选版本迁移，再备份、停止、原子替换和启动；新版本启动失败时自动恢复备份。

# Windows Server 部署

在线/离线部署选择、数据库配置和安装后检查见仓库根目录的 [`docs/部署指南.md`](../../docs/部署指南.md)。Windows 目标机使用预构建程序，不需要安装 Go 或 Node.js。

在仓库根目录构建无控制台窗口的精简版本：

```powershell
pwsh -File scripts/build-windows.ps1 -Arch amd64
```

实际入口为 `./cmd/jingshield`，构建器采用 `go build -ldflags "-s -w -H=windowsgui" -trimpath`；`-H=windowsgui` 仅用于 Windows，Linux 构建不会使用该参数。

建议目录为 `C:\ProgramData\JingShield`，包含 `bin\jingshield.exe`、`config.yaml`、`jingshield.env` 和 `service-run.ps1`。环境文件示例：

```ini
JINGSHIELD_DB_PASS=<数据库密码>
JINGSHIELD_SESSION_KEY=<至少32字节随机值>
```

以管理员身份运行 PowerShell：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
& 'C:\ProgramData\JingShield\run.ps1' -Initialize
```

脚本生成 30 年 PEM 测试证书、迁移数据库，并注册以 SYSTEM 运行的开机计划任务。首次初始化凭据只显示一次。程序当前不是原生 Windows Service，因此脚本不使用 `sc.exe create`。

升级：

```powershell
& 'C:\ProgramData\JingShield\upgrade.ps1' -Candidate 'D:\packages\jingshield-new.exe'
```

升级脚本先迁移、再备份和替换；健康检查失败会恢复上一版。生产环境请替换自签名证书、将 `session.secure` 设为 `true`，并通过 Windows 防火墙禁止外部直连源站端口。

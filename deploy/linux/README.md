# JingShield Linux release assets

<p align="right"><strong>English</strong> · <a href="#中文">中文</a></p>

The repository-root `run.sh` and `upgrade.sh` are the lifecycle entry points. This directory contains the remaining configuration and systemd templates used to assemble the complete Linux release. Target servers do not build the frontend or Go program.

The generated archive exposes two lifecycle commands:

- `run.sh`: installs a complete package on first use; in `/opt/jingshield/`, migrates and restarts an installed node.
- `upgrade.sh`: upgrades directly from a newly extracted complete package and automatically restores the previous binary if startup fails.

Build an operator-ready package from the repository root:

```powershell
pwsh -File scripts/build-linux-package.ps1 -Arch amd64
```

The default `-NetworkProfile Auto` selects a reachable, faster Go module proxy for the current build. `Direct` and `China` are available as explicit overrides.

Install it locally:

```bash
tar -xzf jingshield-0.1.0-linux-amd64.tar.gz
cd jingshield-0.1.0-linux-amd64
sudo ./run.sh
```

Upgrade it later:

```bash
tar -xzf jingshield-<new-version>-linux-amd64.tar.gz
cd jingshield-<new-version>-linux-amd64
sudo ./upgrade.sh
```

Installed paths:

Application-owned production files are kept in one directory. `/opt/jingshield` is the default and `JINGSHIELD_INSTALL_ROOT` can select another absolute path; only the systemd unit is installed outside it.

- Binary: `/opt/jingshield/jingshield`
- Configuration: `/opt/jingshield/config.yaml`
- Secret environment file: `/opt/jingshield/jingshield.env` (`0640`)
- Lifecycle scripts: `/opt/jingshield/run.sh` and `/opt/jingshield/upgrade.sh`
- TLS, rules, data, logs, and backups: subdirectories or files under `/opt/jingshield/`

`config.yaml` listens on HTTP `18080` and HTTPS `18443`, uses `127.0.0.1:8080` as the initial fallback upstream, and permits management from loopback and RFC 1918 private networks. Tighten these values for the actual production network.

The generated 30-year self-signed certificate is for isolated testing. Replace it with a trusted certificate and enable secure session cookies before production use. Restrict the real upstream so clients cannot bypass JingShield.

`install-remote-test.sh` and the test upstream unit remain development fixtures; they are not included in the complete release package.

---

<h2 id="中文">中文</h2>

<p align="right"><a href="#jingshield-linux-release-assets">English</a> · <strong>中文</strong></p>

仓库根目录的 `run.sh` 和 `upgrade.sh` 是生命周期入口。本目录保存其余 Linux 配置与 systemd 模板，目标服务器不需要构建前端或 Go 程序。

生成的完整包只需要两个入口：

- `run.sh`：首次执行安装完整包；安装到 `/opt/jingshield/` 后负责迁移和启动现有节点。
- `upgrade.sh`：在新解压的完整包中直接升级；新版本启动失败时自动恢复旧二进制。

维护者构建发行包：

```powershell
pwsh -File scripts/build-linux-package.ps1 -Arch amd64
```

默认 `-NetworkProfile Auto` 会为当前构建自动选择可用且更快的 Go 模块代理，也可以显式使用 `Direct` 或 `China`。

目标机本地安装：

```bash
tar -xzf jingshield-0.1.0-linux-amd64.tar.gz
cd jingshield-0.1.0-linux-amd64
sudo ./run.sh
```

后续升级：

```bash
tar -xzf jingshield-<新版本>-linux-amd64.tar.gz
cd jingshield-<新版本>-linux-amd64
sudo ./upgrade.sh
```

应用生产文件默认全部集中在 `/opt/jingshield`，也可以通过 `JINGSHIELD_INSTALL_ROOT` 选择其他绝对目录；目录外只安装 systemd 必需的服务单元。

默认配置监听 HTTP `18080` 和 HTTPS `18443`，初始兼容源站为 `127.0.0.1:8080`，管理访问允许回环地址和 RFC 1918 私有网段。生产部署必须根据实际网络收紧配置、替换自签测试证书，并限制真实源站只能由 WAF 访问。

`install-remote-test.sh` 和测试上游单元仅供开发验证，不会进入完整发行包。

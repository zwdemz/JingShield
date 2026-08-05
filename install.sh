#!/usr/bin/env bash
set -e

JINGSHIELD_RELEASE_BASE="${JINGSHIELD_RELEASE_BASE:-https://release.jingshield.example/releases}"
JINGSHIELD_DEFAULT_VERSION="latest"
JINGSHIELD_INSTALL_DIR="${JINGSHIELD_INSTALL_ROOT:-/opt/jingshield}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
log_warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
log_step()  { printf "\n${CYAN}${BOLD}>>> %s${NC}\n" "$*"; }

banner() {
  cat <<'EOF'

     _       _            ____  _     _     _ _
    | | __ _(_)_ __   ___/ ___|| |__ (_) __| | |
 _  | |/ _` | | '_ \ / _ \___ \| '_ \| |/ _` | |
| |_| | (_| | | | | | (_) |__) | | | | | (_| | |
 \___/ \__, |_|_| |_|\___/____/|_| |_|_|\__,_|_|
       |___/

  Lightweight Reverse-Proxy Web Application Firewall

EOF
}

usage() {
  cat <<EOF
Usage:
  bash -c "\$(curl -fsSLk ${JINGSHIELD_RELEASE_BASE}/install.sh)"

  Or with options:
  bash -c "\$(curl -fsSLk ${JINGSHIELD_RELEASE_BASE}/install.sh)" -s -- \\
    [--version VERSION] [--install-dir DIR] [--admin-user USER] \\
    [--skip-db-provision] [--secrets-file PATH] [--no-start]

Options:
  --version VERSION      Install a specific version (default: latest)
  --install-dir DIR      Installation directory (default: /opt/jingshield)
  --admin-user USER      Initial administrator username
  --admin-email EMAIL    Initial administrator email
  --db-admin-user USER   MySQL provisioning account (default: root)
  --secrets-file PATH    Read deployment credentials from a KEY=VALUE file
  --consume-secrets      Delete secrets file after reading
  --skip-db-provision    Connect to a pre-existing database
  --force-config         Replace existing config.yaml
  --no-start             Install without starting the service
  -h, --help             Show this help message

Environment variables:
  JINGSHIELD_RELEASE_BASE   Override release download base URL
  JINGSHIELD_INSTALL_ROOT   Override installation directory

Examples:
  # One-liner install (latest version)
  bash -c "\$(curl -fsSLk https://release.jingshield.example/install.sh)"

  # Install specific version with admin user
  curl -fsSLk https://release.jingshield.example/install.sh | bash -s -- \\
    --version 0.2.0 --admin-user myadmin

  # Remote database with secrets file
  curl -fsSLk https://release.jingshield.example/install.sh | bash -s -- \\
    --skip-db-provision --secrets-file /tmp/db.values --consume-secrets
EOF
}

# ─── 参数解析（本脚本参数 + 透传给 run.sh 的参数） ──────────────────────────

INSTALL_VERSION="${JINGSHIELD_DEFAULT_VERSION}"
INSTALL_DIR="${JINGSHIELD_INSTALL_DIR}"
FORWARDED_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { log_error "--version requires a value"; exit 1; }
      INSTALL_VERSION="$2"; shift 2 ;;
    --install-dir)
      [[ $# -ge 2 ]] || { log_error "--install-dir requires a value"; exit 1; }
      INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      FORWARDED_ARGS+=("$1"); shift ;;
  esac
done

# ─── Stage 1: 环境检测 ───────────────────────────────────────────────────────

banner

log_step "环境检测"

if [[ "${EUID}" -ne 0 ]]; then
  log_error "安装脚本必须以 root 身份运行（请使用 sudo）"
  exit 1
fi
log_info "root 权限 ✓"

kernel="$(uname -s)"
if [[ "${kernel}" != "Linux" ]]; then
  log_error "JingShield 仅支持 Linux 系统，当前系统: ${kernel}"
  exit 1
fi
log_info "Linux 系统 ✓"

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)   echo "arm64" ;;
    *)
      log_error "不支持的 CPU 架构: ${machine}（仅支持 amd64 / arm64）"
      exit 1
      ;;
  esac
}

ARCH="$(detect_arch)"
log_info "CPU 架构: ${ARCH} ✓"

detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

DISTRO="$(detect_distro)"
log_info "发行版: ${DISTRO}"

# ─── 检查 systemd ────────────────────────────────────────────────────────────

if ! command -v systemctl &>/dev/null; then
  log_error "未检测到 systemd（systemctl 不可用）"
  log_error "JingShield 需要 systemd 作为服务管理器"
  exit 1
fi
log_info "systemd ✓"

# ─── 检查下载工具 ────────────────────────────────────────────────────────────

if command -v curl &>/dev/null; then
  DOWNLOAD_CMD="curl"
elif command -v wget &>/dev/null; then
  DOWNLOAD_CMD="wget"
else
  log_error "未找到 curl 或 wget"
  exit 1
fi
log_info "下载工具: ${DOWNLOAD_CMD} ✓"

# ─── 检查 sha256sum ──────────────────────────────────────────────────────────

if ! command -v sha256sum &>/dev/null; then
  log_error "sha256sum 不可用，无法校验下载完整性"
  exit 1
fi
log_info "sha256sum ✓"

# ─── 检查/安装 MySQL 客户端 ─────────────────────────────────────────────────

install_mysql_client() {
  log_info "正在安装 MySQL 客户端..."
  case "${DISTRO}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq mysql-client
      ;;
    centos|rhel|rocky|almalinux|fedora|amzn|alinux|anolis|tencentos)
      if command -v dnf &>/dev/null; then
        dnf install -y -q mysql
      else
        yum install -y -q mysql
      fi
      ;;
    alpine)
      apk add --no-cache mysql-client
      ;;
    *)
      log_error "无法自动安装 MySQL 客户端，发行版: ${DISTRO}"
      log_error "请手动安装后重试"
      exit 1
      ;;
  esac
}

if command -v mysql &>/dev/null; then
  log_info "MySQL 客户端 ✓"
else
  log_warn "未检测到 MySQL 客户端"
  if [[ -t 0 ]]; then
    read -r -p "$(printf "${YELLOW}是否自动安装 MySQL 客户端？[y/N]:${NC} ")" REPLY
    echo
    if [[ "${REPLY}" =~ ^[Yy]$ ]]; then
      install_mysql_client
      log_info "MySQL 客户端已安装 ✓"
    else
      log_error "MySQL 客户端是必需的，请手动安装后重试"
      exit 1
    fi
  else
    log_info "非交互模式，尝试自动安装..."
    install_mysql_client
    log_info "MySQL 客户端已安装 ✓"
  fi
fi

# ─── 检查是否已安装 ─────────────────────────────────────────────────────────

if [[ -f "${INSTALL_DIR}/jingshield" && -f "${INSTALL_DIR}/run.sh" ]]; then
  log_warn "检测到已有安装: ${INSTALL_DIR}"
  if [[ -t 0 ]]; then
    read -r -p "$(printf "${YELLOW}是否继续覆盖安装？[y/N]:${NC} ")" REPLY
    echo
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
      log_info "安装已取消"
      exit 0
    fi
  else
    log_info "非交互模式，继续安装"
  fi
fi

# ─── Stage 2: 下载完整包 ─────────────────────────────────────────────────────

log_step "下载 JingShield ${INSTALL_VERSION} (${ARCH})"

PACKAGE_NAME="jingshield-${INSTALL_VERSION}-linux-${ARCH}"
TARBALL_URL="${JINGSHIELD_RELEASE_BASE}/${INSTALL_VERSION}/${PACKAGE_NAME}.tar.gz"
CHECKSUM_URL="${TARBALL_URL}.sha256"

STAGING_DIR="$(mktemp -d /tmp/jingshield-install.XXXXXXXXXX)"
trap 'rm -rf -- "${STAGING_DIR}"' EXIT

TARBALL_FILE="${STAGING_DIR}/${PACKAGE_NAME}.tar.gz"
CHECKSUM_FILE="${STAGING_DIR}/${PACKAGE_NAME}.tar.gz.sha256"

download_file() {
  local url="$1" dest="$2"
  if [[ "${DOWNLOAD_CMD}" == "curl" ]]; then
    curl -4fsSLk -o "${dest}" "${url}"
  else
    wget -q --no-check-certificate -O "${dest}" "${url}"
  fi
}

log_info "下载地址: ${TARBALL_URL}"

if ! download_file "${TARBALL_URL}" "${TARBALL_FILE}"; then
  log_error "下载失败: ${TARBALL_URL}"
  log_error "请检查网络连接或版本号是否正确"
  exit 1
fi
log_info "下载完成 ✓"

# ─── 校验 SHA-256 ────────────────────────────────────────────────────────────

log_step "校验完整性"

if download_file "${CHECKSUM_URL}" "${CHECKSUM_FILE}" 2>/dev/null; then
  EXPECTED="$(awk '{print $1}' "${CHECKSUM_FILE}")"
  ACTUAL="$(sha256sum "${TARBALL_FILE}" | awk '{print $1}')"
  if [[ "${EXPECTED}" != "${ACTUAL}" ]]; then
    log_error "SHA-256 校验失败"
    log_error "期望: ${EXPECTED}"
    log_error "实际: ${ACTUAL}"
    exit 1
  fi
  log_info "SHA-256 校验通过 ✓"
else
  log_warn "校验文件不可用，跳过 SHA-256 校验"
fi

# ─── 解压 ────────────────────────────────────────────────────────────────────

log_step "解压安装包"

tar -xzf "${TARBALL_FILE}" -C "${STAGING_DIR}"

PACKAGE_DIR="${STAGING_DIR}/${PACKAGE_NAME}"
if [[ ! -d "${PACKAGE_DIR}" ]]; then
  PACKAGE_DIR="$(find "${STAGING_DIR}" -mindepth 1 -maxdepth 1 -type d | head -1)"
fi

[[ -d "${PACKAGE_DIR}" ]] || { log_error "解压后找不到包目录"; exit 1; }
[[ -f "${PACKAGE_DIR}/run.sh" ]] || { log_error "包不完整: 缺少 run.sh"; exit 1; }

log_info "解压完成 ✓"

# ─── Stage 3: 调用 run.sh ───────────────────────────────────────────────────

log_step "执行安装"
log_info "安装目录: ${INSTALL_DIR}"

export JINGSHIELD_INSTALL_ROOT="${INSTALL_DIR}"

exec bash "${PACKAGE_DIR}/run.sh" "${FORWARDED_ARGS[@]}"

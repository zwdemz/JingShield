#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
package_mode=0
[[ -f "${script_dir}/payload/jingshield" ]] && package_mode=1

if [[ "${package_mode}" -eq 1 ]]; then
  install_root="${JINGSHIELD_INSTALL_ROOT:-/opt/jingshield}"
else
  install_root="${JINGSHIELD_INSTALL_ROOT:-${script_dir}}"
fi
config_file="${JINGSHIELD_CONFIG:-${install_root}/config.yaml}"
env_file="${JINGSHIELD_ENV_FILE:-${install_root}/jingshield.env}"
service_file="${JINGSHIELD_SERVICE_FILE:-/etc/systemd/system/jingshield.service}"
admin_username=""
admin_email=""
db_admin_user="root"
secrets_file=""
consume_secrets=0
force_config=0
skip_db_provision=0
no_start=0
initialize=0

usage() {
  cat <<'EOF'
Usage:
  First install from a complete package: sudo ./run.sh [options]
  Start an installed node:             sudo /opt/jingshield/run.sh

Options for a complete package:
  --admin-user USER       Initial administrator name (never prefilled)
  --admin-email EMAIL     Initial administrator email
  --db-admin-user USER    Local MySQL provisioning account (default: root)
  --secrets-file PATH     Read deployment values from a protected KEY=VALUE file
  --consume-secrets       Delete --secrets-file immediately after reading it
  --skip-db-provision     Connect to an existing database/account
  --force-config          Replace config.yaml and retain a timestamped backup
  --no-start              Install and migrate without starting systemd

Options for an installed node:
  --init                  Initialize an empty database
  --username USER         Administrator name used with --init

Supported secret-file/environment keys:
  JINGSHIELD_DB_ADMIN_PASS, JINGSHIELD_DB_PASS, JINGSHIELD_SESSION_KEY,
  JINGSHIELD_DB_HOST, JINGSHIELD_DB_PORT, JINGSHIELD_DB_USER,
  JINGSHIELD_DB_NAME, JINGSHIELD_UPSTREAM, JINGSHIELD_LISTEN,
  JINGSHIELD_TLS_LISTEN, JINGSHIELD_TLS_CERT_FILE, JINGSHIELD_TLS_KEY_FILE
EOF
}

while (($#)); do
  case "$1" in
    --admin-user|--username) shift; admin_username="${1:?administrator username is required}" ;;
    --admin-email) shift; admin_email="${1:?--admin-email requires a value}" ;;
    --db-admin-user) shift; db_admin_user="${1:?--db-admin-user requires a value}" ;;
    --secrets-file) shift; secrets_file="${1:?--secrets-file requires a value}" ;;
    --consume-secrets) consume_secrets=1 ;;
    --skip-db-provision) skip_db_provision=1 ;;
    --force-config) force_config=1 ;;
    --no-start) no_start=1 ;;
    --init) initialize=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "run.sh must be run as root (use sudo)" >&2
  exit 1
fi

run_installed() {
	local binary="${JINGSHIELD_BINARY:-${install_root}/jingshield}"
	if [[ -z "${JINGSHIELD_BINARY:-}" && ! -f "${binary}" && -f "${install_root}/bin/jingshield" ]]; then
		binary="${install_root}/bin/jingshield"
	fi
	if [[ -z "${JINGSHIELD_CONFIG:-}" && ! -f "${config_file}" && -f /etc/jingshield/config.yaml ]]; then
		config_file="/etc/jingshield/config.yaml"
	fi
	if [[ -z "${JINGSHIELD_ENV_FILE:-}" && ! -f "${env_file}" && -f /etc/jingshield/jingshield.env ]]; then
		env_file="/etc/jingshield/jingshield.env"
	fi
	for required in "${binary}" "${config_file}" "${env_file}" "${service_file}"; do
    [[ -f "${required}" ]] || { echo "missing required file: ${required}" >&2; exit 1; }
  done

  set -a
  # shellcheck disable=SC1090
  source "${env_file}"
  set +a

  local cert_file="${JINGSHIELD_TLS_CERT_FILE:-${install_root}/tls/jingshield.crt}"
  local key_file="${JINGSHIELD_TLS_KEY_FILE:-${install_root}/tls/jingshield.key}"
  if grep -Eq '^[[:space:]]*tls_listen:[[:space:]]*"[^"[:space:]]+' "${config_file}" && \
      [[ ! -s "${cert_file}" || ! -s "${key_file}" ]]; then
    install -d -o root -g jingshield -m 0750 "$(dirname "${cert_file}")"
    local node_ip
    node_ip="$(hostname -I | awk '{print $1}')"
    "${binary}" cert --cert "${cert_file}" --key "${key_file}" --hosts "${node_ip},localhost" --days 10950
    chown root:jingshield "${cert_file}" "${key_file}"
    chmod 0644 "${cert_file}"
    chmod 0640 "${key_file}"
  fi

  "${binary}" migrate -c "${config_file}"
  if [[ "${initialize}" -eq 1 ]]; then
    require_admin_username
    "${binary}" init -c "${config_file}" --username "${admin_username}" --email "${admin_email}"
  fi
  systemctl daemon-reload
  systemctl enable jingshield.service >/dev/null
  systemctl restart jingshield.service
  systemctl --no-pager --full status jingshield.service
}

require_admin_username() {
  if [[ -z "${admin_username}" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "Initial administrator username: " admin_username
    else
      echo "administrator username is required; pass --admin-user (or --username with --init)" >&2
      exit 2
    fi
  fi
  [[ "${admin_username}" =~ ^[A-Za-z0-9_.-]{3,50}$ ]] || {
    echo "invalid administrator username" >&2
    exit 1
  }
}

if [[ "${package_mode}" -eq 0 ]]; then
  run_installed
  exit 0
fi

for command in install systemctl sha256sum getent useradd groupadd od tr mysql readlink sed; do
  command -v "${command}" >/dev/null || { echo "missing required command: ${command}" >&2; exit 1; }
done
install_root="$(readlink -m -- "${install_root}")"
[[ "${install_root}" =~ ^/[A-Za-z0-9._/-]+$ && "${install_root}" != "/" && "${install_root}" != *"/../"* ]] || {
  echo "JINGSHIELD_INSTALL_ROOT must be a safe absolute directory" >&2
  exit 1
}
config_file="${JINGSHIELD_CONFIG:-${install_root}/config.yaml}"
env_file="${JINGSHIELD_ENV_FILE:-${install_root}/jingshield.env}"
for required in \
  "${script_dir}/payload/jingshield" \
  "${script_dir}/config/config.yaml" \
  "${script_dir}/systemd/jingshield.service" \
  "${script_dir}/upgrade.sh"; do
  [[ -f "${required}" ]] || { echo "incomplete package, missing: ${required}" >&2; exit 1; }
done
[[ -f "${script_dir}/SHA256SUMS" ]] || { echo "incomplete package, missing SHA256SUMS" >&2; exit 1; }
(cd "${script_dir}" && sha256sum -c SHA256SUMS)

allowed_key() {
  case "$1" in
    JINGSHIELD_DB_ADMIN_PASS|JINGSHIELD_DB_PASS|JINGSHIELD_SESSION_KEY|\
    JINGSHIELD_DB_HOST|JINGSHIELD_DB_PORT|JINGSHIELD_DB_USER|JINGSHIELD_DB_NAME|\
    JINGSHIELD_UPSTREAM|JINGSHIELD_LISTEN|JINGSHIELD_TLS_LISTEN|\
    JINGSHIELD_TLS_CERT_FILE|JINGSHIELD_TLS_KEY_FILE) return 0 ;;
    *) return 1 ;;
  esac
}

load_values() {
  local file="$1" overwrite="$2" line key value
  [[ -f "${file}" && ! -L "${file}" ]] || { echo "invalid values file: ${file}" >&2; exit 1; }
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    [[ "${line}" == *=* ]] || { echo "invalid line in ${file}" >&2; exit 1; }
    key="${line%%=*}"
    value="${line#*=}"
    allowed_key "${key}" || { echo "unsupported key in ${file}: ${key}" >&2; exit 1; }
    if [[ "${overwrite}" -eq 1 || -z "${!key+x}" ]]; then
      printf -v "${key}" '%s' "${value}"
      export "${key}"
    fi
  done < "${file}"
}

legacy_config_file="/etc/jingshield/config.yaml"
legacy_env_file="/etc/jingshield/jingshield.env"
legacy_tls_dir="/etc/jingshield/tls"
if [[ -f "${env_file}" ]]; then
  load_values "${env_file}" 0
elif [[ "${env_file}" != "${legacy_env_file}" && -f "${legacy_env_file}" ]]; then
  echo "importing credentials from legacy layout: ${legacy_env_file}"
  load_values "${legacy_env_file}" 0
fi
if [[ -n "${secrets_file}" ]]; then
  load_values "${secrets_file}" 1
  if [[ "${consume_secrets}" -eq 1 ]]; then
    rm -f -- "${secrets_file}"
    secrets_file=""
  fi
fi

db_host="${JINGSHIELD_DB_HOST:-127.0.0.1}"
db_port="${JINGSHIELD_DB_PORT:-3306}"
db_user="${JINGSHIELD_DB_USER:-jingshield}"
db_name="${JINGSHIELD_DB_NAME:-jyj_ccpro}"
db_password="${JINGSHIELD_DB_PASS:-}"
session_key="${JINGSHIELD_SESSION_KEY:-}"
db_admin_password="${JINGSHIELD_DB_ADMIN_PASS:-}"

[[ "${db_port}" =~ ^[0-9]{1,5}$ ]] && ((db_port >= 1 && db_port <= 65535)) || { echo "invalid database port" >&2; exit 1; }
[[ "${db_host}" =~ ^[A-Za-z0-9.:-]+$ ]] || { echo "invalid database host" >&2; exit 1; }
[[ "${db_user}" =~ ^[A-Za-z0-9_]{1,32}$ ]] || { echo "invalid database user" >&2; exit 1; }
[[ "${db_name}" =~ ^[A-Za-z0-9_]{1,64}$ ]] || { echo "invalid database name" >&2; exit 1; }
[[ "${db_admin_user}" =~ ^[A-Za-z0-9_]{1,32}$ ]] || { echo "invalid database administrator user" >&2; exit 1; }
[[ "${admin_email}" != *$'\n'* && "${admin_email}" != *$'\r'* ]] || { echo "invalid administrator email" >&2; exit 1; }
if [[ -n "${db_password}" && ! "${db_password}" =~ ^[A-Za-z0-9._~!@%+=:-]+$ ]]; then
  echo "JINGSHIELD_DB_PASS contains characters that are unsafe in the systemd environment file" >&2
  exit 1
fi
if [[ -n "${session_key}" && ! "${session_key}" =~ ^[A-Za-z0-9._~!@%+=:-]{32,256}$ ]]; then
  echo "JINGSHIELD_SESSION_KEY must be 32-256 safe printable characters" >&2
  exit 1
fi

random_hex() {
  od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'
}
[[ -n "${session_key}" ]] || session_key="$(random_hex 32)"

if [[ "${skip_db_provision}" -eq 0 ]]; then
  [[ "${db_host}" == "127.0.0.1" || "${db_host}" == "localhost" ]] || {
    echo "automatic provisioning supports only local MySQL; use --skip-db-provision for a remote database" >&2
    exit 1
  }
  mysql_admin() {
    if [[ -n "${db_admin_password}" ]]; then
      MYSQL_PWD="${db_admin_password}" mysql --batch --skip-column-names --user="${db_admin_user}" "$@"
    else
      mysql --batch --skip-column-names --user="${db_admin_user}" "$@"
    fi
  }
  account_exists="$(mysql_admin -e "SELECT COUNT(*) FROM mysql.user WHERE User='${db_user}' AND Host='127.0.0.1';")"
  if [[ "${account_exists}" == "0" ]]; then
    [[ -n "${db_password}" ]] || db_password="$(random_hex 24)"
    [[ "${db_password}" =~ ^[A-Za-z0-9._~!@%+=:-]{16,128}$ ]] || {
      echo "JINGSHIELD_DB_PASS must be 16-128 safe printable characters for automatic provisioning" >&2
      exit 1
    }
    mysql_admin <<SQL
CREATE DATABASE IF NOT EXISTS \`${db_name}\` DEFAULT CHARACTER SET utf8mb4;
CREATE USER '${db_user}'@'127.0.0.1' IDENTIFIED BY '${db_password}';
GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
  else
    [[ -n "${db_password}" ]] || {
      echo "database account ${db_user}@127.0.0.1 exists but its password is unavailable" >&2
      echo "provide JINGSHIELD_DB_PASS or preserve ${env_file}" >&2
      exit 1
    }
    mysql_admin -e "CREATE DATABASE IF NOT EXISTS \`${db_name}\` DEFAULT CHARACTER SET utf8mb4; GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'127.0.0.1'; FLUSH PRIVILEGES;"
  fi
else
  [[ -n "${db_password}" ]] || { echo "JINGSHIELD_DB_PASS is required with --skip-db-provision" >&2; exit 1; }
fi

getent group jingshield >/dev/null || groupadd --system jingshield
getent passwd jingshield >/dev/null || \
  useradd --system --gid jingshield --home-dir "${install_root}" --shell /usr/sbin/nologin jingshield

install -d -o root -g root -m 0755 "${install_root}" "${install_root}/rules"
install -d -o root -g jingshield -m 0750 "${install_root}/tls"
install -d -o jingshield -g jingshield -m 0750 "${install_root}/data" "${install_root}/logs"

timestamp="$(date +%Y%m%d%H%M%S)"
if [[ ! -f "${config_file}" || "${force_config}" -eq 1 ]]; then
  if [[ -f "${config_file}" ]]; then
    cp --preserve=mode,ownership,timestamps "${config_file}" "${config_file}.backup.${timestamp}"
  fi
  config_source="${script_dir}/config/config.yaml"
  if [[ "${force_config}" -eq 0 && -f "${legacy_config_file}" && "${config_file}" != "${legacy_config_file}" ]]; then
    echo "importing configuration from legacy layout: ${legacy_config_file}"
    config_source="${legacy_config_file}"
  fi
  sed \
    -e "s|@INSTALL_ROOT@|${install_root}|g" \
    -e "s|/etc/jingshield/tls|${install_root}/tls|g" \
    -e "s|/var/log/jingshield|${install_root}/logs|g" \
    "${config_source}" > "${install_root}/.config.yaml.${timestamp}"
  install -o root -g jingshield -m 0640 "${install_root}/.config.yaml.${timestamp}" "${config_file}"
  rm -f -- "${install_root}/.config.yaml.${timestamp}"
fi

if [[ -d "${legacy_tls_dir}" && "${install_root}/tls" != "${legacy_tls_dir}" ]]; then
  for tls_name in jingshield.crt jingshield.key; do
    if [[ -s "${legacy_tls_dir}/${tls_name}" && ! -e "${install_root}/tls/${tls_name}" ]]; then
      install -o root -g jingshield -m 0640 "${legacy_tls_dir}/${tls_name}" "${install_root}/tls/${tls_name}"
    fi
  done
  [[ ! -f "${install_root}/tls/jingshield.crt" ]] || chmod 0644 "${install_root}/tls/jingshield.crt"
fi

candidate="${install_root}/.jingshield.next"
install -o root -g root -m 0755 "${script_dir}/payload/jingshield" "${candidate}"
"${candidate}" help >/dev/null
mv -f -- "${candidate}" "${install_root}/jingshield"
install -o root -g root -m 0755 "${script_dir}/run.sh" "${install_root}/run.sh"
install -o root -g root -m 0755 "${script_dir}/upgrade.sh" "${install_root}/upgrade.sh"
sed "s|@INSTALL_ROOT@|${install_root}|g" "${script_dir}/systemd/jingshield.service" > "${install_root}/.jingshield.service.${timestamp}"
install -o root -g root -m 0644 "${install_root}/.jingshield.service.${timestamp}" "${service_file}"
rm -f -- "${install_root}/.jingshield.service.${timestamp}"
if [[ -d "${script_dir}/rules" ]]; then
  cp -a "${script_dir}/rules/." "${install_root}/rules/"
  chown -R root:root "${install_root}/rules"
fi

env_tmp="${install_root}/.jingshield.env.${timestamp}"
{
  printf 'JINGSHIELD_DB_HOST=%s\n' "${db_host}"
  printf 'JINGSHIELD_DB_PORT=%s\n' "${db_port}"
  printf 'JINGSHIELD_DB_USER=%s\n' "${db_user}"
  printf 'JINGSHIELD_DB_NAME=%s\n' "${db_name}"
  printf 'JINGSHIELD_DB_PASS=%s\n' "${db_password}"
  printf 'JINGSHIELD_SESSION_KEY=%s\n' "${session_key}"
  for key in JINGSHIELD_UPSTREAM JINGSHIELD_LISTEN JINGSHIELD_TLS_LISTEN JINGSHIELD_TLS_CERT_FILE JINGSHIELD_TLS_KEY_FILE; do
    if [[ -n "${!key:-}" ]]; then
      [[ "${!key}" != *[[:space:]]* ]] || { echo "${key} must not contain whitespace" >&2; exit 1; }
      printf '%s=%s\n' "${key}" "${!key}"
    fi
  done
} > "${env_tmp}"
chown root:jingshield "${env_tmp}"
chmod 0640 "${env_tmp}"
mv -f -- "${env_tmp}" "${env_file}"

set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a
"${install_root}/jingshield" migrate -c "${config_file}"

mysql_app() {
  MYSQL_PWD="${db_password}" mysql --batch --skip-column-names \
    --host="${db_host}" --port="${db_port}" --user="${db_user}" "$@"
}
user_count="$(mysql_app -e "SELECT COUNT(*) FROM \`${db_name}\`.jyj_users;")"
if [[ "${user_count}" == "0" ]]; then
  require_admin_username
  "${install_root}/jingshield" init -c "${config_file}" --username "${admin_username}" --email "${admin_email}"
else
  echo "administrator already exists; initialization skipped"
fi

systemctl daemon-reload
if [[ "${no_start}" -eq 0 ]]; then
  run_installed
  echo "JingShield installation complete: service=active config=${config_file}"
else
  echo "JingShield installation complete without service start (--no-start)"
fi

#!/usr/bin/env bash
set -euo pipefail

install_root="${JINGSHIELD_INSTALL_ROOT:-/opt/jingshield}"
config_file="${JINGSHIELD_CONFIG:-/etc/jingshield/config.yaml}"
env_file="${JINGSHIELD_ENV_FILE:-/etc/jingshield/jingshield.env}"
service_file="${JINGSHIELD_SERVICE_FILE:-/etc/systemd/system/jingshield.service}"
initialize=0
username="admin"

while (($#)); do
  case "$1" in
    --init) initialize=1 ;;
    --username) shift; username="${1:?--username requires a value}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "run.sh must be run as root (use sudo)" >&2
  exit 1
fi

binary="${install_root}/bin/jingshield"
for required in "${binary}" "${config_file}" "${env_file}" "${service_file}"; do
  [[ -f "${required}" ]] || { echo "missing required file: ${required}" >&2; exit 1; }
done

set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

cert_file="/etc/jingshield/tls/jingshield.crt"
key_file="/etc/jingshield/tls/jingshield.key"
if grep -Eq '^[[:space:]]*tls_listen:[[:space:]]*"[^"[:space:]]+' "${config_file}" && [[ ! -s "${cert_file}" || ! -s "${key_file}" ]]; then
  install -d -o root -g jingshield -m 0750 "$(dirname "${cert_file}")"
  node_ip="$(hostname -I | awk '{print $1}')"
  "${binary}" cert --cert "${cert_file}" --key "${key_file}" --hosts "${node_ip},localhost" --days 10950
  chown root:jingshield "${cert_file}" "${key_file}"
  chmod 0644 "${cert_file}"
  chmod 0640 "${key_file}"
fi

"${binary}" migrate -c "${config_file}"
if [[ "${initialize}" -eq 1 ]]; then
  "${binary}" init -c "${config_file}" --username "${username}"
fi

systemctl daemon-reload
systemctl enable jingshield.service >/dev/null
systemctl restart jingshield.service
systemctl --no-pager --full status jingshield.service


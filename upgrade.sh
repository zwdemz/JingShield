#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "upgrade.sh must be run as root (use sudo)" >&2
  exit 1
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
package_mode=0
if [[ $# -eq 0 && -f "${script_dir}/payload/jingshield" ]]; then
  package_mode=1
  [[ -f "${script_dir}/SHA256SUMS" ]] || { echo "incomplete package, missing SHA256SUMS" >&2; exit 1; }
  (cd "${script_dir}" && sha256sum -c SHA256SUMS)
  candidate="$(readlink -f -- "${script_dir}/payload/jingshield")"
elif [[ $# -eq 1 ]]; then
  candidate="$(readlink -f -- "$1")"
else
  echo "usage: sudo ./upgrade.sh [new-jingshield-binary]" >&2
  echo "when executed from a complete package, no argument is required" >&2
  exit 2
fi
[[ -f "${candidate}" ]] || { echo "candidate binary not found: ${candidate}" >&2; exit 1; }

if [[ "${package_mode}" -eq 1 ]]; then
  install_root="${JINGSHIELD_INSTALL_ROOT:-/opt/jingshield}"
else
  install_root="${JINGSHIELD_INSTALL_ROOT:-${script_dir}}"
fi
config_file="${JINGSHIELD_CONFIG:-${install_root}/config.yaml}"
env_file="${JINGSHIELD_ENV_FILE:-${install_root}/jingshield.env}"
current="${JINGSHIELD_BINARY:-${install_root}/jingshield}"
if [[ -z "${JINGSHIELD_BINARY:-}" && ! -f "${current}" && -f "${install_root}/bin/jingshield" ]]; then
  current="${install_root}/bin/jingshield"
fi
if [[ -z "${JINGSHIELD_CONFIG:-}" && ! -f "${config_file}" && -f /etc/jingshield/config.yaml ]]; then
  config_file="/etc/jingshield/config.yaml"
fi
if [[ -z "${JINGSHIELD_ENV_FILE:-}" && ! -f "${env_file}" && -f /etc/jingshield/jingshield.env ]]; then
  env_file="/etc/jingshield/jingshield.env"
fi
binary_dir="$(dirname -- "${current}")"
next="${binary_dir}/.jingshield.next"
backup="${binary_dir}/jingshield.backup.$(date +%Y%m%d%H%M%S)"
lock_file="/run/lock/jingshield-upgrade.lock"

for required in "${current}" "${config_file}" "${env_file}"; do
  [[ -f "${required}" ]] || { echo "missing required file: ${required}" >&2; exit 1; }
done

exec 9>"${lock_file}"
flock -n 9 || { echo "another JingShield upgrade is running" >&2; exit 1; }

install -o root -g root -m 0755 "${candidate}" "${next}"
"${next}" help >/dev/null
set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a
"${next}" migrate -c "${config_file}"
cp --preserve=mode,ownership,timestamps "${current}" "${backup}"

systemctl stop jingshield.service
mv -f "${next}" "${current}"
if ! systemctl start jingshield.service || ! systemctl is-active --quiet jingshield.service; then
  echo "new version failed to start; rolling back to ${backup}" >&2
  cp --preserve=mode,ownership,timestamps "${backup}" "${current}"
  systemctl start jingshield.service
  exit 1
fi

if [[ "${package_mode}" -eq 1 ]]; then
  install -o root -g root -m 0755 "${script_dir}/run.sh" "${install_root}/run.sh"
  install -o root -g root -m 0755 "${script_dir}/upgrade.sh" "${install_root}/upgrade.sh"
  if [[ -d "${script_dir}/rules" ]]; then
    install -d -o root -g root -m 0755 "${install_root}/rules"
    cp -a "${script_dir}/rules/." "${install_root}/rules/"
    chown -R root:root "${install_root}/rules"
  fi
fi

echo "upgrade complete; rollback binary: ${backup}"
systemctl --no-pager --full status jingshield.service

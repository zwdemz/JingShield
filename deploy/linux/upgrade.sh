#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "upgrade.sh must be run as root (use sudo)" >&2
  exit 1
fi
if [[ $# -ne 1 ]]; then
  echo "usage: sudo ./upgrade.sh /absolute/path/to/jingshield-linux-amd64" >&2
  exit 2
fi

candidate="$(readlink -f -- "$1")"
[[ -f "${candidate}" ]] || { echo "candidate binary not found: ${candidate}" >&2; exit 1; }

install_root="${JINGSHIELD_INSTALL_ROOT:-/opt/jingshield}"
config_file="${JINGSHIELD_CONFIG:-/etc/jingshield/config.yaml}"
env_file="${JINGSHIELD_ENV_FILE:-/etc/jingshield/jingshield.env}"
current="${install_root}/bin/jingshield"
next="${install_root}/bin/jingshield.next"
backup="${install_root}/bin/jingshield.backup.$(date +%Y%m%d%H%M%S)"
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

echo "upgrade complete; rollback binary: ${backup}"
systemctl --no-pager --full status jingshield.service


#!/usr/bin/env bash
set -euo pipefail

stage_dir="${1:-/home/ubuntu/jingshield-stage}"
for file in jingshield config.yaml jingshield.service jingshield-test-upstream.service test-index.html; do
  test -f "${stage_dir}/${file}" || { echo "missing ${stage_dir}/${file}" >&2; exit 1; }
done

if ! getent passwd jingshield >/dev/null; then
  useradd --system --home-dir /opt/jingshield --shell /usr/sbin/nologin jingshield
fi

install -d -o root -g root -m 0755 /opt/jingshield/bin /etc/jingshield
install -d -o root -g jingshield -m 0750 /etc/jingshield/tls
install -d -o jingshield -g jingshield -m 0750 /opt/jingshield/data /opt/jingshield/upstream /var/log/jingshield
install -o root -g root -m 0755 "${stage_dir}/jingshield" /opt/jingshield/bin/jingshield
install -o root -g jingshield -m 0640 "${stage_dir}/config.yaml" /etc/jingshield/config.yaml
install -o jingshield -g jingshield -m 0644 "${stage_dir}/test-index.html" /opt/jingshield/upstream/index.html
install -o root -g root -m 0644 "${stage_dir}/jingshield.service" /etc/systemd/system/jingshield.service
install -o root -g root -m 0644 "${stage_dir}/jingshield-test-upstream.service" /etc/systemd/system/jingshield-test-upstream.service

if [[ ! -s /etc/jingshield/tls/jingshield.crt || ! -s /etc/jingshield/tls/jingshield.key ]]; then
  node_ip="$(hostname -I | awk '{print $1}')"
  openssl req -x509 -newkey rsa:3072 -sha256 -days 10950 -nodes \
    -subj "/CN=${node_ip}/O=JingShield Test" \
    -addext "subjectAltName=IP:${node_ip},DNS:localhost" \
    -keyout /etc/jingshield/tls/jingshield.key \
    -out /etc/jingshield/tls/jingshield.crt
fi
chown root:jingshield /etc/jingshield/tls/jingshield.crt /etc/jingshield/tls/jingshield.key
chmod 0644 /etc/jingshield/tls/jingshield.crt
chmod 0640 /etc/jingshield/tls/jingshield.key

if ! mysql -NBe "SELECT 1 FROM mysql.user WHERE User='jingshield' AND Host='127.0.0.1'" | grep -qx 1; then
  db_password="$(openssl rand -hex 24)"
  mysql --binary-mode <<SQL
CREATE DATABASE IF NOT EXISTS jyj_ccpro DEFAULT CHARACTER SET utf8mb4;
CREATE USER 'jingshield'@'127.0.0.1' IDENTIFIED BY '${db_password}';
GRANT ALL PRIVILEGES ON jyj_ccpro.* TO 'jingshield'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
  session_key="$(openssl rand -hex 32)"
  umask 077
  printf 'JINGSHIELD_DB_PASS=%s\nJINGSHIELD_SESSION_KEY=%s\n' "${db_password}" "${session_key}" > /etc/jingshield/jingshield.env
elif [[ ! -s /etc/jingshield/jingshield.env ]]; then
  echo "database user exists but /etc/jingshield/jingshield.env is missing; refusing to reset credentials" >&2
  exit 1
fi
chown root:jingshield /etc/jingshield/jingshield.env
chmod 0640 /etc/jingshield/jingshield.env

set -a
# shellcheck disable=SC1091
source /etc/jingshield/jingshield.env
set +a
/opt/jingshield/bin/jingshield migrate -c /etc/jingshield/config.yaml

user_count="$(mysql -NBe 'SELECT COUNT(*) FROM jyj_ccpro.jyj_users')"
if [[ "${user_count}" == "0" ]]; then
  /opt/jingshield/bin/jingshield init -c /etc/jingshield/config.yaml --username admin
else
  echo "管理员已存在，跳过 init"
fi

systemctl daemon-reload
systemctl enable --now jingshield-test-upstream.service
systemctl enable --now jingshield.service
systemctl --no-pager --full status jingshield-test-upstream.service
systemctl --no-pager --full status jingshield.service

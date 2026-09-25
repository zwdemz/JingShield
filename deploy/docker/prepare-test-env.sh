#!/usr/bin/env sh
set -eu

target_dir=${1:-.}
target_file="${target_dir}/.env.test"
if [ -e "$target_file" ]; then
  printf '%s\n' 'The test environment file already exists; keeping its credentials.'
  exit 0
fi

umask 077
root_password=$(openssl rand -hex 24)
db_password=$(openssl rand -hex 24)
session_key=$(openssl rand -hex 32)
printf 'MYSQL_ROOT_PASSWORD=%s\nJINGSHIELD_DB_PASS=%s\nJINGSHIELD_SESSION_KEY=%s\n' \
  "$root_password" "$db_password" "$session_key" > "$target_file"
chmod 600 "$target_file"
printf '%s\n' 'Created test-only credentials with owner-only permissions.'

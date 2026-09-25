#!/bin/sh
# MANUAL, ONE-TIME INITIALIZATION ONLY. Review existing firewall policy first.
# Creates empty dedicated sets and inserts only their source-IP drop references.
# Never flushes, deletes, replaces or disables an existing table or chain.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo 'Run manually with administrative privileges after reviewing this file.' >&2
  exit 1
fi
for executable in /usr/sbin/ipset /usr/sbin/iptables /usr/sbin/ip6tables; do
  if [ ! -x "$executable" ]; then
    echo "Required administrator-provisioned executable is missing: $executable" >&2
    exit 1
  fi
done
# Refuse to reuse an existing set: ownership must not be inferred from a name.
if /usr/sbin/ipset list jingshield_blocked_v4 >/dev/null 2>&1 || /usr/sbin/ipset list jingshield_blocked_v6 >/dev/null 2>&1; then
  echo 'Dedicated set name already exists. Review ownership manually; nothing changed.' >&2
  exit 1
fi
/usr/sbin/ipset create jingshield_blocked_v4 hash:ip family inet timeout 0 maxelem 20000
/usr/sbin/ipset create jingshield_blocked_v6 hash:ip family inet6 timeout 0 maxelem 20000
/usr/sbin/iptables -I INPUT 1 -m set --match-set jingshield_blocked_v4 src -j DROP
/usr/sbin/iptables -I FORWARD 1 -m set --match-set jingshield_blocked_v4 src -j DROP
/usr/sbin/ip6tables -I INPUT 1 -m set --match-set jingshield_blocked_v6 src -j DROP
/usr/sbin/ip6tables -I FORWARD 1 -m set --match-set jingshield_blocked_v6 src -j DROP
echo 'Empty dedicated sets and input/forward references created. No IP was blocked.'
echo 'Persist these dedicated references with your existing firewall manager after review.'

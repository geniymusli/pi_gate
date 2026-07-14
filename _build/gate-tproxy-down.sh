#!/usr/bin/env bash
#
# gate-tproxy-down.sh — снимает TPROXY-перехват (клиентов и самой малины),
# Force-DNS и IPv6-killswitch. После этого клиентский трафик никуда не идёт
# (fail-closed), а малина возвращается к обычной маршрутизации через WAN.
#
AP_SUBNET="${AP_SUBNET:-192.168.50.0/24}"
MARK_TP="${MARK_TP:-1}"
MARK_OUT="${MARK_OUT:-255}"
TABLE_TP="${TABLE_TP:-100}"

# PREROUTING (клиенты)
iptables -t mangle -D PREROUTING -j GATE_TP 2>/dev/null || true
iptables -t mangle -F GATE_TP 2>/dev/null || true
iptables -t mangle -X GATE_TP 2>/dev/null || true

# OUTPUT (трафик самой малины)
iptables -t mangle -D OUTPUT -j GATE_TP_LOCAL 2>/dev/null || true
iptables -t mangle -F GATE_TP_LOCAL 2>/dev/null || true
iptables -t mangle -X GATE_TP_LOCAL 2>/dev/null || true

# nat Force-DNS
iptables -t nat -D PREROUTING -j GATE_DNS 2>/dev/null || true
iptables -t nat -F GATE_DNS 2>/dev/null || true
iptables -t nat -X GATE_DNS 2>/dev/null || true

iptables -D FORWARD -s "$AP_SUBNET" -j DROP 2>/dev/null || true
while ip rule del fwmark "$MARK_TP" lookup "$TABLE_TP" 2>/dev/null; do :; done
while ip rule del fwmark "$MARK_OUT" lookup main 2>/dev/null; do :; done
ip route flush table "$TABLE_TP" 2>/dev/null || true

# IPv6: снимаем killswitch и возвращаем стек
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -D FORWARD -j DROP 2>/dev/null || true
  ip6tables -D OUTPUT -j GATE_TP6 2>/dev/null || true
  ip6tables -F GATE_TP6 2>/dev/null || true
  ip6tables -X GATE_TP6 2>/dev/null || true
fi
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
sysctl -qw net.ipv6.conf.default.disable_ipv6=0 2>/dev/null || true

echo "tproxy down (fail-closed)"

#!/usr/bin/env bash
#
# gate-tproxy-up.sh — заворачивает трафик в xray TPROXY.
#   • клиенты AP (forward)  : mangle PREROUTING -> TPROXY
#   • сама малина (local)   : mangle OUTPUT -> MARK -> петля через lo -> TPROXY
# Цепочка: → reality-s1 → C1 (реле) → reality-s2 → C2.
# Fail-closed: xray лёг → TPROXY бьёт в пустой сокет → пакеты дропаются.
#
# Защита от утечек:
#   • Force-DNS : весь plaintext DNS клиентов (:53) принудительно -> локальный
#                 dnscrypt (-> туннель). Клиент не обойдёт свой DNS.
#   • IPv6      : fail-closed. Туннель только IPv4; любой исходящий v6 рубится.
#
# МИМО туннеля (иначе сломается управление и сам туннель):
#   • трафик самого xray   — помечен mark 255 (sockopt) -> RETURN
#   • хопы (из chain.json) — xray:443 (mark255) и ssh:22 (управление) идут напрямую
#   • приватные/служебные сети — локалка, мультикаст, броадкаст
#
set -e
# Параметры AP — из /etc/gate/gate.conf (пишется при установке; интерфейсы ВЫБИРАЮТСЯ, не хардкод).
# Приоритет: env (отладка) → gate.conf → дефолт. AP_IFACE — имя из gate.conf, AP_IF — внутреннее.
[ -f /etc/gate/gate.conf ] && . /etc/gate/gate.conf || true
AP_SUBNET="${AP_SUBNET:-192.168.50.0/24}"
AP_ADDR="${AP_ADDR:-192.168.50.1}"
AP_IF="${AP_IF:-${AP_IFACE:-wlan1}}"
MARK_TP="${MARK_TP:-1}"        # метка доставки в прозрачный сокет (фикс. константа)
TABLE_TP="${TABLE_TP:-100}"    # таблица local-доставки tproxy (фикс. константа)
CHAIN_JSON="${CHAIN_JSON:-/etc/gate/chain.json}"

# Значения, которые ОБЯЗАНЫ совпадать с конфигом xray, берём из chain.json — единого
# источника правды (пишется при gate setup). Приоритет: env (отладка) → chain.json → дефолт.
# НИКАКИХ зашитых IP/портов хопов: всё из chain.json.
_cj(){ python3 -c "import json,sys;print(json.load(open('$CHAIN_JSON')).get(sys.argv[1]) or '')" "$1" 2>/dev/null; }
TPROXY_PORT="${TPROXY_PORT:-$(_cj tproxy_port)}"; TPROXY_PORT="${TPROXY_PORT:-12345}"  # = xray tproxy-in
MARK_OUT="${MARK_OUT:-$(_cj egress_mark)}";       MARK_OUT="${MARK_OUT:-255}"          # = reality-out sockopt.mark

# IP всех хопов цепочки (C1/C2/C3…) — обходим мимо туннеля, чтобы:
#   • data plane xray:443 к первому хопу шёл напрямую (он и так mark 255),
#   • прямое управление (ssh:22 малина→любой хоп) не уезжало в туннель.
# СТРОГО из chain.json; нет файла → список ПУСТ (старый IP не зашиваем — иначе мина при замене хопа).
HOP_IPS="$(python3 -c "import json;print(' '.join(h['host'] for h in json.load(open('$CHAIN_JSON'))['hops']))" 2>/dev/null || echo "")"
[ -n "$HOP_IPS" ] || echo "gate-tproxy-up: ВНИМАНИЕ — hops из $CHAIN_JSON не прочитаны, обход хопов ПУСТ" >&2

# IP тоннельного DNS-шлюза (VPN-режим, пишет vpn_on): его НЕ исключаем как приватный, а
# ЗАВОРАЧИВАЕМ в tproxy → цепочка → C2 → ppp0 → форвардер ISP. Так клиентский DNS резидентный.
# может быть НЕСКОЛЬКО резолверов (по одному в строке) — заворачиваем каждый
VPN_DNS="$(cat /etc/gate/vpn-dns 2>/dev/null | tr '\n' ' ' || true)"
# IP клиентов с персональным выходом (<MAC> <IP> <канал> <выход> [имя]) — их DNS идёт в полосу
LANE_CLIENTS="$(awk '!/^#/ && NF>=4 {print $2}' /etc/gate/client-lanes.conf 2>/dev/null | tr '\n' ' ')"

# приватные/служебные сети, которые НЕ заворачиваем (клиенты и сама малина)
PRIV="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32"

# 1) форвардинг + ослабленный rp_filter (доставка tproxy идёт через lo)
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf.lo.rp_filter=0 2>/dev/null || true
sysctl -qw "net.ipv4.conf.$AP_IF.rp_filter=0" 2>/dev/null || true

# 1b) IPv6 fail-closed (best-effort, не должно ронять IPv4-туннель):
#     туннель только IPv4 -> любой исходящий v6 = утечка мимо туннеля.
sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -C FORWARD -j DROP 2>/dev/null || ip6tables -A FORWARD -j DROP 2>/dev/null || true
  ip6tables -F GATE_TP6 2>/dev/null || true
  ip6tables -N GATE_TP6 2>/dev/null || true
  ip6tables -C OUTPUT -j GATE_TP6 2>/dev/null || ip6tables -A OUTPUT -j GATE_TP6 2>/dev/null || true
  ip6tables -A GATE_TP6 -o lo -j RETURN 2>/dev/null || true        # loopback ок
  ip6tables -A GATE_TP6 -d fe80::/10 -j RETURN 2>/dev/null || true # link-local (NDP) ок
  ip6tables -A GATE_TP6 -d ff00::/8 -j RETURN 2>/dev/null || true  # multicast ок
  ip6tables -A GATE_TP6 -j DROP 2>/dev/null || true                # остальной v6 наружу — рубим
fi

# 2) policy routing:
#    fwmark 1  (tproxy)       -> table 100 = local 0.0.0.0/0 dev lo  (отдать сокету)
#    fwmark 255 (xray egress) -> main                               (наружу через WAN)
ip rule add fwmark "$MARK_TP" lookup "$TABLE_TP" priority 100 2>/dev/null || true
ip route replace local 0.0.0.0/0 dev lo table "$TABLE_TP"
# КРИТИЧНО (kernel 6.x): source-validation помеченного пакета тоже смотрит в
# table 100; без юникастового маршрута клиентской подсети источник резолвится
# как RTN_LOCAL -> ядро рубит пакет как "martian source". Этот маршрут чинит.
ip route replace "$AP_SUBNET" dev "$AP_IF" table "$TABLE_TP"
ip rule add fwmark "$MARK_OUT" lookup main priority 90 2>/dev/null || true

# 3a) PREROUTING (GATE_TP): трафик КЛИЕНТОВ (forward) + завёрнутый локальный (через lo)
iptables -t mangle -F GATE_TP 2>/dev/null || true
iptables -t mangle -N GATE_TP 2>/dev/null || true
iptables -t mangle -C PREROUTING -j GATE_TP 2>/dev/null || iptables -t mangle -A PREROUTING -j GATE_TP
# исключения (мимо tproxy): все хопы цепочки напрямую, приватные/служебные сети
for ip in $HOP_IPS; do iptables -t mangle -A GATE_TP -d "$ip" -j RETURN; done
# VPN-DNS шлюз — заворачиваем в tproxy ДО исключения приватных (иначе уйдёт в RETURN и умрёт)
for d in $VPN_DNS; do
  iptables -t mangle -A GATE_TP -d "$d" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TP"
  iptables -t mangle -A GATE_TP -d "$d" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TP"
done
for n in $PRIV; do iptables -t mangle -A GATE_TP -d "$n" -j RETURN; done
# Клиенты с ПЕРСОНАЛЬНЫМ выходом (gate client … exit …): их :53 идёт в СВОЮ полосу, а не в
# локальный резолвер. Иначе DNS у всех уходил бы одной полосой и страна резолвера не
# совпадала бы с выходом устройства (ноут на C2 получал бы DNS американского провайдера).
# Правило ДО общего RETURN ниже — порядок в цепочке решает. Резолвер им раздаёт DHCP
# (dnsmasq tag:laneN), см. lanes_dhcp_write в `gate`.
for cip in $LANE_CLIENTS; do
  iptables -t mangle -A GATE_TP -i "$AP_IF" -s "$cip" -p udp --dport 53     -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TP"
  iptables -t mangle -A GATE_TP -i "$AP_IF" -s "$cip" -p tcp --dport 53     -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TP"
done
# Force-DNS для ОСТАЛЬНЫХ: их :53 не отдаём в tproxy — перехватит nat DNAT (ниже)
iptables -t mangle -A GATE_TP -i "$AP_IF" -p udp --dport 53 -j RETURN
iptables -t mangle -A GATE_TP -i "$AP_IF" -p tcp --dport 53 -j RETURN
# перехват всего остального TCP+UDP
iptables -t mangle -A GATE_TP -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TP"
iptables -t mangle -A GATE_TP -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_TP"

# 3b) OUTPUT (GATE_TP_LOCAL): трафик САМОЙ малины — метим mark 1, чтобы он по
#     ip rule fwmark 1 завернулся в table 100 -> lo -> снова PREROUTING -> TPROXY.
iptables -t mangle -F GATE_TP_LOCAL 2>/dev/null || true
iptables -t mangle -N GATE_TP_LOCAL 2>/dev/null || true
iptables -t mangle -C OUTPUT -j GATE_TP_LOCAL 2>/dev/null || iptables -t mangle -A OUTPUT -j GATE_TP_LOCAL
# не заворачиваем: трафик самого xray (mark 255 -> иначе петля), хопы, приватное
iptables -t mangle -A GATE_TP_LOCAL -m mark --mark "$MARK_OUT" -j RETURN
for ip in $HOP_IPS; do iptables -t mangle -A GATE_TP_LOCAL -d "$ip" -j RETURN; done
# VPN-DNS шлюз (см. VPN_DNS выше) — МЕТИМ для туннеля ДО PRIV-RETURN ниже (шлюз приватный 10.0.0.x)
for d in $VPN_DNS; do iptables -t mangle -A GATE_TP_LOCAL -d "$d" -j MARK --set-mark "$MARK_TP"; done
for n in $PRIV; do iptables -t mangle -A GATE_TP_LOCAL -d "$n" -j RETURN; done
iptables -t mangle -A GATE_TP_LOCAL -p tcp -j MARK --set-mark "$MARK_TP"
iptables -t mangle -A GATE_TP_LOCAL -p udp -j MARK --set-mark "$MARK_TP"

# 3c) nat PREROUTING (GATE_DNS): Force-DNS — DNAT клиентского :53 на локальный
#     резолвер (dnsmasq -> dnscrypt -> туннель). Клиент не обойдёт свой DNS.
iptables -t nat -F GATE_DNS 2>/dev/null || true
iptables -t nat -N GATE_DNS 2>/dev/null || true
iptables -t nat -C PREROUTING -j GATE_DNS 2>/dev/null || iptables -t nat -A PREROUTING -j GATE_DNS
# назначенные клиенты в DNAT НЕ попадают: их DNS уже ушёл в свою полосу (mangle выше)
for cip in $LANE_CLIENTS; do
  iptables -t nat -A GATE_DNS -i "$AP_IF" -s "$cip" -j RETURN
done
iptables -t nat -A GATE_DNS -i "$AP_IF" -p udp --dport 53 -j DNAT --to-destination "$AP_ADDR:53"
iptables -t nat -A GATE_DNS -i "$AP_IF" -p tcp --dport 53 -j DNAT --to-destination "$AP_ADDR:53"

# 4) killswitch: клиентский трафик НЕ должен форвардиться наружу мимо tproxy
iptables -C FORWARD -s "$AP_SUBNET" -j DROP 2>/dev/null || iptables -A FORWARD -s "$AP_SUBNET" -j DROP

echo "tproxy up: clients($AP_SUBNET) + local -> :$TPROXY_PORT | force-dns on | ipv6 off | хопы в обход: $HOP_IPS"

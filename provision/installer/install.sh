#!/usr/bin/env bash
#
# gate-install — установщик privacy-роутера на ЧИСТЫЙ Raspberry Pi OS Lite 64 (Debian 12/13).
# Запускается из распакованного бандла (рядом лежат каталоги bin/ share/ extra/).
# Обычно вызывается обёрткой gate-install.run (самораспаковка), но можно и напрямую: sudo ./install.sh
#
# Режимы:
#   (по умолчанию)  полная установка: пакеты, xray, ВЫБОР интерфейсов AP/WAN, конфиги, сервисы.
#   --update        обновить ТОЛЬКО tooling (скрипты/юниты), сохранив конфиги/ключи/цепочку.
#
# Что НЕ делает: не создаёт цепочку/ключи — это потом `gate setup` (у каждого своя).
#
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── вывод ─────────────────────────────────────────────────────────────
B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'
say(){ printf "%s\n" "$*"; }
ok(){  printf "  ${G}✓${N} %s\n" "$*"; }
warn(){ printf "  ${Y}⚠${N} %s\n" "$*"; }
die(){ printf "${R}✗ %s${N}\n" "$*" >&2; exit 1; }
ask(){ # ask <prompt> <default> -> echo answer (default если пусто/неинтерактивно)
  local p="$1" def="${2:-}" a=""
  if [ -t 0 ]; then read -r -p "$p${def:+ [$def]}: " a || true; fi
  printf "%s" "${a:-$def}"
}

# ── preflight ─────────────────────────────────────────────────────────
[ "$(id -u)" = 0 ] || die "запускать через sudo: sudo ./install.sh"
[ -d "$SELF_DIR/bin" ] && [ -d "$SELF_DIR/share" ] || die "не вижу bin/ share/ рядом — запусти из распакованного бандла"
arch="$(uname -m)"; [ "$arch" = aarch64 ] || warn "архитектура $arch (ожидался aarch64); xray-инсталлер сам подберёт"
command -v apt-get >/dev/null || die "нужен apt (Raspberry Pi OS / Debian)"

MODE=install; [ "${1:-}" = "--update" ] && MODE=update
[ "$MODE" = install ] && [ -f /etc/gate/chain.json ] && {
  warn "Обнаружена существующая установка (/etc/gate/chain.json)."
  [ "$(ask "Перейти в режим ОБНОВЛЕНИЯ (сохранить конфиги/ключи)? y/n" y)" = y ] && MODE=update
}

# ── копирование tooling (общее для install и update) ─────────────────
install_tooling(){
  say "${B}→ Устанавливаю утилиты gate…${N}"
  install -d /usr/local/bin /usr/local/share/gate /etc/bash_completion.d /etc/profile.d /etc/systemd/system
  # bin: исполняемые
  for f in "$SELF_DIR"/bin/*; do install -m 755 "$f" "/usr/local/bin/$(basename "$f")"; done
  # share: C2-side скрипты и bootstrap (стейджатся на малине, доставляются на хопы)
  for f in "$SELF_DIR"/share/*; do install -m 755 "$f" "/usr/local/share/gate/$(basename "$f")"; done
  # extra: completion, banner, systemd-юниты
  [ -f "$SELF_DIR/extra/gate-completion.bash" ] && install -m 644 "$SELF_DIR/extra/gate-completion.bash" /etc/bash_completion.d/gate
  [ -f "$SELF_DIR/extra/gate-banner.sh" ]       && install -m 644 "$SELF_DIR/extra/gate-banner.sh" /etc/profile.d/gate-banner.sh
  for u in gate-tunnel gate-web gate-monitor; do
    [ -f "$SELF_DIR/extra/$u.service" ] && install -m 644 "$SELF_DIR/extra/$u.service" "/etc/systemd/system/$u.service"
  done
  systemctl daemon-reload
  ok "утилиты обновлены"
}

# ── режим обновления: только tooling, конфиги не трогаем ─────────────
if [ "$MODE" = update ]; then
  say "${B}РЕЖИМ ОБНОВЛЕНИЯ${N} — обновляю только скрипты/юниты, конфиги и ключи сохраняю."
  install_tooling
  # перезапустить веб-панель, если активна (gate-vpn/osfp на хопы доедут сами при следующем on — по sha)
  systemctl is-active --quiet gate-web 2>/dev/null && systemctl restart gate-web && ok "веб-панель перезапущена"
  say "${G}${B}Обновление завершено.${N} Цепочка/конфиги/ключи не тронуты."
  # применение изменений дата-плейна (tproxy/xray на малине) — по желанию, с коротким разрывом:
  if systemctl is-active --quiet gate-tunnel 2>/dev/null; then
    say "  ${D}чтобы применить изменения перехвата: ${N}gate tunnel restart${D}  (кратко разорвёт клиентов) или ${N}sudo reboot"
  fi
  exit 0
fi

# ═══════════════════ ПОЛНАЯ УСТАНОВКА ═══════════════════
say "${B}gate — установка privacy-роутера${N}  ${D}(Raspberry Pi OS Lite 64)${N}"
echo

# 1) пакеты
say "${B}→ Ставлю пакеты (hostapd, dnsmasq, dnscrypt-proxy, iptables, iw, curl)…${N}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || warn "apt update с ошибками — продолжаю"
apt-get install -y -qq hostapd dnsmasq dnscrypt-proxy iptables iw curl rfkill >/dev/null \
  || die "не удалось поставить пакеты"
command -v nmcli >/dev/null || warn "NetworkManager (nmcli) не найден — на Pi OS Lite он обычно есть; проверь сеть вручную"
ok "пакеты установлены"
rfkill unblock wifi 2>/dev/null || true

# 2) xray — из БИНАРЯ бандла (офлайн; малина друга в РФ тоже не видит GitHub).
#    Юнит XTLS пишем сами (1:1 как офиц. установщик): nobody + AmbientCapabilities.
write_xray_unit(){
  cat > /etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
RuntimeDirectory=xray
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
UNIT
}
case "$arch" in aarch64|arm64) xray_bundled="$SELF_DIR/share/xray-linux-arm64";; x86_64|amd64) xray_bundled="$SELF_DIR/share/xray-linux-amd64";; *) xray_bundled="";; esac
if command -v xray >/dev/null 2>&1; then
  ok "xray уже установлен ($(xray version 2>/dev/null | head -1))"
elif [ -n "$xray_bundled" ] && [ -f "$xray_bundled" ]; then
  say "${B}→ Ставлю xray из бандла (офлайн, без GitHub)…${N}"
  install -m 755 "$xray_bundled" /usr/local/bin/xray
  install -d /usr/local/etc/xray /var/log/xray; chown nobody /var/log/xray 2>/dev/null || true
  write_xray_unit; systemctl daemon-reload
  ok "xray установлен из бандла ($(/usr/local/bin/xray version 2>/dev/null | head -1))"
else
  warn "бинаря xray для $arch в бандле нет — фоллбэк на GitHub (нужен интернет)…"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1 \
    && ok "xray установлен (GitHub)" || die "не удалось поставить xray (нет бинаря и нет интернета?)"
fi

# 3) tooling
install_tooling

# 4) ВЫБОР интерфейсов ─ AP (раздача) и WAN (приём интернета)
say ""
say "${B}→ Интерфейсы.${N} ${D}Раздача (AP) — Wi-Fi-адаптер с поддержкой AP; приём — eth/wifi/USB.${N}"
mapfile -t WIFI < <(for d in /sys/class/net/*/wireless; do basename "$(dirname "$d")"; done 2>/dev/null)
mapfile -t ALL  < <(for d in /sys/class/net/*; do b=$(basename "$d"); [ "$b" = lo ] || echo "$b"; done)
say "  Wi-Fi адаптеры:  ${WIFI[*]:-<нет>}"
say "  Все интерфейсы:  ${ALL[*]:-<нет>}"
# дефолт AP: первый wifi, который НЕ встроенный wlan0 (обычно USB), иначе wlan0
ap_def=""; for w in "${WIFI[@]:-}"; do [ "$w" != wlan0 ] && { ap_def="$w"; break; }; done; ap_def="${ap_def:-${WIFI[0]:-wlan1}}"
AP_IFACE="$(ask "Какой интерфейс РАЗДАЁТ (AP)?" "$ap_def")"
# дефолт WAN: eth0 если есть, иначе первый не-AP
wan_def=""; for i in "${ALL[@]:-}"; do [ "$i" = eth0 ] && wan_def=eth0; done
[ -z "$wan_def" ] && for i in "${ALL[@]:-}"; do [ "$i" != "$AP_IFACE" ] && { wan_def="$i"; break; }; done
WAN_IF="$(ask "Какой интерфейс ПРИНИМАЕТ интернет (uplink)?" "${wan_def:-eth0}")"
[ "$AP_IFACE" = "$WAN_IF" ] && die "AP и WAN не могут быть одним интерфейсом ($AP_IFACE)"
# разложим WAN на eth/wifi для gate wan eth|wifi.
# builtin_wifi — встроенный Wi-Fi, свободный ПОД WAN. Если под раздачу отдан wlan0
# (нет USB-свистка), то СВОБОДНОГО радиомодуля нет → WAN_WIFI пуст: gate откажет в wifi-WAN,
# WAN только по кабелю. Раньше тут был баг: WAN_WIFI фоллбэчил в wlan0 = тот же, что раздаёт.
case "$AP_IFACE" in wlan0) builtin_wifi="";; *) builtin_wifi=wlan0;; esac
if [ "${WAN_IF#eth}" != "$WAN_IF" ] || [ "${WAN_IF#en}" != "$WAN_IF" ]; then
  WAN_ETH="$WAN_IF"; WAN_WIFI="$builtin_wifi"
else
  WAN_WIFI="$WAN_IF"; WAN_ETH="eth0"
fi
if [ -n "$WAN_WIFI" ]; then
  ok "AP=$AP_IFACE  •  WAN=$WAN_IF  (WAN_ETH=$WAN_ETH, WAN_WIFI=$WAN_WIFI)"
else
  ok "AP=$AP_IFACE (одна радиокарта)  •  WAN=$WAN_IF — только кабель, wifi-WAN недоступен"
fi

# 5) параметры AP
SSID="$(ask "Имя Wi-Fi сети (SSID)" "gate-${AP_IFACE}")"
while :; do
  PASS="$(ask "Пароль Wi-Fi (мин. 8 символов)" "")"
  [ "${#PASS}" -ge 8 ] && break; warn "минимум 8 символов"
done
# Страна по умолчанию — US (нейтрально, без авто-подхвата регдомена, чтобы не привязываться к месту).
COUNTRY="$(ask "Код страны (2 буквы, для каналов Wi-Fi)" "US")"
COUNTRY="${COUNTRY:-US}"
AP_ADDR="$(ask "IP роутера в сети раздачи" "192.168.50.1")"
AP_NET="${AP_ADDR%.*}.0/24"   # 192.168.50.1 -> 192.168.50.0/24

# 6) рендер конфигов под выбор
say "${B}→ Пишу конфиги под $AP_IFACE / $WAN_IF…${N}"
install -d /etc/gate
cat > /etc/gate/gate.conf <<EOF
# Создано установщиком gate. Переопределяет дефолты в /usr/local/bin/gate.
WAN_ETH="$WAN_ETH"
WAN_WIFI="$WAN_WIFI"
AP_IFACE="$AP_IFACE"
AP_ADDR="$AP_ADDR"
AP_SUBNET="$AP_NET"
EOF

cat > /etc/hostapd/hostapd.conf <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
country_code=$COUNTRY
ieee80211d=1
hw_mode=g
channel=6
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$PASS
ignore_broadcast_ssid=0
EOF
chmod 600 /etc/hostapd/hostapd.conf
# debian: hostapd по умолчанию masked — снимаем; конфиг читает из /etc/hostapd/hostapd.conf
sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd 2>/dev/null || true
systemctl unmask hostapd 2>/dev/null || true

# drop-in: вешаем IP на AP-интерфейс при старте hostapd (NM им не управляет)
install -d /etc/systemd/system/hostapd.service.d
cat > /etc/systemd/system/hostapd.service.d/override.conf <<EOF
[Unit]
Wants=network.target
After=network.target
[Service]
ExecStartPre=/sbin/ip addr flush dev $AP_IFACE
ExecStartPre=/sbin/ip addr add $AP_ADDR/24 dev $AP_IFACE
ExecStartPre=/sbin/ip link set $AP_IFACE up
EOF

# dnsmasq: DHCP/DNS только на AP-интерфейсе; апстрим резолвер = локальный dnscrypt
install -d /etc/dnsmasq.d
cat > /etc/dnsmasq.d/gate.conf <<EOF
interface=$AP_IFACE
bind-interfaces
dhcp-range=${AP_ADDR%.*}.10,${AP_ADDR%.*}.200,255.255.255.0,24h
dhcp-option=3,$AP_ADDR
dhcp-option=6,$AP_ADDR
domain-needed
bogus-priv
no-resolv
server=127.0.0.1#5300
filter-AAAA
address=/mask.icloud.com/0.0.0.0
address=/mask-h2.icloud.com/0.0.0.0
address=/captive.apple.com/$AP_ADDR
EOF
cat > /etc/dnsmasq.d/gate-web.conf <<EOF
address=/gate/$AP_ADDR
EOF

# dnscrypt: слушать 127.0.0.1:5300, резолвер по умолчанию cloudflare (меняется gate dns resolver)
TOML=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
if [ -f "$TOML" ]; then
  sed -i "s|^listen_addresses =.*|listen_addresses = ['127.0.0.1:5300']|" "$TOML"
  if grep -qE "^#? *server_names" "$TOML"; then
    sed -i "s|^#\? *server_names =.*|server_names = ['cloudflare']|" "$TOML"
  else
    printf "\nserver_names = ['cloudflare']\n" >> "$TOML"
  fi
  # Сокет dnscrypt (debian, 127.0.2.1:53) НЕ трогаем — он безвреден и не конфликтует с dnsmasq
  # (тот на 127.0.0.1:53 + AP:53). dnscrypt дополнительно слушает 127.0.0.1:5300 из toml — туда
  # и форвардит dnsmasq (server=127.0.0.1#5300). Так на рабочей малине, повторяем 1:1.
fi

# NetworkManager: AP-интерфейс — unmanaged; резолвер малины = локальный; зонд связи off
install -d /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/99-gate-unmanaged.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:$AP_IFACE
EOF
cat > /etc/NetworkManager/conf.d/00-gate-dns.conf <<'EOF'
# Резолвер самой малины = локальный dnsmasq/dnscrypt (без утечки на роутер), на всех интерфейсах.
[global-dns-domain-*]
servers=127.0.0.1
EOF
cat > /etc/NetworkManager/conf.d/01-gate-noprobe.conf <<'EOF'
[connectivity]
enabled=false
EOF

# sysctl: форвардинг, BBR, ослабленный rp_filter (для tproxy), v6 off, mtu probing
cat > /etc/sysctl.d/99-gate-tproxy.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
cat > /etc/sysctl.d/99-gate-ipv6off.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
cat > /etc/sysctl.d/99-gate-mtu.conf <<'EOF'
net.ipv4.tcp_mtu_probing=1
EOF
sysctl --system >/dev/null 2>&1 || true
ok "конфиги записаны"

# 7) sudoers: пользователю pi полный passwordless sudo (gate всюду использует sudo по SSH-по-ключу)
LOGIN_USER="${SUDO_USER:-pi}"
echo "$LOGIN_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/011-pi-nopasswd
chmod 440 /etc/sudoers.d/011-pi-nopasswd
visudo -c >/dev/null 2>&1 && ok "sudo без пароля для $LOGIN_USER" || { rm -f /etc/sudoers.d/011-pi-nopasswd; warn "sudoers не прошёл проверку — пропущено"; }

# 8) сервисы: поднимаем инфраструктуру (БЕЗ gate-tunnel — его поднимет gate setup, см. ниже)
say "${B}→ Включаю сервисы…${N}"
systemctl enable --now dnscrypt-proxy >/dev/null 2>&1 || warn "dnscrypt-proxy не стартовал"
# ВАЖНО: сначала отдаём AP-интерфейс из-под NetworkManager (unmanaged уже записан выше),
# и только ПОТОМ поднимаем hostapd — иначе NM держит wlan0 и hostapd не может его забрать
# (частый провал при AP на встроенном wlan0). Раньше NM перезапускался ПОСЛЕ hostapd → фейл.
nmcli device set "$AP_IFACE" managed no >/dev/null 2>&1 || true
systemctl restart NetworkManager      >/dev/null 2>&1 || true
sleep 1
systemctl enable --now hostapd        >/dev/null 2>&1 \
  || warn "hostapd не стартовал (проверь rfkill/поддержку AP на $AP_IFACE; после reboot обычно встаёт)"
systemctl enable --now dnsmasq        >/dev/null 2>&1 || warn "dnsmasq не стартовал"
ok "hostapd / dnsmasq / dnscrypt-proxy включены"

# 9) заморозка риск-пакетов: apt upgrade не должен внезапно менять ядро/Wi-Fi-драйвер/
#    firmware/iptables и ломать роутер. Ставим hold на текущих (только что установленных)
#    версиях. Полный пин: gate freeze all. Разморозить: gate unfreeze.
say "${B}→ Замораживаю риск-пакеты (ядро/firmware/сеть/iptables)…${N}"
_held=0
for p in raspberrypi-kernel raspberrypi-bootloader linux-image-rpi-v8 linux-image-rpi-2712 \
         firmware-brcm80211 raspi-firmware iptables hostapd dnsmasq dnscrypt-proxy wpasupplicant network-manager; do
  dpkg-query -W "$p" >/dev/null 2>&1 && apt-mark hold "$p" >/dev/null 2>&1 && _held=$((_held+1))
done
ok "заморожено риск-пакетов: $_held  (gate freeze all — заморозить всё; gate unfreeze — снять)"

# финал
echo
say "${G}${B}Базовая установка завершена.${N}"
say "Сеть раздачи: ${B}$SSID${N} на ${B}$AP_IFACE${N} ($AP_ADDR), интернет с ${B}$WAN_IF${N}."
echo
say "${B}Дальше:${N}"
say "  1) ${B}sudo reboot${N}            ${D}(чтобы NM-unmanaged и AP встали чисто)${N}"
say "  2) ${B}gate setup${N}             ${D}визард: создаст ЦЕПОЧКУ C1→C2 и ключи (свои у каждого)${N}"
say "  3) ${B}gate web passwd && gate web on${N}   ${D}веб-панель http://gate:8088${N}"
say "  ${D}автозапуск туннеля после setup: sudo systemctl enable gate-tunnel${N}"
echo
say "${D}WAN переключается: gate wan eth | gate wan wifi  •  статус: gate info${N}"

#!/usr/bin/env bash
#
# vps-bootstrap.sh — подготовка ЧИСТОГО VPS (Ubuntu/Debian) под звено цепочки.
# Запускается от root НА самом сервере (визард малины заливает и зовёт его сам).
# Идемпотентен: повторный запуск ничего не ломает.
#
# Делает:
#   • префлайт: предупреждает про OpenVZ/LXC и отсутствие /dev/net/tun
#   • вычищает Docker, если он предустановлен (мусор в iptables, обход ufw)
#   • базовые пакеты (curl, ca-certificates, ufw) + VPN-клиенты (openvpn, ppp, pptp-linux)
#     + зависимости gate-osfp (python3-scapy + netfilterqueue) для подмены OS-отпечатка
#   • GRE-модули для PPTP-выхода (nf_conntrack_pptp/ip_gre)
#   • xray: из бинаря, переданного малиной (офлайн, без GitHub); фоллбэк — офиц.
#     установщик XTLS, если бинарь не передан. + каталоги логов/конфига
#   • BBR (fq + bbr) в sysctl.d
#   • ufw: разрешить 22 (SSH) и 443 (reality), включить
#   • SSH только по ключу (пароль выключаем — НО лишь если ключ уже стоит)
#   • плейсхолдер-конфиг, чтобы сервис стартовал (реальный зальёт визард следом)
#
# Требования к VPS: KVM (НЕ OpenVZ/LXC — иначе нет BBR/TUN/полного iptables),
#   Ubuntu 22.04/24.04 LTS или Debian 11/12, amd64, доступ root. Свежая система
#   (предустановленный Docker вычищается автоматически).
#
# НЕ настраивает саму цепочку — это делает рендерер/визард отдельно.
#
# Параметры (env):
#   XRAY_BIN=      — путь к УЖЕ ПЕРЕДАННОМУ бинарю xray (amd64). Визард малины
#                    стейджит его сюда ПЕРЕД запуском (base64 по цепочке). Если задан
#                    и существует — ставим ИЗ НЕГО, без выхода в интернет (нужно для
#                    серверов в РФ: GitHub недоступен). По умолчанию /tmp/gate-xray.bin.
#   XRAY_VERSION=  — версия xray для ФОЛЛБЭКА через GitHub (если бинарь не передан).
#   SSH_PORT=22    — порт SSH для правила ufw
#   KEEP_PASSWORD=0 — 1, чтобы НЕ выключать парольный вход (на свой риск)
#
set -euo pipefail
XRAY_BIN="${XRAY_BIN:-/tmp/gate-xray.bin}"
XRAY_VERSION="${XRAY_VERSION:-26.6.1}"
SSH_PORT="${SSH_PORT:-22}"
KEEP_PASSWORD="${KEEP_PASSWORD:-0}"

log(){ printf '\e[32m[bootstrap]\e[0m %s\n' "$*"; }
warn(){ printf '\e[33m[bootstrap]\e[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "нужен root"; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# ── префлайт: предупреждаем о несовместимом окружении (не фейлим) ───────
virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
case "$virt" in
  openvz|lxc|lxc-libvirt|systemd-nspawn)
    warn "виртуализация: $virt — BBR/iptables/TUN могут не работать. Нужен KVM-VPS." ;;
esac
[ -e /dev/net/tun ] || warn "нет /dev/net/tun — ovpn/pptp-выход на этом хопе не поднимется (нужен KVM)"

log "пакеты…"
apt-get update -qq
# базовое + VPN-клиенты (ppp/pptp/openvpn) + зависимости gate-osfp (NFQUEUE OS-спуф):
# python3-scapy (есть в apt), netfilterqueue ставим pip'ом (нет в apt) с build-deps.
apt-get install -y -qq curl ca-certificates ufw unzip ppp pptp-linux openvpn \
  python3-scapy python3-pip build-essential python3-dev libnetfilter-queue-dev >/dev/null
log "netfilterqueue (для gate-osfp)…"
python3 -c 'import netfilterqueue' 2>/dev/null \
  || pip3 install --break-system-packages -q netfilterqueue >/dev/null 2>&1 \
  || warn "netfilterqueue не поставился — gate osfp не заработает, поставь вручную: pip3 install --break-system-packages netfilterqueue"

# ── xray ──────────────────────────────────────────────────────────────
# Пишем стандартный юнит XTLS (1:1 как ставит офиц. установщик): User=nobody,
# AmbientCapabilities дают право на :443 без root и без setcap на бинаре.
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

if command -v xray >/dev/null 2>&1; then
  log "xray уже стоит: $(xray version 2>/dev/null | head -1)"
elif [ -f "$XRAY_BIN" ]; then
  # ОФЛАЙН: ставим из переданного малиной бинаря (для серверов без GitHub).
  log "ставлю xray из переданного бинаря ($XRAY_BIN) — без интернета…"
  install -m 755 "$XRAY_BIN" /usr/local/bin/xray
  write_xray_unit
  systemctl daemon-reload
  rm -f "$XRAY_BIN"   # временный, больше не нужен
  log "xray поставлен: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
else
  # ФОЛЛБЭК: бинарь не передан — тянем офиц. установщик с GitHub (нужен интернет!).
  warn "бинарь xray не передан ($XRAY_BIN нет) — фоллбэк на GitHub (сервер должен видеть инет)"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version "$XRAY_VERSION" >/dev/null \
    || { warn "не удалось поставить xray ни из бинаря, ни с GitHub"; exit 1; }
  log "xray поставлен (GitHub): $(xray version 2>/dev/null | head -1)"
fi
mkdir -p /usr/local/etc/xray /var/log/xray
chown nobody /var/log/xray 2>/dev/null || true   # юнит работает под nobody

# плейсхолдер-конфиг (валидный, ничего не делает) — чтобы сервис мог стартовать,
# пока визард не зальёт настоящий. Не трогаем, если конфиг уже непустой/настоящий.
if ! grep -q reality /usr/local/etc/xray/config.json 2>/dev/null; then
  cat > /usr/local/etc/xray/config.json <<'JSON'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [ { "tag": "direct", "protocol": "freedom" } ]
}
JSON
  log "записан плейсхолдер-конфиг (заменит визард)"
fi
systemctl enable xray >/dev/null 2>&1 || true

# ── BBR ───────────────────────────────────────────────────────────────
log "BBR…"
cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
# дефолт для туннелей: probing спасает от чёрных дыр PMTU (path Pi→C1 бывает 1480, не 1500)
net.ipv4.tcp_mtu_probing=1
EOF
sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')
log "congestion control: $cc"

# ── VPN-выход (OpenVPN/PPTP): пакеты ставятся выше, тут — GRE для PPTP ──
# PPTP несёт данные по GRE (proto 47); нужен conntrack-хелпер, иначе обратный GRE
# дропается фаерволом → pppd виснет на «LCP timeout». Грузим модули персистентно.
# (OpenVPN-выход GRE не требует — он по TCP/UDP.)
cat > /etc/modules-load.d/gate-gre.conf <<'EOF'
nf_conntrack_pptp
nf_conntrack_proto_gre
ip_gre
EOF
modprobe nf_conntrack_pptp 2>/dev/null || true
modprobe nf_conntrack_proto_gre 2>/dev/null || true
modprobe ip_gre 2>/dev/null || true
log "GRE-модули для PPTP загружены"

# ── вычистка Docker (некоторые «голые» образы идут с предустановленным) ─
# Docker гадит в iptables (цепочки DOCKER*/masquerade, FORWARD policy DROP) и
# обходит ufw — на звене цепочки он не нужен и ломает фаервол/policy-routing
# выходного хопа (gate-vpn: fwmark 2 → table 200). Найден → выпиливаем и чистим.
if command -v dockerd >/dev/null 2>&1 || command -v docker >/dev/null 2>&1 \
   || dpkg-query -W -f='${Status}\n' docker.io docker-ce containerd containerd.io 2>/dev/null \
        | grep -q 'install ok installed'; then
  warn "обнаружен Docker — удаляю (мешает iptables/ufw на звене цепочки)…"
  systemctl disable --now docker.service docker.socket containerd.service >/dev/null 2>&1 || true
  apt-get purge -y -qq docker-ce docker-ce-cli docker.io docker-doc docker-compose \
    docker-compose-plugin docker-buildx-plugin podman-docker containerd containerd.io runc \
    >/dev/null 2>&1 || true
  apt-get autoremove -y -qq >/dev/null 2>&1 || true
  rm -rf /var/lib/docker /var/lib/containerd /etc/docker /etc/containerd >/dev/null 2>&1 || true
  # сброс iptables к ACCEPT — снимает docker-остатки; ufw ниже соберёт фаервол заново
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    "$ipt" -P INPUT ACCEPT 2>/dev/null || true
    "$ipt" -P FORWARD ACCEPT 2>/dev/null || true
    "$ipt" -P OUTPUT ACCEPT 2>/dev/null || true
    for tb in '' '-t nat' '-t mangle'; do
      "$ipt" $tb -F 2>/dev/null || true; "$ipt" $tb -X 2>/dev/null || true
    done
  done
  log "Docker удалён, iptables очищены"
fi

# ── ufw ───────────────────────────────────────────────────────────────
log "ufw: разрешаю $SSH_PORT и 443…"
ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

# ── SSH только по ключу ───────────────────────────────────────────────
# Выключаем пароль ТОЛЬКО если ключ root уже на месте (иначе не залочиться).
if [ "$KEEP_PASSWORD" != "1" ] && [ -s /root/.ssh/authorized_keys ]; then
  log "SSH: выключаю парольный вход (ключ root найден)…"
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-gate.conf <<'EOF'
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
EOF
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
else
  warn "парольный вход НЕ трогаю (нет ключа root или KEEP_PASSWORD=1)"
fi

# ── финал ─────────────────────────────────────────────────────────────
log "x25519 доступен: $(xray x25519 >/dev/null 2>&1 && echo да || echo НЕТ)"
echo "BOOTSTRAP_OK $(hostname) xray=$(xray version 2>/dev/null | head -1 | awk '{print $2}') bbr=$cc"

#!/usr/bin/env python3
"""
chain-render.py — единый рендерер конфигов xray для всей цепочки.

Источник правды — chain.json (см. ниже). По нему генерятся:
  • config малины (entry)  : tproxy/socks -> reality к hops[0]
  • config реле (relay)    : reality-in -> reality-out к hops[i+1]
  • config выхода (exit)   : reality-in -> direct (последний хоп)

Роль хопа определяется позицией: последний в hops = exit, остальные = relay.

Использование:
  chain-render.py pi    chain.json          > config малины
  chain-render.py node  chain.json <index>  > config хопа №index (с 0)
  chain-render.py role  chain.json <index>          # печатает relay|exit
  chain-render.py check chain.json                  # валидация структуры

Формат chain.json:
{
  "sni":            "ya.ru",              # SNI/камуфляж (общий на всю цепочку)
  "target":         "ya.ru:443",          # dest для reality-in (по умолчанию sni:443)
  "tproxy_port":    12345,
  "socks_test_port":10808,
  "egress_mark":    255,
  "hops": [
    { "name":"C1", "host":"1.2.3.4", "port":443,
      "uuid":"...", "privkey":"...", "pubkey":"...", "shortid":"..." },
    { "name":"C2", "host":"5.6.7.8", "port":443,
      "uuid":"...", "privkey":"...", "pubkey":"...", "shortid":"..." }
  ]
}

На каждый хоп хранится идентичность его reality-INBOUND:
  uuid     — id клиента inbound == id юзера в outbound апстрима
  privkey  — приватный ключ reality этого inbound (стоит на сервере)
  pubkey   — публичный ключ пары (кладётся в outbound того, кто к хопу коннектится)
  shortid  — shortId reality (общий для inbound и апстрим-outbound)
Апстрим (предыдущий хоп или малина) коннектится к хопу по {host,port,uuid,pubkey,shortid,sni}.

Опц. поля хопа (когда у сервера несколько IPv4):
  listen        — IP, на котором хоп принимает reality-in (по умолч. 0.0.0.0 = все).
  send_through  — IP-источник ИСХОДЯЩЕГО плеча этого хопа (к следующему хопу / в инет):
                  применяется и к reality-out (xray sendThrough), и к управляющему SSH
                  (ssh -b), и к запиранию :22 следующего хопа. Так апстрим заходит на host,
                  а следующий хоп видит только send_through (вход host НЕ светится).
"""
import json
import shlex
import sys

PRIVATE_CIDRS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
]


def load(path):
    with open(path) as f:
        c = json.load(f)
    c.setdefault("sni", "ya.ru")
    c.setdefault("target", c["sni"] + ":443")
    c.setdefault("tproxy_port", 12345)
    c.setdefault("socks_test_port", 10808)
    c.setdefault("egress_mark", 255)
    if not c.get("hops"):
        sys.exit("chain.json: пустой список hops")
    for i, h in enumerate(c["hops"]):
        for k in ("host", "port", "uuid", "privkey", "pubkey", "shortid"):
            if not h.get(k):
                sys.exit(f"chain.json: hop[{i}] ({h.get('name','?')}) без поля '{k}'")
    return c


def role(c, i):
    return "exit" if i == len(c["hops"]) - 1 else "relay"


def _log():
    # Серверам (реле/выход) файловые логи НЕ пишем: xray бежит под nobody, а файл в
    # /var/log/xray, созданный root'ом при `xray -test`, для nobody недоступен на запись
    # → сервис не стартует. error идёт в stderr → journald (виден `journalctl -u xray`),
    # access отключён (приватность + меньше износ диска). Как у малины в _pi_log().
    return {
        "loglevel": "warning",
        "access": "none",
    }


LOG_CONF = "/etc/gate/log.conf"


def _flag(key, default=False):
    """Прочитать флаг из /etc/gate/log.conf (управляется `gate logs ...`)."""
    try:
        with open(LOG_CONF) as f:
            for line in f:
                line = line.strip()
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().lower() in ("on", "1", "true", "yes")
    except OSError:
        pass
    return default


def _pi_log():
    """Лог малины. Два независимых тумблера в /etc/gate/log.conf:
      XRAY    (дефолт on)  — системный лог xray в journald: warning ↔ none;
      TRAFFIC (дефолт off) — access-лог соединений в файл ↔ none (про соединения
                             не пишется ничего, бережём SD и приватность).
    error не уводим в файл — пусть идёт в journald (виден через `gate logs xray`)."""
    return {
        "loglevel": "warning" if _flag("XRAY", default=True) else "none",
        "access": "/var/log/xray/access.log" if _flag("TRAFFIC") else "none",
    }


SOCKS_STATE = "/etc/gate/socks.state"   # on/off (пишет `gate socks on|off`)
SOCKS_CAPS = "/etc/gate/socks.caps"     # TCP/RDNS/UDP=ok|fail (пишет `gate socks test`)
VPN_STATE = "/etc/gate/vpn.state"       # on/off (пишет `gate vpn on|off`)
VPN_DNS_FILE = "/etc/gate/vpn-dns"      # IP тоннельного DNS-шлюза в VPN-режиме (пишет vpn_on)


def _vpn_dns():
    """Резолверы туннеля (все pushed-DNS, по одному в строке) — список, иначе пусто.
    Клиентский DNS малина форвардит на них → резолвер у клиентов резидентный (как у
    выхода), а не dnscrypt. Их адреса надо завернуть В ЦЕПОЧКУ, иначе не доедут."""
    try:
        return [x.strip() for x in open(VPN_DNS_FILE) if x.strip()]
    except OSError:
        return []


# ─── Каналы: у клиента может быть СВОЙ выход ──────────────────────────────────
LANE_MAIN = "lane-main"
CLIENT_LANES = "/etc/gate/client-lanes.conf"   # <MAC> <IP> <канал> <выход> [имя] (пишет `gate client`)

# КАНАЛЫ (безымянные полосы). У reality-inbound каждого хопа помимо основной идентичности
# (hop.uuid, email lane-main) заводится пул одинаковых по смыслу каналов: hop.lane_uuids =
# {"1": uuid, "2": uuid, ...}, email lane-1, lane-2… Канал сам по себе НИЧЕГО не значит —
# он просто отдельная «труба» через цепочку. Чем канал заканчивается (прямой C2 / tun0 /
# конкретный носок), решает ТОЛЬКО конфиг выхода C2, который собирает `gate` (exit_apply).
# Поэтому добавить второй носок = поменять конфиг C2, БЕЗ передеплоя C1 и новых uuid.
# Малина решает, какой клиент в какой канал, по source-IP (см. CLIENT_LANES).


def lane_email(ch):
    return "lane-" + str(ch)


def _ch_key(ch):
    return (0, int(ch)) if str(ch).isdigit() else (1, str(ch))


def _channels(c):
    """Каналы, заданные у ВСЕХ хопов. Частично заданный канал не отдаём: клиент ушёл бы
    в несуществующую на каком-то хопе идентичность."""
    names = set()
    for h in c["hops"]:
        names |= set((h.get("lane_uuids") or {}).keys())
    out = [ch for ch in names if all((h.get("lane_uuids") or {}).get(ch) for h in c["hops"])]
    return sorted(out, key=_ch_key)


def _lane_ips():
    """{канал: [IP клиентов]} из CLIENT_LANES. Нет файла / не назначено → пусто."""
    m = {}
    try:
        for line in open(CLIENT_LANES):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            f = line.split()
            if len(f) >= 4 and f[1] and f[2]:
                m.setdefault(f[2], []).append(f[1])
    except OSError:
        pass
    return m


def _socks_on():
    try:
        return open(SOCKS_STATE).read().strip() == "on"
    except OSError:
        return False


def _vpn_on():
    try:
        return open(VPN_STATE).read().strip() == "on"
    except OSError:
        return False


def _cap(key):
    """Возможность носка из socks.caps (ok → True). Дефолт False (fail-closed)."""
    try:
        for line in open(SOCKS_CAPS):
            if line.strip().startswith(key + "="):
                return line.strip().split("=", 1)[1].strip().lower() == "ok"
    except OSError:
        pass
    return False


def _lane_clients(hop):
    """Клиенты reality-inbound хопа: основная идентичность + все каналы пула."""
    cl = [{"id": hop["uuid"], "flow": "xtls-rprx-vision", "email": LANE_MAIN}]
    for ch in sorted((hop.get("lane_uuids") or {}), key=_ch_key):
        if hop["lane_uuids"][ch]:
            cl.append({"id": hop["lane_uuids"][ch], "flow": "xtls-rprx-vision",
                       "email": lane_email(ch)})
    return cl


def _reality_inbound(c, hop):
    """reality-in: то, что хоп показывает наружу (апстрим к нему коннектится)."""
    return {
        "tag": "reality-in",
        "listen": hop.get("listen") or "0.0.0.0",
        "port": hop["port"],
        "protocol": "vless",
        "settings": {
            # email — метка полосы: по нему роутинг ЭТОГО хопа решает, куда отдать трафик
            # (см. LANE_MAIN/LANE_VPN). Вторая идентичность появляется только если задан uuid_b.
            "clients": _lane_clients(hop),
            "decryption": "none",
        },
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "target": c["target"],
                "serverNames": [c["sni"]],
                "privateKey": hop["privkey"],
                "shortIds": [hop["shortid"]],
            },
        },
    }


def _reality_outbound(c, tag, dst, send_through=None, lane_ch=None):
    """reality-out: коннект к следующему хопу dst по его inbound-идентичности.
    send_through (опц.) — IP источника на ЭТОМ хопе (xray sendThrough): если у хопа
    несколько IPv4, исходящее плечо к следующему хопу уходит именно с него."""
    ob = {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": dst["host"],
                "port": dst["port"],
                "users": [{
                    # lane_ch → коннектимся идентичностью канала, иначе основной
                    "id": (dst.get("lane_uuids") or {})[lane_ch] if lane_ch else dst["uuid"],
                    "encryption": "none",
                    "flow": "xtls-rprx-vision",
                }],
            }],
        },
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "sockopt": {"mark": c["egress_mark"]},
            "realitySettings": {
                "show": False,
                "fingerprint": "chrome",
                "serverName": c["sni"],
                "publicKey": dst["pubkey"],
                "shortId": dst["shortid"],
                "spiderX": "/",
            },
        },
    }
    if send_through:
        ob["sendThrough"] = send_through
    return ob


def render_pi(c):
    h0 = c["hops"][0]
    socks_on = _socks_on()
    vpn_on = _vpn_on()
    # DNS-политика: домен резолвит носок (routeOnly=False) ТОЛЬКО если носок включён и
    # умеет remote-DNS; иначе (VPN-выход / прямой C2 / носок без RDNS) несём уже
    # отрезолвленный (через Force-DNS/Cloudflare) IP.
    route_only = not (socks_on and _cap("RDNS"))
    # QUIC (udp:443) пропускаем сквозь цепочку если: носок включён и умеет UDP (UDP
    # ASSOCIATE), ИЛИ включён VPN-выход (tun/ppp несёт UDP нативно). Иначе режем → HTTP/2.
    quic_through = (socks_on and _cap("UDP")) or vpn_on

    rules = []
    vpn_dns = _vpn_dns()
    if vpn_dns:
        # тоннельный DNS-шлюз (часто приватный, напр. 10.0.0.10) — в цепочку ДО private-block,
        # иначе зарежется как приватный. На C2 он уже роутится в vpn-out → ppp0 → форвардер ISP.
        rules.append({"type": "field", "ip": vpn_dns, "outboundTag": "reality-s1"})
    rules.append({"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "blocked"})
    if not quic_through:
        rules.append({"type": "field", "network": "udp", "port": 443, "outboundTag": "blocked"})
    # КАНАЛЫ: клиент с персональным выходом (`gate client <устройство> exit …`) уходит
    # ОТДЕЛЬНЫМ каналом → C1 передаст канал дальше → C2 завершит его нужным выходом.
    # Правила ДО общего catch-all ниже (порядок правил = приоритет); неназначенные идут
    # основной идентичностью и получают ГЛОБАЛЬНЫЙ выход (gate global …).
    lane_ips = _lane_ips()
    outbounds = [_reality_outbound(c, "reality-s1", h0)]
    for ch in _channels(c):
        tag = "reality-s1-" + ch
        outbounds.append(_reality_outbound(c, tag, h0, lane_ch=ch))
        if lane_ips.get(ch):
            rules.append({"type": "field", "source": lane_ips[ch], "outboundTag": tag})
    rules.append({"type": "field",
                  "inboundTag": ["tproxy-in", "socks-test"],
                  "outboundTag": "reality-s1"})

    return {
        "log": _pi_log(),
        "inbounds": [
            {
                "tag": "tproxy-in",
                "listen": "0.0.0.0",
                "port": c["tproxy_port"],
                "protocol": "dokodemo-door",
                "settings": {"network": "tcp,udp", "followRedirect": True},
                "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": route_only,
                },
            },
            {
                "tag": "socks-test",
                "listen": "127.0.0.1",
                "port": c["socks_test_port"],
                "protocol": "socks",
                "settings": {"udp": True},
            },
        ],
        "outbounds": outbounds + [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


def render_node(c, i):
    hop = c["hops"][i]
    cfg = {"log": _log(), "inbounds": [_reality_inbound(c, hop)]}
    if role(c, i) == "relay":
        nxt = c["hops"][i + 1]
        obs = [_reality_outbound(c, "reality-out", nxt, send_through=hop.get("send_through"))]
        rules = []
        # КАНАЛЫ: кто пришёл идентичностью lane-N — уходит к следующему хопу тем же каналом
        # (его uuid). Признак — email клиента на НАШЕМ inbound (xray UserMatcher).
        # Этот кусок статичен: смена выхода у канала конфиг реле НЕ трогает.
        for ch in _channels(c):
            tag = "reality-out-" + ch
            obs.append(_reality_outbound(c, tag, nxt, send_through=hop.get("send_through"),
                                         lane_ch=ch))
            rules.append({"type": "field", "user": [lane_email(ch)],
                          "inboundTag": ["reality-in"], "outboundTag": tag})
        rules.append({"type": "field", "inboundTag": ["reality-in"], "outboundTag": "reality-out"})
        cfg["outbounds"] = obs + [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ]
        cfg["routing"] = {"domainStrategy": "AsIs", "rules": rules}
    else:  # exit
        direct = {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}}
        if hop.get("send_through"):
            direct["sendThrough"] = hop["send_through"]   # выход в инет с выбранного IP, если их несколько
        cfg["outbounds"] = [
            direct,
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        ]
        cfg["routing"] = {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "blocked"},
            ],
        }
    return cfg


SSH_OPTS = "-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"


def node_cmd(c, idx, payload):
    """Полная ВЛОЖЕННАЯ ssh-команда, выполняющая payload на хопе idx.
    Модель ключей-на-хопах: малина→hop0 ключом малины (mgmt_key), а каждое
    звено hop[k]→hop[k+1] — ключом hop[k] (next_key, лежит НА hop[k]).
    Так доступ к C2 идёт через C1 (C1 коннектится своим ключом), к C3 — через C2.
    Возвращает строку для `bash -c`. shlex.quote экранирует вложение на каждом
    уровне, поэтому payload (хоть с heredoc/кавычками) переживает любую глубину."""
    hops = c["hops"]
    user = c.get("ssh_user", "root")
    mgmt = c.get("mgmt_key")
    if not mgmt:
        sys.exit("chain.json: нет mgmt_key (ключ малина→первый хоп)")
    cmd = payload
    for k in range(idx - 1, -1, -1):          # сворачиваем от hop[idx] к hop0
        key = hops[k].get("next_key")
        if not key:
            sys.exit(f"chain.json: hop[{k}] ({hops[k].get('name','?')}) без next_key "
                     f"(ключ для доступа к следующему хопу)")
        # send_through: если у hop[k] два IP, управляющий SSH к следующему хопу тоже
        # уходит с исходящего IP (ssh -b) — чтобы следующий хоп НЕ видел входной IP hop[k].
        st = hops[k].get("send_through")
        bind = f"-b {shlex.quote(st)} " if st else ""
        cmd = (f"ssh {bind}-i {shlex.quote(key)} {SSH_OPTS} "
               f"{user}@{hops[k + 1]['host']} {shlex.quote(cmd)}")
    return (f"ssh -i {shlex.quote(mgmt)} {SSH_OPTS} "
            f"{user}@{hops[0]['host']} {shlex.quote(cmd)}")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, path = sys.argv[1], sys.argv[2]
    c = load(path)
    if cmd == "pi":
        print(json.dumps(render_pi(c), indent=2))
    elif cmd == "node":
        i = int(sys.argv[3])
        print(json.dumps(render_node(c, i), indent=2))
    elif cmd == "role":
        print(role(c, int(sys.argv[3])))
    elif cmd == "exit-cmd":          # payload из stdin -> вложенная ssh до выхода
        print(node_cmd(c, len(c["hops"]) - 1, sys.stdin.read()), end="")
    elif cmd == "node-cmd":          # payload из stdin -> вложенная ssh до hop idx
        print(node_cmd(c, int(sys.argv[3]), sys.stdin.read()), end="")
    elif cmd == "host":
        print(c["hops"][int(sys.argv[3])]["host"])
    elif cmd == "egress-host":       # IP, с которого хоп i выходит наружу (send_through или host)
        h = c["hops"][int(sys.argv[3])]
        print(h.get("send_through") or h["host"])
    elif cmd == "prev-host":
        i = int(sys.argv[3])
        print(c["hops"][i - 1]["host"] if i > 0 else "")
    elif cmd == "check":
        print(f"OK: {len(c['hops'])} хопов, выход = {c['hops'][-1]['name']} "
              f"({c['hops'][-1]['host']}), SNI = {c['sni']}")
    else:
        sys.exit(f"неизвестная команда: {cmd}")


if __name__ == "__main__":
    main()

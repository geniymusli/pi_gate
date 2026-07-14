#!/usr/bin/env python3
# gate-osfp — на ВЫХОДНОМ хопе (C2): переписывает исходящие TCP SYN под сигнатуру
# выбранной ОС (p0f / Zardaxt OS scoring), чтобы выход выглядел как Apple/Windows/Linux,
# а не как Linux-ядро C2. Только SYN (низкая нагрузка). С PPTP/OpenVPN (L3+NAT)
# переписанные TCP-опции переживают туннель → детектор на сайте видит выбранную ОС +
# резидентный IP. С носком НЕ работает (нода носка пересоздаёт TCP своим ядром).
# Подключается через NFQUEUE (правило ставит контроллер gate-osfp, с --queue-bypass).
#
# Запуск: gate-osfp.py <queue-num> [profile]   profile = apple|windows|linux (дефолт apple).
import sys
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

QNUM = int(sys.argv[1]) if len(sys.argv) > 1 else 1
PROFILE = (sys.argv[2] if len(sys.argv) > 2 else "apple").lower()

# Профили TCP-сигнатуры. opts — функция (mss, tsval) → список опций scapy в нужном ПОРЯДКЕ
# (порядок опций — ключевой признак для p0f). ttl/window — фиксируем, wscale внутри opts.
PROFILES = {
    # Darwin (macOS/iOS): один стек на оба Apple-устройства.
    "apple": dict(ttl=64, window=65535, opts=lambda mss, ts: [
        ("MSS", mss), ("NOP", None), ("WScale", 6), ("NOP", None), ("NOP", None),
        ("Timestamp", (ts, 0)), ("SAckOK", b""), ("EOL", None)]),
    # Windows 10/11: TTL 128, без Timestamp, wscale 8.
    "windows": dict(ttl=128, window=64240, opts=lambda mss, ts: [
        ("MSS", mss), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None),
        ("SAckOK", b"")]),
    # Linux (современное ядро): TS включён, wscale 7, иной порядок.
    "linux": dict(ttl=64, window=64240, opts=lambda mss, ts: [
        ("MSS", mss), ("SAckOK", b""), ("Timestamp", (ts, 0)),
        ("NOP", None), ("WScale", 7)]),
}
PROF = PROFILES.get(PROFILE, PROFILES["apple"])


def build_opts(orig):
    mss, tsval = 1460, 0
    for o in orig:
        if o[0] == "MSS": mss = o[1]
        elif o[0] == "Timestamp": tsval = o[1][0]
    return PROF["opts"](mss, tsval)


def cb(pkt):
    try:
        ip = IP(pkt.get_payload())
        t = ip.getlayer(TCP)
        if t is not None and t.flags == 0x02:        # чистый SYN (без ACK)
            ip.ttl = PROF["ttl"]
            t.window = PROF["window"]
            t.options = build_opts(t.options)
            del ip.len; del ip.chksum
            del t.dataofs; del t.chksum
            pkt.set_payload(bytes(ip))
    except Exception:
        pass
    pkt.accept()


nfq = NetfilterQueue()
nfq.bind(QNUM, cb)
try:
    nfq.run()
except KeyboardInterrupt:
    pass
finally:
    nfq.unbind()

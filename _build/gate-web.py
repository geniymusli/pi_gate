#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# gate-web.py — локальная веб-морда управления privacy-роутером.
#
# Тонкая обёртка над CLI `gate`: морда дёргает СТРОГО заданный allowlist команд
# (никакого shell, никакого произвольного ввода в argv → инъекции невозможны).
#
# Безопасность:
#   • Доступ только из LAN: сервер бьёт INPUT-firewall (chain GATE_WEB) — порт открыт
#     лишь для loopback/RFC1918, остальное (WAN/туннель) DROP. Плюс per-request проверка
#     источника. Из интернета морда недоступна, даже если роутер пробросит порт.
#   • Пароль: PBKDF2-HMAC-SHA256 (соль в /etc/gate/web.conf, root-only 0600).
#   • Сессия: HMAC-подписанная кука (SameSite=Strict, HttpOnly) + кастомный заголовок
#     на API (анти-CSRF).
#   • Живёт независимо от tproxy/killswitch (трафик к самой малине идёт через INPUT) →
#     «пульт» доступен даже когда туннель лёг и клиенты fail-closed.
#
# Запуск:  gate-web.py serve            (systemd-юнит gate-web.service)
# Пароль:  gate-web.py passwd [пароль]  (или пароль из stdin)
#
import os, sys, json, hmac, hashlib, base64, secrets, subprocess, time, ipaddress, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONF        = "/etc/gate/web.conf"
GATE_CONF   = "/etc/gate/gate.conf"
GATE        = "/usr/local/bin/gate"
DEFAULT_PORT= 8088
COOKIE      = "gate_session"
SESSION_TTL = 8 * 3600
PBKDF2_ITERS= 200_000
ANSI_RE     = re.compile(r"\x1b\[[0-9;]*m")
NAME_RE     = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PTYPES      = ("socks", "pptp", "ovpn")

# AP-подсеть берём из gate.conf, если переопределена; иначе дефолт.
AP_SUBNET = "192.168.50.0/24"
try:
    for _ln in open(GATE_CONF):
        _ln = _ln.strip()
        if _ln.startswith("AP_SUBNET="):
            AP_SUBNET = _ln.split("=", 1)[1].strip().strip('"').strip("'") or AP_SUBNET
except OSError:
    pass

LAN_NETS = [ipaddress.ip_network(n) for n in
            ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


# ─── конфиг (key=value, 0600) ─────────────────────────────────────────
def load_conf():
    d = {}
    try:
        for ln in open(CONF):
            ln = ln.strip()
            if "=" in ln and not ln.startswith("#"):
                k, v = ln.split("=", 1)
                d[k] = v
    except FileNotFoundError:
        pass
    return d


def save_conf(d):
    os.makedirs("/etc/gate", exist_ok=True)
    fd = os.open(CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for k, v in d.items():
            f.write("%s=%s\n" % (k, v))


def set_password(pw):
    d = load_conf()
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PBKDF2_ITERS).hex()
    d["PASS_SALT"] = salt
    d["PASS_HASH"] = h
    d.setdefault("SECRET", secrets.token_hex(32))
    d.setdefault("PORT", str(DEFAULT_PORT))
    save_conf(d)


def check_password(pw):
    d = load_conf()
    if "PASS_HASH" not in d or "PASS_SALT" not in d:
        return False
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(d["PASS_SALT"]), PBKDF2_ITERS).hex()
    return hmac.compare_digest(h, d["PASS_HASH"])


# ─── сессия (HMAC-кука) ───────────────────────────────────────────────
def make_token(secret):
    exp = str(int(time.time()) + SESSION_TTL)
    sig = hmac.new(secret.encode(), exp.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s.%s" % (exp, sig)).encode()).decode()


def valid_token(secret, tok):
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
        exp, sig = raw.split(".", 1)
        good = hmac.new(secret.encode(), exp.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good) and int(exp) > time.time()
    except Exception:
        return False


# ─── источник запроса ─────────────────────────────────────────────────
def src_ok(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in LAN_NETS)


# ─── allowlist действий → argv для `gate` ─────────────────────────────
def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def build_argv(action, p):
    """Маппинг действие→argv. Любой динамический параметр строго валидируется.
       Бросает ValueError на неизвестное действие/плохие параметры."""
    fixed = {
        "info":            ["info"],
        "exit_status":     ["exit"],
        "dns_test":        ["dns"],
        "tunnel_status":   ["tunnel", "status"],
        "tunnel_up":       ["tunnel", "up"],
        "tunnel_down":     ["tunnel", "down"],
        # Глобальный выход (для всех НЕназначенных). Включение живёт в `gate global …`;
        # отдельных socks/ovpn/pptp on-off больше нет — осталась только их настройка.
        "global_status":   ["global"],
        "global_off":      ["global", "off"],
        "global_ovpn_on":  ["global", "ovpn", "on"],
        "global_pptp_on":  ["global", "pptp", "on"],
        "socks_test":      ["socks", "test"],
        "socks_status":    ["socks", "status"],
        "ovpn_status":     ["ovpn", "status"],
        "pptp_status":     ["pptp", "status"],
        # Каналы и персональные выходы устройств
        "client_list":     ["client", "list"],
        "lanes_status":    ["lanes", "status"],
        "lanes_apply":     ["lanes", "apply"],
        "osfp_off":        ["osfp", "off"],
        "osfp_status":     ["osfp", "status"],
        "dns_fallback_on": ["dns", "fallback", "on"],
        "dns_fallback_off":["dns", "fallback", "off"],
        "profile_list":    ["profile", "list"],
        "wipe":            ["-y", "wipe"],
    }
    if action in fixed:
        return fixed[action]

    if action == "global_socks_on":
        prof = p.get("profile", "")
        if prof and not NAME_RE.match(prof):
            raise ValueError("bad socks profile")
        return ["global", "socks", "on"] + ([prof] if prof else [])

    if action == "client_exit":
        # устройство адресуем по MAC (стабильнее IP), цель — c2|vpn|auto|socks:<профиль>
        mac = (p.get("mac") or "").lower()
        target = p.get("target") or ""
        if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
            raise ValueError("bad mac")
        if target in ("c2", "vpn", "auto"):
            pass
        elif target.startswith("socks:") and NAME_RE.match(target[6:]):
            pass
        else:
            raise ValueError("bad target")
        return ["client", mac, "exit", target]

    if action == "socks_promote":
        n = p.get("name", "")
        if not NAME_RE.match(n):
            raise ValueError("bad name")
        return ["socks", "promote", n]

    if action == "lanes_init":
        n = str(p.get("n", "4"))
        if not n.isdigit() or not (1 <= int(n) <= 16):
            raise ValueError("bad pool size")
        return ["lanes", "init", n]

    if action == "osfp_on":
        prof = p.get("profile", "")
        if prof not in ("apple", "windows", "linux"):
            raise ValueError("bad osfp profile")
        return ["osfp", "on", prof]

    if action == "dns_resolver":
        r = p.get("resolver", "")
        if r not in ("cf", "quad9"):
            raise ValueError("bad resolver")
        return ["dns", "resolver", r]

    if action in ("profile_use", "profile_rm"):
        t, n = p.get("ptype", ""), p.get("name", "")
        if t not in PTYPES or not NAME_RE.match(n):
            raise ValueError("bad profile params")
        return ["profile", "use" if action == "profile_use" else "rm", t, n]

    if action == "profile_save_socks":
        n, ip, port = p.get("name", ""), p.get("ip", ""), str(p.get("port", ""))
        user, pw = p.get("user", ""), p.get("pass", "")
        if not NAME_RE.match(n) or not valid_ip(ip):
            raise ValueError("bad name/ip")
        if not port.isdigit() or not (0 < int(port) < 65536):
            raise ValueError("bad port")
        if any(c in (user + pw) for c in "\r\n"):
            raise ValueError("bad creds")
        argv = ["profile", "save", "socks", n, ip, port]
        if user or pw:
            argv += [user, pw]
        return argv

    if action == "profile_save_pptp":
        n, srv = p.get("name", ""), p.get("server", "")
        user, pw = p.get("user", ""), p.get("pass", "")
        if not NAME_RE.match(n):
            raise ValueError("bad name")
        if not re.match(r"^[A-Za-z0-9._:-]{1,253}$", srv):
            raise ValueError("bad server")
        if not user or not pw:
            raise ValueError("need user+pass")
        if any(c in (user + pw) for c in "\r\n"):
            raise ValueError("bad creds")
        return ["profile", "save", "pptp", n, srv, user, pw]

    raise ValueError("unknown action: %s" % action)


def strip_ansi(s):
    return ANSI_RE.sub("", s or "")


def run_gate(argv, timeout=120):
    env = dict(os.environ)
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    try:
        pr = subprocess.run([GATE] + argv, capture_output=True, text=True,
                            timeout=timeout, env=env)
        return pr.returncode, strip_ansi((pr.stdout or "") + (pr.stderr or ""))
    except subprocess.TimeoutExpired:
        return 124, "таймаут команды (gate %s)" % " ".join(argv)
    except Exception as e:
        return 1, "ошибка запуска gate: %s" % e


def parse_profiles():
    """Парсит `gate profile list` в {socks:[],pptp:[],ovpn:[]}."""
    _, out = run_gate(["profile", "list"])
    res = {t: [] for t in PTYPES}
    cur = None
    for ln in out.splitlines():
        s = ln.strip()
        if s.endswith(":") and s[:-1] in PTYPES:
            cur = s[:-1]
        elif cur and s and s != "(пусто)":
            res[cur].append(s)
    return res


def read_state():
    """Текущее состояние выхода — ЛОКАЛЬНО (без SSH к C2), для подсветки в морде."""
    def rd(p):
        try:
            return open(p).read().strip()
        except OSError:
            return ""
    socks = rd("/etc/gate/socks.state")
    vpn = rd("/etc/gate/vpn.state")
    vtype = ""
    try:
        for ln in open("/etc/gate/vpn.conf"):
            if ln.startswith("TYPE="):
                vtype = ln.split("=", 1)[1].strip()
    except OSError:
        pass
    # Глобальный выход = то, что получают НЕназначенные клиенты (пишет `gate global …`).
    g = {}
    try:
        for ln in open("/etc/gate/global-exit.conf"):
            ln = ln.strip()
            if "=" in ln and not ln.startswith("#"):
                k, v = ln.split("=", 1)
                g[k.strip()] = v.strip()
    except OSError:
        pass
    gexit = g.get("GLOBAL") or "c2"
    mode = {"socks": "socks", "ovpn": "ovpn", "pptp": "pptp"}.get(gexit, "direct")
    resolver = ""
    try:
        for ln in open("/etc/dnscrypt-proxy/dnscrypt-proxy.toml"):
            s = ln.strip()
            if s.startswith("server_names"):
                if "quad9" in s:
                    resolver = "quad9"
                elif "cloudflare" in s:
                    resolver = "cf"
                break
    except OSError:
        pass
    return {
        "exit": mode,
        "global": gexit,
        "global_socks": g.get("GLOBAL_SOCKS") or "",
        "socks": socks or "off",
        "vpn": vpn or "off",
        "vtype": vtype,
        "dns_fallback": rd("/etc/gate/dns-fallback.state") or "off",
        "resolver": resolver,
    }


def read_devices():
    """Устройства раздачи + их персональные выходы + доступные носки и пул каналов.
    Читаем файлы напрямую (морда бежит root'ом): парсить цветной вывод CLI хрупко."""
    # назначения: <MAC> <IP> <канал> <выход> [имя]
    assigned = {}
    for ln in _lines("/etc/gate/client-lanes.conf"):
        f = ln.split()
        if len(f) >= 4:
            assigned[f[0].lower()] = {"ch": f[2], "target": f[3]}
    devs, seen = [], set()
    # аренды dnsmasq: <expiry> <mac> <ip> <hostname> <clientid>
    for ln in _lines("/var/lib/misc/dnsmasq.leases"):
        f = ln.split()
        if len(f) >= 3:
            mac, ip = f[1].lower(), f[2]
            if mac in seen:
                continue
            seen.add(mac)
            a = assigned.get(mac)
            devs.append({"mac": mac, "ip": ip,
                         "name": (f[3] if len(f) > 3 and f[3] != "*" else ""),
                         "target": (a or {}).get("target", ""),
                         "ch": (a or {}).get("ch", "")})
    # профили носков
    profs = []
    try:
        for fn in sorted(os.listdir("/etc/gate/profiles/socks")):
            if fn.endswith(".conf"):
                profs.append(fn[:-5])
    except OSError:
        pass
    # пул каналов из chain.json
    pool, used = 0, len({v["ch"] for v in assigned.values() if v["ch"]})
    try:
        hops = json.load(open("/etc/gate/chain.json"))["hops"]
        if hops:
            common = set((hops[0].get("lane_uuids") or {}).keys())
            for h in hops:
                common &= {k for k, v in (h.get("lane_uuids") or {}).items() if v}
            pool = len(common)
    except Exception:
        pass
    # Текущий безымянный носок (gate socks set) — он НЕ профиль, поэтому раньше в панели
    # его не было видно вообще. Показываем адрес; логин/пароль наружу не отдаём.
    cur = {}
    for ln in _lines("/etc/gate/socks.conf"):
        if "=" in ln:
            k, v = ln.split("=", 1)
            cur[k.strip()] = v.strip()
    socks_current = ({"ip": cur.get("SOCKS_IP", ""), "port": cur.get("SOCKS_PORT", ""),
                      "auth": bool(cur.get("SOCKS_USER"))}
                     if cur.get("SOCKS_IP") else None)
    return {"devices": devs, "socks_profiles": profs, "socks_current": socks_current,
            "pool": pool, "used": used,
            "vpn_live": (open("/etc/gate/vpn.state").read().strip() == "on"
                         if os.path.exists("/etc/gate/vpn.state") else False)}


def _lines(path):
    try:
        return [l.strip() for l in open(path) if l.strip() and not l.startswith("#")]
    except OSError:
        return []


# ─── firewall: открыть порт только LAN, остальное DROP ────────────────
def apply_firewall(port):
    def ipt(*a):
        subprocess.run(["iptables"] + list(a), capture_output=True)
    subprocess.run(["iptables", "-N", "GATE_WEB"], capture_output=True)  # создать (или уже есть)
    ipt("-F", "GATE_WEB")
    if subprocess.run(["iptables", "-C", "INPUT", "-j", "GATE_WEB"],
                      capture_output=True).returncode != 0:
        ipt("-I", "INPUT", "1", "-j", "GATE_WEB")
    for n in dict.fromkeys([AP_SUBNET, "127.0.0.0/8", "10.0.0.0/8",
                            "172.16.0.0/12", "192.168.0.0/16"]):
        ipt("-A", "GATE_WEB", "-p", "tcp", "--dport", str(port), "-s", n, "-j", "ACCEPT")
    ipt("-A", "GATE_WEB", "-p", "tcp", "--dport", str(port), "-j", "DROP")


# ─── HTTP ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "gate-web"

    def log_message(self, *a):  # тихо
        pass

    # — helpers —
    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def _authed(self):
        secret = load_conf().get("SECRET", "")
        return bool(secret) and valid_token(secret, self._cookies().get(COOKIE, ""))

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for h, v in (headers or []):
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _client_ip(self):
        return self.client_address[0]

    # — routing —
    def do_GET(self):
        if not src_ok(self._client_ip()):
            return self._send(403, "forbidden", "text/plain; charset=utf-8")
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(200, PAGE if self._authed() else LOGIN)
        if not self._authed():
            return self._json(401, {"error": "auth"})
        if path == "/api/info":
            code, out = run_gate(["info"])
            return self._json(200, {"code": code, "out": out})
        if path == "/api/profiles":
            return self._json(200, parse_profiles())
        if path == "/api/state":
            return self._json(200, read_state())
        if path == "/api/devices":
            return self._json(200, read_devices())
        return self._send(404, "not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if not src_ok(self._client_ip()):
            return self._send(403, "forbidden", "text/plain; charset=utf-8")
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        if path == "/login":
            pw = ""
            for kv in raw.decode("utf-8", "replace").split("&"):
                if kv.startswith("password="):
                    from urllib.parse import unquote_plus
                    pw = unquote_plus(kv.split("=", 1)[1])
            if check_password(pw):
                tok = make_token(load_conf()["SECRET"])
                ck = "%s=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d" % (COOKIE, tok, SESSION_TTL)
                return self._send(303, "", "text/plain", [("Location", "/"), ("Set-Cookie", ck)])
            return self._send(200, LOGIN_BAD)

        if path == "/logout":
            ck = "%s=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" % COOKIE
            return self._send(303, "", "text/plain", [("Location", "/"), ("Set-Cookie", ck)])

        if path == "/api/action":
            if not self._authed():
                return self._json(401, {"error": "auth"})
            if self.headers.get("X-Gate") != "1":     # анти-CSRF: простой fetch не выставит
                return self._json(403, {"error": "csrf"})
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
                action = body.get("action", "")
                argv = build_argv(action, body)
            except (ValueError, json.JSONDecodeError) as e:
                return self._json(400, {"error": str(e)})
            code, out = run_gate(argv)
            return self._json(200, {"code": code, "out": out})

        return self._send(404, "not found", "text/plain; charset=utf-8")


# ─── страницы ─────────────────────────────────────────────────────────
LOGIN = """<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>gate · вход</title><style>
:root{color-scheme:dark}
body{background:#11151a;color:#dfe6ee;font:15px/1.5 system-ui,sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
form{background:#1a2029;padding:28px;border-radius:14px;width:280px;box-shadow:0 8px 30px #0007}
h1{font-size:18px;margin:0 0 14px}
input{width:100%;box-sizing:border-box;padding:10px;margin:8px 0;border-radius:8px;
border:1px solid #2c3440;background:#0e1217;color:#dfe6ee}
button{width:100%;padding:10px;border:0;border-radius:8px;background:#3b82f6;color:#fff;
font-weight:600;cursor:pointer;margin-top:6px}
.err{color:#f87171;font-size:13px;margin:4px 0 0}
</style></head><body><form method=post action=/login>
<h1>🔒 gate — панель</h1>
<input type=password name=password placeholder="пароль" autofocus>
<button>Войти</button>%ERR%</form></body></html>"""
LOGIN_BAD = LOGIN.replace("%ERR%", "<p class=err>Неверный пароль</p>")
LOGIN = LOGIN.replace("%ERR%", "")

PAGE = r"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>gate · панель</title><style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{background:#11151a;color:#dfe6ee;font:15px/1.5 system-ui,sans-serif;margin:0;padding:16px;max-width:920px;margin:0 auto}
header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
header h1{font-size:18px;margin:0;flex:1}
a.logout{color:#9aa7b6;font-size:13px;text-decoration:none}
.card{background:#1a2029;border-radius:12px;padding:14px 16px;margin:12px 0}
.card h2{font-size:14px;margin:0 0 10px;color:#9fb3c8;text-transform:uppercase;letter-spacing:.04em}
pre{background:#0e1217;border:1px solid #232b35;border-radius:8px;padding:12px;overflow:auto;
white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 ui-monospace,monospace;margin:0}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
button{padding:8px 12px;border:0;border-radius:8px;background:#273241;color:#dfe6ee;cursor:pointer;font-size:13px}
button:hover{background:#314255}
button.on{background:#1e3a2b}button.on:hover{background:#1c7d48}
button.off{background:#3a2222}button.off:hover{background:#991b1b}
button.go{background:#3b82f6;color:#fff}button.go:hover{background:#2f6fd6}
button.danger{background:#7f1d1d}
/* активный сейчас режим — яркая заливка + кольцо */
button.on.active{background:#16a34a;color:#fff;box-shadow:0 0 0 2px #16a34a55}
button.off.active{background:#dc2626;color:#fff;box-shadow:0 0 0 2px #dc262655}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;background:#0e1217;border:1px solid #2c3440;
color:#9fe6c0;font-size:12px;font-weight:700;margin-left:8px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#6b7785;margin-right:6px;vertical-align:middle}
.dot.live{background:#16a34a}
select,input{padding:7px 9px;border-radius:8px;border:1px solid #2c3440;background:#0e1217;color:#dfe6ee;font-size:13px}
.lbl{color:#9aa7b6;font-size:13px;margin-right:4px}
.plist{display:flex;flex-direction:column;gap:6px}
.pitem{display:flex;gap:8px;align-items:center;background:#0e1217;border:1px solid #232b35;border-radius:8px;padding:6px 10px}
.pitem b{flex:1}
.muted{color:#6b7785;font-size:12px}
#out{min-height:34px}
.spin{opacity:.5}
</style></head><body>
<header><h1>🛰 gate — панель</h1><a class=logout href=# onclick="logout()">выйти</a></header>

<div class=card>
  <h2>Статус <button class=go style="float:right;padding:4px 10px" onclick="loadInfo()">⟳</button></h2>
  <pre id=info class=spin>загрузка…</pre>
</div>

<div class=card>
  <h2>Выход по умолчанию <span class=badge>сейчас: <span id=curmode>…</span></span></h2>
  <p class=muted>Действует на все устройства, которым не задан персональный выход (ниже).</p>
  <div class=row>
    <button id=di_off class=off onclick="act('global_off')">прямой C2</button>
    <button id=ov_on class=on onclick="act('global_ovpn_on')">OpenVPN</button>
    <button id=pp_on class=on onclick="act('global_pptp_on')">PPTP</button>
  </div>
  <div class=row style="margin-top:8px">
    <span class=lbl>носок:</span>
    <select id=gsock></select>
    <button id=so_on class=on onclick="act('global_socks_on',{profile:gsockVal()})">сделать основным</button>
    <button onclick="act('socks_test')">тест</button>
  </div>
  <div class=row id=curSockRow style="margin-top:8px;display:none">
    <span class=lbl>текущий носок:</span>
    <span id=curSock class=muted></span>
    <input id=promoName placeholder="имя профиля" size=10>
    <button class=go onclick="promoteSocks()">сохранить как профиль</button>
  </div>
  <p class=muted>Повесить носок на КОНКРЕТНОЕ устройство можно только профилем — сохрани текущий под именем.</p>
</div>

<div class=card>
  <h2>Устройства — персональный выход
    <span class=badge>каналы: <span id=chinfo>…</span></span>
  </h2>
  <p class=muted>Ноут прямым C2, один телефон через VPN, другой — через свой носок. Одновременно.</p>
  <div id=devs class=plist><span class=muted>загрузка…</span></div>
  <p class=muted>Если выход устройства выключен, его трафик блокируется (fail-closed), а не идёт мимо назначения.</p>
</div>

<div class=card>
  <h2>OS-отпечаток (osfp)</h2>
  <div class=row>
    <select id=osfp><option value=apple>apple</option><option value=windows>windows</option><option value=linux>linux</option></select>
    <button class=on onclick="act('osfp_on',{profile:osfpVal()})">вкл</button>
    <button class=off onclick="act('osfp_off')">выкл</button>
    <button onclick="act('osfp_status')">статус</button>
  </div>
  <p class=muted>работает только с VPN-выходом (ovpn/pptp), не с носком.</p>
</div>

<div class=card>
  <h2>DNS</h2>
  <div class=row>
    <span class=lbl>резолвер (прямой):</span>
    <select id=res><option value=cf>Cloudflare</option><option value=quad9>Quad9</option></select>
    <button class=go onclick="act('dns_resolver',{resolver:resVal()})">применить</button>
  </div>
  <div class=row style="margin-top:8px">
    <span class=lbl>fallback:</span>
    <button id=fb_on class=on onclick="act('dns_fallback_on')">вкл</button>
    <button id=fb_off class=off onclick="act('dns_fallback_off')">выкл</button>
    <button onclick="act('dns_test')">проба утечки</button>
  </div>
</div>

<div class=card>
  <h2>Профили</h2>
  <div id=profiles class=plist><span class=muted>загрузка…</span></div>
  <div class=row style="margin-top:10px">
    <span class=lbl>+ носок:</span>
    <input id=pn placeholder=имя size=8>
    <input id=pip placeholder=ip size=12>
    <input id=pp placeholder=порт size=6>
    <input id=pu placeholder=user size=8>
    <input id=ppw placeholder=pass size=10>
    <button class=go onclick="saveSocks()">сохранить</button>
  </div>
  <div class=row style="margin-top:8px">
    <span class=lbl>+ PPTP:</span>
    <input id=qn placeholder=имя size=8>
    <input id=qs placeholder=server size=14>
    <input id=qu placeholder=user size=8>
    <input id=qpw placeholder=pass size=10>
    <button class=go onclick="savePptp()">сохранить</button>
  </div>
  <p class=muted>OpenVPN-профиль добавляется через CLI: <code>gate profile save ovpn &lt;имя&gt; &lt;файл.ovpn&gt;</code> (нужна загрузка файла).</p>
</div>

<div class=card>
  <h2>Туннель / обслуживание</h2>
  <div class=row>
    <button class=on onclick="act('tunnel_up')">tunnel up</button>
    <button class=off onclick="act('tunnel_down')">tunnel down</button>
    <button onclick="act('tunnel_status')">статус</button>
    <button class=danger onclick="doWipe()">очистка (wipe)</button>
  </div>
</div>

<div class=card>
  <h2>Вывод последней команды</h2>
  <pre id=out>—</pre>
</div>

<script>
function osfpVal(){return document.getElementById('osfp').value}
function resVal(){return document.getElementById('res').value}
function setOut(t,busy){var o=document.getElementById('out');o.textContent=t;o.className=busy?'spin':''}
async function api(path,opt){opt=opt||{};opt.headers=Object.assign({'X-Gate':'1','Content-Type':'application/json'},opt.headers||{});
  var r=await fetch(path,opt);
  if(r.status===401){location.reload();return null}
  return r.json()}
async function loadInfo(){var i=document.getElementById('info');i.className='spin';
  var d=await api('/api/info');if(!d)return;i.textContent=d.out||'(пусто)';i.className=''}
function mark(id,on){var e=document.getElementById(id);if(e)e.classList.toggle('active',on)}
function gsockVal(){var e=document.getElementById('gsock');return e?e.value:''}
async function loadState(){var s=await api('/api/state');if(!s)return;
  var names={socks:'носок'+(s.global_socks?' «'+s.global_socks+'»':''),ovpn:'OpenVPN',pptp:'PPTP',direct:'прямой C2'};
  document.getElementById('curmode').textContent=names[s.exit]||s.exit;
  mark('so_on',s.exit==='socks');
  mark('ov_on',s.exit==='ovpn');
  mark('pp_on',s.exit==='pptp');
  mark('di_off',s.exit==='direct');
  mark('fb_on',s.dns_fallback==='on'); mark('fb_off',s.dns_fallback!=='on');
  if(s.resolver)document.getElementById('res').value=s.resolver}

// ── устройства: у каждого выпадашка выхода ──
async function loadDevs(){var d=await api('/api/devices');if(!d)return;
  document.getElementById('chinfo').textContent=d.used+' из '+d.pool;
  // список носков в селектор глобального выхода
  var gs=document.getElementById('gsock');
  if(gs){var cur=gs.value;gs.innerHTML='';
    if(d.socks_current){var oc=document.createElement('option');oc.value='';
      oc.textContent='текущий · '+d.socks_current.ip+':'+d.socks_current.port;gs.appendChild(oc)}
    else if(!d.socks_profiles.length){var o=document.createElement('option');o.value='';o.textContent='(носков нет)';gs.appendChild(o)}
    d.socks_profiles.forEach(function(n){var o=document.createElement('option');o.value=n;o.textContent=n;gs.appendChild(o)});
    if(cur)gs.value=cur}
  var row=document.getElementById('curSockRow'),lab=document.getElementById('curSock');
  if(d.socks_current&&row){row.style.display='';
    lab.textContent=d.socks_current.ip+':'+d.socks_current.port+(d.socks_current.auth?' (с авторизацией)':'')+
      (d.socks_profiles.length?'':' — профиля нет, поэтому его не выбрать устройству')}
  else if(row){row.style.display='none'}
  var box=document.getElementById('devs');box.innerHTML='';
  if(!d.devices.length){box.innerHTML='<span class=muted>нет активных аренд — подключи устройство к Wi-Fi</span>';return}
  d.devices.forEach(function(dev){
    var row=document.createElement('div');row.className='pitem';
    var title=(dev.name||dev.mac)+' · '+dev.ip;
    var lbl=document.createElement('b');lbl.textContent=title;
    var sel=document.createElement('select');
    var opts=[['','по умолчанию'],['c2','прямой C2'],['vpn','VPN (tun0 на C2)']];
    d.socks_profiles.forEach(function(n){opts.push(['socks:'+n,'носок «'+n+'»'])});
    opts.forEach(function(o){var e=document.createElement('option');e.value=o[0];e.textContent=o[1];sel.appendChild(e)});
    sel.value=dev.target||'';
    sel.onchange=function(){setDev(dev.mac,sel.value)};
    var note=document.createElement('span');note.className='muted';
    if(dev.target==='vpn'&&!d.vpn_live)note.textContent='⚠ VPN выключен → блок';
    else if(dev.ch)note.textContent='канал '+dev.ch;
    row.appendChild(lbl);row.appendChild(note);row.appendChild(sel);box.appendChild(row)})}
function promoteSocks(){var n=(document.getElementById('promoName').value||'').trim();
  if(!n){setOut('укажи имя профиля');return}
  act('socks_promote',{name:n});document.getElementById('promoName').value=''}
async function setDev(mac,target){
  setOut('… назначаю выход',true);
  var d=await api('/api/action',{method:'POST',
    body:JSON.stringify({action:'client_exit',mac:mac,target:target||'auto'})});
  if(!d)return;
  if(d.error){setOut('ошибка: '+d.error);return}
  setOut(d.out||('код '+d.code));refresh()}
async function refresh(){loadInfo();loadState();loadProfiles();loadDevs()}
async function act(action,extra){setOut('… '+action,true);
  var body=Object.assign({action:action},extra||{});
  var d=await api('/api/action',{method:'POST',body:JSON.stringify(body)});
  if(!d)return;
  if(d.error){setOut('ошибка: '+d.error);return}
  setOut(d.out||('код '+d.code));refresh()}
async function loadProfiles(){var d=await api('/api/profiles');if(!d)return;
  var box=document.getElementById('profiles');box.innerHTML='';
  var any=false;
  ['socks','pptp','ovpn'].forEach(function(t){(d[t]||[]).forEach(function(n){any=true;
    var el=document.createElement('div');el.className='pitem';
    el.innerHTML='<span class=muted>'+t+'</span><b></b>';
    el.querySelector('b').textContent=n;
    var use=document.createElement('button');use.className='on';use.textContent='use';
    use.onclick=function(){act('profile_use',{ptype:t,name:n})};
    var rm=document.createElement('button');rm.className='off';rm.textContent='✕';
    rm.onclick=function(){if(confirm('Удалить профиль '+t+'/'+n+'?'))act('profile_rm',{ptype:t,name:n})};
    el.appendChild(use);el.appendChild(rm);box.appendChild(el)})});
  if(!any)box.innerHTML='<span class=muted>профилей нет — добавь носок ниже или через CLI</span>'}
function gv(id){return document.getElementById(id).value.trim()}
function saveSocks(){var b={name:gv('pn'),ip:gv('pip'),port:gv('pp'),user:gv('pu'),pass:gv('ppw')};
  if(!b.name||!b.ip||!b.port){setOut('нужны имя, ip и порт');return}
  act('profile_save_socks',b);
  ['pn','pip','pp','pu','ppw'].forEach(function(id){document.getElementById(id).value=''})}
function savePptp(){var b={name:gv('qn'),server:gv('qs'),user:gv('qu'),pass:gv('qpw')};
  if(!b.name||!b.server||!b.user||!b.pass){setOut('нужны имя, server, user, pass');return}
  act('profile_save_pptp',b);
  ['qn','qs','qu','qpw'].forEach(function(id){document.getElementById(id).value=''})}
function doWipe(){if(confirm('ОЧИСТКА: удалить ВСЕ профили, стейт и креды на C2? Необратимо.'))act('wipe')}
async function logout(){await fetch('/logout',{method:'POST'});location.reload()}
refresh();setInterval(function(){loadInfo();loadState();loadDevs()},20000);
</script></body></html>"""


# ─── CLI ──────────────────────────────────────────────────────────────
def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd in ("passwd", "passwd-stdin"):
        pw = sys.argv[2] if (cmd == "passwd" and len(sys.argv) > 2) else sys.stdin.readline().rstrip("\n")
        if not pw:
            print("пустой пароль", file=sys.stderr); sys.exit(1)
        set_password(pw)
        print("пароль веб-морды задан")
        return
    if cmd == "serve":
        d = load_conf()
        if "PASS_HASH" not in d:
            print("Пароль не задан. Сначала: gate web passwd", file=sys.stderr); sys.exit(1)
        port = int(d.get("PORT", DEFAULT_PORT))
        apply_firewall(port)
        httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        print("gate-web слушает :%d (LAN-only)" % port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        return
    print("использование: gate-web.py {serve|passwd [пароль]}", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()

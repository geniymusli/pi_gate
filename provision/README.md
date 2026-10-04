# gate — провижининг цепочки Reality (малина → C1 → C2 → [C3])

Воспроизводимое развёртывание privacy-цепочки. Купил новый VPS — добавил
ключ малины — запустил визард — всё настроилось.

## Архитектура

```
устройства ─Wi-Fi─> малина ─Reality─> C1 ─Reality─> C2 ─Reality─> [C3] ─> интернет
            (AP)    (TPROXY)  (реле)     (реле/      (выход)
                                          выход)
```

- **Малина (entry)** — TPROXY заворачивает трафик клиентов и свой собственный
  в xray → reality-s1 → первый хоп.
- **Реле (relay)** — каждый хоп кроме последнего: `reality-in` → `reality-out`
  к следующему хопу. Чистый прокидыватель.
- **Выход (exit)** — последний хоп: `reality-in` → `direct`. Точка выхода в
  интернет. Сюда же надевается «носок» (`gate socks on`).

**Адаптивный носок.** `gate socks test` пробует носок с точки C2 (функционально, т.к.
носки врут на handshake): TCP+auth, remote-DNS (CONNECT по домену), UDP (UDP ASSOCIATE +
реальный DNS-запрос через релей). Результат → `/etc/gate/socks.caps`. `gate socks on`
по возможностям сам собирает роутинг: UDP→носок если умеет (QUIC оживает), иначе режет;
DNS резолвит носок если умеет remote-DNS (иначе несём Cloudflare-IP). `chain-render.py`
читает `socks.state`+`socks.caps` и подстраивает конфиг малины (`routeOnly`, QUIC-блок) —
переживает `redeploy`. Дефолт всё равно fail-closed: не подтверждено → закрыто.

**Hardening выхода.** При `socks on` на C2 outbound `direct` **убирается совсем** —
остаются только `socks-out` и `blocked`, дефолтный outbound = `blocked` (дроп), плюс
финальное catch-all правило `→ blocked`. Выйти с реального IP C2 физически нечем: отвал
UDP/DNS носка = поломка соединения, а не утечка. При `socks off` outbounds пересобираются
в `[direct, blocked]` (дефолт `direct`) → C2 снова выходит в интернет напрямую.

**VPN-выход (второй exit-mode, взаимоисключающий с носком).** `gate vpn` терминирует
OpenVPN/PPTP на выходном хопе — устройства ничего не ставят. C2-side скрипт `gate-vpn`
(стейджится на малине в `/usr/local/share/gate/gate-vpn`, заливается на хоп через цепочку
base64-ом) ставит клиента, поднимает `tun0`/`ppp0` и делает policy-routing: трафик xray
метится `fwmark 2` → таблица `200` → VPN-интерфейс. SSH, reality-канал от C1 и сокет
самого VPN-клиента НЕ метятся → идут по `eth0` (доступ к хопу не теряется). Killswitch:
в таблице 200 `blackhole default` (metric 1000) — интерфейс не поднялся → меченый трафик
дропается (проверено: dummy-конфиг → tun0 down → выход `—`, IP C2 не утёк). На C2 xray:
outbounds `[blocked, vpn-out]` (vpn-out=freedom+mark, direct убран, дефолт=blocked),
правила tcp/udp→vpn-out + catch-all→blocked. **DNS-анти-утечка:** берём DNS, которые
push'ит сам туннель (usepeerdns у pptp, `--up`-хук у ovpn парсит `dhcp-option DNS`) —
общий накопитель `/etc/gate/vpn/pushed-dns`; xray гонит их в `vpn-out`, не с eth0 C2.
Если туннель DNS не дал и включён `gate dns fallback on` — берём CF+Google, иначе DNS-секции
нет. `render_pi` при vpn on: `routeOnly=true`
(резолв Cloudflare, несём IP), QUIC пропускается (tun/ppp несёт UDP нативно). Конфиг:
`gate ovpn set <файл.ovpn> [user] [pass]` и `gate pptp set <server> <user> <pass>`
(PPTP крипта слабая — предупреждение). Оба конфига могут лежать на хопе одновременно
(`client.ovpn` и `/etc/ppp/peers/gate-vpn`), переключение через `on`. Состояние:
`/etc/gate/vpn.state`+`vpn.conf` (активный TYPE), конфиги на хопе в `/etc/gate/vpn/`.

**Три exit-режима взаимоисключающи** (socks / ovpn / pptp / прямой). Любой `… on`
проверяет активный режим и при конфликте переспрашивает «переключить?» (`-y` — без
вопроса) → выключает старый → включает новый. Единый статус — `gate exit` (алиас
`gate vpn status`), выключить активный — `gate exit off`.

Роль определяется позицией в цепочке: последний хоп = выход, остальные = реле.
Добавить C3 = просто сделать цепочку из 3 хопов (бывший выход C2 станет реле).

## Файлы

| Файл | Куда ставится | Что делает |
|------|---------------|------------|
| `chain-render.py` | `/usr/local/bin/` | рендерит config.json для малины/реле/выхода + строит SSH-цепочку, из `chain.json` |
| `vps-bootstrap.sh` | `/usr/local/share/gate/` | готовит чистый VPS: xray, BBR, ufw, SSH-по-ключу |
| `gate-setup` | `/usr/local/bin/` | визард (`gate setup`): развернуть/пересобрать цепочку |
| `gate-web.py` | `/usr/local/bin/` | локальная веб-панель (LAN-only, пароль); юнит `gate-web.service` |
| `chain.json` | `/etc/gate/` (pi:pi 600) | единый источник правды: хопы, ключи, SNI |

`chain.json` хранит **приватные ключи** — режим 600, в снапшоте, не публиковать.

## Модель управления (важно)

- **Данные** идут по Reality: малина → C1 → C2 → … Каждое плечо — отдельный туннель (от хопа
  к хопу, не вложенный): реле снимает свой слой и шифрует заново к следующему хопу, поэтому
  адреса назначения реле видит; IP малины знает только первый хоп.
- **Управление** (`gate socks`, `gate setup redeploy`) идёт по SSH **вложенно,
  ключами-на-хопах**: малина→C1 ключом малины (`mgmt_key`), C1→C2 ключом C1
  (`hops[0].next_key`, лежит НА C1), C2→C3 ключом C2 — и т.д. Доступ к C2 идёт
  «через C1», к C3 — «через C2». Компрометация ключа малины даёт только C1.
- **Firewall**: на каждом хопе `:443` (Reality) открыт миру (камуфляж),
  `:22` — у первого хопа открыт по ключу, у остальных **заперт на предыдущий
  узел** (C2 доступен по :22 только с C1, C3 — только с C2).
- **Первичный провижн** свежего VPS визард делает ПРЯМЫМ доступом ключом малины
  (ты добавляешь его в `authorized_keys` при создании VPS, :22 ещё открыт);
  затем раздаёт ключи-на-хопах и в конце запирает :22. Дальше — только вложенно.

## Требования к VPS

Чтобы цепочка вставала гладко (и 2 хопа C1-C2, и 3 хопа C1-C2-C3):

- **KVM-виртуализация, НЕ OpenVZ/LXC.** На контейнерных VPS не грузится BBR, нет
  `/dev/net/tun` (ovpn/pptp-выход на C2 не поднимется), урезаны iptables/ip-rule.
  Это главный источник «у одного хостера гладко, у другого нет». `vps-bootstrap.sh`
  на старте делает префлайт (`systemd-detect-virt`, наличие `/dev/net/tun`) и
  предупреждает, но не фейлит — бери KVM.
- **Ubuntu 22.04/24.04 LTS или Debian 11/12, amd64, доступ root** (xray-установщик
  XTLS и `systemd-detect-virt` есть из коробки; не Alpine — там нет apt/systemd).
- **Свежая система.** Некоторые «голые» образы идут с предустановленным Docker,
  который гадит в iptables (цепочки `DOCKER*`, `FORWARD` policy DROP, masquerade) и
  обходит ufw. Bootstrap его **автоматически выпиливает** (purge + сброс iptables к
  ACCEPT, после чего ufw собирает фаервол заново) — отдельных действий не нужно.

## Купить и добавить новый сервер

Запусти на малине `gate setup`. Визард спросит SNI, число хопов и их IP, затем
разворачивает **по одному хопу по очереди** и для КАЖДОГО показывает, какой ключ
добавить на этот VPS (модель ключей-на-хопах):

1. **C1** — показывает **ключ малины**. Создаёшь VPS (Ubuntu 22.04/24.04 x86_64),
   вставляешь ключ в `root@authorized_keys` (поле SSH-ключа при создании или
   веб-консоль), Enter. Визард ставит C1 напрямую.
2. **C2** — показывает **ключ C1** (визард сам сгенерил его и положил на C1).
   Создаёшь VPS с этим ключом, Enter. Визард ставит C2 **вложенно через C1** и
   запирает :22 C2 на C1.
3. **C3** (если есть) — показывает **ключ C2**, ставится вложенно через C2.

Для каждого хопа визард делает: bootstrap (xray+BBR+ufw), рендер+деплой конфига,
запирание :22 на предыдущий узел, генерацию ключа к следующему хопу. В конце —
малина и проверка выхода. **Ключ малины попадает только на C1.**

### Заменить «выход» / добавить C3

Запусти `gate setup` заново и укажи нужное число хопов и их IP. Reality-ключи для
знакомых IP переиспользуются; для новых — генерятся.

## Частые операции

```
gate setup              # развернуть/пересобрать цепочку (визард)
gate setup show         # показать цепочку (без секретов)   == gate chain
gate setup redeploy     # перелить конфиги по текущему chain.json (без вопросов,
                        #   без bootstrap) — после ручной правки или замены сервера
gate info               # общий статус (панель; = gate / gate status)
gate traffic [iface]    # живой монитор трафика ↓↑ до Ctrl+C (= gate tr)
gate tunnel up|down|status
gate socks set <ip> <port> [user] [pass]   # задать носок
gate socks test         # проба носка с C2: TCP / remote-DNS / UDP (функционально)
gate socks on|off|status               # «носок» на выходном хопе (адаптивно)

gate ovpn set <файл.ovpn> [user] [pass]    # OpenVPN-выход на C2 (залить через цепочку)
gate ovpn test|on|off|status           # проба(изолированно)/вкл/выкл/статус OpenVPN
gate pptp set <server> <user> <pass>   # PPTP-выход (крипта слабая!)
gate pptp test|on|off|status           # проба/вкл/выкл/статус PPTP
gate exit                              # ЕДИНЫЙ статус выхода (режим/iface/IP)
gate exit off                          # выключить активный выход → прямой C2
gate dns [N]                           # проба DNS-утечки: чей резолвер видит мир
                                       #   (N проб edns.ip-api; ✗ если страна резолвера = C2)
gate dns fallback on|off               # запасной DNS (Cloudflare+Google) для VPN-режима —
                                       #   ТОЛЬКО если туннель свой DNS не дал (по умолч. off)
gate dns resolver cloudflare|quad9     # резолвер малины для ПРЯМОГО выхода (нет VPN/носка);
                                       #   меняет dnscrypt-proxy, дефолт quad9 (no-log).
                                       #   google убран — не отвечает с РФ-IP выхода
gate osfp on [apple|windows|linux]     # подмена OS-отпечатка (p0f) на выходе; вручную
gate osfp off|status                   #   только с VPN-выходом (PPTP/OpenVPN), не с носком
# socks/ovpn/pptp взаимоисключающи: «on» спросит про переключение (или -y без вопроса).
# у каждого режима свой status (gate socks/ovpn/pptp status); gate vpn — убран.

# ── профили: запомнить носки/VPN, не вводить/грузить заново ──
gate profile list [socks|pptp|ovpn]        # что сохранено
gate profile save socks <имя> <ip> <port> [user] [pass]
gate profile save pptp  <имя> <server> <user> <pass>
gate profile save ovpn  <имя> <файл.ovpn> [user] [pass]   # .ovpn копируется в профиль
gate profile use <тип> <имя>               # активировать сохранённый (ovpn перельётся на C2)
gate profile rm  <тип> <имя>               # удалить профиль
gate wipe                                  # очистка: ВСЕ профили + стейт + креды на C2
                                           #   (-y — без подтверждения)

gate logs               # что логируется + размеры (по умолчанию всё тихо)
gate logs xray [N]      # журнал xray малины (= gate logs xray view)
gate logs xray on|off   # системный лог xray: loglevel warning ↔ none
gate logs traffic on|off|view   # лог соединений (xray access; off = access:none)
gate logs perf on|off|view      # CPU/RAM/темп/потери к C1 (служба gate-monitor)
gate logs off           # выключить traffic+perf (бережём SD)
```

Лог малины — два независимых тумблера, флаги в `/etc/gate/log.conf`, читает
`chain-render.py` (переживают `redeploy`):

- **XRAY** (дефолт on) — системный лог xray в journald: `warning` ↔ `none`.
  journald на малине volatile (на SD почти не пишет), но `off` даёт абсолютную тишину.
- **TRAFFIC** (дефолт off) — access-лог соединений: `/var/log/xray/access.log` ↔
  `access:none` (про соединения не пишется ничего — ни файл, ни journald).

xray логирует в journald просто потому, что это systemd-сервис (его stdout/stderr
забирает journald) — это не файловая запись. `gate logs perf` — отдельная служба
`gate-monitor` (по умолчанию остановлена).

## Веб-панель (управление из локалки)

Лёгкая морда на самой малине (stdlib `http.server`, без зависимостей) — обёртка над `gate`
со строгим allowlist команд (никакого shell, ввод не попадает в argv → инъекции исключены).

```
gate web passwd            # задать/сменить пароль (PBKDF2, /etc/gate/web.conf 0600)
gate web on                # включить (сам доставит systemd-юнит + имя http://gate в dnsmasq)
gate web off|restart|status|log
```

Открывать: **http://gate:8088** (или `http://192.168.50.1:8088`) с устройства в раздаче/локалке.

Безопасность:
- **Только LAN.** Сервис бьёт INPUT-firewall (цепочка `GATE_WEB`): порт открыт лишь для
  loopback/RFC1918, остальное (WAN/туннель) — DROP. Плюс per-request проверка источника.
- **Пароль** обязателен (`gate web on` не стартует без него). Сессия — HMAC-кука
  (SameSite=Strict, HttpOnly); на API кастомный заголовок (анти-CSRF).
- **Живёт независимо от tproxy/killswitch** — трафик к самой малине идёт через `INPUT`, не
  `FORWARD`. Значит «пульт» доступен, даже когда туннель лёг и клиенты fail-closed.

Морда умеет: статус (`gate info`, авто-обновление), тумблеры socks/ovpn/pptp, osfp, выбор
DNS-резолвера и fallback, список/переключение/удаление профилей (+ форма «добавить носок»),
tunnel up/down и кнопку очистки (`wipe`). Сервис запускается под root (внутри `gate` использует
sudo для iptables/render/ssh-цепочки); поэтому привязан к LAN и под паролем.

## Формат chain.json

```json
{
  "sni": "ya.ru",
  "target": "ya.ru:443",
  "tproxy_port": 12345,
  "socks_test_port": 10808,
  "egress_mark": 255,
  "mgmt_key": "/home/pi/.ssh/gate_to_s1",
  "ssh_user": "root",
  "hops": [
    { "name": "C1", "host": "1.2.3.4",   "port": 443,
      "uuid": "...", "privkey": "...", "pubkey": "...", "shortid": "...",
      "next_key": "/root/.ssh/s1_to_s2",
      "send_through": "1.2.3.5" },
    { "name": "C2", "host": "5.6.7.8",   "port": 443,
      "uuid": "...", "privkey": "...", "pubkey": "...", "shortid": "..." }
  ]
}
```

- Reality-идентичность хопа (его **INBOUND**): `uuid` (id клиента), `privkey`
  (приватный ключ, стоит на сервере), `pubkey` (в `outbound` того, кто к хопу
  коннектится), `shortid`. Апстрим коннектится по `{host,port,uuid,pubkey,shortid,sni}`.
- `mgmt_key` — ключ малины (Pi→C1). `next_key` у хопа — путь SSH-ключа НА этом
  хопе для доступа к СЛЕДУЮЩЕМУ (C1→C2 и т.д.); у выхода `next_key` нет.

### Опц. поля хопа — два IP на сервере (dual-IP)

Когда у сервера несколько IPv4 и хочется разнести вход и исходящее плечо:
- `host` — IP, на который **заходит апстрим** (малина/предыдущий хоп); по нему же идёт
  обращение и rendering `address`.
- `send_through` — IP, **с которого хоп уходит наружу** (к следующему хопу / в инет).
  Применяется к reality-`outbound` (xray `sendThrough`), к `direct`-выходу у exit-хопа
  И к управляющему SSH (`ssh -b` в `node_cmd`), а :22 следующего хопа запирается на этот
  IP. Итог: следующий хоп видит ТОЛЬКО `send_through`, входной `host` ему не светится.
- `listen` — IP, на котором слушает reality-in (по умолч. `0.0.0.0` = все).

Визард `gate setup` спрашивает про второй IP на каждом хопе (Enter — пропустить).
Поля опциональны: без них всё рендерится как обычный single-IP хоп.

## Ручной рендер (отладка)

```
chain-render.py check  chain.json            # валидация
chain-render.py pi     chain.json            # конфиг малины
chain-render.py node   chain.json 0          # конфиг хопа 0 (реле)
chain-render.py node   chain.json 1          # конфиг хопа 1 (выход)
chain-render.py role   chain.json 1          # relay|exit
```

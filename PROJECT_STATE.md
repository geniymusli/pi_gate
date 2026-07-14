# pi_gate — состояние проекта (handoff)

Самодостаточная сводка, чтобы продолжить проект в новой сессии/на новой машине, даже если чат и
авто-память не переехали. Если открываешь это как Claude в новой сессии — прочитай и продолжай.

## Что это
Privacy-роутер на Raspberry Pi 5: устройства → Wi-Fi AP малины → TPROXY → xray VLESS **Reality**
(двойной вложенный туннель) → C1 (реле, РФ) → C2 (выход, ЕС) → интернет. Плюс выборные выходы
на C2: прямой / SOCKS5 / OpenVPN / PPTP, подмена OS-отпечатка (osfp), защита DNS.

Крипта: VLESS без своего шифра; шифрует **Reality** = настоящий TLS 1.3 (X25519 ECDHE,
AES-128-GCM/ChaCha20-Poly1305), камуфляж под SNI (ya.ru), flow=xtls-rprx-vision, fp=chrome.

## Раскладка репозитория
- `_build/` — исходники утилит малины: `gate` (панель, версия в `GATE_VERSION`), `gate-web.py`
  (веб-панель), `gate-tproxy-up.sh/-down.sh`, `gate-vpn`/`gate-osfp[.py]` (скрипты выходного хопа),
  `gate-monitor`, `gate-snapshot`, `gate-*.service`, `gate-completion.bash`, `gate-banner.sh`.
- `provision/` — `chain-render.py` (рендер конфигов xray + SSH-цепочки из chain.json),
  `gate-setup` (визард развёртывания цепочки), `vps-bootstrap.sh` (подготовка VPS),
  `installer/install.sh` (установщик на чистый Pi OS Lite), `make-gate-dist.sh` (сборщик раздачи).
- `dist/` — РЕЗУЛЬТАТ раздачи: `gate-<версия>.tar.gz` (прозрачный tar из plain-файлов + README +
  SHA256SUMS). Текущая версия — **0.1**.

## Раздача друзьям (готово)
Собрать: `bash provision/make-gate-dist.sh` → `dist/gate-0.1.tar.gz`. Отдаёшь ОДИН этот файл.
Друг (чистый Pi OS Lite 64): `tar xzf gate-0.1.tar.gz && cd gate-0.1 && sudo ./install.sh`
(спросит интерфейсы AP/WAN — ВЫБИРАЮТСЯ, не хардкод; SSID/пароль/страна US). Потом `sudo reboot`,
`gate setup` (своя цепочка/ключи), `gate web passwd && gate web on`.
Обновление: новый tar → `sudo ./install.sh --update` (только tooling, конфиги/ключи сохраняются).
Принцип: РАЗДАВАТЬ ОТКРЫТЫМ ИСХОДНИКОМ (юзер за прозрачность; base64-`.run` удалён).

## Управление малиной/серверами
- Малина: `ssh -i ~/.ssh/pi_gate pi@raspberry` (eth0 ≈ 192.168.0.102). Юзер pi = passwordless sudo.
- Серверы цепочки: ТОЛЬКО через C1 (правило: к C2/хопам напрямую НЕ ходить, даже ping). `gate`
  строит вложенный SSH через `chain-render.py exit-cmd`. Ключ малины `~/.ssh/gate_to_s1`
  (`mgmt_key` в /etc/gate/chain.json).
- Экспериментируешь — сперва `gate socks off` / выключи активный выход; не убивать `gate ovpn/pptp on`
  на полпути (изолирует C2 → лечится только ребутом хопа из панели хостера).

## Бэклог (СПЛАНИРОВАНО, не реализовано)
1. **Per-client выбор выхода** — полный микс (socks/ovpn/pptp/direct) разным клиентам по MAC;
   механика: параллельные xray-пользователи (полосы) на каждом хопе, C2 маршрутит user→выход,
   малина раскидывает клиентов по source-IP; полосы вкл/выкл для экономии RAM; dhcp-host пин MAC→IP.
2. **Padding** (анти-трафик-анализ на плече малина→C1): xray-встроенный / cover-traffic
   (`gate-padding`, заготовка есть) / padding размеров. Постоянный или адаптивный (idle) — решить.
3. **`gate factory-reset`** — полная очистка личного (ключи, chain.json, xray-конфиги, web.conf,
   socks/vpn/профили, hostapd SSID/пароль, аренды, history, machine-id, логи, снапшоты) для «передарить».

## Ключевые грабли (не наступать снова)
- `gate-tproxy-up.sh` под `set -e`: любое `$(cat опц-файл)` ОБЯЗАНО иметь `|| true`, иначе в
  direct-режиме скрипт падает ДО создания GATE_TP → tproxy лежит → клиенты fail-closed.
- В НЕэкранированных heredoc (`<<PYEOF`) внутри `gate` НЕЛЬЗЯ писать бэктики/`$()` даже в
  `#`-комментариях python — шелл их ВЫПОЛНЯЕТ (был баг: `pptp on` молча включал dns fallback).
- Чужой `.ovpn` с `redirect-gateway def1`: `gate-vpn` поднимает openvpn с `--route-noexec`
  (иначе уводит default route выходного хопа в туннель → изоляция хопа). `gate ovpn set`
  нормализует Windows-only директивы (block-outside-dns и пр.) через `ignore-unknown-option`.

## Что нужно сохранить при переезде на другую ОС
1. Эту папку проекта (держать по пути `C:\Claude Projects\pi_gate`).
2. Память Claude: `C:\Users\User\.claude\projects\C--Claude-Projects-pi-gate\memory\` (привязана к
   пути проекта — при том же пути подхватится).
3. SSH-ключи: `~/.ssh/pi_gate`, `~/.ssh/gate_to_s1`.

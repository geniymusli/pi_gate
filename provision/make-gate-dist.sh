#!/usr/bin/env bash
#
# make-gate-dist.sh — собирает ПРОЗРАЧНЫЙ дистрибутив gate: обычные читаемые файлы
# (никакого base64/бинарников), README с описанием каждого файла и SHA256SUMS.
# Итог: dist/gate-<версия>/ (папка) и dist/gate-<версия>.tar.gz.
#
# Друг может прочитать ЛЮБОЙ файл глазами перед запуском:
#   tar xzf gate-<версия>.tar.gz && cd gate-<версия>
#   less install.sh ; less bin/gate ; ...        # читаем что угодно
#   sha256sum -c SHA256SUMS                        # целостность
#   sudo ./install.sh                              # установка
#
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/_build"; PROV="$REPO/provision"
# Версия — единый источник правды: GATE_VERSION из _build/gate (та же, что показывает gate --version).
VER="$(sed -n 's/^GATE_VERSION="\(.*\)"/\1/p' "$BUILD/gate" | head -1)"; VER="${VER:-0}"
BUILT="$(date +%Y-%m-%d)"
DIST="$REPO/dist/gate-$VER"
rm -rf "$DIST"; mkdir -p "$DIST/bin" "$DIST/share" "$DIST/extra"

cp_req(){ [ -f "$1" ] || { echo "НЕТ файла: $1" >&2; exit 1; }; install -m "${3:-755}" "$1" "$2"; }

# xray-бинарники не в git — дотягиваем по пину/SHA, если их нет (после свежего клона).
if [ ! -f "$PROV/vendor/xray/xray-linux-amd64" ] || [ ! -f "$PROV/vendor/xray/xray-linux-arm64" ]; then
  echo "→ бинарников xray нет — тяну fetch-xray.sh…"; "$PROV/fetch-xray.sh"
fi

# bin/ — утилиты (часть _build, часть provision)
for f in gate gate-monitor gate-snapshot gate-tproxy-up.sh gate-tproxy-down.sh gate-web.py; do
  cp_req "$BUILD/$f" "$DIST/bin/$f"
done
cp_req "$PROV/gate-setup"      "$DIST/bin/gate-setup"
cp_req "$PROV/chain-render.py" "$DIST/bin/chain-render.py"
# share/ — скрипты выходного хопа + bootstrap серверов
for f in gate-vpn gate-osfp gate-osfp.py; do cp_req "$BUILD/$f" "$DIST/share/$f"; done
cp_req "$PROV/vps-bootstrap.sh" "$DIST/share/vps-bootstrap.sh"
# share/ — пиннованные бинарники xray (офлайн-установка без GitHub; малина/серверы в РФ).
# arm64 → сама малина (install.sh), amd64 → серверы (визард шлёт по цепочке).
cp_req "$PROV/vendor/xray/xray-linux-arm64" "$DIST/share/xray-linux-arm64"
cp_req "$PROV/vendor/xray/xray-linux-amd64" "$DIST/share/xray-linux-amd64"
cp_req "$PROV/vendor/xray/MANIFEST.txt"     "$DIST/share/xray-MANIFEST.txt" 644
# extra/ — completion, banner, systemd-юниты
cp_req "$BUILD/gate-completion.bash" "$DIST/extra/gate-completion.bash" 644
cp_req "$BUILD/gate-banner.sh"       "$DIST/extra/gate-banner.sh" 644
for u in gate-tunnel gate-web gate-monitor; do cp_req "$BUILD/$u.service" "$DIST/extra/$u.service" 644; done
# install.sh — оркестратор
cp_req "$PROV/installer/install.sh" "$DIST/install.sh"

# синтаксис-проверка перед раздачей
bash -n "$DIST/install.sh"; bash -n "$DIST/bin/gate"

# README — прозрачность: что это, что делает, как проверить
cat > "$DIST/README.md" <<EOF
# gate — privacy-роутер (версия $VER, сборка $BUILT)

Раздаётся **открытым исходником**: все скрипты ниже — обычный текст, читай любым редактором.
Никакой телеметрии или «звонков домой». Единственные бинарники — **официальный xray**
(\`share/xray-linux-{amd64,arm64}\`), пиннованные и **сверяемые** с публичными чек-суммами XTLS
(см. \`share/xray-MANIFEST.txt\`). Они уложены в раздачу, чтобы установка работала **офлайн** —
серверам и малине в РФ GitHub недоступен. Из интернета при установке тянутся только apt-пакеты Debian.

## Как убедиться, что всё чисто
\`\`\`
less install.sh          # главный установщик — читается сверху вниз
less bin/gate            # панель управления
grep -rn "curl\|wget\|http" .          # все обращения в сеть на виду
cat share/xray-MANIFEST.txt            # версия и SHA256 бинарей xray
sha256sum share/xray-linux-amd64       # сверь с MANIFEST и с релизом XTLS
sha256sum -c SHA256SUMS  # целостность всех файлов раздачи
\`\`\`

## Установка (чистый Raspberry Pi OS Lite 64)
\`\`\`
sudo ./install.sh          # спросит интерфейсы (раздача/интернет), SSID, пароль
sudo reboot
gate setup                 # своя цепочка серверов и ключи (генерятся у тебя, никому не уходят)
gate web passwd && gate web on
\`\`\`
Обновление позже: \`sudo ./install.sh --update\` (обновит только скрипты, конфиги сохранит).

## Что установщик меняет в системе
- ставит apt-пакеты: hostapd, dnsmasq, dnscrypt-proxy, iptables, iw, curl;
- ставит официальный xray в /usr/local/bin/xray (+ systemd-юнит) из бинаря бандла, без GitHub;
- кладёт утилиты gate в /usr/local/bin и /usr/local/share/gate;
- пишет конфиги: hostapd (точка доступа), dnsmasq (DHCP/DNS для клиентов),
  dnscrypt-proxy (шифрованный DNS), NetworkManager (не трогать AP-адаптер),
  sysctl (форвардинг/BBR), /etc/gate/gate.conf (твой выбор интерфейсов);
- даёт пользователю pi sudo без пароля (управление по SSH-ключу).
- НЕ создаёт никаких серверов/ключей — это делаешь ты сам командой \`gate setup\`.

## Файлы
| Файл | Назначение |
|------|-----------|
| install.sh | установщик: пакеты, xray, выбор интерфейсов, конфиги, сервисы |
| bin/gate | панель управления (статус, выход, DNS, носок/VPN, профили, wipe, web) |
| bin/gate-setup | визард: развернуть цепочку C1→C2, сгенерировать ключи |
| bin/chain-render.py | рендер конфигов xray и SSH-цепочки из chain.json |
| bin/gate-tproxy-up.sh / -down.sh | подъём/снятие прозрачного перехвата (TPROXY) |
| bin/gate-web.py | локальная веб-панель (только из твоей сети, под паролем) |
| bin/gate-monitor / gate-snapshot | монитор нагрузки / бэкап конфигов |
| share/gate-vpn, gate-osfp[.py] | скрипты выходного сервера (VPN-выход, подмена OS-отпечатка) |
| share/vps-bootstrap.sh | подготовка чистого VPS под узел цепочки |
| share/xray-linux-{amd64,arm64} | пиннованный официальный xray (amd64 — серверы, arm64 — малина); офлайн, без GitHub |
| share/xray-MANIFEST.txt | версия xray + SHA256 (сверяемо с релизом XTLS) |
| extra/*.service | systemd-юниты; gate-completion/banner — автодополнение/приветствие |

Вопросы по любому куску кода — спрашивай, тут нечего прятать.
EOF

# SHA256SUMS — по всем файлам (для sha256sum -c)
( cd "$DIST" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs sha256sum > SHA256SUMS )

# tarball (распакуется в gate-<версия>/)
TARBALL="$REPO/dist/gate-$VER.tar.gz"
tar czf "$TARBALL" -C "$REPO/dist" "gate-$VER"

echo "✓ прозрачный дистрибутив собран:"
echo "  папка:   $DIST"
echo "  архив:   $TARBALL  ($(du -h "$TARBALL" | cut -f1))"
echo "  файлов:  $(find "$DIST" -type f | wc -l)   (скрипты — текст; xray-бинари сверяемы по SHA256)"
echo
echo "друг: tar xzf gate-$VER.tar.gz && cd gate-$VER && less install.sh && sudo ./install.sh"

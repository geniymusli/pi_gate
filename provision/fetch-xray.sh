#!/usr/bin/env bash
#
# fetch-xray.sh — скачать пиннованные бинарники xray в provision/vendor/xray/.
# Бинари НЕ хранятся в git (тяжёлые); здесь только MANIFEST.txt с версией и SHA256.
# Версия и все хеши берутся ИЗ MANIFEST.txt (единственный источник правды).
# Идемпотентно: если бинарь на месте и SHA совпал — пропускаем.
#
# Нужен интернет до GitHub (запускается на dev-машине/малине, НЕ на РФ-серверах).
# Зовётся из make-gate-dist.sh и сборки .deb, когда бинарей нет.
#
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/vendor/xray"
MAN="$DIR/MANIFEST.txt"
[ -f "$MAN" ] || { echo "нет $MAN" >&2; exit 1; }

VER="$(awk '/^версия:/{print $2}' "$MAN")"
[ -n "$VER" ] || { echo "не разобрал версию из MANIFEST" >&2; exit 1; }
BASE="https://github.com/XTLS/Xray-core/releases/download/v${VER}"

# arch → имя zip у XTLS. binary/zip SHA берём из MANIFEST по имени.
declare -A ZIP=( [amd64]="Xray-linux-64.zip" [arm64]="Xray-linux-arm64-v8a.zip" )

man_sha(){ awk -v k="$1" '$1==k{print $3; exit}' "$MAN"; }  # строка "<имя>  sha256 <hash>"

fetch_one(){
  local arch="$1"
  local out="$DIR/xray-linux-$arch"
  local zip="${ZIP[$arch]}"
  local binsha zipsha; binsha="$(man_sha "xray-linux-$arch")"; zipsha="$(man_sha "$zip")"
  [ -n "$binsha" ] && [ -n "$zipsha" ] || { echo "нет SHA для $arch в MANIFEST" >&2; exit 1; }

  if [ -f "$out" ] && echo "$binsha  $out" | sha256sum -c --status; then
    echo "  ✓ $arch уже на месте (SHA ок)"; return 0
  fi
  echo "  → качаю xray $VER $arch ($zip)…"
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$zip" "$BASE/$zip"
  echo "$zipsha  $tmp/$zip" | sha256sum -c --status || { echo "✗ zip SHA не совпал ($arch)!" >&2; rm -rf "$tmp"; exit 1; }
  unzip -o -q "$tmp/$zip" -d "$tmp/x"
  install -m 755 "$tmp/x/xray" "$out"
  echo "$binsha  $out" | sha256sum -c --status || { echo "✗ бинарь SHA не совпал ($arch)!" >&2; rm -rf "$tmp"; exit 1; }
  rm -rf "$tmp"
  echo "  ✓ $arch готов (SHA сверен с MANIFEST и релизом XTLS)"
}

echo "fetch-xray: версия $VER → $DIR"
for a in amd64 arm64; do fetch_one "$a"; done
echo "готово."

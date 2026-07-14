# /etc/profile.d/gate-banner.sh — приветствие pi_gate при интерактивном входе.
# ВАЖНО: это sourced-скрипт → только `return`, никогда `exit` (иначе закроет сессию).
case $- in *i*) ;; *) return 0 2>/dev/null || true ;; esac   # только интерактивные шеллы
[ -t 1 ] || return 0 2>/dev/null || true                      # только если stdout = терминал

if command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  _gC=$(tput setaf 6); _gG=$(tput setaf 2); _gB=$(tput bold); _gD=$(tput setaf 8); _gR=$(tput sgr0)
else
  _gC=''; _gG=''; _gB=''; _gD=''; _gR=''
fi

printf '\n'
printf '  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$_gC" "$_gR"
printf '   %s%s▌ pi_gate%s %s· privacy-роутер%s\n' "$_gB" "$_gC" "$_gR" "$_gD" "$_gR"
printf '  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$_gC" "$_gR"
printf '   %sсправка%s → %sgate help%s   %s(gate -h · gate --help)%s\n' "$_gD" "$_gR" "$_gG" "$_gR" "$_gD" "$_gR"
printf '   %sстатус%s  → %sgate info%s\n\n' "$_gD" "$_gR" "$_gG" "$_gR"

unset _gC _gG _gB _gD _gR

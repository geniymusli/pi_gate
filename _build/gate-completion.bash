# /etc/bash_completion.d/gate — tab-дополнение для gate
#
# ВАЖНО: держать в синхроне с диспетчером в конце `gate` и с case'ами cmd_*.
# Здесь перечисляем только то, что команда РЕКЛАМИРУЕТ в своём usage: внутренние
# и устаревшие ветки (`gate socks on`, `gate ovpn on` — переехали в `gate global`)
# намеренно НЕ дополняем, чтобы не тянуть людей в снятый интерфейс.

# ── динамические источники (всё читается без sudo) ─────────────────────
_gate_prof(){   # $1 = socks|pptp|ovpn → имена профилей
  case "$1" in
    ovpn) find /etc/gate/profiles/ovpn -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null ;;
    *)    find /etc/gate/profiles/"$1" -maxdepth 1 -name '*.conf' -printf '%f\n' 2>/dev/null | sed 's/\.conf$//' ;;
  esac
}
_gate_socks_specs(){ local p; for p in $(_gate_prof socks); do printf 'socks:%s\n' "$p"; done; }
_gate_devs(){   # IP и MAC известных устройств (подписи не дополняем — в них пробелы)
  # строку `self` из раскладки пропускаем: это сама малина, `gate client` её не найдёт
  # среди аренд DHCP и ответит «не нашёл».
  { awk '{print $3; print $2}' /var/lib/misc/dnsmasq.leases 2>/dev/null
    awk '$1!="self"{print $2; print $1}' /etc/gate/client-lanes.conf 2>/dev/null; } \
  | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-f]{2}:){5}[0-9a-f]{2}$' | sort -u
}

_gate() {
  local cur cword
  cur="${COMP_WORDS[COMP_CWORD]}"; cword=$COMP_CWORD

  # Полный список команд диспетчера (`case "${1:-help}"` в конце gate)
  local top="info clients client global lanes traffic tunnel doctor clock freeze unfreeze
             socks ovpn pptp profile wipe web exit dns osfp setup chain logs
             wan eth wifi ap version help"

  if [ "$cword" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$top" -- "$cur") ); return
  fi

  local c1="${COMP_WORDS[1]}" c2="${COMP_WORDS[2]:-}" c3="${COMP_WORDS[3]:-}"
  case "$c1" in
    # ── полосы: персональный выход устройству ────────────────────────
    client)
      case "$cword" in
        2) COMPREPLY=( $(compgen -W "list $(_gate_devs)" -- "$cur") ) ;;
        3) [ "$c2" = list ] || COMPREPLY=( $(compgen -W "exit name" -- "$cur") ) ;;
        4) [ "$c2" = list ] || { [ "$c3" = exit ] && \
             COMPREPLY=( $(compgen -W "c2 vpn auto $(_gate_socks_specs)" -- "$cur") ); } ;;
      esac ;;
    # ── выход по умолчанию для всех ──────────────────────────────────
    global)
      case "$cword" in
        2) COMPREPLY=( $(compgen -W "status off ovpn pptp socks" -- "$cur") ) ;;
        3) case "$c2" in
             ovpn|pptp) COMPREPLY=( $(compgen -W "on off" -- "$cur") ) ;;
             socks)     COMPREPLY=( $(compgen -W "on" -- "$cur") ) ;;
           esac ;;
        4) [ "$c2" = socks ] && [ "$c3" = on ] && COMPREPLY=( $(compgen -W "$(_gate_prof socks)" -- "$cur") ) ;;
      esac ;;
    lanes)  [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "init apply status" -- "$cur") ) ;;
    tunnel) [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "up down restart status" -- "$cur") ) ;;
    doctor) [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "check" -- "$cur") ) ;;
    clock)  [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "status sync install" -- "$cur") ) ;;
    freeze) [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "all risk status" -- "$cur") ) ;;
    # ── выходы: только НАСТРОЙКА (включение — через gate global) ──────
    socks)  [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "set promote test status" -- "$cur") ) ;;
    ovpn)   case "$cword" in
              2) COMPREPLY=( $(compgen -W "set check test status log" -- "$cur") ) ;;
              3) case "$c2" in set|check) COMPREPLY=( $(compgen -f -X '!*.ovpn' -- "$cur") ) ;; esac ;;
            esac ;;
    pptp)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "set test status" -- "$cur") ) ;;
    exit)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "status off" -- "$cur") ) ;;
    profile)
      case "$cword" in
        2) COMPREPLY=( $(compgen -W "list save use rm" -- "$cur") ) ;;
        3) COMPREPLY=( $(compgen -W "socks pptp ovpn" -- "$cur") ) ;;
        4) case "$c2" in use|rm) COMPREPLY=( $(compgen -W "$(_gate_prof "$c3")" -- "$cur") ) ;; esac ;;
      esac ;;
    web)    [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "passwd on off restart status log" -- "$cur") ) ;;
    dns)
      case "$cword" in
        2) COMPREPLY=( $(compgen -W "fallback resolver lane" -- "$cur") ) ;;
        3) case "$c2" in
             fallback) COMPREPLY=( $(compgen -W "on off status" -- "$cur") ) ;;
             resolver) COMPREPLY=( $(compgen -W "cloudflare quad9 status" -- "$cur") ) ;;
             lane)     COMPREPLY=( $(compgen -W "c2 vpn $(_gate_socks_specs)" -- "$cur") ) ;;
           esac ;;
      esac ;;
    osfp)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "on off status" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = on ] && COMPREPLY=( $(compgen -W "apple windows linux" -- "$cur") ) ;;
    setup)  [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "show redeploy" -- "$cur") ) ;;
    wan)    [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "eth wifi auto" -- "$cur") ) ;;
    eth)    [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "mac" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = mac ] && COMPREPLY=( $(compgen -W "random reset" -- "$cur") ) ;;
    wifi)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "connect scan disconnect mac" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = mac ] && COMPREPLY=( $(compgen -W "random reset" -- "$cur") ) ;;
    ap)     [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "on off restart iface ssid pass mac show" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = mac ] && COMPREPLY=( $(compgen -W "random reset" -- "$cur") ) ;;
    logs)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "xray traffic perf off" -- "$cur") )
            if [ "$cword" -eq 3 ]; then case "$c2" in
              xray|traffic|perf) COMPREPLY=( $(compgen -W "on off view" -- "$cur") ) ;;
            esac; fi ;;
  esac
}
complete -F _gate gate

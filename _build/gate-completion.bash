# /etc/bash_completion.d/gate — tab-дополнение для gate
_gate() {
  local cur cword
  cur="${COMP_WORDS[COMP_CWORD]}"; cword=$COMP_CWORD
  local top="info clients traffic tunnel socks ovpn pptp profile wipe web exit dns osfp setup chain logs wan eth wifi ap version help"

  if [ "$cword" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$top" -- "$cur") ); return
  fi

  local c1="${COMP_WORDS[1]}" c2="${COMP_WORDS[2]:-}"
  case "$c1" in
    tunnel) [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "up down restart status" -- "$cur") ) ;;
    socks)  [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "set test on off status" -- "$cur") ) ;;
    ovpn)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "set check test on off status" -- "$cur") ) ;;
    pptp)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "set test on off status" -- "$cur") ) ;;
    profile)[ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "list save use rm" -- "$cur") )
            [ "$cword" -eq 3 ] && COMPREPLY=( $(compgen -W "socks pptp ovpn" -- "$cur") ) ;;
    web)    [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "passwd on off restart status log" -- "$cur") ) ;;
    exit)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "status off" -- "$cur") ) ;;
    dns)    [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "fallback resolver" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = fallback ] && COMPREPLY=( $(compgen -W "on off status" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = resolver ] && COMPREPLY=( $(compgen -W "cloudflare quad9 status" -- "$cur") ) ;;
    osfp)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "on off status" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = on ] && COMPREPLY=( $(compgen -W "apple windows linux" -- "$cur") ) ;;
    setup)  [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "show redeploy" -- "$cur") ) ;;
    wan)    [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "eth wifi auto" -- "$cur") ) ;;
    eth)    [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "mac" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = mac ] && COMPREPLY=( $(compgen -W "random reset" -- "$cur") ) ;;
    wifi)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "connect scan disconnect mac" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = mac ] && COMPREPLY=( $(compgen -W "random reset" -- "$cur") ) ;;
    ap)     [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "on off restart ssid pass mac" -- "$cur") )
            [ "$cword" -eq 3 ] && [ "$c2" = mac ] && COMPREPLY=( $(compgen -W "random reset" -- "$cur") ) ;;
    logs)   [ "$cword" -eq 2 ] && COMPREPLY=( $(compgen -W "xray traffic perf off" -- "$cur") )
            if [ "$cword" -eq 3 ]; then case "$c2" in
              xray) COMPREPLY=( $(compgen -W "on off view" -- "$cur") ) ;;
              traffic|perf) COMPREPLY=( $(compgen -W "on off view" -- "$cur") ) ;;
            esac; fi ;;
  esac
}
complete -F _gate gate

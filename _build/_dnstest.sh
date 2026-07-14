set -u
echo "--- модули ---"; lsmod | grep -iE 'gre|pptp' || echo "НЕТ модулей"
echo "--- iptables gre правила + счётчики ---"; iptables -vnL INPUT | grep -i gre; iptables -vnL OUTPUT | grep -i gre
echo "--- обнуляю счётчики gre, жду 15с попыток pppd ---"; iptables -Z >/dev/null 2>&1; sleep 15
echo "--- GRE out/in за 15с (out>0,in=0 → возврат режется/сервер молчит) ---"
iptables -vnL INPUT | grep -i gre; iptables -vnL OUTPUT | grep -i gre
echo "--- nf_conntrack_helper sysctl (0 = хелпер выключен) ---"; sysctl -n net.netfilter.nf_conntrack_helper 2>/dev/null || echo "n/a"

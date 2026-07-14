set -u
# запустить перехватчик (если не запущен), затем правило с queue-bypass
pkill -f gate-osfp.py 2>/dev/null; sleep 1
nohup python3 /usr/local/bin/gate-osfp.py 1 >/var/log/gate-osfp.log 2>&1 &
sleep 2
pgrep -f gate-osfp.py >/dev/null && echo "перехватчик запущен (pid $(pgrep -f gate-osfp.py))" || { echo "НЕ запустился:"; tail -5 /var/log/gate-osfp.log; exit 1; }
# правило: исходящий SYN в туннель ppp0 → NFQUEUE 1 (bypass = если хендлера нет, пропускать)
iptables -t mangle -C POSTROUTING -o ppp0 -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null \
  || iptables -t mangle -A POSTROUTING -o ppp0 -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -j NFQUEUE --queue-num 1 --queue-bypass
echo "правило NFQUEUE поставлено"
echo "--- ловлю переписанный SYN на ppp0 (12с) ---"
timeout 12 tcpdump -i ppp0 -n -c 1 -vv 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null || echo "(SYN не пойман — открой что-нибудь через цепочку)"

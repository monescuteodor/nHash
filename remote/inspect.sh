#!/usr/bin/env bash
# Read-only inspection of the 2500K box: CPU/cache, running miner, how it autostarts, build tools.
echo "=== CPU / cache ==="
lscpu | grep -Ei 'model name|^CPU\(s\)|Thread|Core|L1d|L1i|L2|L3|MHz'
echo
echo "=== running miner processes ==="
ps -eo pid,pcpu,pmem,comm,args | grep -Ei 'xmrig|monero|miner|minerd|cpuminer' | grep -v grep || echo "no obvious miner process"
echo
echo "=== systemd services matching miner ==="
systemctl list-units --type=service 2>/dev/null | grep -Ei 'xmr|monero|miner' || echo "none matching in systemd"
echo
echo "=== systemd user services ==="
systemctl --user list-units --type=service 2>/dev/null | grep -Ei 'xmr|monero|miner' || echo "none matching in user systemd"
echo
echo "=== crontab (user) ==="
crontab -l 2>/dev/null || echo "no user crontab"
echo
echo "=== autostart hints (rc.local, profile, .bashrc) ==="
grep -Eil 'xmrig|monero|miner' /etc/rc.local ~/.bashrc ~/.profile ~/.bash_profile 2>/dev/null || echo "no hits in common startup files"
echo
echo "=== build tools ==="
which g++ gcc make 2>/dev/null || echo "no compiler in PATH"
g++ --version 2>/dev/null | head -1 || echo "g++ not installed"
echo
echo "=== free memory ==="
free -h | head -2

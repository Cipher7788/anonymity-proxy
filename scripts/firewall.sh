#!/usr/bin/env bash
# Linux Docker iptables backend only. Default is a reviewable dry run.
set -euo pipefail
mode=${1:---dry-run}
[[ "$mode" == --dry-run || "$mode" == --apply || "$mode" == --remove ]] || { echo 'Use --dry-run, --apply or --remove' >&2; exit 1; }
: "${CLIENT_CIDR:?Set the allowed IPv4 client CIDR}"
: "${DNS_IP:?Set a trusted public IPv4 DNS resolver}"
python3 - "$CLIENT_CIDR" "$DNS_IP" <<'PY'
import ipaddress, sys
assert ipaddress.ip_network(sys.argv[1], strict=False).version == 4
assert ipaddress.ip_address(sys.argv[2]).version == 4
assert ipaddress.ip_address(sys.argv[2]).is_global, "Use a public resolver or review a private-resolver exception separately"
PY
run() { printf '%q ' "$@"; printf '\n'; if [[ "$mode" != --dry-run ]]; then "$@"; fi; }
if [[ "$mode" != --dry-run ]]; then
  [[ $EUID == 0 ]] || { echo 'Apply/remove requires root' >&2; exit 1; }
  iptables -S DOCKER-USER >/dev/null
  [[ $(docker network inspect anonymity-proxy --format '{{.EnableIPv6}}') == false ]] || { echo 'Requires IPv4-only Compose network' >&2; exit 1; }
fi
if [[ "$mode" == --remove ]]; then
  while iptables -C DOCKER-USER -i br-anonproxy ! -o br-anonproxy -j AP_EGRESS 2>/dev/null; do run iptables -D DOCKER-USER -i br-anonproxy ! -o br-anonproxy -j AP_EGRESS; done
  while iptables -C DOCKER-USER ! -i br-anonproxy -o br-anonproxy -p tcp --dport 8080 -j AP_INGRESS 2>/dev/null; do run iptables -D DOCKER-USER ! -i br-anonproxy -o br-anonproxy -p tcp --dport 8080 -j AP_INGRESS; done
  run iptables -F AP_EGRESS; run iptables -X AP_EGRESS
  run iptables -F AP_INGRESS; run iptables -X AP_INGRESS
  exit 0
fi
if [[ "$mode" != --dry-run ]] && { iptables -S AP_EGRESS >/dev/null 2>&1 || iptables -S AP_INGRESS >/dev/null 2>&1; }; then
  echo 'Existing AP rules found; remove explicitly before reapplying. Keep proxy bound to loopback while changing rules.' >&2; exit 1
fi
run iptables -N AP_EGRESS
run iptables -N AP_INGRESS
for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 168.63.129.16/32; do
  run iptables -A AP_EGRESS -d "$cidr" -j REJECT
done
run iptables -A AP_EGRESS -d "$DNS_IP" -p udp --dport 53 -j RETURN
run iptables -A AP_EGRESS -d "$DNS_IP" -p tcp --dport 53 -j RETURN
run iptables -A AP_EGRESS -p tcp -m multiport --dports 80,443 -j RETURN
run iptables -A AP_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
run iptables -A AP_EGRESS -j REJECT
run iptables -A AP_INGRESS -s "$CLIENT_CIDR" -j RETURN
run iptables -A AP_INGRESS -j DROP
run iptables -I DOCKER-USER 1 -i br-anonproxy ! -o br-anonproxy -j AP_EGRESS
run iptables -I DOCKER-USER 1 ! -i br-anonproxy -o br-anonproxy -p tcp --dport 8080 -j AP_INGRESS


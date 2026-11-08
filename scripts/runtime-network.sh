#!/usr/bin/env bash
# Only for the disposable runtime bridge. Does not affect the production bridge.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Requires root on the disposable Linux Docker host' >&2; exit 1; }
case ${1:-apply} in
  apply)
    iptables -N AP_RUNTIME
    iptables -A AP_RUNTIME -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    iptables -A AP_RUNTIME -j REJECT
    iptables -I DOCKER-USER 1 -i br-anon-test ! -o br-anon-test -j AP_RUNTIME
    ;;
  remove)
    while iptables -C DOCKER-USER -i br-anon-test ! -o br-anon-test -j AP_RUNTIME 2>/dev/null; do
      iptables -D DOCKER-USER -i br-anon-test ! -o br-anon-test -j AP_RUNTIME
    done
    if iptables -S AP_RUNTIME >/dev/null 2>&1; then iptables -F AP_RUNTIME; iptables -X AP_RUNTIME; fi
    ;;
  *) echo 'Use apply or remove' >&2; exit 1 ;;
esac

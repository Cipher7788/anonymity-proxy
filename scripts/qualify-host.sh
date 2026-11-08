#!/usr/bin/env bash
# Run only against an upstream you own or are authorized to load-test.
set -euo pipefail
: "${PROXY_URL:?Set HTTPS proxy URL without credentials}"
: "${TARGET_URL:?Set authorized controlled HTTP/HTTPS upstream}"
: "${PROXY_USERNAME:?Set proxy username}"
: "${PROXY_PASSWORD_FILE:?Set protected password file path}"
: "${PROXY_CA_FILE:?Set proxy/origin CA bundle}"
duration=${DURATION:-5m}
concurrency=${CONCURRENCY:-16}
mkdir -p reports
chmod 700 reports
report="reports/host-load-$(date -u +%Y%m%dT%H%M%SZ)"
docker compose ps > "$report-containers.txt"
./dist/proxyctl load -proxy "$PROXY_URL" -ca "$PROXY_CA_FILE" -target "$TARGET_URL" \
  -duration "$duration" -concurrency "$concurrency" \
  -max-error-rate "${MAX_ERROR_RATE:-0.01}" -p95-limit "${P95_LIMIT:-3s}" \
  -output "$report.json" > "$report-output.txt" &
load_pid=$!
trap 'kill "$load_pid" 2>/dev/null || true' EXIT
while kill -0 "$load_pid" 2>/dev/null; do
  docker stats --no-stream --format '{{json .}}' >> "$report-resources.jsonl"
  sleep 1
done
result=0
wait "$load_pid" || result=$?
trap - EXIT
printf 'Qualification evidence: %s\n' "$report"
exit "$result"

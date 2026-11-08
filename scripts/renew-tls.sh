#!/usr/bin/env bash
# Install as a Certbot deploy hook after configuring these values on the host.
set -euo pipefail
: "${PROXY_DEPLOY_DIR:?Set absolute deployment directory}"
: "${PROXY_HOSTNAME:?Set client-facing certificate hostname}"
: "${RENEWED_LINEAGE:?Certbot supplies the renewed certificate directory}"
cd "$PROXY_DEPLOY_DIR"
./dist/proxyctl tls -directory . -hostname "$PROXY_HOSTNAME" \
  -cert "$RENEWED_LINEAGE/fullchain.pem" -key "$RENEWED_LINEAGE/privkey.pem"
docker compose run --rm --no-deps proxy -config /etc/proxy/config.json -check-config
docker compose up -d --force-recreate --wait proxy prometheus

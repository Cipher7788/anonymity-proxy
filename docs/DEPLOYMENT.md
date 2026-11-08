# Deployment

## Native platforms

Build with a supported patched Go compiler. Set PROXY_USERNAME and PROXY_PASSWORD_FILE through a secret manager. Restrict the file to the service account. Run `proxy -config /path/config.json -check-config` before starting.

Remote service requires a literal bind address plus tls_cert and tls_key paths. Use a certificate covering the client-facing hostname. Clients configure `https://your-proxy-host:8080`. Automate renewal and restart after renewal. Terminate TLS in this process or use TCP passthrough; ordinary web-hosting HTTP routing is generally unsuitable for CONNECT.

Linux: supervise using a dedicated systemd account, Restart=on-failure, NoNewPrivileges=true, ProtectSystem=strict, ProtectHome=true, PrivateTmp=true, an appropriate LimitNOFILE and TimeoutStopSec=20s. Deliver protected credentials and restrict firewall ingress/egress. macOS: use launchd. Windows: use a terminal or approved service wrapper; the executable does not implement the Windows Service Control Manager protocol. Use Ctrl+C for graceful console shutdown.

## Docker

1. Create Git-ignored tls/ and secrets/ directories.
2. Install the trusted certificate chain at tls/cert.pem and key at tls/key.pem. Container UID 10001 must be able to read these; restrict key access.
3. Put a strong password in secrets/proxy_password and set PROXY_USERNAME.
4. Run `docker compose config` and `docker compose up --build -d`.
5. Verify authenticated health and a proxied HTTPS request. For a private CA, curl supports --proxy-cacert. Never use --proxy-insecure.

The default mapping is localhost-only. To expose remotely, intentionally change the mapping and install ingress firewall restrictions. Keep TLS enabled. Do not use host networking or mount the Docker socket. Kubernetes needs a TCP Service and secret volumes; choose TCP passthrough unless the ingress explicitly supports forward proxy CONNECT.

## Monitoring and qualification

Monitor authenticated /healthz, restarts, CPU, memory, open sockets and descriptors, plus a synthetic proxied HTTPS request. Avoid retaining authentication headers or browsing metadata. Readiness does not verify upstream DNS/internet access.

Ramp a controlled workload below, toward and above max_concurrent. Record success/error rates, p50/p95/p99 latency, resident memory, descriptors and goroutines. Test large streaming bodies, slow headers/uploads/downloads, idle tunnels, DNS failure, mixed public/private answers, disconnects and SIGTERM. Verify resources stabilize after clients disconnect. Set deployment limits from actual measurements; no throughput target is claimed.

## Recovery

Rotate exposed credentials immediately and restart. Patch Go and images regularly, run CI and image scans, canary the update and retain the last verified image for rollback. No database migration is needed. Back up protected configuration separately from secrets. Enforce network-level metadata/internal-address denial as defense in depth; investigate policy failures rather than weakening filters.

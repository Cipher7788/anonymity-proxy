# Linux Docker Compose deployment

Requirements: a patched Linux host, Docker Engine with the iptables firewall backend, Docker Compose v2 with --wait support, a patched Go 1.26+ compiler for building the operator tool, and Python 3/iptables for the optional host firewall helper. The default setup binds only to loopback. Monitoring ports always remain loopback-only.

## Local development and runtime qualification

```sh
go build -trimpath -o dist/proxyctl ./cmd/proxyctl
./dist/proxyctl init -mode development -hostname localhost
docker compose config --quiet
docker compose up --build -d --wait
docker compose exec proxy /usr/local/bin/proxy -config /etc/proxy/config.json -healthcheck
```

The initializer generates two independent 256-bit random secrets, a 30-day development certificate/CA, a non-secret .env, and monitoring/alerting configuration. It refuses to overwrite existing deployment files. Development mode refuses non-loopback binds. Development CA certificates are for testing only; never install them as production trust anchors.

The source secret/TLS/generated directories are mode 0700. Individual files are read-only and bind-mounted as Compose secrets so the unprivileged container users can read them. Parent-directory protection is essential on the host; do not copy these files to world-traversable directories. Local Compose secrets are not encrypted at rest. Use encrypted disks/backups and a host secret manager where required. Git and Docker build contexts exclude all generated material. On a shared production host run initialization and Compose under the same restricted administrative account (or root) and secure Docker socket access.

## Production certificates and alert routing

Obtain a trusted certificate for the real proxy hostname using your ACME client or organizational CA. Certbot supports standalone issuance and renewal deploy hooks; port 80 must be reachable for HTTP-01, or use DNS-01. Do not place account credentials in Git. See the [Certbot user guide](https://eff-certbot.readthedocs.io/en/stable/using.html).

On a clean deployment directory:

```sh
go build -trimpath -o dist/proxyctl ./cmd/proxyctl
./dist/proxyctl init -mode production -hostname proxy.example.com \
  -cert /etc/letsencrypt/live/proxy.example.com/fullchain.pem \
  -key /etc/letsencrypt/live/proxy.example.com/privkey.pem \
  -alert-webhook-file /secure/path/alert-webhook
docker compose up --build -d --wait
```

Use your own hostname and paths. The initializer validates hostname, chain, private-key match, validity and at least seven days remaining. Linux system CA trust is the default; supply -ca for an organizational CA bundle. Production mode requires a protected file containing a real HTTPS Alertmanager-compatible webhook URL. It configures routing but does not contact the receiver during initialization. Verify actual firing, delivery and resolution before release. Development mode deliberately has no notification receiver.

The generated proxy username is operator. Store secrets/proxy_password in your approved password manager and configure clients using an HTTPS proxy URL. Use --proxy-cacert with curl for a private CA, not --proxy-insecure. A generic HTTP ingress is unsuitable unless it supports forward proxy CONNECT; use native TLS or TCP passthrough.

## Firewall and remote access

Keep PROXY_BIND_IP=127.0.0.1 until the firewall is verified. Docker published traffic can bypass ordinary host INPUT/UFW rules. This repo includes an IPv4 DOCKER-USER plan following [Docker's iptables guidance](https://docs.docker.com/engine/network/firewall-iptables/):

```sh
CLIENT_CIDR=192.0.2.10/32 DNS_IP=1.1.1.1 bash scripts/firewall.sh --dry-run
# Replace documentation addresses with your real approved client subnet/resolver.
sudo env CLIENT_CIDR=YOUR_CLIENT_CIDR DNS_IP=YOUR_PUBLIC_DNS_IP bash scripts/firewall.sh --apply
```

The Compose network must exist first. The helper restricts remote proxy ingress to CLIENT_CIDR and outgoing bridge traffic to public HTTP/HTTPS plus the chosen public DNS resolver. Private/metadata ranges are rejected before established-flow allowance. Same-bridge monitoring is retained. It changes only dedicated AP chains and their DOCKER-USER jumps; it does not change SSH rules or flush the host firewall. Review the printed plan before applying. Use --remove to remove those dedicated rules. Keep the proxy loopback-bound while replacing rules. Persist the tested rules using your distribution's firewall manager after Docker creates DOCKER-USER on reboot; never assume this script alone persists across restarts.

The helper requires Docker's iptables backend, the named br-anonproxy bridge, and IPv6 disabled for this stack. It is not a Docker nftables-backend or host-IPv6 policy. Do not apply it to the isolated runtime network. Docker's embedded DNS can use host-generated resolver traffic; host DNS policy needs separate review. Configure the daemon/resolver and cloud security group accordingly, and test from a separate approved and denied client machine. Publicly addressed internal services and custom routing require additional deny rules.

After verification, set PROXY_BIND_IP in .env to the intended host IPv4 and recreate the proxy. Keep ports 9090/9093 local. Do not mount the Docker socket or use host networking. Reserve the fixed network/bridge names for this one deployment.

## Monitoring and health

Compose runs Prometheus and Alertmanager with persistent named volumes. Access http://127.0.0.1:9090 and :9093 through an SSH tunnel. Prometheus verifies proxy TLS and authenticates with a dedicated Bearer token. That token can read /metrics but cannot forward requests; proxy credentials cannot read /metrics. Aggregate metrics include connections/capacity, operations, policy denials, upstream failures, heap, goroutines and TLS expiry. No URL/client labels are emitted.

Alerts cover process/scrape failure, certificate expiry within 14 days, sustained socket saturation, upstream error ratio and high Go heap. Tune thresholds from measurements. Proxy requests include health probes, so the upstream failure ratio is approximate. Readiness is not proof of internet reachability; monitor a separately authorized synthetic upstream if needed. Keep monitoring secret/config files and alert destinations out of artifacts. Health checks mark an unhealthy process; Docker's restart policy restarts exited processes, not a merely unhealthy process. Alert on both.

Validate rules and configuration with the same promtool/amtool commands used in .github/workflows/ci.yml. Test actual notifications using Alertmanager's API on loopback, then verify receipt and resolution with the receiver owner.

## Renewal and rotation

Build dist/proxyctl on the host. Install scripts/renew-tls.sh as a Certbot deploy hook with protected PROXY_DEPLOY_DIR and PROXY_HOSTNAME values. The hook validates the new keypair, replaces TLS files, checks config, then recreates proxy and Prometheus. Run and inspect a renewal dry run with your CA's supported process. Existing tunnels reconnect during renewal. See the [Certbot deploy-hook behavior](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

Rotate both operator and read-only metrics secrets:

```sh
./dist/proxyctl rotate -directory .
docker compose up -d --force-recreate --wait proxy prometheus
```

Update clients' password manager entry afterward. File-backed Compose secrets require container recreation after atomic file replacement; docker compose restart alone can retain the old inode. No secret is printed by the tool. Alert receiver changes also require updating the protected secret and recreating Alertmanager.

## Load and failure evidence

CI uses a separate bridge, explicit rules rejecting new external egress, and a controlled origin; it does not weaken production address policy. The deliberately synthetic 11.254.0.0/24 subnet must remain isolated by the runtime firewall. Published host ports remain reachable so the runner can exercise the stack. Do not run it beside production because it uses the same localhost ports.

```sh
# Use a clean development setup and stop the normal stack first.
docker compose down
sudo bash scripts/runtime-network.sh apply
docker compose -f compose.yaml -f compose.runtime.yaml up --build -d --wait
PROXY_RUNTIME_TEST=1 PROXY_DEPLOY_DIR="$PWD" go test ./tests -run TestContainerRuntime -v -count=1 -timeout=5m
docker compose -f compose.yaml -f compose.runtime.yaml down -v --remove-orphans
sudo bash scripts/runtime-network.sh remove
```

Tests cover verified TLS, authentication, HTTP/HTTPS forwarding, private/metadata denial, reset and timeout behavior, streaming, metric isolation, tunnel expiry, load, non-root/read-only/resource settings, monitoring scraping, graceful shutdown, and crash recovery. --down -v deletes only this disposable test stack's named volumes; never use that command on production monitoring data.

For the actual host, use an upstream you own or have permission to load-test:

```sh
export PROXY_URL=https://proxy.example.com:8080
export TARGET_URL=https://your-controlled-upstream.example/health
export PROXY_USERNAME=operator
export PROXY_PASSWORD_FILE="$PWD/secrets/proxy_password"
export PROXY_CA_FILE="$PWD/tls/ca.pem"
DURATION=5m CONCURRENCY=16 MAX_ERROR_RATE=0.01 P95_LIMIT=3s bash scripts/qualify-host.sh
```

The CLI writes aggregate error/latency/RPS results and fails when configured thresholds are exceeded. Latency percentiles use a bounded histogram with 1 ms resolution and a 60 s overflow bucket. Cancelled requests at the scheduled end are excluded from completed-request statistics. The host script samples container resource use throughout the run. Ramp below, toward and beyond capacity, inspect recovery, and set budgets appropriate to your hardware. CI's short regression load is not a production capacity guarantee.

## Release and recovery

Follow RELEASE_CHECKLIST.md and obtain an independent review using security/REVIEW.md. Scan/SBOM artifacts do not replace that review. Patch and pin verified image/action digests, stage a canary, retain the previous verified image and protected configuration for rollback, and rehearse recovery. The proxy has no database; preserve monitoring volumes unless intentionally resetting them. A live host, domain, alert receiver and independent reviewer cannot be provisioned just by committing files.

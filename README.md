# Anonymity Proxy

Authenticated HTTP forwarding and HTTPS CONNECT tunneling in Go, using only the standard library. Native Linux, macOS, and Windows builds; Docker deployment included.

**Status: hardened baseline pending independent security review and production load qualification.** This is a single-hop proxy. Destinations see the proxy IP, but cookies, accounts, fingerprints and traffic patterns can still identify users. DPI resistance, malware detection, multi-hop anonymity and system firewall features are not implemented. HTTPS is tunneled without interception.

## Build and run

Use the latest security patch of Go 1.26 or newer. From the repository root:

```sh
go build -trimpath -o dist/proxy ./cmd/proxy
export PROXY_USERNAME=operator
read -rs -p 'Proxy password (at least 16 characters): ' PROXY_PASSWORD; echo
export PROXY_PASSWORD
./dist/proxy -config config/proxy.json
```

Windows PowerShell:

```powershell
go build -trimpath -o dist/proxy.exe ./cmd/proxy
$env:PROXY_USERNAME = 'operator'
$secret = Read-Host 'Proxy password (at least 16 characters)' -AsSecureString
$env:PROXY_PASSWORD = [System.Net.NetworkCredential]::new('', $secret).Password
./dist/proxy.exe -config config/proxy.json
```

The default listener is localhost-only. Test with curl (it prompts for the proxy password):

```sh
curl --proxy http://127.0.0.1:8080 --proxy-basic --proxy-user operator https://example.com/
curl --proxy http://127.0.0.1:8080 --proxy-basic --proxy-user operator http://example.com/
```

All requests require credentials. For deployment use a secret manager and `PROXY_PASSWORD_FILE`; it overrides `PROXY_PASSWORD`, stripping trailing CR/LF. Use at least 32 random bytes for production passwords. Restrict secret files to the service account. Environment secrets remain visible to sufficiently privileged processes.

## Configuration

Strict JSON replaces the original unused YAML. Unknown fields, trailing JSON values and invalid ranges fail startup. `-check-config` validates configuration, credentials and certificate loading without listening.

| Field | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8080` | Literal IP and port; bracket IPv6 |
| `tls_cert`, `tls_key` | empty | PEM certificate chain and key; configure both |
| `max_concurrent` | 128 | Maximum client sockets and concurrent operations; 1–10000 |
| `request_timeout_seconds` | 60 | Entire HTTP forwarding lifetime; 1–3600 |
| `tunnel_timeout_seconds` | 300 | Absolute CONNECT lifetime; 1–86400 |
| `allowed_ports` | `["80","443"]` | Explicit numeric destination TCP ports |

Non-loopback listeners require TLS. Remote clients must use an HTTPS proxy URL and trust its certificate. Do not disable verification. Generic HTTP website hosting/ingress often cannot serve CONNECT; use a VM/container platform with TCP support.

Only public destinations are accepted. Private, loopback, link-local, multicast and special-purpose networks are denied, including mapped IPv6 equivalents. Mixed public/private DNS answers are rejected; the checked literal IP is dialed without re-resolving. No private-network override exists.

## Containers

See [deployment instructions](docs/DEPLOYMENT.md). Supply `tls/cert.pem`, `tls/key.pem`, `secrets/proxy_password`, and environment variable `PROXY_USERNAME` first:

```sh
docker compose config
docker compose up --build -d
docker compose logs --tail 30
```

Compose publishes to host loopback only. The container uses TLS, a non-root account, read-only root filesystem, dropped capabilities and CPU/memory/PID limits. Missing secrets or certificates cause startup failure.

## Operations

Authenticated origin-form `GET /healthz` returns `{"status":"ready"}`. Send `Proxy-Authorization: Basic <base64(username:password)>` directly to the listener using a secret-aware monitoring agent. Ordinary Authorization is not proxy authentication. This tests process readiness, not upstream internet availability.

Startup/shutdown logs contain listener information and aggregate request and authentication/capacity rejection counts. URLs, bodies, credentials and client IPs are not intentionally logged; external infrastructure may still log them. Destination rejections are represented by HTTP status rather than that aggregate rejection counter.

SIGTERM/Ctrl+C closes tracked tunnels and drains HTTP requests for up to 15 seconds. Credentials, configuration and renewed certificates require restart. Clients reconnect after tunnel lifetime expiry.

## Validation

```sh
go test ./...
go test -race ./...  # requires a C compiler on some platforms
go vet ./...
go test ./internal/proxy -run=^$ -fuzz=FuzzValidateTarget -fuzztime=15s
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
docker build -t anonymity-proxy .
```

Integration tests cover forwarding/streaming, header isolation, HTTPS tunnels with certificate validation, buffered CONNECT bytes, shutdown, authentication, private destinations, timeouts, capacity and config validation. A local upstream dialer is injected only by tests; production has no bypass. CI runs native checks on Linux, macOS and Windows and security/Docker checks on Linux.

An optional live integration test checks real public HTTP and HTTPS egress: set `PROXY_TEST_INTERNET=1` and run `go test ./internal/proxy -run TestPublicInternet -count=1`. It contacts example.com through an ephemeral local proxy and sends no proxy credentials to the origin.

## Limits

- One shared credential; no multi-tenant quotas or distributed rate limiting.
- HTTP/1 proxy ingress only. Protocols can negotiate inside CONNECT. No SOCKS, UDP, QUIC, or plaintext HTTP Upgrade forwarding.
- DNS uses the proxy host resolver. The operator, DNS provider and network can observe metadata.
- Direct public egress only; no upstream anonymity route or multi-hop exit selection.
- HTTP content is plaintext; use end-to-end HTTPS. Common identity headers are stripped, but application data is not anonymized.
- Connection/time bounds do not protect against all denial-of-service attacks.
- Versioned image tags are not digest-locked; pin verified digests during release qualification.

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [security policy](SECURITY.md), and [roadmap](docs/ROADMAP.md).

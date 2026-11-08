# Roadmap

Implemented: authenticated HTTP/CONNECT, public-address/port policy, strict config, native TLS, resource limits, shutdown, Docker configuration, native CI and integration/fuzz tests.

Before public production release:

- Owner enables private vulnerability reporting. MIT licensing is included.
- Independently review security and current special-purpose address registries.
- Pass Linux/macOS/Windows CI, Linux race detection, Docker build and image scanning.
- Publish platform load/failure-test results and tune limits.
- Pin release action/image digests and publish signed artifacts, checksums and SBOM.
- Configure renewal, rotation, monitoring and ingress/egress firewalls.

Future design work: multi-user quotas, live aggregate metrics, authenticated upstream transports with fail-closed behavior, address-policy maintenance automation. Multi-hop anonymity, DPI resistance and threat detection require separate designs and evidence; they are not current features.

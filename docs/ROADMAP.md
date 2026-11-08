# Roadmap

Implemented: authenticated HTTP/CONNECT, public-address/port policy, strict config, native TLS, resource limits, shutdown, Docker configuration, native CI and integration/fuzz tests; Linux deployment initializer, secret rotation, renewal hook, read-only metrics and alerts, firewall plan/apply helper, controlled load and isolated container runtime suites, image scan/SBOM pipeline, and independent-review handoff.

Before public production release:

- Owner enables private vulnerability reporting. MIT licensing is included.
- Independently review security and current special-purpose address registries.
- Pass the current native, security, load and container-runtime CI jobs and inspect their evidence artifacts.
- Publish platform load/failure-test results and tune limits.
- Pin release action/image digests and publish signed release artifacts/checksums; CI generates an image SBOM.
- Apply and verify renewal, rotation, monitoring and ingress/egress firewall tooling on the real host.

Future design work: multi-user quotas, authenticated upstream transports with fail-closed behavior, address-policy maintenance automation. Multi-hop anonymity, DPI resistance and threat detection require separate designs and evidence; they are not current features.

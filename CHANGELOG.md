# Changelog

## Unreleased baseline

- Added Linux Compose setup, certificate/secret initialization and rotation, renewal hook, health checks, read-only metrics, Prometheus/Alertmanager, firewall tooling, load/resource qualification, isolated runtime fault tests, image scanning/SBOM artifacts, and security review/release records.

- Fixed delayed small streaming responses by flushing headers and copied chunks; added an SSE regression test.

- Replaced the non-compiling HTTP scaffold with authenticated HTTP forwarding and HTTPS CONNECT.
- Added strict JSON config, secret-file support, TLS listener requirements and fail-fast validation.
- Added public-address/port filtering, DNS rebinding resistance and proxy credential/header isolation.
- Bounded client sockets, concurrent operations, headers, transport pools and request/tunnel lifetimes.
- Added tracked tunnel shutdown, streaming support and authenticated process readiness.
- Replaced broken Docker files with a non-root image and restricted Compose deployment.
- Added native integration tests, fuzz coverage, cross-platform CI, vulnerability checks and dependency updates.
- Replaced placeholder architecture with deployment instructions, a threat model, security policy and roadmap.
- Added MIT license with owner approval. Removed empty Rust and test scaffolds and unsupported feature claims.

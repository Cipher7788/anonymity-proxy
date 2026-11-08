# Validation record — 2026-11-08

Base: Cipher7788/anonymity-proxy commit 457713c846837a0795f8a53a36ac2a6305b3e4c5. These results describe local validation before publication; consult the pull request checks for subsequent CI results.

Environment: Windows amd64; official checksum-verified Go 1.27.3 toolchain. Source compatibility floor: Go 1.26.0. No application third-party modules.

Completed:

- Native unit/integration tests, including concurrent forwarding, streaming, credentials, destination policy, strict config, request timeout, socket capacity, tunnel lifetime and shutdown.
- HTTPS proxy ingress and tunneled origin TLS certificate verification with separate trusted test certificates.
- Public HTTP and HTTPS smoke tests to example.com using the production DNS resolver/address policy and an ephemeral local proxy.
- go vet and formatting checks.
- FuzzValidateTarget: 10 seconds, approximately 881,000 generated inputs, no failure.
- govulncheck: no known vulnerabilities found for the analyzed source/toolchain.
- Windows amd64 binary build; cross-compilation for Linux amd64 and macOS arm64. Cross-compiled binaries were not executed on those OSes.
- git diff whitespace check.

Not completed here:

- Race detector: no C compiler/cgo available. CI is configured to run it.
- Docker image build, Compose execution and container image vulnerability scan: Docker unavailable.
- Native Linux/macOS execution and GitHub-hosted CI: workflows are provided but not executed in this local session.
- Sustained load/fault qualification, public TLS deployment, firewall setup, independent security audit, signed release artifacts and SBOM.

One combined background-process smoke-test command was rejected by automatic approval review. The live egress behavior was subsequently verified through an in-process integration test without launching a persistent background service.

Production approval requires the target-platform checks in DEPLOYMENT.md and ROADMAP.md. No measured throughput, anonymity, DPI resistance or security-audit claim is made.

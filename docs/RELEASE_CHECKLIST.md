# Deployment acceptance record

Use the exact intended release commit/image digest. Keep private host evidence outside Git when it contains secrets or addresses.

- [ ] CI is green: native/race tests, controlled load/resource recovery, container runtime, scans and monitoring rule validation.
- [ ] Download and inspect the load, runtime and security artifact reports; record measured limits for this host.
- [ ] Run sustained load against an authorized controlled upstream on the actual host at expected peak traffic, then overload; set p95/error/heap budgets explicitly.
- [ ] Verify timeout, reset, saturation, crash recovery, graceful stop, secret rotation, TLS renewal and rollback on the host.
- [ ] Production certificate hostname/chain verified; development CA is absent from production.
- [ ] Restrict secret directories and files; keep generated secrets/keys/config out of Git and backups without encryption.
- [ ] Review/apply firewall plan for the correct Docker backend; verify internal/metadata denial and approved client ingress from a separate machine. Confirm IPv6 is disabled for the stack or add a separately tested IPv6 policy.
- [ ] Keep monitoring ports loopback-only; verify Prometheus scrape, alert firing and delivery to the real webhook; test resolution notifications.
- [ ] Renew with a Certbot deploy hook (or equivalent) and verify a renewal dry run, recreated containers and updated expiry metric.
- [ ] An independent reviewer completes security/reviews/TEMPLATE.md for this release and high/critical findings are resolved.
- [ ] Pin verified image/action digests, record SBOM/scan/checksums, and rehearse rollback.

Record operator, host/platform, date, commit, image digest, report links, thresholds, reviewer reference and remaining accepted risks. An unchecked item remains outstanding; CI success is not a host deployment or an independent audit.

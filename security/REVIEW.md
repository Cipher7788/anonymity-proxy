# Independent security review handoff

Status: **not independently reviewed**. Automated tests/scans and an author review are not an independent audit. No review approval is implied by adding this document.

Give a reviewer the exact commit, threat model, architecture, CI evidence artifacts, SBOM and image scan, Docker/Compose files, and the target host/network configuration. Run the isolated runtime tests before handoff. Ask the reviewer to reproduce credential isolation, DNS/IP policy, CONNECT lifecycle, stream cancellation, saturation and shutdown; inspect secret permissions, image provenance, CA trust, certificate renewal, firewall coverage (including Docker rules), monitoring and alert delivery, and request/response parsing boundaries.

Capture findings with severity, affected commit, reproduction, impact, proposed fix, verification and residual risk. Security-sensitive findings should use the private channel in SECURITY.md. Remediate critical/high findings, rerun CI and platform tests, and request reviewer revalidation before release. Public artifacts must contain no customer URLs, client identifiers, credentials or keys.

Record the result in a new file based on reviews/TEMPLATE.md; never mark it approved on behalf of the reviewer. A repository maintainer must verify the reviewer identity and independence outside this template.

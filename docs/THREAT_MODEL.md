# Threat model

Intended use: a trusted operator offers authenticated clients single-hop access to public HTTP/HTTPS destinations. Goals are to reject unauthenticated use, restrict internal-network access, protect proxy credentials from forwarding, and bound common resource exhaustion paths.

The operator sees client addresses, destinations, DNS, timing and plaintext HTTP. HTTPS inside CONNECT remains encrypted to the origin. Destinations see the proxy IP and application identifiers. The host resolver/network can observe DNS. A compromised proxy host, stolen credential, traffic correlation, browser fingerprinting and login identity are outside the guarantees. Remote clients must authenticate the proxy TLS certificate. Localhost clients still require authentication.

Controls: mandatory credential checks using constant-time digest comparison; TLS on non-loopback listeners; port allowlist; all-answer IP validation and direct checked-IP dialing; no environment proxy inheritance; generic errors; minimal logs; bounded sockets, operations, headers, pools and lifetimes; unprivileged container configuration.

Residual risks: the address denylist must track special-purpose allocations. Custom NAT64 prefixes, publicly addressed internal services, routing changes and compromised infrastructure require external egress enforcement. CONNECT may carry arbitrary protocols on allowed ports. Shared credentials provide no per-user quotas. Floods can deny service despite bounded resource consumption. Application headers or content can identify users.

Production gates: review current address registries, test DNS/IP leak behavior on the actual network, verify TLS renewal and secret rotation, exercise restart under load, inspect infrastructure logs, and obtain independent code/security review. There is no guarantee of anonymity, DPI resistance or malware detection.

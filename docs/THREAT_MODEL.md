<!-- SPDX-License-Identifier: MPL-2.0 -->

# Threat model

The toolkit treats the public network, forwarding headers, request targets,
cookies, credentials, and stored request records as untrusted. Application code,
the configured trusted-proxy set, server filesystem permissions, and explicitly
selected storage adapters are trusted.

Controls include explicit proxy trust, bounded parsing, cryptographic request
and session identifiers, digest-only session storage, Argon2id passwords,
constant-time comparisons, same-origin and CSRF primitives, fail-closed storage
errors, and separate safe/sensitive analytics projections.

The toolkit does not sandbox application handlers, secure an incorrectly
configured reverse proxy, authorize application routes automatically, encrypt a
compromised host, or decide how long an operator may lawfully retain personal
request evidence.

Local storage adapters assume the parent directory and host account are trusted.
They reject a symlink at the configured final path and apply private file modes,
but they do not defend against a concurrent privileged actor replacing path
ancestors during an open. The synchronous JSONL adapter deliberately favors
durable, bounded evidence over maximum request throughput; the application owns
rotation, retention, disk monitoring, and health escalation.

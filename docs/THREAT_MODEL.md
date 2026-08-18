<!-- SPDX-License-Identifier: MPL-2.0 -->

# Threat model

The toolkit treats the public network, forwarding headers, request targets,
cookies, credentials, and stored request records as untrusted. Application code,
the configured trusted-proxy set, server filesystem permissions, and explicitly
selected storage adapters are trusted.

Controls include explicit proxy trust, bounded parsing, cryptographic request
and session identifiers, digest-only session storage, Argon2id passwords,
constant-time comparisons, same-origin and CSRF primitives, fail-closed storage
errors, separate safe/sensitive analytics projections, organization-scoped
bindings, single-use invitation digests, and short-lived audited break-glass
grants.

An application may create an account with a cryptographically generated
temporary credential and `RequirePasswordChange`. Successful rotation compares
the current credential, replaces its Argon2id hash, clears the requirement, and
revokes every session in one repository transaction. The application must
restrict such a principal to password change and logout until rotation succeeds;
the library does not infer route policy. Temporary credentials must be written
to a private channel or mode-`0600` file and must never be printed into logs,
manifests, process arguments, or deployment state.

Administrative recovery is deliberately a separate capability. The storage
adapter atomically replaces the credential, restores the password-change
requirement, revokes all sessions, and appends a generic audit event. The core
library does not expose a recovery HTTP handler, deliver the credential, or
authorize the local operator. Applications must keep that command local,
generate the credential cryptographically, and write it only to a newly created
private file. A recovery must not reveal whether an account exists through a
public request surface.

Unsafe methods without an exact Origin or trustworthy same-origin Fetch
Metadata fail the origin check. Authentication middleware fails closed when its
service or `__Host-` cookie policy is invalid. Imported request records have
bounded byte and duration fields before analytics sums them.

The toolkit does not sandbox application handlers, secure an incorrectly
configured reverse proxy, authorize application routes automatically, encrypt a
compromised host, or decide how long an operator may lawfully retain personal
request evidence.

Applications must pass the authenticated user and requested resource hierarchy
to `access.Authorize`; possessing a platform-level `auth` role does not bypass
that decision. Team membership is resolved by the repository rather than
accepted from request input. Break-glass access lasts at most one hour and is
not a substitute for ordinary role policy.

Local storage adapters assume the parent directory and host account are trusted.
They reject a symlink at the configured final path and apply private file modes,
but they do not defend against a concurrent privileged actor replacing path
ancestors during an open. The synchronous JSONL adapter deliberately favors
durable, bounded evidence over maximum request throughput; the application owns
rotation, retention, disk monitoring, and health escalation.

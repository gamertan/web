<!-- SPDX-License-Identifier: MPL-2.0 -->

# Security policy

Report suspected vulnerabilities privately to `security@sandwichhime.com`.
Include the affected package/version, a minimal reproduction, impact, and any
suggested mitigation. Please do not place secrets, personal request logs, live
databases, or exploit details in a public issue.

The maintainer aims to acknowledge reports within three business days, provide
an initial triage within seven, and keep reporters updated at least every
fourteen days while work remains open. These are best-effort targets, not a
service-level agreement. There is no bug bounty.

The preview supports only versions explicitly listed in release notes. Security
claims stop at the documented trust boundaries and executable tests.

Password recovery is an explicitly local administrative capability. It must
not be wired directly to a public route. Applications using it are responsible
for local operator authorization and exclusive mode-`0600` credential delivery;
the library transaction requires a new password change, revokes all sessions,
and records a secret-free audit event.

<!-- SPDX-License-Identifier: MPL-2.0 -->

# Architecture

The package dependency direction is intentionally one-way:

```text
analytics ──> requestlog ──> requestmeta
abuse ─────────────────────> requestmeta
authhttp ──> websec ───────> requestmeta
authhttp ──> auth <───────── authsqlite
    │          ▲                 ▲
    └──> authwebauthn ───────────┘
organizations <───────────── authsqlite
access <──────────────────── authsqlite
```

An ordinary `net/http` application composes whichever branches it needs.

Packages never own application routes, templates, authorization policy, cache
policy, or deployment. Middleware communicates through typed request context.
Storage and reporting surfaces are interfaces so an application can retain its
existing database and user interface while replacing one implementation at a
time.

Authentication establishes one user identity and session. Organizations own
projects, environments, and services; teams group organization members; scoped
access resolves roles against that hierarchy. Existing `auth` roles remain a
platform-level compatibility surface and do not implicitly grant access to an
organization's data. Emergency access is a separate, expiring, audited grant.

`authwebauthn` owns relying-party policy and ceremony orchestration but not
application routes. It stores only opaque token digests, bounded verifier
session state, credential public records, and audit metadata through an
interface implemented by `authsqlite`. The existing `auth` service issues the
ordinary opaque session only after the passkey verifier succeeds.

The package model is developed from explicit threat and data contracts, not by
moving an existing application's internals into a shared directory. See
[ADOPTION.md](ADOPTION.md), [GETTING_STARTED.md](GETTING_STARTED.md), and the
[module-boundary policy](MODULES.md).

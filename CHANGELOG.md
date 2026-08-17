<!-- SPDX-License-Identifier: MPL-2.0 -->

# Changelog

## v0.1.0-preview.2 — 2026-08-17

- Add storage-neutral organizations, teams, projects, environments, services,
  single-use invitations, and independently scoped access roles.
- Separate platform-level authentication roles from organization data access.
- Add expiring break-glass grants with transactional organization-visible audit
  events and a no-CGO SQLite implementation.
- Keep `v0.1.0-preview.1` immutable; applications adopt these additive packages
  by explicitly selecting Preview 2.

## v0.1.0-preview.1 — 2026-08-16

- Establish independent request metadata, logging, browser security, abuse,
  authentication, SQLite, and analytics package boundaries.
- Add a minimal 0BSD `net/http` starter.
- Fail closed when unsafe requests lack same-origin evidence or authentication
  middleware is constructed with invalid cookie/service configuration.
- Bound untrusted request-record byte and duration fields before aggregation.
- Support Linux as the maintained release platform; native Windows is not a
  release gate or compatibility promise.

No compatibility promise is made before a stable release.

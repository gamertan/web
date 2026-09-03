<!-- SPDX-License-Identifier: MPL-2.0 -->

# Changelog

## v0.1.0-preview.10 — 2026-09-03

- Add atomic public-account registration with required canonical email,
  password authentication, printable recovery codes, a personal organization,
  direct owner access, and an optional initial passkey. Pending registrations
  cannot authenticate, and abandoned drafts expire without reserving identity
  fields indefinitely.
- Add password verification without session issuance plus operation-bound
  WebAuthn completion hooks, allowing applications to require fresh passkeys
  for sensitive actions without imposing passkeys on ordinary customer use.
- Add digest-only recovery-code persistence and short-lived, single-use
  recovery grants that consume a code and revoke existing sessions atomically.
- Add bounded raster/PDF media preparation and a hardened content-addressed
  local filesystem adapter with atomic writes, private modes, and symlink
  rejection.
- Add explicit SQLite open-without-migration and schema-requirement APIs while
  preserving the historical migrating `Open` behavior for existing adopters.
- Record application dogfood findings and the independent future commerce
  module boundary.

## v0.1.0-preview.9 — 2026-09-03

- Add a documented root package and executable composition example so the
  module landing page presents its purpose, package-selection guidance,
  security model, and `net/http` integration rather than only a directory
  index.
- Add the repository's default MPL-2.0 licence at the conventional root path
  so Go package tooling can identify the library licence while preserving the
  existing file-level exceptions for starters and operational machinery.
- Rework the public README around progressive adoption, explicit design
  promises, package selection, assurance gates, and canonical project links.

## v0.1.0-preview.8 — 2026-08-28

- Preserve `http.Hijacker` through the request-evidence middleware so audited,
  authenticated WebSocket and other HTTP upgrade handlers can operate without
  bypassing request logging. Successful upgrades are recorded as HTTP 101;
  upgraded-protocol bytes remain outside HTTP body-byte accounting.

- Add revisioned active/archived lifecycles for organizations and teams,
  invitation listing and revocation, membership suspension/removal, team-member
  removal, and transactional organization-visible audit events.
- Make archived organizations and teams ineffective during authorization and
  preserve the final active direct owner during membership changes.
- Allow invitations to carry one bounded direct role and reviewed team
  memberships, applied atomically with single-use acceptance.
- Add an atomic password-to-passkey migration ceremony that stores the first
  passkey, retires the password credential, revokes all sessions, and records
  the migration audit event in one transaction.

## v0.1.0-preview.6 — 2026-08-24

- Add an explicit mode-`0640` JSONL option for applications that authorize one
  narrowly scoped collector group, while keeping private mode `0600` as the
  default and rejecting permissive modes.
- Document the setgid-directory ownership boundary for Observatory-style
  collection without granting the collector broader application access.
- Make vendored dependency and public-snapshot verification portable across
  the maintained Linux gate and native macOS development environments.
- Keep Previews 1–5 immutable; applications select Preview 6 explicitly when
  adopting collector-readable request evidence.

## v0.1.0-preview.5 — 2026-08-21

- Add storage-neutral passkey registration, discoverable login, and
  operation-bound fresh assertions without adding self-registration, password
  fallback, TOTP, email recovery, or application-owned routes.
- Require exact HTTPS relying-party origins, user verification, discoverable
  credentials, no attestation conveyance, and an initial ES256-only algorithm
  policy.
- Add transactional SQLite credential, ceremony, enrollment, recovery, and
  last-credential protections with atomic single-use consumption.
- Add a neutral session-issuance boundary for independently verified
  credentials while retaining existing password behavior.
- Pin WebAuthn protocol verification to `github.com/go-webauthn/webauthn`
  `v0.17.1` and record its source identity, module checksums, licence, and
  transitive security boundary.
- Add self-service passkey enrollment and removal primitives with fresh
  assertion, session revocation, and last-credential protection.
- Keep Previews 1–4 immutable; applications select Preview 5 explicitly when
  adopting the passkey boundary.

## v0.1.0-preview.4 — 2026-08-18

- Add an explicit local-administrator password recovery operation without
  adding a public recovery endpoint or network protocol.
- Atomically install a one-time Argon2id credential, restore mandatory password
  rotation, revoke every session, and append a secret-free audit event.
- Prove transaction rollback when the audit event cannot commit and document
  private mode-`0600` delivery as application-owned policy.
- Keep Previews 1–3 immutable; applications select Preview 4 explicitly when
  adopting administrative recovery.

## v0.1.0-preview.3 — 2026-08-18

- Add cryptographically generated temporary credentials and an explicit
  password-change-required account state.
- Replace credentials, clear the requirement, and revoke all existing sessions
  in one repository transaction after verifying the current password.
- Migrate existing SQLite users with the new requirement disabled; applications
  continue to own first-login routing, private credential delivery, and audit
  policy.
- Keep Preview 1 and Preview 2 immutable; applications select Preview 3
  explicitly when adopting forced bootstrap rotation.

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

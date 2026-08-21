<!-- SPDX-License-Identifier: MPL-2.0 -->

# Changelog

## Unreleased

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

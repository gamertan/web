<!-- SPDX-License-Identifier: MPL-2.0 -->

# Web Foundations dogfood notes

This living note records concrete pressure discovered while Gamertan services
adopt Web Foundations. It is implementation evidence, not a promise that every
application concern belongs in the shared module.

## Gamertan accounts and commerce

- The account email remains required and unique. Gamertan uses normalized
  email as the canonical login identifier and keeps username as a stable public
  identity. Until a mail package exists, the application must not describe an
  address as verified merely because it was entered during registration.
- Password authentication is sufficient for an ordinary customer base
  session. Privileged application actions use an exact operation binding with
  `authwebauthn.BeginApproval` and `FinishApproval`; that is safer than a broad
  long-lived "elevated" session. A user without a passkey can use ordinary
  features but must enroll one before performing protected work.
- `auth.Service.VerifyPassword` remains available for flows that truly require
  password plus passkey before session issuance.
- Public registration exposed a cross-package transaction boundary. The
  `account` package now keeps an unusable bounded registration draft and makes
  recovery-code digests, personal organization, membership, owner binding,
  activation, audits, and an optional initial passkey one repository commit.
  A failed WebAuthn ceremony can be restarted, or an ordinary password account
  can finish without it, without persisting a partly privileged account.
- Media belongs behind a storage-neutral interface with a hardened local
  adapter. Content workflow, references, and authorization remain application
  policy.
- Historical `authsqlite.Open` still migrates for compatibility. Applications
  with reviewed deployment gates use `OpenWithOptions` with migration disabled,
  require the current schema at startup, and invoke `Migrate` only from an
  explicit operator command.
- Commerce remains a separately versioned nested module so payment-provider
  policy and catalog evolution do not enlarge the authentication core.
- Self-service enrollment exposed an authorization seam: completing a valid
  ceremony and checking its user only after persistence is too late.
  `FinishRegistrationForUser` now consumes mismatched ceremonies and checks
  the application-authenticated user before storing a credential.

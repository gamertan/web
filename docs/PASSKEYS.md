<!-- SPDX-License-Identifier: MPL-2.0 -->

# Passkey integration

`authwebauthn` is a passkey ceremony service, not a login page or account
policy. An application supplies its exact relying-party identity, routes,
authorization decisions, session cookie, HTML, and local recovery command.

## Fixed security policy

- Use an exact HTTPS origin whose hostname equals the relying-party ID.
- Reject cross-origin ceremonies.
- Require discoverable credentials and user verification.
- Request no attestation conveyance.
- Permit ES256 only until another algorithm has explicit interoperability and
  security evidence.
- Store random challenges and verifier session data only behind opaque,
  single-use ceremony tokens.
- Treat clone warnings as audit signals rather than automatic lockout for
  synchronized passkeys.

The service uses a random WebAuthn challenge for every ceremony. A sensitive
application operation is bound separately by storing the SHA-256 digest of its
canonical payload with that ceremony. Never substitute an operation hash,
timestamp, UUID, or counter for the random challenge.

## Application flow

1. A local command calls `authwebauthn.Bootstrap`, `authwebauthn.Recover`, or
   `bootstrap.Start` and writes the returned enrollment token once to a newly
   created mode-`0600` file. Use `bootstrap.Start` for the first application
   owner so identity, organization membership, direct owner access, and audits
   cannot be partially committed.
2. A server-rendered enrollment page calls `BeginEnrollment`; the browser uses
   `navigator.credentials.create` with the returned `public_key` value.
3. The browser posts the credential and opaque ceremony token to a bounded JSON
   endpoint; authenticated self-service flows use
   `FinishRegistrationForUser` so the application session's user ID is checked
   before any public credential is stored.
4. Login uses `BeginLogin`, `navigator.credentials.get`, and `FinishLogin`.
   The successful result contains an ordinary opaque `auth` session token.
5. Sensitive operations call `BeginApproval` with a canonical application
   payload and `FinishApproval` with those exact same bytes. Any drift fails.

For an existing password-backed account, call `BeginPasswordMigration` only
from an authenticated account session and finish with
`FinishPasswordMigration`. The registration ceremony is bound to that user.
Successful completion stores the passkey, removes the password credential,
clears the password-change flag, revokes every session and pending ceremony,
and appends the audit event atomically. The application must clear the current
session cookie and return the user to passkey login after success.

`authhttp.WritePasskeyBegin` and `authhttp.ReadPasskeyFinish` provide bounded
JSON framing only. They do not register routes, authorize requests, serve
JavaScript, or set sessions automatically.

## Recovery and credential lifecycle

Administrator-assisted `authwebauthn.Recover` is deliberately host-local and
must never be reachable through an HTTP handler. It revokes all user sessions
and pending ceremonies, replaces prior enrollment tokens, appends a
secret-free audit event, and returns one 15-minute token. It does not delete
existing passkeys. After enrolling a replacement, the operator reviews
credential labels and removes lost keys with a fresh passkey-bound removal
ceremony. The final passkey cannot be removed remotely.

An account may separately expose self-service password-plus-recovery-code
recovery through `authrecovery`. `Begin` verifies the password, consumes one
printable code, revokes sessions, and returns a short-lived grant—not a normal
session. Keep that grant in a narrowly scoped, Secure, HttpOnly, SameSite cookie
and never place it in a URL. `BeginPasskey` binds its digest into the WebAuthn
ceremony. `FinishPasskey` atomically consumes the grant, stores the verified
replacement passkey, replaces the entire recovery-code set, revokes any
sessions or ceremonies created during recovery, and returns the new plaintext
codes exactly once. It does not issue a session; return the user to normal
login after displaying and saving the new codes.

A failed storage commit leaves the restricted grant available for a fresh
ceremony until expiry. A binding mismatch consumes the mismatched ceremony.
Applications must use generic failure responses and the same credential-attempt
rate limiting as login.

Before enabling production mutations, applications should require at least two
independent passkeys and complete a local recovery drill.

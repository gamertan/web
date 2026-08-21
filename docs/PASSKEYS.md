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

1. A local command calls `Bootstrap` or `Recover` and writes the returned
   enrollment token once to a newly created mode-`0600` file.
2. A server-rendered enrollment page calls `BeginEnrollment`; the browser uses
   `navigator.credentials.create` with the returned `public_key` value.
3. The browser posts the credential and opaque ceremony token to a bounded JSON
   endpoint; `FinishRegistration` verifies and stores the public credential.
4. Login uses `BeginLogin`, `navigator.credentials.get`, and `FinishLogin`.
   The successful result contains an ordinary opaque `auth` session token.
5. Sensitive operations call `BeginApproval` with a canonical application
   payload and `FinishApproval` with those exact same bytes. Any drift fails.

`authhttp.WritePasskeyBegin` and `authhttp.ReadPasskeyFinish` provide bounded
JSON framing only. They do not register routes, authorize requests, serve
JavaScript, or set sessions automatically.

## Recovery and credential lifecycle

Recovery is deliberately host-local and should never be reachable through an
HTTP handler. It revokes all user sessions and pending ceremonies, replaces
prior enrollment tokens, appends a secret-free audit event, and returns one
15-minute token. It does not delete existing passkeys. After enrolling a
replacement, the operator reviews credential labels and removes lost keys with
a fresh passkey-bound removal ceremony. The final passkey cannot be removed
remotely.

Before enabling production mutations, applications should require at least two
independent passkeys and complete a local recovery drill.

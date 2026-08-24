<!-- SPDX-License-Identifier: MPL-2.0 -->

# Getting started

Gamertan Web Foundations is adopted one boundary at a time. Start with the
smallest package that solves a problem the application actually has; do not
install an imagined framework lifecycle around it.

## Choose a first slice

| Application need | Begin with | What remains application-owned |
| --- | --- | --- |
| Request IDs and trustworthy client addresses | `requestmeta` | Proxy configuration and operational logs |
| Bounded structured request evidence | `requestmeta`, `requestlog` | Route names, sensitive-field policy, rotation, retention, and access |
| Browser and HTTP safety primitives | `requestmeta`, `websec` | Exact CSP, route authorization, and response policy |
| Persistent request-abuse decisions | `requestmeta`, `abuse` | Route classification, storage, appeals, and operator policy |
| Users, credentials, permissions, and sessions | `auth` | Roles, permissions, login UX, and account policy |
| Secure browser cookies around `auth` | `authhttp` | Login routes, redirects, pages, and authorization decisions |
| SQLite persistence for `auth` | `authsqlite` | Database placement, backup, migration approval, and recovery |
| One account across organizations and teams | `organizations`, `authsqlite` | Invitation UX, organization naming, and lifecycle policy |
| Organization-scoped authorization | `access`, `authsqlite` | Role definitions, resource ownership, and route enforcement |
| Aggregate projections over request records | `analytics` | Collection policy, access control, report UI, and retention |

The packages are ordinary Go imports. Pin the current preview and verify its
module checksum:

```bash
go get gamertan.com/web/requestmeta@v0.1.0-preview.6
go mod verify
```

## Preserve middleware order

Packages that consume request metadata must run inside the resolver. Build the
handler from the application outward; the final resolver assignment becomes
the first middleware to receive a request:

```go
var handler http.Handler = router
handler = requestlog.Middleware(sink, logPolicy)(handler)
handler = websec.Headers(headerPolicy)(handler)
handler = resolver.Middleware(handler)
```

The complete, copyable composition is in [`starters/basic`](../starters/basic).
It binds to loopback, shuts down gracefully, and keeps request logging optional.

`requestlog.OpenJSONL` creates a private mode-`0600` file. If a separate,
unprivileged collector such as Observatory is the only approved reader, prepare
a trusted setgid directory whose group is that collector, then opt into
`requestlog.OpenJSONLWithOptions(path, requestlog.JSONLOptions{FileMode: 0o640})`.
The application still owns rotation, retention, disk monitoring, and sink-error
health. Never use a world-readable log or add the collector to the application
account's broader groups merely to make collection convenient.

Configure trusted proxy networks narrowly. A forwarding header is not evidence
by itself; it becomes usable only when the immediate peer and skipped proxy
hops satisfy the resolver's trust policy. Metadata, authentication, or storage
failures that affect security decisions should stop the request rather than
quietly changing identity or policy.

## Bootstrap an account without inventing a permanent password

`auth.GenerateTemporaryPassword` returns 256 bits of URL-safe cryptographic
entropy. An application can store that value in a newly created private file
and provision an account with `RequirePasswordChange: true`. The library does
not write or print the credential because file ownership, operator identity,
and delivery are application policy.

After authentication, inspect `principal.User.PasswordChangeRequired`. Until it
is false, permit only password change and logout. `auth.ChangePassword` verifies
the current credential, rejects reuse, writes the new Argon2id hash, clears the
requirement, and revokes every existing session atomically through the storage
adapter. Clear the browser cookie and require a fresh login after success. Do
not treat a redirect alone as enforcement; apply the restriction before every
protected handler.

For operator-led recovery, expose `auth.ResetPassword` only through a local
administrative command—not a public HTTP endpoint. The operation installs an
application-generated one-time credential, sets `PasswordChangeRequired`,
revokes every existing session, and appends a secret-free audit event in the
same repository transaction. Deliver that credential through an exclusive
root-owned mode-`0600` file, delete it after successful rotation, and never put
it in command arguments, stdout, logs, manifests, or deployment state.

## Add HTML without merging responsibilities

Handlers should convert request and service state into typed display data.
They may then render those values with any HTML system. Gamertan's preferred
companion is [Sandwich Hime](SANDWICH_HIME.md), whose generated components keep
templates typed while leaving this middleware stack and the `net/http`
application in control.

## Verify the application boundary

After adopting a package:

```bash
go mod verify
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

Test the composed handler with `httptest`, not only the package in isolation.
Include a normal request, malformed or spoofed metadata, a downstream failure,
and the application's intended response headers. Existing applications should
follow the differential and rollback sequence in [ADOPTION.md](ADOPTION.md).

Deeper tutorials for accounts, analytics, and persistent abuse policy will be
written after multiple application migrations have validated those seams. The
preview documentation describes demonstrated contracts rather than prescribing
an unfinished application framework.

See [Organizations and scoped access](ORGANIZATIONS.md) before storing tenant
data. In particular, do not interpret a platform role as permission to inspect
an organization's records.

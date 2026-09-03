<!-- SPDX-License-Identifier: MPL-2.0 -->

# Gamertan Web Foundations

[![Go Reference](https://pkg.go.dev/badge/gamertan.com/web.svg)](https://pkg.go.dev/gamertan.com/web)
[![Verify](https://gitea.speelman.ca/gamertan/web/actions/workflows/verify.yml/badge.svg?branch=main)](https://gitea.speelman.ca/gamertan/web/actions?workflow=verify.yml)

**Security-conscious building blocks for ordinary `net/http` applications.**

Web Foundations provides small, composable Go packages for the unglamorous
boundaries of a careful web application: request identity, structured request
evidence, browser security, authentication, passkeys, permissions,
organizations, SQLite persistence, abuse controls, and private analytics.

It is a toolkit, not an application framework. Your application keeps its
router, handlers, HTML, authorization decisions, cache behavior, and
deployment. Adopt one boundary at a time; Go compiles and links only the
packages you import.

> **Public preview:** `v0.1.0-preview.13`. APIs may change before a stable
> release. Linux is the maintained release platform.

## Why Web Foundations?

| Design promise | What it means in an application |
| --- | --- |
| `net/http` native | Keep the standard router or any compatible router; there is no framework lifecycle. |
| Explicit security boundaries | Trusted proxies, sensitive log fields, browser origins, and scoped authority are configured deliberately. |
| Bounded and fail-closed | Untrusted inputs are size-limited, and security-critical configuration or storage failures do not quietly weaken policy. |
| Storage-neutral core | Interfaces separate identity and access policy from the optional no-CGO SQLite adapter. |
| Self-hosted by default | No Redis, message broker, hosted identity provider, telemetry service, or JavaScript framework is required. |

## Start with one boundary

| Application need | Begin with |
| --- | --- |
| Request IDs and trustworthy client addresses | [`requestmeta`](requestmeta) |
| Bounded structured request evidence | [`requestmeta`](requestmeta) + [`requestlog`](requestlog) |
| Browser and HTTP security primitives | [`websec`](websec) |
| Users, credentials, permissions, and sessions | [`auth`](auth) + [`authhttp`](authhttp) |
| Atomic password-plus-passkey registration | [`account`](account) |
| Passkey login and sensitive-operation step-up | [`authwebauthn`](authwebauthn) |
| Atomic first-owner and organization setup | [`bootstrap`](bootstrap) |
| Printable single-use recovery codes | [`authrecovery`](authrecovery) |
| Private SQLite persistence | [`authsqlite`](authsqlite) |
| Bounded media and private local blobs | [`media`](media) + [`medialocal`](medialocal) |
| Organizations, teams, and invitations | [`organizations`](organizations) |
| Organization-scoped roles and temporary access | [`access`](access) |
| Application-classified request abuse | [`abuse`](abuse) |
| Disposable request-log summaries | [`analytics`](analytics) |

The [getting-started guide](docs/GETTING_STARTED.md) explains what each package
owns—and, just as importantly, what remains application policy.

## Install

Pin the preview in an application module:

```bash
go get gamertan.com/web@v0.1.0-preview.13
go mod verify
```

An application may name the first package it intends to adopt:

```bash
go get gamertan.com/web/requestmeta@v0.1.0-preview.13
```

The version belongs to the `gamertan.com/web` module. See the
[module-boundary policy](docs/MODULES.md) before selecting a first slice.

## Compose a request path

Build middleware from the application outward. The request metadata resolver
is outermost so every package inside it observes the same request identity:

```text
request
  └─ requestmeta ─ websec ─ requestlog ─ your router and handlers
```

```go
var handler http.Handler = router
handler = requestlog.Middleware(sink, logPolicy)(handler)
handler = websec.Headers(headerPolicy)(handler)
handler = resolver.Middleware(handler)
```

The copyable [`starters/basic`](starters/basic) server demonstrates that
composition with loopback binding, graceful shutdown, and optional private
JSONL logging.

## Identity and access

- [`auth`](auth) defines storage-neutral users, password credentials, opaque
  sessions, platform permissions, and audit events.
- [`account`](account) composes the first password, printable recovery codes,
  personal organization, and owner access as one registration transaction,
  optionally including an initial passkey.
- [`authhttp`](authhttp) connects those sessions to secure browser cookies and
  request context without owning login routes or pages.
- [`authwebauthn`](authwebauthn) provides discoverable passkey login,
  enrollment, operation-bound fresh approval, and bounded recovery.
- [`organizations`](organizations) and [`access`](access) keep platform
  operation separate from organization-data authority while supporting teams,
  invitations, scoped roles, and audited temporary access.

See the [passkey integration guide](docs/PASSKEYS.md) and
[organization/access model](docs/ORGANIZATIONS.md) before exposing account or
administration routes.

## Security and assurance

Client addresses are accepted from forwarding headers only when the immediate
peer and every skipped proxy are explicitly trusted. Sensitive request fields
are off by default. Cryptographic entropy failures fail closed. Logs and
account databases remain private application data and never belong in source
releases.

Every change is checked with formatting, tests, the race detector, vet,
dependency policy, licence policy, public-snapshot allowlisting, and a
reproducible starter build. Scheduled assurance adds vulnerability scanning and
bounded fuzz campaigns.

Read [SECURITY.md](SECURITY.md), the [threat model](docs/THREAT_MODEL.md),
[adoption contract](docs/ADOPTION.md), and
[dependency boundary](docs/DEPENDENCIES.md) before production adoption.

## HTML and templates

Web Foundations deliberately does not provide a template language. Sandwich
Hime is the preferred companion for Gamertan applications that want HTML-first,
typed, ahead-of-time Go templates. The projects remain independently usable.

See [HTML with Sandwich Hime](docs/SANDWICH_HIME.md) and the official
[first-site tutorial](https://sandwichhime.com/docs/tutorial/).

## Source, support, and licensing

Canonical source, issues, security policy, and release notes live on
[Speelman Forge](https://gitea.speelman.ca/gamertan/web). GitHub is a read-only
discovery snapshot rather than a second release origin.

The libraries and adapters are MPL-2.0. Starters and reusable examples are
0BSD. Future standalone services and operational machinery are
AGPL-3.0-only. Exact file-level SPDX identifiers remain authoritative; see the
[licensing map](LICENSES.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

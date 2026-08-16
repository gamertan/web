<!-- SPDX-License-Identifier: MPL-2.0 -->

# Gamertan Web Foundations

> Status: `v0.1.0-preview.1` public preview. APIs may change before a stable
> release; Linux is the maintained release platform.

Small, composable Go packages for the unglamorous boundaries of a careful web
application: request identity, structured request logs, browser security,
passwords and sessions, permissions, SQLite persistence, and private analytics.

This is a toolkit, not an application framework. Your application keeps its
router, HTTP policy, HTML, authorization decisions, cache behavior, and
deployment. Each package works with `net/http` and can be adopted independently.

The first preview targets modest Linux servers, local files, SQLite, and normal
Go binaries. It requires no Redis, message broker, hosted identity provider,
telemetry service, or JavaScript framework.

## Install

Pin the preview in an application module, then import only the packages that
application needs:

```bash
go get gamertan.com/web@v0.1.0-preview.1
go mod verify
```

Canonical source, issues, security policy, and release notes live on
[Gamertan Gitea](https://gitea.speelman.ca/gamertan/web). GitHub is a read-only
discovery snapshot rather than a second release origin.

Linux is the required and supported release platform. WSL may be used as a
Linux development environment. Native Windows is not a release gate or support
promise; downstream users may evaluate the ordinary Go packages elsewhere
without turning that portability into a maintained compatibility claim.

## Packages

- `requestmeta`: trusted-proxy resolution, HTTPS/origin metadata, and request IDs.
- `requestlog`: bounded versioned records, middleware, sinks, and private JSONL.
- `websec`: headers, origin checks, CSRF, redirects, body limits, and rate limits.
- `abuse`: application-classified request abuse with pluggable persistence.
- `auth`, `authhttp`, `authsqlite`: passwords, sessions, permissions, cookies,
  and a no-CGO SQLite adapter.
- `analytics`: safe and sensitive aggregate projections over request records.

The copyable starter under `starters/basic` demonstrates the packages without
turning them into a router or template system.

## Security boundary

Client addresses are accepted from forwarding headers only when the immediate
peer and every skipped proxy are explicitly trusted. Sensitive request fields
are off by default. Cryptographic entropy failures fail closed. Logs and account
databases remain private application data and never belong in source releases.

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
the [application adoption contract](docs/ADOPTION.md), and
[docs/SERVICES_ROADMAP.md](docs/SERVICES_ROADMAP.md).

## Licensing

This is a multi-license repository with exact file-level SPDX identifiers:

- embeddable packages and adapters: MPL-2.0;
- future standalone network services and operational machinery: AGPL-3.0-only;
- starters, examples, and reusable configuration: 0BSD.

See [LICENSES.md](LICENSES.md). No standalone auth or logging server is included
in this preview.

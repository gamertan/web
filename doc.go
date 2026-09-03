// SPDX-License-Identifier: MPL-2.0

// Package web is the documentation root for Gamertan Web Foundations.
//
// Web Foundations is a collection of small, composable Go packages for the
// security-sensitive edges of a web application: request identity, structured
// request evidence, browser security, authentication, passkeys, permissions,
// organizations, SQLite persistence, abuse controls, and private analytics.
//
// It is a toolkit rather than an application framework. Applications keep
// their router, handlers, HTML, authorization decisions, deployment, and
// operational policy. Packages use net/http and can be adopted independently.
// No Redis, message broker, hosted identity provider, telemetry service, or
// JavaScript framework is required.
//
// # Choose a first boundary
//
// Start with the smallest package that owns the boundary you need:
//
//   - [requestmeta] resolves request IDs, client addresses, and trusted-proxy
//     metadata once for downstream security and logging.
//   - [requestlog] records bounded, versioned request observations with
//     sensitive fields disabled by default.
//   - [websec] supplies HTTP headers, same-origin checks, CSRF protection,
//     redirects, body limits, and rate limits.
//   - [auth], [authhttp], [authwebauthn], and [authsqlite] provide
//     storage-neutral identity, secure browser sessions, passkeys, and an
//     optional no-CGO SQLite adapter.
//   - [organizations] and [access] model organizations, teams, invitations,
//     scoped roles, and audited temporary access.
//   - [abuse] applies application-classified request-abuse decisions.
//   - [analytics] creates bounded, disposable projections from requestlog
//     records without becoming a telemetry service.
//
// # Compose with net/http
//
// Middleware is wrapped from the application outward. A request metadata
// resolver should be outermost so packages inside it agree about request
// identity. The package example shows a complete, executable composition.
// A copyable server with graceful shutdown and optional private JSONL logging
// is available in the repository's starters/basic directory.
//
// # Security model
//
// Untrusted values are bounded before storage or aggregation. Forwarding
// headers affect identity only through explicitly trusted proxies. Sensitive
// request fields require field-by-field opt-in. Security-relevant
// configuration and persistence failures fail closed rather than silently
// weakening policy.
//
// This root package intentionally exports no runtime API. Applications import
// only the subpackages they use.
//
// [abuse]: https://pkg.go.dev/gamertan.com/web/abuse
// [access]: https://pkg.go.dev/gamertan.com/web/access
// [analytics]: https://pkg.go.dev/gamertan.com/web/analytics
// [auth]: https://pkg.go.dev/gamertan.com/web/auth
// [authhttp]: https://pkg.go.dev/gamertan.com/web/authhttp
// [authsqlite]: https://pkg.go.dev/gamertan.com/web/authsqlite
// [authwebauthn]: https://pkg.go.dev/gamertan.com/web/authwebauthn
// [organizations]: https://pkg.go.dev/gamertan.com/web/organizations
// [requestlog]: https://pkg.go.dev/gamertan.com/web/requestlog
// [requestmeta]: https://pkg.go.dev/gamertan.com/web/requestmeta
// [websec]: https://pkg.go.dev/gamertan.com/web/websec
package web

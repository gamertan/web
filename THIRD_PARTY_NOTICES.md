<!-- SPDX-License-Identifier: MPL-2.0 -->

# Third-party notices

## go-webauthn

- Module: `github.com/go-webauthn/webauthn`
- Version: `v0.17.1`
- Source commit: `de0a809e3027957ca15b72b252540317f9ba581b`
- Module sum: `h1:N8/ycHNeibifKhG+0ZFuQZsDvYiNRE5UpukUc8hb+k4=`
- Go module sum: `h1:mQC6L0lZ5Kiu35G70zeB2WnrW4+vbHjR8Koq4HdVaMg=`
- Downloaded module ZIP SHA-256:
  `6f1e06307fdc998087675db3a6cb5f133fdf7b91ac0a4ced689c336a5f28a91e`
- Licence: BSD-3-Clause; the upstream licence text is preserved in
  `LICENSES/BSD-3-Clause-go-webauthn.txt`, the unchanged audit source, and the
  compiled internal derivative.

The complete upstream module is retained unchanged at
`third_party/go-webauthn`. `third_party/go-webauthn.SHA256SUMS` records every
source file. The required non-test packages are compiled from
`internal/webauthnvendored`; a deterministic gate derives that tree from the
audited source, rewrites only the self-import prefix, and requires an exact
match. The public module contains no local replacement because downstream Go
modules do not honor dependency replacement directives.

The module performs WebAuthn protocol parsing, CBOR/COSE handling, attestation
and assertion verification, and signature-counter updates. Web Foundations
retains relying-party policy, storage, sessions, recovery, operation binding,
and application authorization.

Transitive modules and their exact checksums are recorded in `go.mod` and
`go.sum`. Release assurance runs `go mod verify`, licence-boundary checks,
`govulncheck`, race tests, and bounded malformed-response fuzzing.

The 2026-08-19 Go 1.26.6 `govulncheck` review found no reachable
vulnerabilities. It reported `GO-2026-5932` against the unmaintained
`golang.org/x/crypto/openpgp` package at the module level; Web Foundations uses
`argon2` and does not import or call `openpgp`.

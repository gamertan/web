<!-- SPDX-License-Identifier: MPL-2.0 -->

# Dependency boundary

Most packages use only the Go standard library. The principal implementation
dependencies are pinned:

- `golang.org/x/crypto` supplies the reviewed Argon2id implementation used by
  `auth` (BSD-3-Clause upstream licence).
- `modernc.org/sqlite` supplies the no-CGO SQLite adapter in `authsqlite`
  (BSD-3-Clause upstream licence).
- `github.com/go-webauthn/webauthn` `v0.17.1` supplies the audited source for
  WebAuthn Level 3 parsing and cryptographic verification in `authwebauthn`
  (BSD-3-Clause upstream licence; source commit
  `de0a809e3027957ca15b72b252540317f9ba581b`). Its imported transitive modules
  are pinned directly in `go.mod` because the verifier is compiled internally.

The exact, unchanged `go-webauthn` module source is retained at
`third_party/go-webauthn`. The non-test Go files from the packages used by
`authwebauthn` are copied into `internal/webauthnvendored`; only their
self-import prefix is mechanically rewritten. A derivation gate recreates that
internal tree from the audited source and requires a byte-for-byte match before
tests or builds. The complete upstream file manifest, upstream module checksum,
source commit, licence, and downloaded module ZIP SHA-256 are checked in.
The derivative is exercised by ordinary and race-enabled tests, but is excluded
from repository formatting so that gate cannot rewrite the audited upstream
source. The repository still runs `go vet` over the complete graph and permits
only the exact upstream warning for its unexported COSE structure sentinel;
every other vet diagnostic fails verification.

This arrangement is deliberate. A `replace` directive in a library module is
ignored by downstream consumers, so it cannot guarantee which verifier source
an application compiles. The public module has no local replacement and no
direct `github.com/go-webauthn/webauthn` module requirement; applications
compile the checked internal derivative instead. Its transitive modules remain
pinned by `go.mod`, `go.sum`, and SumDB. Release builders populate an isolated
verified module cache before offline compilation.

A conventional repository-wide `go mod vendor` would also copy the SQLite and
full transitive graph, currently roughly 143 MiB and more than 2,300 files.
That unrelated expansion is deliberately avoided: only the security-sensitive
WebAuthn verifier named by the policy is source-vendored here.

Applications that do not import `auth` or `authsqlite` do not link those
implementations into their binaries. Optional GeoIP enrichment is an interface
only; the base toolkit performs no lookup and adds no GeoIP dependency.

All packages currently share one Go module, so these requirements remain
visible in the module graph even when an application imports only
`requestmeta`. Go still avoids compiling or linking unused packages. A future
nested module may isolate a heavyweight adapter such as `authsqlite` when its
independent dependency and release lifecycle justify the additional tags,
vanity metadata, and CI. See [MODULES.md](MODULES.md).

`go.sum`, `go mod verify`, checksum-database verification, vulnerability
scanning, and the public snapshot allowlist are release gates. Binary
distributors remain responsible for preserving all applicable upstream notices.

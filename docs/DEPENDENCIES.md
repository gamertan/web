<!-- SPDX-License-Identifier: MPL-2.0 -->

# Dependency boundary

Most packages use only the Go standard library. Two direct modules are pinned:

- `golang.org/x/crypto` supplies the reviewed Argon2id implementation used by
  `auth` (BSD-3-Clause upstream licence).
- `modernc.org/sqlite` supplies the no-CGO SQLite adapter in `authsqlite`
  (BSD-3-Clause upstream licence).

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

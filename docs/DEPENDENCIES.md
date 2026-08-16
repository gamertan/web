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

`go.sum`, `go mod verify`, checksum-database verification, vulnerability
scanning, and the public snapshot allowlist are release gates. Binary
distributors remain responsible for preserving all applicable upstream notices.

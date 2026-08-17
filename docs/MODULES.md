<!-- SPDX-License-Identifier: MPL-2.0 -->

# Packages, modules, and repositories

These boundaries solve different problems:

- a **package** owns one Go responsibility and import path;
- a **module** owns dependency selection and semantic versions; and
- a **repository** owns contribution, security, and release operations.

The first preview uses one repository and one module, `gamertan.com/web`, with
several independently importable packages. An application may write:

```go
import "gamertan.com/web/requestmeta"
```

and request the containing module at an exact version:

```bash
go get gamertan.com/web/requestmeta@v0.1.0-preview.1
```

Only imported packages are compiled and linked. The packages nevertheless
share the module's version and dependency graph.

## Why not one repository per package?

Separate repositories would multiply release credentials, security updates,
vanity-import records, tags, CI, issue tracking, and coordinated API changes.
A focused pull request can already change and test one package directory. A
repository boundary is reserved for software with an independently operated
lifecycle, such as a future standalone `authd` service.

## When a nested module is justified

A package may become a nested module inside this repository when all of these
are true:

1. it introduces materially heavier or different dependencies;
2. consumers can usefully version it independently;
3. its API boundary has survived real application adoption; and
4. separate tags, release ordering, vanity metadata, and CI are less costly
   than keeping it in the root module.

`authsqlite` is the clearest current candidate because it carries the optional
SQLite implementation and its transitive module graph. A future split could
retain the import path `gamertan.com/web/authsqlite` while giving that directory
its own `go.mod` and tags such as `authsqlite/v0.1.0-preview.1`.

Do not split merely to make an architecture diagram look modular. Package
interfaces provide source-level modularity today; modules are introduced only
for an independent dependency and release lifecycle.

## Session boundaries

Authenticated sessions currently belong to three deliberate packages:

- `auth` owns opaque token creation, digest-backed session lookup, revocation,
  and the storage interface;
- `authhttp` binds those sessions to secure browser cookies and request
  context; and
- `authsqlite` persists the storage contract.

A separate `session` package would be appropriate only for a genuinely
identity-neutral need, such as anonymous application sessions with no user,
role, or credential semantics. It should not duplicate `auth` under a more
general name.

This policy may evolve before a stable release. Any split must include a
migration guide and preserve already published versions at their original
module coordinates.

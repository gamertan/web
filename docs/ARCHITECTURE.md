<!-- SPDX-License-Identifier: MPL-2.0 -->

# Architecture

The dependency direction is intentionally one-way:

```text
net/http application
  -> requestmeta
  -> requestlog / websec / abuse / authhttp
  -> auth and analytics interfaces
  -> optional authsqlite and JSONL adapters
```

Packages never own application routes, templates, authorization policy, cache
policy, or deployment. Middleware communicates through typed request context.
Storage and reporting surfaces are interfaces so an application can retain its
existing database and user interface while replacing one implementation at a
time.

The package model is developed from explicit threat and data contracts, not by
moving an existing application's internals into a shared directory. See
[ADOPTION.md](ADOPTION.md).

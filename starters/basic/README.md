<!-- SPDX-License-Identifier: 0BSD -->

# Basic starter

This deliberately small server shows package composition without inventing a
router or framework lifecycle. It binds to loopback, applies request metadata
before dependent middleware, emits security headers, optionally appends a
private safe-field JSONL log, and shuts down gracefully.

Copy it, change it, or do not—we are glad you are here with us.

```bash
go run ./starters/basic -listen 127.0.0.1:8080
```

Production configuration and secrets belong outside the source tree. This
starter does not load `.env` files automatically.

Continue with the [getting-started guide](../../docs/GETTING_STARTED.md) for
package selection and middleware order. To replace the plain-text response
with typed HTML without changing ownership of the server, follow
[HTML with Sandwich Hime](../../docs/SANDWICH_HIME.md).

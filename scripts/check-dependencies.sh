#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if grep -Fq 'github.com/go-webauthn/webauthn' go.mod go.sum; then
	echo 'go-webauthn must be compiled from the checked internal derivative, not resolved as a module' >&2
	exit 1
fi
if grep -Eq '^replace[[:space:]]|^replace[[:space:]]*\(' go.mod; then
	echo 'local replacements are forbidden in the public module' >&2
	exit 1
fi
compiled_dependencies=$(go list -deps ./...)
if grep -Fxq 'github.com/go-webauthn/webauthn' <<<"$compiled_dependencies"; then
	echo 'upstream go-webauthn unexpectedly appears in the compiled dependency graph' >&2
	exit 1
fi
grep -Fq 'de0a809e3027957ca15b72b252540317f9ba581b' THIRD_PARTY_NOTICES.md
./scripts/check-vendored-webauthn.sh
./scripts/check-embedded-webauthn.sh
go mod verify

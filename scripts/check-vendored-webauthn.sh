#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

test -f third_party/go-webauthn/LICENSE
cmp -s LICENSES/BSD-3-Clause-go-webauthn.txt third_party/go-webauthn/LICENSE
sha256sum -c third_party/go-webauthn.SHA256SUMS >/dev/null
expected=$(sed -n 's#  third_party/go-webauthn/.*#&#p' third_party/go-webauthn.SHA256SUMS | wc -l)
actual=$(find third_party/go-webauthn -type f | wc -l)
test "$expected" -eq "$actual"

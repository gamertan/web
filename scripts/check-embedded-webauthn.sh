#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

source_root=third_party/go-webauthn
embedded_root=internal/webauthnvendored
derived=$(mktemp -d)
trap 'rm -rf "$derived"' EXIT

packages=(
	metadata
	protocol
	protocol/webauthncbor
	protocol/webauthncose
	webauthn
)

install -D -m 0644 "$source_root/LICENSE" "$derived/LICENSE"
for package in "${packages[@]}"; do
	while IFS= read -r source; do
		relative=${source#"$source_root"/}
		install -D -m 0644 "$source" "$derived/$relative"
	done < <(find "$source_root/$package" -maxdepth 1 -type f -name '*.go' ! -name '*_test.go' | sort)
done

while IFS= read -r source; do
	sed -i \
		's#github.com/go-webauthn/webauthn#gamertan.com/web/internal/webauthnvendored#g' \
		"$source"
done < <(find "$derived" -type f -name '*.go' | sort)

cmp -s LICENSES/BSD-3-Clause-go-webauthn.txt "$embedded_root/LICENSE"
if ! diff -ru --no-dereference "$derived" "$embedded_root"; then
	echo 'compiled WebAuthn verifier differs from its audited mechanical derivation' >&2
	exit 1
fi

test "$(find "$embedded_root" -type f | wc -l)" -eq 57

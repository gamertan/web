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

install_file() {
	source=$1
	destination=$2
	mkdir -p "$(dirname "$destination")"
	install -m 0644 "$source" "$destination"
}

install_file "$source_root/LICENSE" "$derived/LICENSE"
for package in "${packages[@]}"; do
	for source in "$source_root/$package"/*.go; do
		case $source in
			*_test.go) continue ;;
		esac
		relative=${source#"$source_root"/}
		install_file "$source" "$derived/$relative"
	done
done

while IFS= read -r source; do
	temporary="$source.tmp"
	sed \
		's#github.com/go-webauthn/webauthn#gamertan.com/web/internal/webauthnvendored#g' \
		"$source" >"$temporary"
	mv "$temporary" "$source"
done < <(find "$derived" -type f -name '*.go' | sort)

cmp -s LICENSES/BSD-3-Clause-go-webauthn.txt "$embedded_root/LICENSE"
if ! diff -ru "$derived" "$embedded_root"; then
	echo 'compiled WebAuthn verifier differs from its audited mechanical derivation' >&2
	exit 1
fi

test "$(find "$embedded_root" -type f | wc -l)" -eq 57

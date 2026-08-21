#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
./scripts/check-licenses.sh
./scripts/check-dependencies.sh
test -z "$(find . \( -path ./third_party -o -path ./internal/webauthnvendored \) -prune -o -name '*.go' -print0 | xargs -0 gofmt -l)"
go test ./...
go test -race ./...
set +e
vet_output=$(go vet ./... 2>&1)
vet_status=$?
set -e
if test "$vet_status" -ne 0; then
	known='internal/webauthnvendored/protocol/webauthncose/webauthncose.go:33:2: struct field _struct has json tag but is not exported'
	test "$(grep -Fxc "$known" <<<"$vet_output")" -eq 1
	test -z "$(grep -Fvx "$known" <<<"$vet_output")"
elif test -n "$vet_output"; then
	printf '%s\n' "$vet_output" >&2
	exit 1
fi
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
go build -buildvcs=false -trimpath -o "$build_dir/basic" ./starters/basic
git diff --check

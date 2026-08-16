#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
./scripts/check-licenses.sh
test -z "$(gofmt -l .)"
go test ./...
go test -race ./...
go vet ./...
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
go build -trimpath -o "$build_dir/basic" ./starters/basic
git diff --check

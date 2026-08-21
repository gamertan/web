#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
failed=0
while IFS= read -r -d '' file; do
	case $file in
		./.git|./.git/*|./LICENSES/*|./go.sum) continue ;;
		./third_party/go-webauthn/*|./third_party/go-webauthn.SHA256SUMS|./internal/webauthnvendored/*) continue ;;
		./starters/*|./examples/*) expected=0BSD ;;
		./scripts/*|./.gitea/*|./services/*) expected=AGPL-3.0-only ;;
		*) expected=MPL-2.0 ;;
	esac
	if ! head -n 5 "$file" | grep -Fq "SPDX-License-Identifier: $expected"; then
		echo "license mismatch: $file expected $expected" >&2; failed=1
	fi
done < <(find . -type f -print0)
./scripts/check-vendored-webauthn.sh || failed=1
./scripts/check-embedded-webauthn.sh || failed=1
exit "$failed"

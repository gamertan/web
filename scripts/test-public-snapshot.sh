#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
./scripts/export-public.sh "$temporary/export"
(cd "$temporary/export" && find . -type f -printf '%P\n' | sort) >"$temporary/actual"
while IFS= read -r path; do
	if [[ $path = */ ]]; then
		find "${path%/}" -type f -printf '%p\n'
	else
		echo "$path"
	fi
done < <(grep -Ev '^[[:space:]]*(#|$)' scripts/public-snapshot.allow) | sort >"$temporary/expected"
diff -u "$temporary/expected" "$temporary/actual"
private_word='PRI''VATE'
token_word='to''ken'
private_pattern="BEGIN (RSA|OPENSSH|EC) ${private_word} KEY|Authorization: ${token_word}|/home/"'cole'"|/mnt/c/"'Users'"|"'eqlwiki'"-deploy|"'crspeelman'"@gmail\\.com"
if rg -n --hidden --glob '!.git/**' "$private_pattern" "$temporary/export"; then
	echo "private marker escaped into public snapshot" >&2; exit 1
fi
test -z "$(git status --porcelain=v1 --untracked-files=all)"

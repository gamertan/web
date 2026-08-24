#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
usage(){ echo "Usage: export-public.sh OUTPUT_DIRECTORY" >&2; exit 2; }
[[ $# -eq 1 ]] || usage
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=$1
[[ $output = /* && $output != / && ! -e $output ]] || usage
cd "$root"
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || { echo "private source must be clean" >&2; exit 1; }
files=()
while IFS= read -r file; do
	files+=("$file")
done < <(grep -Ev '^[[:space:]]*(#|$)' scripts/public-snapshot.allow)
[[ ${#files[@]} -gt 0 ]] || exit 1
for file in "${files[@]}"; do
	[[ $file != /* && $file != *..* ]] || { echo "invalid allowlisted path: $file" >&2; exit 1; }
	if [[ $file = */ ]]; then
		directory=${file%/}
		[[ -d $directory && ! -L $directory ]] || { echo "invalid allowlisted directory: $file" >&2; exit 1; }
		[[ -n $(git ls-files -- "$directory/") ]] || { echo "empty allowlisted directory: $file" >&2; exit 1; }
	else
		[[ -f $file && ! -L $file ]] || { echo "invalid allowlisted path: $file" >&2; exit 1; }
		git ls-files --error-unmatch -- "$file" >/dev/null
	fi
done
mkdir -m 0700 "$output"
git archive --format=tar HEAD -- "${files[@]}" | tar -x -C "$output"
find "$output" -type d -exec chmod 0755 {} +
"$output/scripts/check-licenses.sh"
echo "exported ${#files[@]} reviewed paths"

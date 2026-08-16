# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $root
try {
    $failed = $false
    Get-ChildItem -Recurse -File | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
        if ($relative.StartsWith('.git/') -or $relative.StartsWith('LICENSES/') -or $relative -eq 'go.sum') { return }
        if ($relative.StartsWith('starters/') -or $relative.StartsWith('examples/')) { $expected = '0BSD' }
        elseif ($relative.StartsWith('scripts/') -or $relative.StartsWith('.gitea/') -or $relative.StartsWith('services/')) { $expected = 'AGPL-3.0-only' }
        else { $expected = 'MPL-2.0' }
        $header = (Get-Content -LiteralPath $_.FullName -TotalCount 5) -join "`n"
        if (-not $header.Contains("SPDX-License-Identifier: $expected")) {
            Write-Error "license mismatch: $relative expected $expected"
            $failed = $true
        }
    }
    if ($failed) { throw "license boundary failed" }

    $unformatted = & gofmt -l .
    if ($LASTEXITCODE -ne 0 -or $unformatted) { throw "gofmt check failed: $unformatted" }
    & go test ./...
    if ($LASTEXITCODE -ne 0) { throw "go test failed" }
    & go test -race ./...
    if ($LASTEXITCODE -ne 0) { throw "race test failed" }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet failed" }
    $build = Join-Path ([IO.Path]::GetTempPath()) ("gamertan-web-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $build | Out-Null
    try {
        & go build -trimpath -o (Join-Path $build 'basic.exe') ./starters/basic
        if ($LASTEXITCODE -ne 0) { throw "starter build failed" }
    } finally {
        Remove-Item -LiteralPath $build -Recurse -Force
    }
    & git diff --check
    if ($LASTEXITCODE -ne 0) { throw "git diff check failed" }
} finally {
    Pop-Location
}

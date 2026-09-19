param(
    [switch]$Debug,
    [ValidateSet('nsis', 'msi', 'all')]
    [string]$Bundle = 'all'
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$tauriDir = Join-Path $repo 'src-tauri'
$binaryDir = Join-Path $tauriDir 'binaries'
if (-not $tauriDir.StartsWith($repo, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resolved Tauri directory is outside the repository.'
}

$hostLine = rustc -vV | Select-String '^host: '
if (-not $hostLine) { throw 'Could not determine the Rust host target.' }
$target = $hostLine.Line.Substring(6).Trim()
$profile = if ($Debug) { 'debug' } else { 'release' }
$cargoArgs = @('build', '-p', 'workstation-elevated-helper')
if (-not $Debug) { $cargoArgs += '--release' }
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { throw 'Elevated helper build failed.' }

New-Item -ItemType Directory -Force -Path $binaryDir | Out-Null
$helperSource = Join-Path $repo "target\$profile\local-pilot-elevated-helper.exe"
$helperTarget = Join-Path $binaryDir "local-pilot-elevated-helper-$target.exe"
if (-not (Test-Path -LiteralPath $helperSource)) { throw "Missing helper binary: $helperSource" }
Copy-Item -LiteralPath $helperSource -Destination $helperTarget -Force

Push-Location $repo
try {
    pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    $tauriArgs = @('tauri', 'build', '--bundles', $Bundle, '--config', 'src-tauri/tauri.bundle.conf.json')
    if ($Debug) { $tauriArgs += '--debug' }
    & pnpm @tauriArgs
    if ($LASTEXITCODE -ne 0) { throw 'Tauri installer build failed.' }
} finally {
    Pop-Location
}

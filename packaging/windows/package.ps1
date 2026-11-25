#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$Version,
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if ([string]::IsNullOrWhiteSpace($Version)) {
    $manifest = Get-Content -LiteralPath (Join-Path $repoRoot 'Cargo.toml') -Raw
    if ($manifest -match '(?ms)^\[workspace\.package\]\s.*?^version\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    } else {
        throw 'Could not read version from workspace Cargo.toml.'
    }
}

if ($Version -notmatch '^[0-9A-Za-z.+_-]+$') {
    throw "Invalid version string: $Version"
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $repoRoot 'dist'
}

$required = @(
    $Binary,
    (Join-Path $repoRoot 'README.md'),
    (Join-Path $repoRoot 'packaging\NOTICE.md'),
    (Join-Path $repoRoot 'packaging\windows\p2p-messenger.wxs')
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing required file: $path"
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("p2p-windows-package-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null

function Write-Sha256([string]$path) {
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = [System.IO.Path]::GetFileName($path)
    Set-Content -LiteralPath "$path.sha256" -Value "$hash  $name" -Encoding ascii
}

try {
    $exePath = Join-Path $stage 'p2p-desktop.exe'
    Copy-Item -LiteralPath $Binary -Destination $exePath
    Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination (Join-Path $stage 'README.md')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'packaging\NOTICE.md') -Destination (Join-Path $stage 'NOTICE.md')

    if (-not [string]::IsNullOrWhiteSpace($env:WINDOWS_SIGNING_THUMBPRINT)) {
        $signtool = (Get-Command signtool.exe -ErrorAction Stop).Source
        & $signtool sign /sha1 $env:WINDOWS_SIGNING_THUMBPRINT /fd SHA256 `
            /tr http://timestamp.digicert.com /td SHA256 $exePath
        if ($LASTEXITCODE -ne 0) { throw 'Failed to sign p2p-desktop.exe.' }
    } else {
        Write-Host 'No WINDOWS_SIGNING_THUMBPRINT set: producing an unsigned executable and MSI.'
    }

    $base = "p2p-messenger-$Version-windows-x86_64"
    $zipPath = Join-Path $OutDir "$base.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force

    $wix = $env:WIX
    if ([string]::IsNullOrWhiteSpace($wix)) {
        throw 'WIX environment variable is not set. Install WiX Toolset 3.x.'
    }
    $candle = Join-Path $wix 'bin\candle.exe'
    $light = Join-Path $wix 'bin\light.exe'
    foreach ($tool in @($candle, $light)) {
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
            throw "WiX tool not found: $tool"
        }
    }

    $wxs = Join-Path $repoRoot 'packaging\windows\p2p-messenger.wxs'
    $wixobj = Join-Path $stage 'p2p-messenger.wixobj'
    & $candle -nologo "-dVersion=$Version" "-dSourceDir=$stage" $wxs -out $wixobj
    if ($LASTEXITCODE -ne 0) { throw 'WiX compilation failed.' }

    $msiPath = Join-Path $OutDir "$base.msi"
    & $light -nologo $wixobj -o $msiPath
    if ($LASTEXITCODE -ne 0) { throw 'WiX linking failed.' }

    if (-not [string]::IsNullOrWhiteSpace($env:WINDOWS_SIGNING_THUMBPRINT)) {
        & $signtool sign /sha1 $env:WINDOWS_SIGNING_THUMBPRINT /fd SHA256 `
            /tr http://timestamp.digicert.com /td SHA256 $msiPath
        if ($LASTEXITCODE -ne 0) { throw 'Failed to sign the MSI.' }
    }

    Write-Sha256 $zipPath
    Write-Sha256 $msiPath

    Write-Host "Created: $zipPath"
    Write-Host "Created: $msiPath"
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}

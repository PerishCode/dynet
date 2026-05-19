$ErrorActionPreference = 'Stop'

$command = if ($args.Length -gt 0) { $args[0] } else { 'install' }
$remaining = if ($args.Length -gt 1) { $args[1..($args.Length - 1)] } else { @() }

$channel = if ($env:DYNET_CHANNEL) { $env:DYNET_CHANNEL } else { 'stable' }
$version = if ($env:DYNET_VERSION) { $env:DYNET_VERSION } else { '' }
$publicUrl = if ($env:DYNET_RELEASES_PUBLIC_URL) { $env:DYNET_RELEASES_PUBLIC_URL } else { '' }
$installRoot = if ($env:DYNET_INSTALL_ROOT) { $env:DYNET_INSTALL_ROOT } else { Join-Path $env:LOCALAPPDATA 'dynet' }
$localBinDir = if ($env:DYNET_LOCAL_BIN_DIR) { $env:DYNET_LOCAL_BIN_DIR } else { Join-Path $env:USERPROFILE '.local\bin' }

for ($i = 0; $i -lt $remaining.Length; $i++) {
    $arg = $remaining[$i]
    switch -Regex ($arg) {
        '^--channel$' { $i++; $channel = $remaining[$i]; continue }
        '^--channel=(.+)$' { $channel = $Matches[1]; continue }
        '^--version$' { $i++; $version = $remaining[$i]; continue }
        '^--version=(.+)$' { $version = $Matches[1]; continue }
        '^--public-url$' { $i++; $publicUrl = $remaining[$i]; continue }
        '^--public-url=(.+)$' { $publicUrl = $Matches[1]; continue }
        '^--install-root$' { $i++; $installRoot = $remaining[$i]; continue }
        '^--install-root=(.+)$' { $installRoot = $Matches[1]; continue }
        '^--bin-dir$' { $i++; $localBinDir = $remaining[$i]; continue }
        '^--bin-dir=(.+)$' { $localBinDir = $Matches[1]; continue }
        '^(-h|--help|help)$' {
            @'
dynet installer

Usage:
  install.ps1 install [--channel stable|beta] [--version vX.Y.Z] [--public-url <url>]
  install.ps1 upgrade [--channel stable|beta] [--version vX.Y.Z] [--public-url <url>]
  install.ps1 uninstall

Environment:
  DYNET_RELEASES_PUBLIC_URL
  DYNET_CHANNEL
  DYNET_VERSION
  DYNET_INSTALL_ROOT
  DYNET_LOCAL_BIN_DIR
'@ | Write-Output
            exit 0
        }
        default { throw "unknown argument: $arg" }
    }
}

function Require-PublicUrl {
    if ([string]::IsNullOrWhiteSpace($publicUrl)) {
        throw 'DYNET_RELEASES_PUBLIC_URL or --public-url is required'
    }
    $script:publicUrl = $publicUrl.TrimEnd('/')
}

function Install-Dynet {
    Require-PublicUrl
    if ([string]::IsNullOrWhiteSpace($version)) {
        $metadataUrl = "$publicUrl/$channel/latest/metadata.json"
        $metadata = Invoke-RestMethod -Uri $metadataUrl
        $script:version = $metadata.releaseVersion
        if ([string]::IsNullOrWhiteSpace($version)) {
            throw 'failed to resolve latest dynet version'
        }
    }

    $archive = 'dynet-x86_64-pc-windows-msvc.zip'
    $tmpdir = Join-Path ([System.IO.Path]::GetTempPath()) ("dynet-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmpdir | Out-Null
    try {
        $archivePath = Join-Path $tmpdir $archive
        Invoke-WebRequest -Uri "$publicUrl/$channel/versions/$version/$archive" -OutFile $archivePath
        $versionRoot = Join-Path $installRoot $version
        New-Item -ItemType Directory -Force -Path $versionRoot | Out-Null
        Expand-Archive -LiteralPath $archivePath -DestinationPath $versionRoot -Force
        New-Item -ItemType Directory -Force -Path $localBinDir | Out-Null
        Copy-Item -Force (Join-Path $versionRoot 'dynet.exe') (Join-Path $localBinDir 'dynet.exe')
        & (Join-Path $localBinDir 'dynet.exe') --version
        Write-Output "installed dynet to $(Join-Path $localBinDir 'dynet.exe')"
    }
    finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmpdir
    }
}

function Uninstall-Dynet {
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $localBinDir 'dynet.exe')
    Write-Output "removed $(Join-Path $localBinDir 'dynet.exe')"
}

switch ($command) {
    'install' { Install-Dynet }
    'upgrade' { Install-Dynet }
    'uninstall' { Uninstall-Dynet }
    default { throw "unknown command: $command" }
}

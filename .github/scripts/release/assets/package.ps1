$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))))
$appDir = Join-Path $root 'crates/dynet-cli'
$name = 'dynet'
$cargoToml = Join-Path $appDir 'Cargo.toml'
$version = (Select-String -Path $cargoToml -Pattern '^version = "(.+)"$').Matches[0].Groups[1].Value
$releaseVersion = if ($args.Length -gt 0 -and -not [string]::IsNullOrWhiteSpace($args[0])) { $args[0] } elseif ($env:RELEASE_VERSION) { $env:RELEASE_VERSION } else { "v$version" }
$target = if ($env:TARGET) { $env:TARGET } else { 'x86_64-pc-windows-msvc' }
$distDir = if ($env:DIST_DIR) { $env:DIST_DIR } else { Join-Path $root 'dist' }
$artifactDir = Join-Path $distDir $releaseVersion

New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
$env:DYNET_BUILD_VERSION = $releaseVersion
cargo build --release --locked -p dynet-cli --target $target

$archive = "$name-$target.zip"
$tmpdir = Join-Path ([System.IO.Path]::GetTempPath()) ("$name-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpdir | Out-Null

try {
    $bin = Join-Path $root "target/$target/release/$name.exe"
    Copy-Item $bin (Join-Path $tmpdir "$name.exe")
    Compress-Archive -LiteralPath (Join-Path $tmpdir "$name.exe") -DestinationPath (Join-Path $artifactDir $archive) -Force
    Write-Output (Join-Path $artifactDir $archive)
}
finally {
    Remove-Item -LiteralPath $tmpdir -Recurse -Force -ErrorAction SilentlyContinue
}
